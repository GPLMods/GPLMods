// ===============================
// 1. IMPORTS
// ===============================
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const multer = require('multer');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const MongoStore = require('connect-mongo');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken'); 
const bodyParser = require('body-parser');
const { sendVerificationEmail } = require('./utils/mailer');

// AdminJS Setup Import
const setupAdmin = require('./config/admin');

// AWS SDK v3 Imports
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

// Mongoose Models
const File = require('./models/file');
const User = require('./models/user');
const Review = require('./models/review');
const Report = require('./models/report');

// ===============================
// 2. INITIALIZATION & CONFIGURATION
// ===============================
const app = express();
const PORT = process.env.PORT || 3000;
const { Types } = mongoose;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ===============================
// 3. MIDDLEWARE
// ===============================
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || 'a-very-secret-key-to-sign-the-cookie',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URI,
        collectionName: 'sessions'
    }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 } // 7 days
}));

app.use(passport.initialize());
app.use(passport.session());

// ===============================
// 4. AWS S3 CLIENT (BACKBLAZE B2)
// ===============================
const s3Client = new S3Client({
    endpoint: `https://${process.env.B2_ENDPOINT}`,
    region: process.env.B2_REGION,
    credentials: {
        accessKeyId: process.env.B2_ACCESS_KEY_ID,
        secretAccessKey: process.env.B2_SECRET_ACCESS_KEY,
    }
});

const sanitizeFilename = (filename) => filename.replace(/[^a-zA-Z0-9.-_]/g, '');

const uploadToB2 = async (file, folder) => {
    const sanitizedFilename = sanitizeFilename(file.originalname);
    const fileName = `${folder}/${Date.now()}-${sanitizedFilename}`;
    const params = { 
        Bucket: process.env.B2_BUCKET_NAME, 
        Key: fileName, 
        Body: file.buffer, 
        ContentType: file.mimetype 
    };
    await s3Client.send(new PutObjectCommand(params));
    return fileName;
};

// ===============================
// 5. DATABASE CONNECTION
// ===============================
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Successfully connected to MongoDB Atlas!'))
    .catch(error => console.error('MongoDB Connection Error:', error));

// ===============================
// 6. PASSPORT STRATEGIES
// ===============================

passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return done(null, false, { message: 'Incorrect email.' });
        
        const isMatch = await user.comparePassword(password);
        if (!isMatch) return done(null, false, { message: 'Incorrect password.' });
        
        if (!user.isVerified) return done(null, false, { message: 'Please verify your email before logging in.' });
        
        return done(null, user);
    } catch (e) { return done(e); }
}));

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback" 
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ email: profile.emails[0].value });
        if (user) return done(null, user);
        
        const username = profile.displayName;
        const existingUsername = await User.findOne({ username });
        const finalUsername = existingUsername ? `${username}${Math.floor(Math.random() * 1000)}` : username;
        
        user = await User.create({
            googleId: profile.id, 
            username: finalUsername,
            email: profile.emails[0].value, 
            isVerified: true 
        });
        done(null, user);
    } catch (err) { done(err, null); }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try { const user = await User.findById(id); done(null, user); } catch (e) { done(e); }
});

app.use((req, res, next) => {
    res.locals.user = req.user || null;
    next();
});

// --- SETUP ADMINJS ---
// Attached after session/passport but before general routes
setupAdmin(app);

// Auth Helpers
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

function ensureAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') return next();
    res.status(403).send("Forbidden: Admins only.");
}

async function verifyRecaptcha(req, res, next) {
    const token = req.body['g-recaptcha-response'];
    if (!token) return res.status(400).send("Complete CAPTCHA verification.");
    try {
        const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${token}`);
        if (response.data.success) return next();
        res.status(400).send("CAPTCHA verification failed.");
    } catch (e) { res.status(500).send("reCAPTCHA Error."); }
}

// ===============================
// 7. CORE APP ROUTES
// ===============================

app.get('/', async (req, res) => {
    try {
        const recentFiles = await File.find({ isLatestVersion: true }).sort({ createdAt: -1 }).limit(12);
        const filesWithUrls = await Promise.all(recentFiles.map(async (file) => {
            const iconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: file.iconKey }), { expiresIn: 3600 });
            return { ...file.toObject(), iconUrl };
        }));
        res.render('pages/index', { files: filesWithUrls });
    } catch (e) { 
        console.error("Homepage Error:", e);
        res.status(500).send("Server error."); 
    }
});

app.get('/category', async (req, res) => {
    try {
        const { cat } = req.query;
        if (!cat) return res.redirect('/');
        const filteredFiles = await File.find({ category: cat, isLatestVersion: true }).sort({ createdAt: -1 });
        const pageTitle = cat.charAt(0).toUpperCase() + cat.slice(1);
        const filesWithUrls = await Promise.all(filteredFiles.map(async (file) => {
            const iconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: file.iconKey }), { expiresIn: 3600 });
            return { ...file.toObject(), iconUrl };
        }));
        res.render('pages/category', { files: filesWithUrls, title: pageTitle, currentCategory: cat });
    } catch (e) { 
        console.error("Category Error:", e);
        res.status(500).send("Category error."); 
    }
});

app.get('/search', async (req, res) => {
    try {
        const query = req.query.q;
        if (!query) return res.redirect('/');
        const results = await File.find({
            isLatestVersion: true,
            $or: [
                { name: { $regex: query, $options: 'i' } },
                { modDescription: { $regex: query, $options: 'i' } },
                { tags: { $regex: query, $options: 'i' } }
            ]
        }).sort({ createdAt: -1 });
        res.render('pages/search', { results, query });
    } catch (e) { 
        console.error("Search Error:", e);
        res.status(500).send("Search Error"); 
    }
});

app.get('/mods/:id', async (req, res) => {
    try {
        const fileId = req.params.id;
        if (!Types.ObjectId.isValid(fileId)) return res.status(404).send("File not found.");

        let currentFile = await File.findById(fileId);
        if (!currentFile) return res.status(404).send("File not found.");

        let versionHistory = [];
        if (currentFile.parentFile) {
            let headFile = await File.findById(currentFile.parentFile).populate('olderVersions');
            versionHistory = [headFile, ...headFile.olderVersions.slice().reverse()]; 
            currentFile = headFile;
        } else {
            await currentFile.populate('olderVersions');
            versionHistory = [currentFile, ...currentFile.olderVersions.slice().reverse()];
        }

        const iconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: currentFile.iconKey }), { expiresIn: 3600 });
        const screenshotUrls = await Promise.all(currentFile.screenshotKeys.map(key => getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 })));

        const reviews = await Review.find({ file: currentFile._id }).sort({ createdAt: -1 });
        const userHasWhitelisted = req.user ? req.user.whitelist.includes(currentFile._id) : false;
        const userHasVotedOnStatus = req.user ? currentFile.votedOnStatusBy.includes(req.user._id) : false;
        
        res.render('pages/download', { 
            file: { ...currentFile.toObject(), iconUrl, screenshotUrls }, 
            versionHistory, reviews, userHasWhitelisted, userHasVotedOnStatus 
        });
    } catch (e) { 
        console.error("Download Page Error:", e);
        res.status(500).send("Server error."); 
    }
});

// ===============================
// 8. AUTHENTICATION ROUTES
// ===============================

app.get('/login', (req, res) => res.render('pages/login', { recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY }));
app.post('/login', verifyRecaptcha, passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' }));

app.get('/register', (req, res) => res.render('pages/register', { recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY }));
app.post('/register', verifyRecaptcha, async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) return res.status(400).send("All fields are required.");

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            if (existingUser.isVerified) return res.status(400).send("A verified user with this email already exists.");
            
            const token = jwt.sign({ userId: existingUser._id }, process.env.JWT_SECRET || 'fallback', { expiresIn: '1d' });
            existingUser.verificationToken = token;
            await existingUser.save();
            await sendVerificationEmail(existingUser);
            return res.render('pages/please-verify');
        }

        const newUser = new User({ username, email: email.toLowerCase(), password });
        const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET || 'fallback', { expiresIn: '1d' });
        newUser.verificationToken = token;
        await newUser.save();
        await sendVerificationEmail(newUser);
        res.render('pages/please-verify');
    } catch (e) { 
        console.error("Registration Error:", e);
        res.status(500).send("Registration error."); 
    }
});

app.get('/verify-email', async (req, res) => {
    try {
        const decoded = jwt.verify(req.query.token, process.env.JWT_SECRET || 'fallback');
        const user = await User.findOne({ _id: decoded.userId, verificationToken: req.query.token });
        if (!user) return res.status(400).send('Invalid or expired token.');
        
        user.isVerified = true;
        user.verificationToken = undefined;
        await user.save();
        req.login(user, () => res.redirect('/profile'));
    } catch (e) { res.status(400).send('Expired or invalid token.'); }
});

app.get('/logout', (req, res, next) => {
    req.logout(err => { if (err) return next(err); res.redirect('/'); });
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => res.redirect('/profile'));

// ===============================
// 9. PROFILE & ACCOUNT MGMT
// ===============================

app.get('/profile', ensureAuthenticated, async (req, res) => {
    try {
        const userWithWhitelist = await User.findById(req.user._id).populate('whitelist');
        const userUploads = await File.find({ uploader: req.user.username, isLatestVersion: true }).sort({ createdAt: -1 });
        res.render('pages/profile', { user: userWithWhitelist, uploads: userUploads });
    } catch (e) { res.status(500).send('Profile fetch error.'); }
});

app.post('/account/delete', ensureAuthenticated, async (req, res, next) => {
    try {
        await File.deleteMany({ uploader: req.user.username });
        await Review.deleteMany({ user: req.user._id });
        await User.findByIdAndDelete(req.user._id);
        req.logout(err => res.redirect('/'));
    } catch (e) { res.status(500).send('Account deletion failed.'); }
});

// ===============================
// 10. FILE MGMT & VERSIONING
// ===============================

const storage = multer.memoryStorage();
const upload = multer({ storage: storage, limits: { fileSize: 100 * 1024 * 1024 } });

app.get('/upload', ensureAuthenticated, (req, res) => res.render('pages/upload'));
app.post('/upload', ensureAuthenticated, upload.fields([{ name: 'softwareIcon', maxCount: 1 }, { name: 'screenshots', maxCount: 4 }, { name: 'modFile', maxCount: 1 }]), async (req, res) => {
    try {
        const { softwareName, softwareVersion, modDescription, officialDescription, category, platforms, tags, videoUrl } = req.body;
        const { softwareIcon, screenshots, modFile } = req.files;

        if (!softwareIcon || !screenshots || !modFile || !softwareName || !category) { 
            return res.status(400).send("A required field or file is missing."); 
        }

        const iconKey = await uploadToB2(softwareIcon[0], 'icons');
        const screenshotKeys = await Promise.all(screenshots.map(f => uploadToB2(f, 'screenshots')));
        const fileKey = await uploadToB2(modFile[0], 'mods');

        let analysisId = null;
        try {
            const formData = new FormData();
            formData.append('file', new Blob([modFile[0].buffer]), modFile[0].originalname);
            const vt = await axios.post('https://www.virustotal.com/api/v3/files', formData, { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY } });
            analysisId = vt.data.data.id;
        } catch (vtE) { console.error("VirusTotal API check failed."); }

        const newFile = new File({
            name: softwareName, version: softwareVersion, modDescription, officialDescription,
            iconKey, screenshotKeys, videoUrl, fileKey, originalFilename: modFile[0].originalname,
            category, platforms: Array.isArray(platforms) ? platforms : [platforms],
            tags: tags ? tags.split(',').map(t => t.trim()) : [],
            uploader: req.user.username, fileSize: modFile[0].size,
            virusTotalAnalysisId: analysisId, isLatestVersion: true
        });
        await newFile.save();
        res.redirect(`/mods/${newFile._id}`);
    } catch (e) { 
        console.error("Upload Error:", e);
        res.status(500).send("Upload failed."); 
    }
});

app.get('/mods/:id/add-version', ensureAuthenticated, async (req, res) => {
    const parentFile = await File.findById(req.params.id);
    if (!parentFile) return res.status(404).send("File not found.");
    if (req.user.username !== parentFile.uploader) return res.status(403).send("Forbidden: Not your file.");
    res.render('pages/add-version', { parentFile });
});

app.post('/mods/:id/add-version', ensureAuthenticated, upload.single('modFile'), async (req, res) => {
    try {
        const headFile = await File.findById(req.params.id);
        if (!headFile) return res.status(404).send("Original file not found.");
        if (req.user.username !== headFile.uploader) return res.status(403).send("Forbidden.");
        
        const fileKey = await uploadToB2(req.file, 'mods');
        const newVersion = new File({
            ...headFile.toObject(), 
            _id: new Types.ObjectId(),
            version: req.body.softwareVersion, 
            fileKey, 
            originalFilename: req.file.originalname,
            fileSize: req.file.size, 
            isLatestVersion: false, 
            parentFile: headFile._id, 
            olderVersions: []
        });
        await newVersion.save();
        await File.findByIdAndUpdate(req.params.id, { $push: { olderVersions: newVersion._id } });
        res.redirect(`/mods/${headFile._id}`);
    } catch (e) { res.status(500).send("Version addition failed."); }
});

app.get('/download-file/:id', async (req, res) => {
    try {
        const file = await File.findByIdAndUpdate(req.params.id, { $inc: { downloads: 1 } });
        if (!file) return res.status(404).send("File not found.");

        const url = await getSignedUrl(s3Client, new GetObjectCommand({ 
            Bucket: process.env.B2_BUCKET_NAME, 
            Key: file.fileKey, 
            ResponseContentDisposition: `attachment; filename="${file.originalFilename}"` 
        }), { expiresIn: 300 }); 
        res.redirect(url);
    } catch (e) { res.status(500).send("Download generation error."); }
});

// ===============================
// 11. SOCIAL & INTERACTION
// ===============================

app.post('/files/:fileId/whitelist', ensureAuthenticated, async (req, res) => {
    try {
        const isWhitelisted = req.user.whitelist.includes(req.params.fileId);
        const update = isWhitelisted ? { $pull: { whitelist: req.params.fileId } } : { $push: { whitelist: req.params.fileId } };
        const fileUpdate = isWhitelisted ? { $inc: { whitelistCount: -1 } } : { $inc: { whitelistCount: 1 } };
        await User.findByIdAndUpdate(req.user._id, update);
        await File.findByIdAndUpdate(req.params.fileId, fileUpdate);
        res.redirect(`/mods/${req.params.fileId}`);
    } catch (e) { res.status(500).send("Whitelist error."); }
});

app.post('/reviews/add/:fileId', ensureAuthenticated, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        if (!rating || !comment) return res.status(400).send("Missing review fields.");
        
        const existing = await Review.findOne({ file: req.params.fileId, user: req.user._id });
        if (existing) return res.redirect(`/mods/${req.params.fileId}`);

        const newReview = new Review({ file: req.params.fileId, user: req.user._id, username: req.user.username, rating: parseInt(rating), comment });
        await newReview.save();

        const stats = await Review.aggregate([{ $match: { file: new Types.ObjectId(req.params.fileId) } }, { $group: { _id: '$file', avg: { $avg: '$rating' }, count: { $sum: 1 } } }]);
        if (stats.length > 0) {
            await File.findByIdAndUpdate(req.params.fileId, { averageRating: stats[0].avg.toFixed(1), ratingCount: stats[0].count });
        }
        res.redirect(`/mods/${req.params.fileId}`);
    } catch (e) { res.status(500).send("Review submission error."); }
});

app.post('/reviews/:reviewId/vote', ensureAuthenticated, async (req, res) => {
    const review = await Review.findById(req.params.reviewId);
    if (review && !review.votedBy.includes(req.user._id)) {
        review.votedBy.push(req.user._id);
        review.isHelpfulCount += 1;
        await review.save();
    }
    res.redirect(`/mods/${review.file}`);
});

app.post('/files/:fileId/vote-status', ensureAuthenticated, async (req, res) => {
    try {
        const { voteType } = req.body;
        if (!['working', 'not-working'].includes(voteType)) return res.status(400).send("Invalid vote type.");
        
        const file = await File.findById(req.params.fileId);
        if (file && !file.votedOnStatusBy.includes(req.user._id)) {
            const update = voteType === 'working' ? { $inc: { workingVoteCount: 1 } } : { $inc: { notWorkingVoteCount: 1 } };
            await File.findByIdAndUpdate(req.params.fileId, { ...update, $push: { votedOnStatusBy: req.user._id } });
        }
        res.redirect(`/mods/${req.params.fileId}`);
    } catch (e) { res.status(500).send("Voting error."); }
});

// ===============================
// 12. REPORTING & ADMIN
// ===============================

app.post('/files/:fileId/report', ensureAuthenticated, async (req, res) => {
    try {
        const { reason, additionalComments } = req.body;
        if (!reason) return res.status(400).send("Reason required.");
        
        const file = await File.findById(req.params.fileId);
        const existing = await Report.findOne({ file: req.params.fileId, reportingUser: req.user._id });
        if (!existing && file) {
            await new Report({ file: req.params.fileId, reportingUser: req.user._id, reportedFileName: file.name, reportingUsername: req.user.username, reason, additionalComments }).save();
        }
        res.redirect(`/mods/${req.params.fileId}?reported=true`);
    } catch (e) { res.status(500).send("Reporting error."); }
});

app.get('/admin/reports', ensureAuthenticated, ensureAdmin, async (req, res) => {
    try {
        const reports = await Report.find().populate('file').populate('reportingUser').sort({ status: 1, createdAt: -1 });
        res.render('pages/admin/reports', { reports });
    } catch (e) { res.status(500).send("Admin access error."); }
});

app.get('/api/search/suggestions', async (req, res) => {
    try {
        const query = req.query.q;
        if (!query || query.length < 2) return res.json([]);
        const suggestions = await File.find({ name: { $regex: `^${query}`, $options: 'i' }, isLatestVersion: true }).limit(10);
        res.json(suggestions.map(f => f.name));
    } catch (e) { res.status(500).json([]); }
});

// ===============================
// 13. STATIC PAGES & START
// ===============================
app.get('/about', (req, res) => res.render('pages/static/about'));
app.get('/faq', (req, res) => res.render('pages/static/faq'));
app.get('/tos', (req, res) => res.render('pages/static/tos'));
app.get('/dmca', (req, res) => res.render('pages/static/dmca'));

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));