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
const { sendVerificationEmail } = require('./utils/mailer');

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

// Set View Engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ===============================
// 3. AWS S3 CLIENT (BACKBLAZE B2)
// ===============================
const s3Client = new S3Client({
    endpoint: `https://${process.env.B2_ENDPOINT}`,
    region: process.env.B2_REGION,
    credentials: {
        accessKeyId: process.env.B2_ACCESS_KEY_ID,
        secretAccessKey: process.env.B2_SECRET_ACCESS_KEY,
    }
});

/**
 * HELPER: Sanitize filenames for S3
 */
const sanitizeFilename = (filename) => {
    return filename.replace(/[^a-zA-Z0-9.-_]/g, '');
};

/**
 * HELPER: Upload buffer to Backblaze B2
 */
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
// 4. DATABASE CONNECTION
// ===============================
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Successfully connected to MongoDB Atlas!'))
    .catch(error => console.error('Error connecting to MongoDB Atlas:', error));

// ===============================
// 5. SESSION & PASSPORT CONFIG
// ===============================
app.use(session({
    secret: process.env.SESSION_SECRET || 'a-very-secret-key-to-sign-the-cookie',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGO_URI,
        collectionName: 'sessions'
    }),
    cookie: {
        maxAge: 1000 * 60 * 60 * 24 * 7 // 7 days
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// --- PASSPORT.JS LOCAL STRATEGY ---
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) { return done(null, false, { message: 'Incorrect email.' }); }
        
        const isMatch = await user.comparePassword(password);
        if (!isMatch) { return done(null, false, { message: 'Incorrect password.' }); }

        if (!user.isVerified) {
            return done(null, false, { message: 'Please verify your email before logging in.' });
        }

        return done(null, user);
    } catch (error) {
        return done(error);
    }
}));

// --- PASSPORT.JS GOOGLE OAUTH STRATEGY ---
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback" 
},
async (accessToken, refreshToken, profile, done) => {
    const newUser = {
        googleId: profile.id,
        username: profile.displayName,
        email: profile.emails[0].value,
        isVerified: true // Accounts from Google are pre-verified
    };

    try {
        let user = await User.findOne({ email: profile.emails[0].value });

        if (user) {
            done(null, user);
        } else {
            const existingUsername = await User.findOne({ username: newUser.username });
            if (existingUsername) {
                newUser.username = `${newUser.username}${Math.floor(Math.random() * 1000)}`;
            }
            user = await User.create(newUser);
            done(null, user);
        }
    } catch (err) {
        done(err, null);
    }
}));

passport.serializeUser((user, done) => { done(null, user.id); });

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error);
    }
});

app.use((req, res, next) => {
    res.locals.user = req.user || null;
    next();
});

// Middleware Helpers
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) { return next(); }
    res.redirect('/login');
}

function ensureAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') {
        return next();
    }
    res.status(403).send("Forbidden: You do not have permission to access this page.");
}

// --- MIDDLEWARE TO VERIFY reCAPTCHA ---
async function verifyRecaptcha(req, res, next) {
    const token = req.body['g-recaptcha-response'];

    if (!token) {
        return res.status(400).send("Please complete the CAPTCHA verification.");
    }
    
    const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${token}`;

    try {
        const response = await axios.post(verificationUrl);
        const { success } = response.data;
        
        if (success) {
            return next();
        } else {
            return res.status(400).send("Failed CAPTCHA verification. Please try again.");
        }
    } catch (error) {
        console.error("reCAPTCHA verification error:", error);
        return res.status(500).send("Server error during CAPTCHA verification.");
    }
}

// ===================================
// 6. STATIC & INFORMATIONAL PAGES
// ===================================

app.get('/about', (req, res) => {
    res.render('pages/static/about');
});

app.get('/faq', (req, res) => {
    res.render('pages/static/faq');
});

app.get('/tos', (req, res) => {
    res.render('pages/static/tos');
});

app.get('/dmca', (req, res) => {
    res.render('pages/static/dmca');
});

// ===============================
// 7. CORE APP ROUTES
// ===============================

// --- INDEX PAGE ---
app.get('/', async (req, res) => {
    try {
        const recentFiles = await File.find({ isLatestVersion: true }).sort({ createdAt: -1 }).limit(12);
        const filesWithUrls = await Promise.all(recentFiles.map(async (file) => {
            const getIconUrlCommand = new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: file.iconKey });
            const iconUrl = await getSignedUrl(s3Client, getIconUrlCommand, { expiresIn: 3600 });
            return { ...file.toObject(), iconUrl };
        }));
        res.render('pages/index', { files: filesWithUrls });
    } catch (error) {
        console.error("Error fetching files for homepage:", error);
        res.status(500).send("Server error.");
    }
});

// --- CATEGORY PAGE ---
app.get('/category', async (req, res) => {
    try {
        const { cat } = req.query;
        if (!cat) { return res.redirect('/'); }
        const filteredFiles = await File.find({ category: cat, isLatestVersion: true }).sort({ createdAt: -1 });
        const pageTitle = cat.charAt(0).toUpperCase() + cat.slice(1);
        const filesWithUrls = await Promise.all(filteredFiles.map(async (file) => {
            const getIconUrlCommand = new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: file.iconKey });
            const iconUrl = await getSignedUrl(s3Client, getIconUrlCommand, { expiresIn: 3600 });
            return { ...file.toObject(), iconUrl };
        }));
        res.render('pages/category', { files: filesWithUrls, title: pageTitle, currentCategory: cat });
    } catch (error) {
        console.error("Error fetching files for category page:", error);
        res.status(500).send("Server error.");
    }
});

// --- INDIVIDUAL MOD/DOWNLOAD PAGE ---
app.get('/mods/:id', async (req, res) => {
    try {
        const fileId = req.params.id;
        if (!Types.ObjectId.isValid(fileId)) { return res.status(404).send("File not found."); }

        let currentFile = await File.findById(fileId);
        if (!currentFile) { return res.status(404).send("File not found."); }

        let versionHistory = [];
        if (currentFile.parentFile) {
            let headFile = await File.findById(currentFile.parentFile).populate('olderVersions');
            versionHistory = [headFile, ...headFile.olderVersions.slice().reverse()]; 
            currentFile = headFile;
        } else {
            await currentFile.populate('olderVersions');
            versionHistory = [currentFile, ...currentFile.olderVersions.slice().reverse()];
        }

        const iconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ 
            Bucket: process.env.B2_BUCKET_NAME, Key: currentFile.iconKey 
        }), { expiresIn: 3600 });

        const screenshotUrls = await Promise.all(
            currentFile.screenshotKeys.map(key => getSignedUrl(s3Client, new GetObjectCommand({ 
                Bucket: process.env.B2_BUCKET_NAME, Key: key 
            }), { expiresIn: 3600 }))
        );

        const reviews = await Review.find({ file: currentFile._id }).sort({ createdAt: -1 });

        let userHasWhitelisted = false;
        if (req.user) {
            userHasWhitelisted = req.user.whitelist.includes(currentFile._id);
        }

        let userHasVotedOnStatus = false;
        if (req.user && currentFile.votedOnStatusBy) {
            userHasVotedOnStatus = currentFile.votedOnStatusBy.includes(req.user._id);
        }
        
        res.render('pages/download', { 
            file: { ...currentFile.toObject(), iconUrl, screenshotUrls }, 
            versionHistory,
            reviews,
            userHasWhitelisted: userHasWhitelisted,
            userHasVotedOnStatus: userHasVotedOnStatus
        });
    } catch (error) {
        console.error("Error fetching file for download page:", error);
        res.status(500).send("Server error.");
    }
});

// --- SEARCH ROUTE ---
app.get('/search', async (req, res) => {
    try {
        const query = req.query.q;
        if (!query) { return res.redirect('/'); }
        
        const searchResults = await File.find({
            isLatestVersion: true,
            $or: [
                { name: { $regex: query, $options: 'i' } },
                { modDescription: { $regex: query, $options: 'i' } },
                { tags: { $regex: query, $options: 'i' } }
            ]
        }).sort({ createdAt: -1 });

        res.render('pages/search', { results: searchResults, query: query });
    } catch (error) {
        console.error("Error during search:", error);
        res.status(500).send("Server Error");
    }
});

// ===============================
// 8. AUTHENTICATION ROUTES
// ===============================

// --- GOOGLE OAUTH ROUTES ---
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        res.redirect('/profile'); 
    });

// --- LOCAL AUTH ROUTES ---
app.get('/register', (req, res) => {
    res.render('pages/register', {
        recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY
    });
});

app.post('/register', verifyRecaptcha, async (req, res, next) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).send("All fields are required.");
        }

        const existingUser = await User.findOne({ email: email.toLowerCase() });

        if (existingUser) {
            if (existingUser.isVerified) {
                return res.status(400).send("A user with this email address already exists and is verified.");
            } else {
                const verificationToken = jwt.sign(
                    { userId: existingUser._id },
                    process.env.JWT_SECRET || 'fallback_secret', 
                    { expiresIn: '1d' }
                );

                existingUser.verificationToken = verificationToken;
                await existingUser.save(); 

                await sendVerificationEmail(existingUser);
                return res.render('pages/please-verify');
            }
        }
        
        const newUser = new User({ username, email: email.toLowerCase(), password });
        
        const verificationToken = jwt.sign(
            { userId: newUser._id },
            process.env.JWT_SECRET || 'fallback_secret',
            { expiresIn: '1d' }
        );

        newUser.verificationToken = verificationToken;
        await newUser.save();
        
        await sendVerificationEmail(newUser);
        res.render('pages/please-verify');

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).send("Server error during registration.");
    }
});

app.get('/verify-email', async (req, res, next) => {
    try {
        const { token } = req.query;
        if (!token) { return res.status(400).send('Verification token is missing.'); }

        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
        const user = await User.findOne({ _id: decoded.userId, verificationToken: token });

        if (!user) { return res.status(400).send('Invalid or expired verification link.'); }
        
        user.isVerified = true;
        user.verificationToken = undefined;
        await user.save();
        
        req.login(user, (err) => {
            if (err) { return next(err); }
            return res.redirect('/profile'); 
        });
    } catch (error) {
        console.error("Verification error:", error);
        res.status(400).send('Invalid or expired token.');
    }
});

app.get('/login', (req, res) => {
    res.render('pages/login', {
        recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY
    });
});

app.post('/login', verifyRecaptcha, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login'
}));

app.get('/logout', (req, res, next) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

// ===============================
// 9. USER PROFILE & MANAGEMENT
// ===============================

app.get('/profile', ensureAuthenticated, async (req, res) => {
    try {
        const userWithWhitelist = await User.findById(req.user._id).populate('whitelist');
        const userUploads = await File.find({ uploader: req.user.username, isLatestVersion: true })
                                      .sort({ createdAt: -1 });

        res.render('pages/profile', {
            user: userWithWhitelist, 
            uploads: userUploads
        });
    } catch (error) {
        console.error("Error fetching profile:", error);
        res.status(500).send('Server Error');
    }
});

app.post('/account/delete', ensureAuthenticated, async (req, res, next) => {
    try {
        const userId = req.user._id;
        const username = req.user.username;
        await File.deleteMany({ uploader: username });
        await Review.deleteMany({ user: userId });
        await User.findByIdAndDelete(userId);
        req.logout(err => {
            if (err) return next(err);
            res.redirect('/');
        });
    } catch (error) {
        res.status(500).send('Could not delete account.');
    }
});

// ===============================
// 10. FILE MANAGEMENT & VERSIONING
// ===============================

const storage = multer.memoryStorage();
const upload = multer({ storage: storage, limits: { fileSize: 100 * 1024 * 1024 } });

app.get('/upload', ensureAuthenticated, (req, res) => {
    res.render('pages/upload');
});

app.post('/upload', ensureAuthenticated, upload.fields([
    { name: 'softwareIcon', maxCount: 1 },
    { name: 'screenshots', maxCount: 4 },
    { name: 'modFile', maxCount: 1 }
]), async (req, res) => {
    const { softwareIcon, screenshots, modFile } = req.files;
    const { softwareName, softwareVersion, modDescription, officialDescription, category, platforms, tags, videoUrl } = req.body;
    
    if (!softwareIcon || !screenshots || !modFile || !softwareName || !category) { 
        return res.status(400).send("A required field or file is missing."); 
    }

    try {
        const iconKey = await uploadToB2(softwareIcon[0], 'icons');
        const screenshotKeys = await Promise.all(screenshots.map(file => uploadToB2(file, 'screenshots')));
        const fileKey = await uploadToB2(modFile[0], 'mods');
        
        let analysisId = null;
        try {
            const formData = new FormData();
            formData.append('file', new Blob([modFile[0].buffer]), modFile[0].originalname);
            const vtResponse = await axios.post('https://www.virustotal.com/api/v3/files', formData, { 
                headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
            });
            analysisId = vtResponse.data.data.id;
        } catch (vtError) {
            console.error("VirusTotal submission failed.");
        }

        const newFile = new File({
            name: softwareName, version: softwareVersion, modDescription, officialDescription,
            iconKey, screenshotKeys, videoUrl, fileKey, originalFilename: modFile[0].originalname,
            category, platforms: Array.isArray(platforms) ? platforms : [platforms],
            tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
            uploader: req.user.username,
            fileSize: modFile[0].size,
            virusTotalAnalysisId: analysisId,
            isLatestVersion: true
        });

        await newFile.save();
        res.redirect(`/mods/${newFile._id}`);
    } catch (error) {
        console.error("Upload process failed:", error);
        res.status(500).send("An error occurred during the upload process.");
    }
});

app.get('/mods/:id/add-version', ensureAuthenticated, async (req, res) => {
    try {
        const parentFile = await File.findById(req.params.id);
        if (!parentFile) return res.status(404).send("File not found.");

        if (req.user.username !== parentFile.uploader) {
            return res.status(403).send("Forbidden: You can only add versions to your own uploads.");
        }

        res.render('pages/add-version', { parentFile });
    } catch (error) {
        console.error('Error loading add-version page:', error);
        res.status(500).send('Server Error');
    }
});

app.post('/mods/:id/add-version', ensureAuthenticated, upload.single('modFile'), async (req, res) => {
    try {
        const parentFileId = req.params.id;
        const headFile = await File.findById(parentFileId);

        if (!headFile) return res.status(404).send("Original file not found.");
        if (req.user.username !== headFile.uploader) {
            return res.status(403).send("Forbidden.");
        }
        
        const fileKey = await uploadToB2(req.file, 'mods');
        
        const newVersion = new File({
            name: headFile.name,
            iconKey: headFile.iconKey,
            screenshotKeys: headFile.screenshotKeys,
            modDescription: headFile.modDescription,
            officialDescription: headFile.officialDescription,
            category: headFile.category,
            platforms: headFile.platforms,
            tags: headFile.tags,
            uploader: headFile.uploader,
            version: req.body.softwareVersion,
            fileKey: fileKey,
            originalFilename: req.file.originalname,
            fileSize: req.file.size,
            isLatestVersion: false, 
            parentFile: headFile._id
        });
        
        await newVersion.save();
        
        await File.findByIdAndUpdate(parentFileId, {
            $push: { olderVersions: newVersion._id }
        });
        
        res.redirect(`/mods/${headFile._id}`);
        
    } catch (error) {
        console.error("Error adding new version:", error);
        res.status(500).send("Server Error");
    }
});

app.get('/download-file/:id', async (req, res) => {
    try {
        const fileId = req.params.id;
        if (!Types.ObjectId.isValid(fileId)) { return res.status(404).send("File not found."); }
        const file = await File.findByIdAndUpdate(fileId, { $inc: { downloads: 1 } });
        if (!file) { return res.status(404).send("File not found."); }
        
        const command = new GetObjectCommand({
            Bucket: process.env.B2_BUCKET_NAME,
            Key: file.fileKey,
            ResponseContentDisposition: `attachment; filename="${file.originalFilename}"`
        });
        
        const presignedUrl = await getSignedUrl(s3Client, command, { expiresIn: 300 }); 
        res.redirect(presignedUrl);
    } catch (error) {
        res.status(500).send("Server error.");
    }
});

// ===============================
// 11. SOCIAL & INTERACTION
// ===============================

// --- WHITELIST / FAVORITES ---
app.post('/files/:fileId/whitelist', ensureAuthenticated, async (req, res) => {
    try {
        const fileId = req.params.fileId;
        const user = req.user; 
        const isWhitelisted = user.whitelist.includes(fileId);
        
        let updateQuery = isWhitelisted ? { $pull: { whitelist: fileId } } : { $push: { whitelist: fileId } };
        let fileUpdateQuery = isWhitelisted ? { $inc: { whitelistCount: -1 } } : { $inc: { whitelistCount: 1 } };

        await User.findByIdAndUpdate(user._id, updateQuery);
        await File.findByIdAndUpdate(fileId, fileUpdateQuery);
        
        res.redirect(`/mods/${fileId}`);
    } catch (error) {
        res.status(500).send("Server Error");
    }
});

// --- FILE STATUS VOTING ---
app.post('/files/:fileId/vote-status', ensureAuthenticated, async (req, res) => {
    try {
        const fileId = req.params.fileId;
        const userId = req.user._id;
        const { voteType } = req.body; 
        
        if (!['working', 'not-working'].includes(voteType)) {
            return res.status(400).send("Invalid vote type.");
        }
        
        const file = await File.findById(fileId);
        if (!file) {
            return res.status(404).send("File not found.");
        }
        
        if (file.votedOnStatusBy.includes(userId)) {
            return res.redirect(`/mods/${fileId}`);
        }
        
        const updateQuery = {
            $push: { votedOnStatusBy: userId }
        };
        
        if (voteType === 'working') {
            updateQuery.$inc = { workingVoteCount: 1 };
        } else {
            updateQuery.$inc = { notWorkingVoteCount: 1 };
        }

        await File.findByIdAndUpdate(fileId, updateQuery);
        res.redirect(`/mods/${fileId}`);
        
    } catch (error) {
        console.error("Error processing file status vote:", error);
        res.status(500).send("Server Error");
    }
});

// --- REVIEW SYSTEM ---
app.post('/reviews/add/:fileId', ensureAuthenticated, async (req, res) => {
    try {
        const fileId = req.params.fileId;
        const { rating, comment } = req.body;

        if (!rating || !comment) { return res.status(400).send("Fields missing."); }

        const existingReview = await Review.findOne({ file: fileId, user: req.user._id });
        if (existingReview) { return res.redirect(`/mods/${fileId}`); }

        const newReview = new Review({
            file: fileId, user: req.user._id, username: req.user.username,
            rating: parseInt(rating), comment: comment
        });
        await newReview.save();

        const stats = await Review.aggregate([
            { $match: { file: new Types.ObjectId(fileId) } },
            { $group: { _id: '$file', avgRating: { $avg: '$rating' }, count: { $sum: 1 } } }
        ]);
        
        if (stats.length > 0) {
            await File.findByIdAndUpdate(fileId, {
                averageRating: stats[0].avgRating.toFixed(1),
                ratingCount: stats[0].count
            });
        }
        res.redirect(`/mods/${fileId}`);
    } catch (error) {
        res.status(500).send("Server error.");
    }
});

app.post('/reviews/:reviewId/vote', ensureAuthenticated, async (req, res) => {
    try {
        const reviewId = req.params.reviewId;
        const review = await Review.findById(reviewId);
        if (!review) { return res.status(404).send("Review not found."); }

        if (review.votedBy.includes(req.user._id)) {
            return res.redirect(`/mods/${review.file}`);
        }

        review.votedBy.push(req.user._id);
        review.isHelpfulCount += 1;
        await review.save();

        res.redirect(`/mods/${review.file}`);
    } catch (error) {
        res.status(500).send("Server Error");
    }
});

// ===================================
// 12. FILE REPORTING ROUTES
// ===================================
app.post('/files/:fileId/report', ensureAuthenticated, async (req, res) => {
    try {
        const fileId = req.params.fileId;
        const { reason, additionalComments } = req.body;

        if (!reason) { return res.status(400).send("A reason is required to submit a report."); }
        
        const fileToReport = await File.findById(fileId);
        if (!fileToReport) { return res.status(404).send("File not found."); }

        const existingReport = await Report.findOne({ file: fileId, reportingUser: req.user._id });
        if (existingReport) { return res.redirect(`/mods/${fileId}`); }

        const newReport = new Report({
            file: fileId,
            reportingUser: req.user._id,
            reportedFileName: fileToReport.name,
            reportingUsername: req.user.username,
            reason: reason,
            additionalComments: additionalComments
        });

        await newReport.save();
        res.redirect(`/mods/${fileId}?reported=true`);

    } catch (error) {
        res.status(500).send("Server Error");
    }
});

// ===================================
// 13. ADMIN ROUTES
// ===================================
app.get('/admin/reports', ensureAuthenticated, ensureAdmin, async (req, res) => {
    try {
        const reports = await Report.find()
                                    .sort({ status: 1, createdAt: -1 })
                                    .populate('file') 
                                    .populate('reportingUser'); 

        res.render('pages/admin/reports', { reports });
    } catch (error) {
        res.status(500).send("Server Error");
    }
});

// ===================================
// 14. API ROUTES (for front-end fetching)
// ===================================

app.get('/api/search/suggestions', async (req, res) => {
    try {
        const query = req.query.q; 

        if (!query || query.length < 2) {
            return res.json([]);
        }
        
        const suggestions = await File.find(
            {
                name: { $regex: `^${query}`, $options: 'i' },
                isLatestVersion: true 
            },
            { name: 1, _id: 0 }
        ).limit(10);
        
        const suggestionNames = suggestions.map(file => file.name);
        
        res.json(suggestionNames);

    } catch (error) {
        console.error("API Suggestion Error:", error);
        res.status(500).json({ error: 'Server error while fetching suggestions.' });
    }
});

// ===============================
// 15. START SERVER
// ===============================
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});