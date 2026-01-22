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
const http = require('http');
const { Server } = require("socket.io");
const crypto = require('crypto');

// Custom Utilities & Config
const { sendVerificationEmail } = require('./utils/mailer');
const adminRouter = require('./config/admin');

// AWS SDK v3 Imports (Backblaze B2)
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

// Mongoose Models
const File = require('./models/file');
const User = require('./models/user');
const Review = require('./models/review');
const Report = require('./models/report');
const Dmca = require('./models/dmca');
const Announcement = require('./models/announcement');

// ===============================
// 2. INITIALIZATION & CONFIGURATION
// ===============================
const app = express();
const PORT = process.env.PORT || 3000;
const { Types } = mongoose;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Helper: Format Date
function timeAgo(date) {
    if (!date) return 'Never';
    return date.toLocaleDateString();
}

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

const sanitizeFilename = (filename) => {
    // Replace spaces with dashes and remove non-safe chars
    const withDashes = filename.replace(/\s+/g, '-');
    return withDashes.replace(/[^a-zA-Z0-9.-_]/g, '');
};

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
    return fileName; // This returns the "Key"
};

// ===============================
// 4. DATABASE CONNECTION
// ===============================
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Successfully connected to MongoDB Atlas!'))
    .catch(error => console.error('MongoDB Connection Error:', error));

// ===============================
// 5. MIDDLEWARE
// ===============================
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- Maintenance Mode ---
app.use((req, res, next) => {
    if (process.env.MAINTENANCE_MODE === 'on') {
        // Allow admin access
        if (req.path.startsWith('/admin') || (req.user && req.user.role === 'admin')) {
            return next();
        }
        return res.status(503).render('pages/maintenance');
    }
    next();
});

// --- Session ---
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-key',
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

// --- User Last Seen Updater ---
app.use(async (req, res, next) => {
    if (req.isAuthenticated()) {
        // Fire and forget update
        User.findByIdAndUpdate(req.user.id, { lastSeen: new Date() }).exec();
    }
    next();
});

// --- Signed Avatar URL Middleware ---
app.use(async (req, res, next) => {
    if (req.isAuthenticated() && req.user && req.user.profileImageKey) {
        try {
            const avatarUrl = await getSignedUrl(s3Client, new GetObjectCommand({
                Bucket: process.env.B2_BUCKET_NAME,
                Key: req.user.profileImageKey
            }), { expiresIn: 3600 });
            req.user.signedAvatarUrl = avatarUrl;
        } catch (error) {
            req.user.signedAvatarUrl = '/images/default-avatar.png';
        }
    }
    next();
});

// --- Globals ---
app.use((req, res, next) => {
    res.locals.user = req.user || null;
    res.locals.timeAgo = timeAgo;
    next();
});

// ===============================
// 6. PASSPORT STRATEGIES
// ===============================
const storage = multer.memoryStorage();
// Increased limit for large mod files
const upload = multer({ storage: storage, limits: { fileSize: 1024 * 1024 * 1024 } }); // 1GB limit

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
    callbackURL: process.env.BASE_URL 
        ? `${process.env.BASE_URL}/auth/google/callback` 
        : "https://gplmods.onrender.com/auth/google/callback"
},
async (accessToken, refreshToken, profile, done) => {
    const googleUserData = {
        googleId: profile.id,
        username: profile.displayName,
        email: profile.emails[0].value,
        profileImageUrl: profile.photos[0].value,
        isVerified: true
    };

    try {
        let user = await User.findOne({ email: googleUserData.email });
        if (user) {
            user.googleId = googleUserData.googleId;
            user.profileImageUrl = user.profileImageUrl || googleUserData.profileImageUrl;
            await user.save();
            done(null, user);
        } else {
            const existingUsername = await User.findOne({ username: googleUserData.username });
            if (existingUsername) {
                googleUserData.username = `${googleUserData.username}${Math.floor(Math.random() * 1000)}`;
            }
            user = await User.create(googleUserData);
            done(null, user);
        }
    } catch (err) { done(err, null); }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try { const user = await User.findById(id); done(null, user); } catch (e) { done(e); }
});

// Auth Helpers
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}
function ensureAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') return next();
    res.status(403).render('pages/403');
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
// 7. PUBLIC ROUTES
// ===============================

// Home
app.get('/', async (req, res) => {
    try {
        const recentFiles = await File.find({ isLatestVersion: true }).sort({ createdAt: -1 }).limit(12);
        const filesWithUrls = await Promise.all(recentFiles.map(async (file) => {
            // Support both old 'iconKey' and new 'iconUrl' naming from DB
            const key = file.iconUrl || file.iconKey; 
            const iconUrl = key 
                ? await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 })
                : '/images/default-avatar.png';
            return { ...file.toObject(), iconUrl };
        }));
        res.render('pages/index', { files: filesWithUrls });
    } catch (e) {
        console.error("Home Error:", e);
        res.status(500).render('pages/500');
    }
});

// Updates / Announcements
app.get('/updates', async (req, res) => {
    try {
        const announcements = await Announcement.find().sort({ createdAt: -1 });
        res.render('pages/updates', { announcements });
    } catch (error) { res.status(500).render('pages/500'); }
});

// Category / Filter
app.get('/category', async (req, res) => {
    try {
        const { platform, category, sort, page = 1 } = req.query;
        const limit = 12;
        const currentPage = parseInt(page);
        const queryFilter = { isLatestVersion: true };

        if (platform && platform !== 'all') {
            // Mapped to match your new upload logic
            queryFilter.category = platform.startsWith('ios') ? 'ios' : platform;
        }

        const sortOptions = {};
        if (sort === 'popular') {
            sortOptions.whitelistCount = -1;
            sortOptions.downloads = -1;
        } else {
            sortOptions.createdAt = -1;
        }

        const totalMods = await File.countDocuments(queryFilter);
        const totalPages = Math.ceil(totalMods / limit);
        const files = await File.find(queryFilter)
            .sort(sortOptions)
            .skip((currentPage - 1) * limit)
            .limit(limit);

        const filesWithUrls = await Promise.all(files.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            const iconUrl = key ? await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 }) : '/images/default-avatar.png';
            return { ...file.toObject(), iconUrl };
        }));

        res.render('pages/category', {
            files: filesWithUrls,
            totalPages,
            currentPage,
            currentFilters: { platform: platform || 'all', category: category || 'all', sort: sort || 'latest' }
        });
    } catch (error) { res.status(500).render('pages/500'); }
});

// Search
app.get('/search', async (req, res) => {
    try {
        const query = req.query.q;
        if (!query) return res.redirect('/');
        
        const searchResults = await File.find({
            isLatestVersion: true,
            $or: [
                { name: { $regex: query, $options: 'i' } },
                { modDescription: { $regex: query, $options: 'i' } },
                { tags: { $regex: query, $options: 'i' } }
            ]
        }).sort({ createdAt: -1 });
        
        const resultsWithUrls = await Promise.all(searchResults.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            const iconUrl = key ? await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 }) : '/images/default-avatar.png';
            return { ...file.toObject(), iconUrl };
        }));

        res.render('pages/search', { results: resultsWithUrls, query }); 
    } catch (e) { res.status(500).send("Search Error"); }
});

// Single Mod Page
app.get('/mods/:id', async (req, res) => {
    try {
        const fileId = req.params.id;
        if (!Types.ObjectId.isValid(fileId)) return res.status(404).send("File not found.");

        let currentFile = await File.findById(fileId);
        if (!currentFile) return res.status(404).send("File not found.");

        // Version History Logic
        let versionHistory = [];
        if (currentFile.parentFile) {
            let headFile = await File.findById(currentFile.parentFile).populate('olderVersions');
            versionHistory = [headFile, ...headFile.olderVersions.slice().reverse()];
            currentFile = headFile;
        } else {
            await currentFile.populate('olderVersions');
            versionHistory = [currentFile, ...currentFile.olderVersions.slice().reverse()];
        }

        // Generate URLs
        const iconKey = currentFile.iconUrl || currentFile.iconKey;
        const iconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: iconKey }), { expiresIn: 3600 });
        
        // Handle screenshot array (support both old 'screenshotKeys' and new 'screenshotUrls')
        const screenKeys = (currentFile.screenshotUrls && currentFile.screenshotUrls.length > 0) 
            ? currentFile.screenshotUrls 
            : (currentFile.screenshotKeys || []);
            
        const screenshotUrls = await Promise.all(screenKeys.map(key => getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 })));

        const reviews = await Review.find({ file: currentFile._id }).sort({ createdAt: -1 }).populate('user', 'profileImageUrl');
        const userHasWhitelisted = req.user ? req.user.whitelist.includes(currentFile._id) : false;
        const userHasVotedOnStatus = req.user ? currentFile.votedOnStatusBy.includes(req.user._id) : false;

        res.render('pages/download', {
            file: { ...currentFile.toObject(), iconUrl, screenshotUrls },
            versionHistory, reviews, userHasWhitelisted, userHasVotedOnStatus
        });
    } catch (e) {
        console.error(e);
        res.status(500).send("Server error.");
    }
});

// Download Action
app.get('/download-file/:id', async (req, res) => {
    try {
        const file = await File.findByIdAndUpdate(req.params.id, { $inc: { downloads: 1 } });
        if (!file) return res.status(404).send("File not found.");

        const key = file.fileUrl || file.fileKey;
        const url = await getSignedUrl(s3Client, new GetObjectCommand({
            Bucket: process.env.B2_BUCKET_NAME,
            Key: key,
            ResponseContentDisposition: `attachment; filename="${file.originalFilename}"`
        }), { expiresIn: 300 }); // Link valid for 5 mins
        res.redirect(url);
    } catch (e) { res.status(500).send("Download generation error."); }
});

// ===============================
// 8. AUTH ROUTES
// ===============================

app.get('/login', (req, res) => {
    res.render('pages/login', {
        recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY,
        message: req.query.message || null
    });
});
app.post('/login', verifyRecaptcha, passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' }));

app.get('/register', (req, res) => res.render('pages/register', { recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY, message: null }));
app.post('/register', verifyRecaptcha, async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) return res.status(400).send("All fields required.");

        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            if (existingUser.isVerified) return res.status(400).send("User exists.");
            // Resend Verification
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
    } catch (e) { res.status(500).send("Registration error."); }
});

app.get('/verify-email', async (req, res) => {
    try {
        const decoded = jwt.verify(req.query.token, process.env.JWT_SECRET || 'fallback');
        const user = await User.findOne({ _id: decoded.userId, verificationToken: req.query.token });
        if (!user) return res.status(400).send('Invalid token.');
        user.isVerified = true;
        user.verificationToken = undefined;
        await user.save();
        req.login(user, () => res.redirect('/profile'));
    } catch (e) { res.status(400).send('Expired token.'); }
});

// Password Recovery
app.get('/forgot-password', (req, res) => res.render('pages/forgot-password'));
app.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email: email });
        if (!user) return res.redirect('/forgot-password?success=If an account exists, a link has been sent.');

        const resetToken = crypto.randomBytes(32).toString('hex');
        user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        user.passwordResetExpires = Date.now() + 3600000; 
        await user.save();
        
        const resetURL = `${process.env.BASE_URL || 'http://localhost:3000'}/reset-password/${resetToken}`;
        // await sendPasswordResetEmail(user, resetURL); // Ensure you have this function
        console.log(`Reset Link: ${resetURL}`); // Debugging

        res.redirect('/forgot-password?success=If an account exists, a link has been sent.');
    } catch (e) { res.redirect('/forgot-password?error=Error.'); }
});

app.get('/reset-password/:token', async (req, res) => {
    try {
        const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
        const user = await User.findOne({ 
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() } // Check if not expired
        });

        if (!user) {
            return res.redirect('/forgot-password?error=Password reset link is invalid or has expired.');
        }
        
        res.render('pages/reset-password', { token: req.params.token });
    } catch (e) {
        res.redirect('/forgot-password?error=An error occurred.');
    }
});

app.post('/reset-password/:token', async (req, res, next) => {
    try {
        const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
        const user = await User.findOne({ 
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() } 
        });
        
        if (!user) {
            return res.redirect('/forgot-password?error=Password reset link is invalid or has expired.');
        }

        if (req.body.password !== req.body.confirmPassword) {
            return res.redirect(`/reset-password/${req.params.token}?error=Passwords do not match.`);
        }
        if (req.body.password.length < 6) {
             return res.redirect(`/reset-password/${req.params.token}?error=Password must be at least 6 characters.`);
        }

        // Set the new password (our pre-save hook will hash it)
        user.password = req.body.password;
        // Invalidate the token
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;

        await user.save();

        // Log the user in and redirect
        req.login(user, (err) => {
            if (err) return next(err);
            res.redirect('/?message=Password has been reset successfully!');
        });
    } catch (e) {
        res.redirect('/forgot-password?error=An error occurred while resetting the password.');
    }
});

app.get('/logout', (req, res, next) => {
    req.logout(err => { if (err) return next(err); res.redirect('/'); });
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => res.redirect('/profile'));

// ===============================
// 9. PROFILE ROUTES
// ===============================

app.get('/profile', ensureAuthenticated, async (req, res) => {
    try {
        const userWithWhitelist = await User.findById(req.user._id).populate('whitelist');
        const userUploads = await File.find({ uploader: req.user.username, isLatestVersion: true }).sort({ createdAt: -1 });
        res.render('pages/profile', { user: userWithWhitelist, uploads: userUploads });
    } catch (e) { res.status(500).send('Profile fetch error.'); }
});

// Public Profile
app.get('/users/:username', async (req, res) => {
    try {
        const username = req.params.username;
        const user = await User.findOne({ username: username });
        if (!user) return res.status(404).render('pages/404');

        if (user.profileImageKey) {
            user.signedAvatarUrl = await getSignedUrl(s3Client, new GetObjectCommand({
                Bucket: process.env.B2_BUCKET_NAME, Key: user.profileImageKey
            }), { expiresIn: 3600 });
        }

        const uploads = await File.find({ uploader: username, isLatestVersion: true }).sort({ createdAt: -1 });
        const uploadsWithUrls = await Promise.all(uploads.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            const iconUrl = key ? await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 }) : '/images/default-avatar.png';
            return { ...file.toObject(), iconUrl };
        }));

        res.render('pages/public-profile', { profileUser: user, uploads: uploadsWithUrls });
    } catch (error) { res.status(500).render('pages/500'); }
});

// Update Account Details
app.post('/account/update-details', ensureAuthenticated, async (req, res, next) => {
    try {
        const { username, email, bio } = req.body;
        const user = await User.findById(req.user.id);

        if (bio !== undefined) user.bio = bio;

        if (username && username !== user.username) {
            const existingUser = await User.findOne({ username });
            if (existingUser) return res.redirect('/profile?error=Username taken.');
            await File.updateMany({ uploader: user.username }, { uploader: username });
            user.username = username;
        }

        if (email && email !== user.email) {
            const existingEmail = await User.findOne({ email });
            if (existingEmail) return res.redirect('/profile?error=Email in use.');
            user.email = email;
            user.isVerified = false;
            const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1d' });
            user.verificationToken = token;
            await sendVerificationEmail(user);
            await user.save();
            req.logout(() => res.redirect('/login?message=Verify your new email.'));
            return;
        }

        await user.save();
        req.login(user, (err) => {
            if (err) return next(err);
            res.redirect('/profile?success=Updated.');
        });
    } catch (e) { res.status(500).redirect('/profile?error=Error.'); }
});

// Update Profile Image
app.post('/account/update-profile-image', ensureAuthenticated, upload.single('profileImage'), async (req, res, next) => {
    try {
        if (!req.file) return res.redirect('/profile?error=No file.');
        const imageKey = await uploadToB2(req.file, 'avatars');
        const updatedUser = await User.findByIdAndUpdate(req.user.id, { profileImageKey: imageKey }, { new: true });
        req.login(updatedUser, (err) => {
            if (err) return next(err);
            res.redirect('/profile?success=Image updated.');
        });
    } catch (e) { next(e); }
});

// Change Password
app.post('/account/change-password', ensureAuthenticated, async (req, res) => {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;
        if (newPassword !== confirmPassword) return res.redirect('/profile?error=Mismatch.');
        const user = await User.findById(req.user.id);
        const isMatch = await user.comparePassword(currentPassword);
        if (!isMatch) return res.redirect('/profile?error=Wrong password.');
        user.password = newPassword;
        await user.save();
        res.redirect('/profile?success=Password changed.');
    } catch (e) { res.status(500).redirect('/profile?error=Error.'); }
});

// Delete Account
app.post('/account/delete', ensureAuthenticated, async (req, res) => {
    try {
        await File.deleteMany({ uploader: req.user.username });
        await Review.deleteMany({ user: req.user._id });
        await User.findByIdAndDelete(req.user._id);
        req.logout(err => res.redirect('/'));
    } catch (e) { res.status(500).send('Deletion failed.'); }
});

// ===============================
// 10. FILE UPLOAD & MANAGEMENT
// ===============================

// Upload Page
app.get('/upload', ensureAuthenticated, (req, res) => res.render('pages/upload'));

// Process Upload (MERGED LOGIC)
// Accepts: modIcon, screenshotFile, modFile (from new form)
app.post('/upload', ensureAuthenticated, upload.fields([
    { name: 'modIcon', maxCount: 1 }, 
    { name: 'screenshotFile', maxCount: 4 }, // Allow up to 4 screenshots
    { name: 'modFile', maxCount: 1 }
]), async (req, res) => {
    try {
        // Extract fields using the NEW names
        const { 
            modName, 
            modVersion, 
            developerName, 
            modPlatform, // Maps to 'category' (e.g., android, windows)
            modCategory, // Maps to 'platforms' (e.g., game, app)
            modFeatures, // Description
            whatsNew,    // Official Desc
            tags, 
            videoUrl 
        } = req.body;

        const { modIcon, screenshotFile, modFile } = req.files;

        if (!modIcon || !screenshotFile || !modFile || !modName || !modPlatform) {
            return res.status(400).send("Missing required fields or files.");
        }

        // Upload to B2
        const iconKey = await uploadToB2(modIcon[0], 'icons');
        // Handle multiple screenshots if sent, or single
        const screenshotKeys = await Promise.all(screenshotFile.map(f => uploadToB2(f, 'screenshots')));
        const fileKey = await uploadToB2(modFile[0], 'mods');

        // VirusTotal Scan
        let analysisId = null, scanDate, positiveCount, totalScans = null;
        try {
            if (process.env.VIRUSTOTAL_API_KEY) {
                const formData = new FormData();
                formData.append('file', new Blob([modFile[0].buffer]), modFile[0].originalname);
                const vtSubmission = await axios.post('https://www.virustotal.com/api/v3/files', formData, {
                    headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
                });
                analysisId = vtSubmission.data.data.id;
                
                // Try immediate fetch (often pending, but good to try)
                const vtReport = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
                    headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
                });
                if (vtReport.data.data.attributes.status === 'completed') {
                    const stats = vtReport.data.data.attributes.stats;
                    scanDate = new Date();
                    positiveCount = stats.malicious + stats.suspicious;
                    totalScans = stats.harmless + stats.malicious + stats.suspicious + stats.undetected;
                }
            }
        } catch (vtError) {
            console.error("VT Error (Non-fatal):", vtError.message);
        }

        // Save to Database (Mapping new form fields to schema)
        const newFile = new File({
            name: modName,
            version: modVersion,
            developer: developerName,
            modDescription: modFeatures,
            officialDescription: whatsNew,
            
            // Storage Keys
            iconKey: iconKey,               // Save as Key
            screenshotKeys: screenshotKeys, // Save as Array of Keys
            fileKey: fileKey,               // Save as Key
            
            // Also save as Url fields for forward compatibility if schema changed
            iconUrl: iconKey,
            screenshotUrls: screenshotKeys,
            fileUrl: fileKey,

            videoUrl,
            originalFilename: modFile[0].originalname,
            
            category: modPlatform,        // e.g. 'android'
            platforms: [modCategory],     // e.g. 'game'
            tags: tags ? tags.split(',').map(t => t.trim()) : [],
            
            uploader: req.user.username,
            fileSize: modFile[0].size,
            isLatestVersion: true,
            
            virusTotalAnalysisId: analysisId,
            virusTotalScanDate: scanDate,
            virusTotalPositiveCount: positiveCount,
            virusTotalTotalScans: totalScans
        });

        await newFile.save();
        
        // Return JSON if requested (AJAX), else Redirect
        if (req.xhr || req.headers.accept.indexOf('json') > -1) {
            return res.status(201).json({ message: "Uploaded!", fileId: newFile._id });
        }
        res.redirect(`/mods/${newFile._id}`);

    } catch (e) {
        console.error("Upload Error:", e);
        res.status(500).send("Upload failed.");
    }
});

// Add Version (Legacy Route - kept for compatibility)
app.get('/mods/:id/add-version', ensureAuthenticated, async (req, res) => {
    const parentFile = await File.findById(req.params.id);
    if (!parentFile || req.user.username !== parentFile.uploader) return res.status(403).send("Forbidden.");
    res.render('pages/add-version', { parentFile });
});

// ===============================
// 11. SOCIAL & ADMIN INTERACTION
// ===============================

// Whitelist
app.post('/files/:fileId/whitelist', ensureAuthenticated, async (req, res) => {
    try {
        const isWhitelisted = req.user.whitelist.includes(req.params.fileId);
        const update = isWhitelisted ? { $pull: { whitelist: req.params.fileId } } : { $push: { whitelist: req.params.fileId } };
        const fileUpdate = isWhitelisted ? { $inc: { whitelistCount: -1 } } : { $inc: { whitelistCount: 1 } };
        await User.findByIdAndUpdate(req.user._id, update);
        await File.findByIdAndUpdate(req.params.fileId, fileUpdate);
        res.redirect(`/mods/${req.params.fileId}`);
    } catch (e) { res.status(500).send("Error."); }
});

// Reviews
app.post('/reviews/add/:fileId', ensureAuthenticated, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        const existing = await Review.findOne({ file: req.params.fileId, user: req.user._id });
        if (existing) return res.redirect(`/mods/${req.params.fileId}`);

        const newReview = new Review({ file: req.params.fileId, user: req.user._id, username: req.user.username, rating: parseInt(rating), comment });
        await newReview.save();
        
        // Update Aggregates
        const stats = await Review.aggregate([{ $match: { file: new Types.ObjectId(req.params.fileId) } }, { $group: { _id: '$file', avg: { $avg: '$rating' }, count: { $sum: 1 } } }]);
        if (stats.length > 0) {
            await File.findByIdAndUpdate(req.params.fileId, { averageRating: stats[0].avg.toFixed(1), ratingCount: stats[0].count });
        }
        res.redirect(`/mods/${req.params.fileId}`);
    } catch (e) { res.status(500).send("Error."); }
});

// Vote Working/Not Working
app.post('/files/:fileId/vote-status', ensureAuthenticated, async (req, res) => {
    try {
        const { voteType } = req.body;
        const file = await File.findById(req.params.fileId);
        if (file && !file.votedOnStatusBy.includes(req.user._id)) {
            const update = voteType === 'working' ? { $inc: { workingVoteCount: 1 } } : { $inc: { notWorkingVoteCount: 1 } };
            await File.findByIdAndUpdate(req.params.fileId, { ...update, $push: { votedOnStatusBy: req.user._id } });
        }
        res.redirect(`/mods/${req.params.fileId}`);
    } catch (e) { res.status(500).send("Error."); }
});

// Reporting
app.post('/files/:fileId/report', ensureAuthenticated, async (req, res) => {
    try {
        const { reason, additionalComments } = req.body;
        const file = await File.findById(req.params.fileId);
        const existing = await Report.findOne({ file: req.params.fileId, reportingUser: req.user._id });
        if (!existing && file) {
            await new Report({ 
                file: req.params.fileId, 
                reportingUser: req.user._id, 
                reportedFileName: file.name, 
                reportingUsername: req.user.username, 
                reason, additionalComments 
            }).save();
        }
        res.redirect(`/mods/${req.params.fileId}?reported=true`);
    } catch (e) { res.status(500).send("Error."); }
});

// Admin Reports
app.get('/admin/reports', ensureAuthenticated, ensureAdmin, async (req, res) => {
    const reports = await Report.find().populate('file').populate('reportingUser').sort({ status: 1, createdAt: -1 });
    res.render('pages/admin/reports', { reports });
});

app.post('/admin/reports/:reportId/status', ensureAuthenticated, ensureAdmin, async (req, res) => {
    await Report.findByIdAndUpdate(req.params.reportId, { status: req.body.status });
    res.redirect('/admin/reports');
});

app.post('/admin/reports/delete-file/:fileId', ensureAuthenticated, ensureAdmin, async (req, res) => {
    await File.findByIdAndDelete(req.params.fileId);
    await Review.deleteMany({ file: req.params.fileId });
    await Report.updateMany({ file: req.params.fileId }, { status: 'resolved' });
    res.redirect('/admin/reports');
});

// Chat
app.get('/community-chat', ensureAuthenticated, (req, res) => res.render('pages/community-chat'));

// ===============================
// 12. STATIC PAGES
// ===============================
app.get('/about', (req, res) => res.render('pages/static/about'));
app.get('/faq', (req, res) => res.render('pages/static/faq'));
app.get('/tos', (req, res) => res.render('pages/static/tos'));
app.get('/dmca', (req, res) => res.render('pages/static/dmca'));
app.get('/privacy-policy', (req, res) => res.render('pages/static/privacy-policy'));

// A placeholder route for a future feature
app.get('/leaderboard', (req, res) => {
    res.render('pages/coming-soon');
});

app.post('/dmca-request', async (req, res) => {
    try {
        await new Dmca(req.body).save();
        res.redirect('/dmca?success=Request submitted.');
    } catch (e) { res.redirect('/dmca?error=Error.'); }
});

// Errors
app.use((req, res) => res.status(404).render('pages/404'));
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).render('pages/500');
});

// ===============================
// 13. SERVER START
// ===============================
const server = http.createServer(app);
const io = new Server(server);

io.on('connection', (socket) => {
    socket.on('chat message', (msg) => {
        io.emit('chat message', { username: msg.username, avatar: msg.avatar, text: msg.text });
    });
});

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));