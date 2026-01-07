// ==========================================
// 1. IMPORTS & INITIALIZATION
// ==========================================
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const MongoStore = require('connect-mongo');
const multer = require('multer');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bodyParser = require('body-parser');
const { Types } = mongoose;

// AWS SDK v3 Imports
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

// Import Models
const File = require('./models/file');
const User = require('./models/user');
const Review = require('./models/review');
const Report = require('./models/report');

// Import Helpers
const { sendVerificationEmail } = require('./utils/mailer');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 2. MIDDLEWARE & CONFIGURATION
// ==========================================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Webhook parser MUST come before express.json()
app.use('/webhook', bodyParser.raw({ type: 'application/json' }));

app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Session Configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'a-fallback-secret-key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ 
        mongoUrl: process.env.MONGO_URI, 
        collectionName: 'sessions' 
    }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 } // 7 days
}));

// ==========================================
// 3. AWS S3 / BACKBLAZE B2 CONFIG
// ==========================================
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

// ==========================================
// 4. PASSPORT CONFIGURATION
// ==========================================
app.use(passport.initialize());
app.use(passport.session());

// Local Strategy
passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return done(null, false, { message: 'Incorrect email.' });
        
        const isMatch = await user.comparePassword(password);
        if (!isMatch) return done(null, false, { message: 'Incorrect password.' });

        if (!user.isVerified) return done(null, false, { message: 'Please verify your email.' });

        return done(null, user);
    } catch (error) { return done(error); }
}));

// Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback" 
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ email: profile.emails[0].value });
        if (user) return done(null, user);

        const newUser = await User.create({
            googleId: profile.id,
            username: profile.displayName,
            email: profile.emails[0].value,
            isVerified: true
        });
        done(null, newUser);
    } catch (err) { done(err, null); }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try { const user = await User.findById(id); done(null, user); } 
    catch (error) { done(error); }
});

// Global User variable for templates
app.use((req, res, next) => {
    res.locals.user = req.user || null;
    next();
});

// ==========================================
// 5. DATABASE CONNECTION
// ==========================================
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Successfully connected to MongoDB Atlas!'))
    .catch(error => console.error('Error connecting to MongoDB Atlas:', error));

// ==========================================
// 6. HELPER MIDDLEWARE
// ==========================================
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
    if (!token) return res.status(400).send("Please complete CAPTCHA.");
    
    try {
        const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${token}`);
        if (response.data.success) return next();
        res.status(400).send("Failed CAPTCHA verification.");
    } catch (error) { res.status(500).send("reCAPTCHA error."); }
}

// ==========================================
// 7. CORE ROUTES
// ==========================================

// Home Page
app.get('/', async (req, res) => {
    try {
        const recentFiles = await File.find({ isLatestVersion: true }).sort({ createdAt: -1 }).limit(12);
        const filesWithUrls = await Promise.all(recentFiles.map(async (file) => {
            const iconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: file.iconKey }), { expiresIn: 3600 });
            return { ...file.toObject(), iconUrl };
        }));
        res.render('pages/index', { files: filesWithUrls });
    } catch (error) { res.status(500).send("Server error."); }
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
                { modDescription: { $regex: query, $options: 'i' } }
            ]
        }).sort({ createdAt: -1 });
        res.render('pages/search', { results: searchResults, query: query });
    } catch (error) { res.status(500).send("Search error."); }
});

// Category
app.get('/category', async (req, res) => {
    try {
        const { cat } = req.query;
        const filteredFiles = await File.find({ category: cat, isLatestVersion: true }).sort({ createdAt: -1 });
        const filesWithUrls = await Promise.all(filteredFiles.map(async (file) => {
            const iconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: file.iconKey }), { expiresIn: 3600 });
            return { ...file.toObject(), iconUrl };
        }));
        res.render('pages/category', { files: filesWithUrls, title: cat, currentCategory: cat });
    } catch (error) { res.status(500).send("Category error."); }
});

// Individual Mod Page
app.get('/mods/:id', async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        if (!file) return res.status(404).send("Not found.");

        const iconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: file.iconKey }), { expiresIn: 3600 });
        const reviews = await Review.find({ file: file._id }).sort({ createdAt: -1 });

        res.render('pages/download', { 
            file: { ...file.toObject(), iconUrl }, 
            reviews,
            userHasWhitelisted: req.user ? req.user.whitelist.includes(file._id) : false
        });
    } catch (error) { res.status(500).send("Error loading mod."); }
});

// ==========================================
// 8. AUTHENTICATION ROUTES
// ==========================================
app.get('/login', (req, res) => res.render('pages/login', { recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY }));
app.post('/login', verifyRecaptcha, passport.authenticate('local', { successRedirect: '/', failureRedirect: '/login' }));

app.get('/register', (req, res) => res.render('pages/register', { recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY }));
app.post('/register', verifyRecaptcha, async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const newUser = new User({ username, email: email.toLowerCase(), password });
        const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET || 'fallback', { expiresIn: '1d' });
        newUser.verificationToken = token;
        await newUser.save();
        await sendVerificationEmail(newUser);
        res.render('pages/please-verify');
    } catch (error) { res.status(500).send("Registration error."); }
});

app.get('/logout', (req, res, next) => {
    req.logout(err => { if (err) return next(err); res.redirect('/'); });
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => res.redirect('/profile'));

// ==========================================
// 9. FILE MANAGEMENT (UPLOAD/DOWNLOAD)
// ==========================================
const storage = multer.memoryStorage();
const upload = multer({ storage: storage, limits: { fileSize: 100 * 1024 * 1024 } });

app.get('/upload', ensureAuthenticated, (req, res) => res.render('pages/upload'));

app.post('/upload', ensureAuthenticated, upload.fields([
    { name: 'softwareIcon', maxCount: 1 },
    { name: 'screenshots', maxCount: 4 },
    { name: 'modFile', maxCount: 1 }
]), async (req, res) => {
    try {
        const { softwareName, softwareVersion, category } = req.body;
        const iconKey = await uploadToB2(req.files.softwareIcon[0], 'icons');
        const fileKey = await uploadToB2(req.files.modFile[0], 'mods');

        const newFile = new File({
            name: softwareName,
            version: softwareVersion,
            category,
            iconKey,
            fileKey,
            uploader: req.user.username,
            isLatestVersion: true
        });
        await newFile.save();
        res.redirect(`/mods/${newFile._id}`);
    } catch (error) { res.status(500).send("Upload failed."); }
});

app.get('/download-file/:id', async (req, res) => {
    try {
        const file = await File.findByIdAndUpdate(req.params.id, { $inc: { downloads: 1 } });
        const command = new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: file.fileKey });
        const url = await getSignedUrl(s3Client, command, { expiresIn: 300 });
        res.redirect(url);
    } catch (error) { res.status(500).send("Download failed."); }
});

// ==========================================
// 10. ADMIN & API
// ==========================================
app.get('/admin/reports', ensureAuthenticated, ensureAdmin, async (req, res) => {
    const reports = await Report.find().populate('file').populate('reportingUser');
    res.render('pages/admin/reports', { reports });
});

app.get('/api/search/suggestions', async (req, res) => {
    const query = req.query.q;
    if (!query || query.length < 2) return res.json([]);
    const suggestions = await File.find({ name: { $regex: `^${query}`, $options: 'i' }, isLatestVersion: true }).limit(10);
    res.json(suggestions.map(f => f.name));
});

// ==========================================
// 11. START SERVER
// ==========================================
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});