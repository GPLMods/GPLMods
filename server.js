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
const cors = require('cors');
const fs = require('fs');
const FormData = require('form-data');

// Custom Utilities & Config
const { sendVerificationEmail, sendPasswordResetEmail } = require('./utils/mailer');
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

// --- NEW SMART HELPER FOR IMAGES ---
async function getSmartImageUrl(key) {
    if (!key) return '/images/default-avatar.png'; // Fallback
    
    // If the admin pasted a direct web URL, just use it directly!
    if (key.startsWith('http://') || key.startsWith('https://')) {
        return key;
    }
    
    // Otherwise, it's a Backblaze key, so generate the secure signed URL
    try {
        return await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 });
    } catch (error) {
        console.error(`Could not sign URL for key: ${key}`);
        return '/images/default-avatar.png';
    }
}
// --------------------------------------

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
    const withDashes = filename.replace(/\s+/g, '-');
    return withDashes.replace(/[^a-zA-Z0-9.-_]/g, '');
};

const uploadToB2 = async (file, folder) => {
    const fileBuffer = file.buffer ? file.buffer : fs.readFileSync(file.path);
    const sanitizedFilename = sanitizeFilename(file.originalname);
    const fileName = `${folder}/${Date.now()}-${sanitizedFilename}`;
    const params = {
        Bucket: process.env.B2_BUCKET_NAME,
        Key: fileName,
        Body: fileBuffer,
        ContentType: file.mimetype
    };
    await s3Client.send(new PutObjectCommand(params));
    return fileName;
};

// ===============================
// 4. MIDDLEWARE
// ===============================
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- ADD CORS MIDDLEWARE HERE ---
const allowedOrigins =[
    'http://localhost:3000',          
    'https://gplmods.webredirect.org'   
];

app.use(cors({
    origin: function (origin, callback) {
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'The CORS policy for this site does not allow access from the specified Origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    }
}));

// --- Maintenance Mode ---
app.use((req, res, next) => {
    if (process.env.MAINTENANCE_MODE === 'on') {
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
        User.findByIdAndUpdate(req.user.id, { lastSeen: new Date() }).exec();
    }
    next();
});

// --- The FINAL, CORRECT Signed Avatar URL Middleware ---
app.use(async (req, res, next) => {
    if (req.isAuthenticated() && req.user) {
        if (req.user.profileImageKey) {
            try {
                const avatarUrl = await getSignedUrl(s3Client, new GetObjectCommand({
                    Bucket: process.env.B2_BUCKET_NAME,
                    Key: req.user.profileImageKey
                }), { expiresIn: 3600 });
                req.user.signedAvatarUrl = avatarUrl;
            } catch (error) {
                console.error(`Error getting signed URL for key: ${req.user.profileImageKey}`, error);
                req.user.signedAvatarUrl = '/images/default-avatar.png';
            }
        } else {
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

// --- SETUP ADMINJS ---
app.use('/admin', ensureAuthenticated, ensureAdmin, adminRouter);

// ===============================
// 5. PASSPORT STRATEGIES & MULTER CONFIG
// ===============================

// UPDATED Multer configuration to use disk storage
const diskStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = 'uploads/';
        fs.mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage: diskStorage });

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
        : "https://gplmods.webredirect.org/auth/google/callback"
},
async (accessToken, refreshToken, profile, done) => {
    const googleUserData = {
        googleId: profile.id,
        username: profile.displayName,
        email: profile.emails[0].value,
        isVerified: true
    };

    try {
        let user = await User.findOne({ email: googleUserData.email });
        if (user) {
            user.googleId = googleUserData.googleId;
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
// 6. PUBLIC ROUTES
// ===============================

// Health Check Endpoint
app.get('/healthz', (req, res) => {
    res.status(200).json({ status: 'ok', message: 'Server is healthy' });
});

// Home
app.get('/', async (req, res) => {
    try {
        const findQuery = { status: 'live', isLatestVersion: true };
        const categories =['android', 'ios', 'wordpress', 'windows'];
        const filesByCategory = {};

        await Promise.all(categories.map(async (cat) => {
            const workingMods = await File.find({ category: cat, ...findQuery }).sort({ averageRating: -1, downloads: -1 }).limit(4);
            const popularMods = await File.find({ category: cat, ...findQuery }).sort({ downloads: -1 }).limit(4);
            const newUpdates = await File.find({ category: cat, ...findQuery }).sort({ createdAt: -1 }).limit(4);
            filesByCategory[cat] = {
                '100-Percent-Working': workingMods,
                'Most-Popular': popularMods,
                'New-Updates': newUpdates,
            };
        }));

        for (const category in filesByCategory) {
            for (const section in filesByCategory[category]) {
                filesByCategory[category][section] = await Promise.all(
                    filesByCategory[category][section].map(async (file) => {
                        const key = file.iconUrl || file.iconKey;
                        let signedIconUrl = '/images/default-avatar.png';
                        if (key) {
                            try {
                                signedIconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 });
                            } catch (urlError) {
                                console.error(`Could not get signed URL for key: ${key}`, urlError);
                            }
                        }
                        return { ...file.toObject(), iconUrl: signedIconUrl };
                    })
                );
            }
        }
        res.render('pages/index', { filesByCategory });
    } catch (error) {
        console.error("Error fetching files for homepage:", error);
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

// Search Route
app.get('/search', async (req, res) => {
    try {
        const query = req.query.q || '';
        const platform = req.query.platform || 'all';
        const sort = req.query.sort || 'newest';
        const page = parseInt(req.query.page) || 1;
        const resultsPerPage = 12;

        if (!query) return res.redirect('/');
        
        let searchQuery = {
            isLatestVersion: true,
            $or:[
                { name: { $regex: query, $options: 'i' } },
                { modDescription: { $regex: query, $options: 'i' } },
                { tags: { $regex: query, $options: 'i' } },
                { developer: { $regex: query, $options: 'i' } }
            ]
        };

        if (platform !== 'all') searchQuery.category = platform;

        let sortQuery = {};
        switch (sort) {
            case 'downloads': sortQuery = { downloads: -1 }; break;
            case 'rating': sortQuery = { averageRating: -1 }; break;
            default: sortQuery = { createdAt: -1 }; break;
        }
        
        const totalResults = await File.countDocuments(searchQuery);
        const totalPages = Math.ceil(totalResults / resultsPerPage);

        const searchResults = await File.find(searchQuery)
            .sort(sortQuery)
            .skip((page - 1) * resultsPerPage)
            .limit(resultsPerPage);

        const resultsWithUrls = await Promise.all(searchResults.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            let signedIconUrl = '/images/default-avatar.png'; 
            if (key) {
                try {
                    signedIconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 });
                } catch (urlError) {
                    console.error(`Could not get signed URL for key: ${key}`);
                }
            }
            return { ...file.toObject(), iconUrl: signedIconUrl };
        }));

        res.render('pages/search', {
            results: resultsWithUrls, 
            query: query,
            totalResults: totalResults,
            totalPages: totalPages,
            currentPage: page,
            currentPlatform: platform,
            currentSort: sort
        });

    } catch (error) {
        res.status(500).render('pages/500');
    }
});

// Single Mod Page
app.get('/mods/:id', async (req, res) => {
    try {
        const fileId = req.params.id;
        if (!Types.ObjectId.isValid(fileId)) return res.status(404).send("File not found.");

        let currentFile = await File.findById(fileId);
        if (!currentFile) return res.status(404).send("File not found.");

        let versionHistory =[];
        if (currentFile.parentFile) {
            let headFile = await File.findById(currentFile.parentFile).populate('olderVersions');
            versionHistory =[headFile, ...headFile.olderVersions.slice().reverse()];
            currentFile = headFile;
        } else {
            await currentFile.populate('olderVersions');
            versionHistory =[currentFile, ...currentFile.olderVersions.slice().reverse()];
        }

        const iconKey = currentFile.iconUrl || currentFile.iconKey;
        const iconUrl = await getSmartImageUrl(iconKey);
        
        const screenKeys = (currentFile.screenshotUrls && currentFile.screenshotUrls.length > 0)
            ? currentFile.screenshotUrls
            : (currentFile.screenshotKeys ||[]);
            
        const screenshotUrls = await Promise.all(screenKeys.map(key => getSmartImageUrl(key)));

        const reviews = await Review.find({ file: currentFile._id }).sort({ createdAt: -1 }).populate('user', 'profileImageKey'); 

        const reviewsWithAvatars = await Promise.all(reviews.map(async (review) => {
            let avatarUrl = '/images/default-avatar.png';
            if (review.user && review.user.profileImageKey) {
                try {
                    avatarUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: review.user.profileImageKey }), { expiresIn: 3600 });
                } catch (e) { console.error("Could not get signed URL for reviewer avatar."); }
            }
            return { ...review.toObject(), user: { ...review.user.toObject(), signedAvatarUrl: avatarUrl } };
        }));

        const userHasWhitelisted = req.user ? req.user.whitelist.includes(currentFile._id) : false;
        const userHasVotedOnStatus = req.user ? currentFile.votedOnStatusBy.includes(req.user._id) : false;

        res.render('pages/download', {
            file: { ...currentFile.toObject(), iconUrl, screenshotUrls },
            versionHistory,
            reviews: reviewsWithAvatars,
            userHasWhitelisted,
            userHasVotedOnStatus
        });
    } catch (e) {
        console.error("Error on /mods/:id route:", e);
        res.status(500).send("Server error.");
    }
});

// --- UPDATED DEVELOPER PAGE ROUTE ---
app.get('/developer', async (req, res) => {
    try {
        const developerName = req.query.name;
        if (!developerName || developerName.trim() === '') return res.redirect('/');
        
        const filesByDeveloper = await File.find({
            developer: { $regex: developerName, $options: 'i' }, 
            isLatestVersion: true,
            status: 'live'
        }).sort({ createdAt: -1 });

        // --- FIX: GENERATE SIGNED URLS FOR IMAGES ---
        const filesWithUrls = await Promise.all(filesByDeveloper.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            let signedIconUrl = '/images/default-avatar.png';
            if (key) {
                try {
                    signedIconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 });
                } catch (e) {}
            }
            return { ...file.toObject(), iconUrl: signedIconUrl };
        }));

        res.render('pages/developer', {
            files: filesWithUrls, // Use the mapped array with real images
            developerName: developerName
        });

    } catch (error) {
        console.error("Developer page error:", error);
        res.status(500).render('pages/500');
    }
});

// ===============================================
// 7. FILE VERSIONING ROUTES
// ===============================================

app.get('/mods/:id/add-version', ensureAuthenticated, async (req, res) => {
    try {
        const parentFile = await File.findById(req.params.id);

        if (!parentFile || req.user.username.toLowerCase() !== parentFile.uploader.toLowerCase()) {
            return res.status(403).render('pages/403');
        }

        res.render('pages/add-version', { parentFile: parentFile });

    } catch (error) {
        console.error('Error loading the add-version page:', error);
        res.status(500).render('pages/500');
    }
});

app.post('/mods/:id/add-version', ensureAuthenticated, upload.single('modFile'), async (req, res) => {
    // Add version processing logic here
});

// Download Action - UPDATED with presigned URL
app.get('/download-file/:id', async (req, res) => {
    try {
        const file = await File.findByIdAndUpdate(req.params.id, { $inc: { downloads: 1 } });
        if (!file) {
            return res.status(404).render('pages/404');
        }

        const fileKey = file.fileKey || file.fileUrl; 

        if (!fileKey) {
            console.error(`File with ID ${file._id} has no fileKey or fileUrl in the database.`);
            return res.status(500).send("File record is incomplete and cannot be downloaded.");
        }

        const command = new GetObjectCommand({
            Bucket: process.env.B2_BUCKET_NAME,
            Key: fileKey, 
            ResponseContentDisposition: `attachment; filename="${file.originalFilename || file.name}"`
        });
        
        const signedUrl = await getSignedUrl(s3Client, command, { expiresIn: 300 });

        res.redirect(signedUrl);
    } catch (e) {
        console.error("Download generation error:", e);
        res.status(500).send("Could not generate download link.");
    }
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
        if (!username || !email || !password) {
            return res.status(400).send("All fields are required.");
        }
        let user = await User.findOne({ email: email.toLowerCase() });

        if (user && user.isVerified) {
            return res.status(400).send("An account with this email already exists.");
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = Date.now() + 600000; 

        if (user && !user.isVerified) {
            user.verificationOtp = otp;
            user.otpExpires = otpExpires;
        } else {
            user = new User({
                username,
                email: email.toLowerCase(),
                password,
                verificationOtp: otp,
                otpExpires: otpExpires
            });
        }
        
        await user.save();
        await sendVerificationEmail(user);
        
        res.render('pages/please-verify', { email: user.email, error: null });

    } catch (e) {
        console.error("Registration error:", e);
        res.status(500).render('pages/500');
    }
});

// --- UPDATED Verify Route ---
app.post('/verify-otp', async (req, res) => {
    try {
        const { otp, email } = req.body; 

        const user = await User.findOne({
            email: email.toLowerCase(),
            verificationOtp: otp,
            otpExpires: { $gt: Date.now() }
        });

        if (!user) {
            // FIX: Render the page again with an error message!
            return res.render('pages/please-verify', { 
                email: email, 
                error: 'Invalid or expired verification code. Please try again.' 
            });
        }

        user.isVerified = true;
        user.verificationOtp = undefined; 
        user.otpExpires = undefined;
        await user.save();
        
        req.login(user, (err) => {
            if (err) return res.redirect('/login');
            return res.redirect('/profile');
        });

    } catch (error) {
        res.status(500).render('pages/500');
    }
});

// --- NEW Route to handle Resend Button ---
app.post('/resend-otp', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email: email.toLowerCase() });
        
        if (user && !user.isVerified) {
            const otp = Math.floor(100000 + Math.random() * 900000).toString();
            user.verificationOtp = otp;
            user.otpExpires = Date.now() + 600000;
            await user.save();
            await sendVerificationEmail(user);
            return res.json({ success: true });
        }
        res.json({ success: false });
    } catch (e) {
        res.status(500).json({ success: false });
    }
});

app.post('/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const user = await User.findOne({ email: email });
        
        if (!user) {
            // Security best practice: don't reveal if email exists or not
            return res.redirect('/forgot-password?success=If an account exists, a link has been sent.');
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        user.passwordResetExpires = Date.now() + 3600000; // 1 hour
        await user.save();
        
        // FIX 1: Smart URL generation using the actual host domain
        const resetURL = `https://${req.get('host')}/reset-password/${resetToken}`;
        
        // FIX 2: Actually trigger the email to send!
        await sendPasswordResetEmail(user, resetURL);

        res.redirect('/forgot-password?success=If an account exists, a link has been sent.');
    } catch (e) { 
        console.error("Forgot Password Error:", e);
        res.redirect('/forgot-password?error=An error occurred while processing your request.'); 
    }
});

app.get('/reset-password/:token', async (req, res) => {
    try {
        const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
        const user = await User.findOne({
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() }
        });

        if (!user) return res.redirect('/forgot-password?error=Password reset link is invalid or has expired.');
        res.render('pages/reset-password', { token: req.params.token });
    } catch (e) { res.redirect('/forgot-password?error=An error occurred.'); }
});

app.post('/reset-password/:token', async (req, res, next) => {
    try {
        const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');
        const user = await User.findOne({
            passwordResetToken: hashedToken,
            passwordResetExpires: { $gt: Date.now() }
        });
        
        if (!user) return res.redirect('/forgot-password?error=Password reset link is invalid or has expired.');
        if (req.body.password !== req.body.confirmPassword) return res.redirect(`/reset-password/${req.params.token}?error=Passwords do not match.`);
        if (req.body.password.length < 6) return res.redirect(`/reset-password/${req.params.token}?error=Password must be at least 6 characters.`);

        user.password = req.body.password;
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save();

        req.login(user, (err) => {
            if (err) return next(err);
            res.redirect('/?message=Password has been reset successfully!');
        });
    } catch (e) { res.redirect('/forgot-password?error=An error occurred.'); }
});

app.get('/logout', (req, res, next) => {
    req.logout(err => { if (err) return next(err); res.redirect('/'); });
});

app.get('/auth/google', passport.authenticate('google', { scope:['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => res.redirect('/profile'));

// ===============================
// 9. PROFILE ROUTES
// ===============================

// Profile Route
app.get('/profile', ensureAuthenticated, async (req, res) => {
    try {
        const userWithWhitelist = await User.findById(req.user._id).populate('whitelist');
        
        const userObj = userWithWhitelist.toObject();
        userObj.signedAvatarUrl = req.user.signedAvatarUrl; 

        const userUploads = await File.find({ uploader: req.user.username, isLatestVersion: true }).sort({ createdAt: -1 });
        
        res.render('pages/profile', { user: userObj, uploads: userUploads });
    } catch (e) { res.status(500).send('Profile fetch error.'); }
});

// My Uploads Route
app.get('/my-uploads', ensureAuthenticated, async (req, res) => {
    try {
        const userUploads = await File.find({ uploader: req.user.username }).sort({ createdAt: -1 });
        
        const uploadsWithUrls = await Promise.all(userUploads.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            let signedIconUrl = '/images/default-avatar.png';
            if (key) {
                try {
                    signedIconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 });
                } catch (urlError) {}
            }
            return { ...file.toObject(), iconUrl: signedIconUrl };
        }));

        res.render('pages/my-uploads', { uploads: uploadsWithUrls }); 
    } catch (error) { res.status(500).render('pages/500'); }
});

app.get('/users/:username', async (req, res) => {
        try {
            const username = req.params.username;
            const user = await User.findOne({ username: username });
            if (!user) return res.status(404).render('pages/404');

            if (user.profileImageKey) {
                try {
                    user.signedAvatarUrl = await getSignedUrl(s3Client, new GetObjectCommand({
                        Bucket: process.env.B2_BUCKET_NAME, Key: user.profileImageKey
                    }), { expiresIn: 3600 });
                } catch (e) { user.signedAvatarUrl = '/images/default-avatar.png'; }
            } else {
                user.signedAvatarUrl = '/images/default-avatar.png';
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

app.post('/account/delete', ensureAuthenticated, async (req, res, next) => {
    try {
        const userId = req.user._id;
        const username = req.user.username;
        const preserveMods = req.body.preserveMods === 'true';

        if (preserveMods) {
            await File.updateMany({ uploader: username }, { uploader: 'GPL Community' });
        } else {
            await File.deleteMany({ uploader: username });
        }
        await Review.deleteMany({ user: userId });
        await User.findByIdAndDelete(userId);

        req.logout(function(err) {
            if (err) return next(err);
            res.redirect('/?message=Your account has been successfully deleted.');
        });
    } catch (error) { res.status(500).render('pages/500'); }
});


// ===================================
// 10. FILE UPLOAD & MANAGEMENT
// ===================================

app.get('/upload', ensureAuthenticated, (req, res) => {
    res.render('pages/upload');
});

app.post('/upload-initial', ensureAuthenticated, upload.single('modFile'), async (req, res) => {
    if (!req.file) {
        return res.status(400).redirect('/upload?error=No file selected.');
    }
    const tempFilePath = req.file.path;
    let newFile = null;

    try {
        console.log("Uploading main file to B2...");
        const fileForB2 = { path: tempFilePath, originalname: req.file.originalname, mimetype: req.file.mimetype };
        const fileKey = await uploadToB2(fileForB2, 'mods');
        console.log("Upload to B2 complete.");

        newFile = new File({
            uploader: req.user.username,
            fileKey: fileKey,
            originalFilename: req.file.originalname,
            fileSize: req.file.size,
            
            name: req.file.originalname, 
            version: 'Draft',
            category: 'android',         
            platforms:[],
            
            status: 'processing' 
        });
        await newFile.save();
        
        console.log("Starting background VirusTotal scan...");
        (async () => {
            try {
                const vtFormData = new FormData();
                vtFormData.append('file', fs.createReadStream(tempFilePath), req.file.originalname);

                const vtResponse = await axios.post('https://www.virustotal.com/api/v3/files', vtFormData, {
                    headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY, ...vtFormData.getHeaders() }
                });
                
                const analysisId = vtResponse.data.data.id;
                await File.findByIdAndUpdate(newFile._id, { virusTotalAnalysisId: analysisId });
                console.log(`VT Scan submitted for ${newFile._id}. Analysis ID: ${analysisId}`);
            } catch (vtError) {
                console.error(`Background VT scan failed for ${newFile._id}:`, vtError.response?.data || vtError.message);
            } finally {
                fs.unlinkSync(tempFilePath); 
            }
        })(); 

        res.redirect(`/upload-details/${newFile._id}`);

    } catch (error) {
        console.error("Initial upload error:", error);
        if (fs.existsSync(tempFilePath)) {
            fs.unlinkSync(tempFilePath);
        }
        res.status(500).render('pages/500');
    }
});

app.get('/upload-details/:fileId', ensureAuthenticated, async (req, res) => {
    try {
        const fileId = req.params.fileId;
        const pendingFile = await File.findById(fileId);

        if (!pendingFile) return res.status(404).render('pages/404');
        if (pendingFile.uploader !== req.user.username) return res.status(403).render('pages/403');

        const filename = pendingFile.originalFilename || "";
        
        const ext = filename.split('.').pop().toLowerCase();
        let defaultPlatform = "";
        if (ext === 'apk' || ext === 'xapk' || ext === 'apks') defaultPlatform = 'android';
        else if (ext === 'exe' || ext === 'msi') defaultPlatform = 'windows';
        else if (ext === 'ipa') defaultPlatform = 'ios-jailed';
        else if (ext === 'deb') defaultPlatform = 'ios-jailbroken';
        else if (ext === 'zip') defaultPlatform = 'wordpress'; 

        let cleanName = filename.replace(/\.[^/.]+$/, ""); 
        let defaultVersion = "";
        const versionMatch = cleanName.match(/v?(\d+\.\d+(\.\d+)?)/i);
        
        if (versionMatch) {
            defaultVersion = versionMatch[1]; 
            cleanName = cleanName.replace(versionMatch[0], "").replace(/[-_]+/g, " ").trim(); 
        } else {
            cleanName = cleanName.replace(/[-_]+/g, " ").trim();
        }

        res.render('pages/upload-details', { 
            fileId: pendingFile._id,
            fileKey: pendingFile.fileKey,
            filename: pendingFile.originalFilename,
            filesize: pendingFile.fileSize,
            defaultName: cleanName,
            defaultVersion: defaultVersion,
            defaultPlatform: defaultPlatform
        });

    } catch (error) {
        console.error("Error loading upload details:", error);
        res.status(500).render('pages/500');
    }
});

// --- NEW: User Delete Mod Route ---
app.post('/mods/:id/delete', ensureAuthenticated, async (req, res) => {
    try {
        const fileId = req.params.id;
        const file = await File.findById(fileId);

        // Security check: Make sure the file exists and the logged-in user owns it
        if (!file || file.uploader !== req.user.username) {
            return res.status(403).json({ success: false, message: 'Unauthorized' });
        }

        // Delete the file and its associated reviews/reports from the database
        await File.findByIdAndDelete(fileId);
        await Review.deleteMany({ file: fileId });
        await Report.updateMany({ file: fileId }, { status: 'resolved' });

        res.json({ success: true, message: 'Mod deleted successfully.' });
    } catch (error) {
        console.error("Error deleting mod:", error);
        res.status(500).json({ success: false });
    }
});

// --- GET Edit Mod Route ---
app.get('/mods/:id/edit', ensureAuthenticated, async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        
        // Security check
        if (!file || file.uploader !== req.user.username) {
            return res.status(403).render('pages/403');
        }

        // Generate signed URLs so the user can see their current images
        const iconUrl = await getSmartImageUrl(file.iconKey);
        const screenshotUrls = await Promise.all((file.screenshotKeys ||[]).map(key => getSmartImageUrl(key)));

        res.render('pages/edit-mod', { 
            file: { ...file.toObject(), iconUrl, screenshotUrls } 
        });
    } catch (error) {
        console.error("Error loading edit page:", error);
        res.status(500).render('pages/500');
    }
});

// --- POST Edit Mod Route ---
app.post('/mods/:id/edit', ensureAuthenticated, upload.fields([
    { name: 'softwareIcon', maxCount: 1 },
    { name: 'screenshots', maxCount: 4 }
]), async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        
        if (!file || file.uploader !== req.user.username) {
            return res.status(403).send("Unauthorized");
        }

        const formData = req.body;
        const { softwareIcon, screenshots } = req.files || {};

        // 1. Update images ONLY IF new ones were uploaded
        if (softwareIcon && softwareIcon.length > 0) {
            file.iconKey = await uploadToB2(softwareIcon[0], 'icons');
        }
        if (screenshots && screenshots.length > 0) {
            file.screenshotKeys = await Promise.all(screenshots.map(f => uploadToB2(f, 'screenshots')));
        }

        // 2. Format tags
        const processedTags = formData.tags ? formData.tags.split(',').map(t => t.trim()) : file.tags;

        // 3. Update all text fields
        file.name = formData.modName || file.name;
        file.version = formData.modVersion || file.version;
        file.developer = formData.developerName || file.developer;
        file.modDescription = formData.modDescription || file.modDescription;
        file.modFeatures = formData.modFeatures || file.modFeatures;
        file.whatsNew = formData.whatsNew || file.whatsNew;
        file.officialDescription = formData.officialDescription || file.officialDescription;
        file.videoUrl = formData.videoUrl || file.videoUrl;
        file.category = formData.modPlatform || file.category;
        file.tags = processedTags;

        if (formData.modCategory) {
            file.platforms = [formData.modCategory];
        }

        // 4. IMPORTANT: If the mod was rejected, switch it back to pending for re-review!
        if (file.status === 'rejected') {
            file.status = 'pending';
            file.rejectionReason = ''; // Clear the old rejection reason
        }

        await file.save();
        res.redirect('/my-uploads');

    } catch (error) {
        console.error("Error updating mod:", error);
        res.status(500).render('pages/500');
    }
});

app.post('/upload-finalize/:fileId', ensureAuthenticated, upload.fields([
    { name: 'softwareIcon', maxCount: 1 },
    { name: 'screenshots', maxCount: 4 }
]), async (req, res) => {
    try {
        const fileId = req.params.fileId;
        const fileToUpdate = await File.findById(fileId);

        if (!fileToUpdate || fileToUpdate.uploader !== req.user.username) {
            return res.status(403).render('pages/403');
        }

        const { softwareIcon, screenshots } = req.files;
        const formData = req.body; 

        if (!softwareIcon || !screenshots) {
            return res.redirect(`/upload-details/${fileId}?error=Icon and screenshots are required.`);
        }

        let iconKey = null;
        if (softwareIcon && softwareIcon.length > 0) {
            iconKey = await uploadToB2(softwareIcon[0], 'icons');
        }
        
        let screenshotKeys =[];
        if (screenshots && screenshots.length > 0) {
            screenshotKeys = await Promise.all(screenshots.map(f => uploadToB2(f, 'screenshots')));
        }

        if (softwareIcon && softwareIcon[0]) fs.unlinkSync(softwareIcon[0].path);
        if (screenshots) screenshots.forEach(f => fs.unlinkSync(f.path));

        const processedTags = formData.tags ? formData.tags.split(',').map(t => t.trim()) :[];

        await File.findByIdAndUpdate(fileId, {
            name: formData.modName,                 
            version: formData.modVersion,           
            developer: formData.developerName || 'N/A',
            modDescription: formData.modDescription,
            modFeatures: formData.modFeatures,
            whatsNew: formData.whatsNew,
            officialDescription: formData.officialDescription,
            videoUrl: formData.videoUrl,
            category: formData.modPlatform,         
            platforms: formData.modCategory ? [formData.modCategory] :[],
            tags: processedTags,
            iconKey: iconKey,
            screenshotKeys: screenshotKeys,
            status: 'pending' 
        });

        res.redirect('/my-uploads?success=Upload complete and submitted for review!');

    } catch (error) {
        console.error("Finalize upload error:", error);
        res.status(500).render('pages/500');
    }
});

// ===================================
// 11. API ROUTES
// ===================================

app.get('/api/search/suggestions', async (req, res) => {
    try {
        const query = req.query.q;
        
        if (!query || query.length < 2) {
            return res.json([]);
        }

        const suggestions = await File.find({
            status: 'live',
            isLatestVersion: true,
            $or:[
                { name: { $regex: query, $options: 'i' } },
                { tags: { $regex: query, $options: 'i' } },
                { category: { $regex: query, $options: 'i' } },
                { developer: { $regex: query, $options: 'i' } }
            ]
        })
        .select('name') 
        .limit(6);      

        const suggestionNames =[...new Set(suggestions.map(file => file.name))];

        res.json(suggestionNames);

    } catch (error) {
        console.error("API Suggestion Error:", error);
        res.status(500).json({ error: 'Server error while fetching suggestions.' });
    }
});

app.get('/api/trending-searches', async (req, res) => {
    try {
        const trendingFiles = await File.find(
            { isLatestVersion: true },
            { name: 1, _id: 0 } 
        )
        .sort({ downloads: -1 }) 
        .limit(5); 

        const trendingNames = trendingFiles.map(file => file.name);
        res.json(trendingNames); 

    } catch (error) {
        console.error("API Trending Searches Error:", error);
        res.status(500).json({ error: 'Could not fetch trending searches.' });
    }
});


// ===============================
// 12. SOCIAL & ADMIN INTERACTION
// ===============================

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

app.post('/reviews/add/:fileId', ensureAuthenticated, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        const existing = await Review.findOne({ file: req.params.fileId, user: req.user._id });
        if (existing) return res.redirect(`/mods/${req.params.fileId}`);

        const newReview = new Review({ file: req.params.fileId, user: req.user._id, username: req.user.username, rating: parseInt(rating), comment });
        await newReview.save();
        
        const stats = await Review.aggregate([{ $match: { file: new Types.ObjectId(req.params.fileId) } }, { $group: { _id: '$file', avg: { $avg: '$rating' }, count: { $sum: 1 } } }]);
        if (stats.length > 0) {
            await File.findByIdAndUpdate(req.params.fileId, { averageRating: stats[0].avg.toFixed(1), ratingCount: stats[0].count });
        }
        res.redirect(`/mods/${req.params.fileId}`);
    } catch (e) { res.status(500).send("Error."); }
});

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

app.post('/files/:fileId/report', ensureAuthenticated, async (req, res) => {
    try {
        const { reason, additionalComments } = req.body;
        const file = await File.findById(req.params.fileId);
        const existing = await Report.findOne({ file: req.params.fileId, reportingUser: req.user._id });
        if (!existing && file) {
            await new Report({
                file: req.params.fileId, reportingUser: req.user._id, reportedFileName: file.name,
                reportingUsername: req.user.username, reason, additionalComments
            }).save();
        }
        res.redirect(`/mods/${req.params.fileId}?reported=true`);
    } catch (e) { res.status(500).send("Error."); }
});

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

app.get('/community-chat', ensureAuthenticated, (req, res) => res.render('pages/community-chat'));

// ===============================
// 13. STATIC PAGES
// ===============================
app.get('/about', (req, res) => res.render('pages/static/about'));
app.get('/faq', (req, res) => res.render('pages/static/faq'));
app.get('/tos', (req, res) => res.render('pages/static/tos'));
app.get('/dmca', (req, res) => res.render('pages/static/dmca'));
app.get('/privacy-policy', (req, res) => res.render('pages/static/privacy-policy'));
app.get('/leaderboard', (req, res) => res.render('pages/coming-soon'));
app.get('/donate', (req, res) => res.render('pages/static/donate'));
app.get('/membership', ensureAuthenticated, (req, res) => res.render('pages/membership'));
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
// --- NEW: DYNAMIC SITEMAP FOR SEO ---
app.get('/sitemap.xml', async (req, res) => {
    // Tell the browser and search engines this is an XML file
    res.header('Content-Type', 'application/xml');
    
    try {
        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        
        // Start the XML structure
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
        xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

        // 1. Add Static Pages
        const staticPages =['', '/about', '/faq', '/dmca', '/tos', '/privacy-policy'];
        staticPages.forEach(page => {
            xml += `  <url>\n    <loc>${baseUrl}${page}</loc>\n    <changefreq>weekly</changefreq>\n    <priority>0.8</priority>\n  </url>\n`;
        });

        // 2. Add Dynamic Category Pages
        const categories =['android', 'ios-jailed', 'ios-jailbroken', 'windows', 'wordpress'];
        categories.forEach(cat => {
             xml += `  <url>\n    <loc>${baseUrl}/category?platform=${cat}</loc>\n    <changefreq>daily</changefreq>\n    <priority>0.7</priority>\n  </url>\n`;
        });

        // 3. Add ALL Live Mods dynamically from the database!
        const liveMods = await File.find({ status: 'live', isLatestVersion: true }).select('_id updatedAt');
        liveMods.forEach(mod => {
            xml += `  <url>\n    <loc>${baseUrl}/mods/${mod._id}</loc>\n    <lastmod>${mod.updatedAt.toISOString()}</lastmod>\n    <changefreq>daily</changefreq>\n    <priority>0.9</priority>\n  </url>\n`;
        });

        // Close the XML structure
        xml += '</urlset>';
        
        // Send the completed XML file
        res.send(xml);
        
    } catch (error) {
        console.error("Sitemap generation error:", error);
        res.status(500).end();
    }
});

// ===============================================
// 14. DATABASE CONNECTION & SERVER STARTUP
// ===============================================

// In-memory store for recent messages
let recentMessages =[];

const startServer = async () => {
    try {
        // --- Step 1: Connect to the Database ---
        await mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true, 
            useUnifiedTopology: true 
        });
        console.log('Successfully connected to MongoDB Atlas!');

        // --- Step 2: Only start the server AFTER the database is connected ---
        const server = http.createServer(app);
        const io = new Server(server, {
            cors: {
                origin: allowedOrigins, 
                methods:["GET", "POST"]
            }
        });

        // Socket.IO logic
        io.on('connection', (socket) => {
            console.log('A user connected to chat');

            socket.emit('chat history', recentMessages);

            socket.on('chat message', (msg) => {
                const messageData = {
                    username: msg.username,
                    avatar: msg.avatar, 
                    text: msg.text,
                    timestamp: new Date()
                };

                recentMessages.push(messageData);
                if (recentMessages.length > 50) {
                    recentMessages.shift();
                }

                io.emit('chat message', messageData);
            });

            socket.on('disconnect', () => {
                console.log('User disconnected from chat');
            });
        });

        server.listen(PORT, () => {
            console.log(`Server is running on port ${PORT} and connected to the database.`);
        });

    } catch (error) {
        console.error('Failed to connect to the database. Server is not starting.', error);
    }
};

// --- Execution ---
startServer();