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
const { Server } = require("socket.io"); // Corrected import
const crypto = require('crypto');
const cors = require('cors');// Added for CORS

// Custom Utilities & Config
const { sendVerificationEmail } = require('./utils/mailer');
const adminRouter = require('./config/admin'); // Updated from adminRouter

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
    return fileName;
};

// ===============================
// 5. MIDDLEWARE
// ===============================
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// --- ADD CORS MIDDLEWARE HERE ---
const allowedOrigins = [
    'http://localhost:3000',          // Your local dev environment
    'https://gplmods.webredirect.org'   // Your live custom domain
];

app.use(cors({
    origin: function (origin, callback) {
        // allow requests with no origin (like mobile apps or curl requests)
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
        // Update user's last seen timestamp in the background
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
            // User is logged in but has no custom avatar
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
// 6. PASSPORT STRATEGIES
// ===============================
const storage = multer.memoryStorage();
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
// 7. PUBLIC ROUTES
// ===============================

// --- NEW: Health Check Endpoint ---
// This is a standard endpoint for health checks from hosting providers.
app.get('/healthz', (req, res) => {
    // Send a simple JSON response with a 200 OK status
    res.status(200).json({ status: 'ok', message: 'Server is healthy' });
});

// Home (UPDATED)
app.get('/', async (req, res) => {
    try {
        const findQuery = { status: 'live', isLatestVersion: true };
        const categories = ['android', 'ios', 'wordpress', 'windows'];
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

// Search
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
            $or: [
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

        res.render('pages/search', {
            results: searchResults,
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

        let versionHistory = [];
        if (currentFile.parentFile) {
            let headFile = await File.findById(currentFile.parentFile).populate('olderVersions');
            versionHistory = [headFile, ...headFile.olderVersions.slice().reverse()];
            currentFile = headFile;
        } else {
            await currentFile.populate('olderVersions');
            versionHistory = [currentFile, ...currentFile.olderVersions.slice().reverse()];
        }

        const iconKey = currentFile.iconUrl || currentFile.iconKey;
        const iconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: iconKey }), { expiresIn: 3600 });
        
        const screenKeys = (currentFile.screenshotUrls && currentFile.screenshotUrls.length > 0)
            ? currentFile.screenshotUrls
            : (currentFile.screenshotKeys || []);
            
        const screenshotUrls = await Promise.all(screenKeys.map(key => getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 })));

        const reviews = await Review.find({ file: currentFile._id }).sort({ createdAt: -1 }).populate('user', 'profileImageKey'); // Populate the key

        // --- NEW: Manually generate signed URLs for each reviewer's avatar ---
        const reviewsWithAvatars = await Promise.all(reviews.map(async (review) => {
            let avatarUrl = '/images/default-avatar.png';
            if (review.user && review.user.profileImageKey) {
                try {
                    avatarUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: review.user.profileImageKey }), { expiresIn: 3600 });
                } catch (e) { console.error("Could not get signed URL for reviewer avatar."); }
            }
            // Return a new object that combines the review and the generated URL
            return { ...review.toObject(), user: { ...review.user.toObject(), signedAvatarUrl: avatarUrl } };
        }));

        const userHasWhitelisted = req.user ? req.user.whitelist.includes(currentFile._id) : false;
        const userHasVotedOnStatus = req.user ? currentFile.votedOnStatusBy.includes(req.user._id) : false;

        // --- Pass the NEW reviews object to the template ---
        res.render('pages/download', {
            file: { ...currentFile.toObject(), iconUrl, screenshotUrls },
            versionHistory,
            reviews: reviewsWithAvatars, // <-- Use the new object
            userHasWhitelisted,
            userHasVotedOnStatus
        });
    } catch (e) {
        console.error("Error on /mods/:id route:", e);
        res.status(500).send("Server error.");
    }
});


// --- NEW DEVELOPER PAGE ROUTE ---
app.get('/developer', async (req, res) => {
    try {
        const developerName = req.query.name;
        if (!developerName || developerName.trim() === '') {
            return res.redirect('/');
        }
        
        // --- THE FIX: Use a simpler, more flexible regex ---
        const filesByDeveloper = await File.find({
            // This now looks for any document where the developer field CONTAINS the developerName, case-insensitively.
            developer: { $regex: developerName, $options: 'i' }, 
            isLatestVersion: true,
            status: 'live' // Also ensure we only show live mods
        }).sort({ createdAt: -1 });

        res.render('pages/developer', {
            files: filesByDeveloper,
            developerName: developerName
        });

    } catch (error) {
        console.error("Error fetching files for developer page:", error);
        res.status(500).render('pages/500');
    }
});


// ===============================================
// FILE VERSIONING ROUTES
// ===============================================

// --- THIS IS THE MISSING GET ROUTE ---
// It displays the form for adding a new version.
app.get('/mods/:id/add-version', ensureAuthenticated, async (req, res) => {
    try {
        const parentFile = await File.findById(req.params.id);

        // Security Check: Ensure the person trying to add a version is the original uploader
        if (!parentFile || req.user.username.toLowerCase() !== parentFile.uploader.toLowerCase()) {
            // If they are not the uploader, show the 403 Forbidden page
            return res.status(403).render('pages/403');
        }

        // If all checks pass, render the page and pass the file data to it
        res.render('pages/add-version', { parentFile: parentFile });

    } catch (error) {
        console.error('Error loading the add-version page:', error);
        res.status(500).render('pages/500');
    }
});

// --- Your POST route for handling the form submission should also be here ---
// It seems you may have this one already, but double-check
app.post('/mods/:id/add-version', ensureAuthenticated, upload.single('modFile'), async (req, res) => {
    // ... all the logic for processing the new version upload ...
});

// Download Action - UPDATED with presigned URL
app.get('/download-file/:id', async (req, res) => {
    try {
        const file = await File.findByIdAndUpdate(req.params.id, { $inc: { downloads: 1 } });
        if (!file) {
            return res.status(404).render('pages/404');
        }

        // --- THE FIX: Check for the file key ---
        const fileKey = file.fileKey || file.fileUrl; // Check for new 'fileKey' OR old 'fileUrl'

        if (!fileKey) {
            console.error(`File with ID ${file._id} has no fileKey or fileUrl in the database.`);
            return res.status(500).send("File record is incomplete and cannot be downloaded.");
        }

        const command = new GetObjectCommand({
            Bucket: process.env.B2_BUCKET_NAME,
            Key: fileKey, // Use the validated key
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

// --- UPDATED /register route with OTP ---
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

        // Generate a 6-digit OTP
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = Date.now() + 600000; // 10 minutes from now

        if (user && !user.isVerified) {
            // If user exists but is not verified, update their OTP and expiry
            user.verificationOtp = otp;
            user.otpExpires = otpExpires;
        } else {
            // If it's a brand new user
            user = new User({
                username,
                email: email.toLowerCase(),
                password,
                verificationOtp: otp,
                otpExpires: otpExpires
            });
        }
        
        await user.save();
        await sendVerificationEmail(user); // Assumes this function sends the 'otp' variable in an email
        
        // Render the OTP entry page and pass the user's email to it
        res.render('pages/please-verify', { email: user.email });

    } catch (e) {
        console.error("Registration error:", e);
        res.status(500).render('pages/500');
    }
});

// --- NEW /verify-otp route (replaces old /verify-email) ---
app.post('/verify-otp', async (req, res) => {
    try {
        // Get email and OTP from the hidden inputs in the form
        const { otp, email } = req.body; 

        if (!otp || !email) {
            // This case should ideally not be hit with frontend validation
            return res.status(400).send("OTP and email are required.");
        }

        const user = await User.findOne({
            email: email.toLowerCase(),
            verificationOtp: otp,
            otpExpires: { $gt: Date.now() } // Check that the OTP is not expired
        });

        if (!user) {
            // If no user is found, the OTP was wrong or has expired.
            // Redirect back to the registration page with an error message for the user.
            return res.redirect('/register?error=Invalid or expired verification code.');
        }

        // OTP is correct, update the user account
        user.isVerified = true;
        user.verificationOtp = undefined; // Invalidate the OTP so it can't be used again
        user.otpExpires = undefined;
        await user.save();
        
        // Log the user in automatically and redirect to their profile page
        req.login(user, (err) => {
            if (err) {
                console.error("Login after verification failed:", err);
                return res.redirect('/login?message=Verification successful. Please log in.');
            }
            return res.redirect('/profile');
        });

    } catch (error) {
        console.error("OTP Verification Error:", error);
        res.status(500).render('pages/500');
    }
});


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
        console.log(`Reset Link: ${resetURL}`); 

        res.redirect('/forgot-password?success=If an account exists, a link has been sent.');
    } catch (e) { res.redirect('/forgot-password?error=Error.'); }
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

app.get('/my-uploads', ensureAuthenticated, async (req, res) => {
    try {
        const userUploads = await File.find({ uploader: req.user.username }).sort({ createdAt: -1 });
        res.render('pages/my-uploads', { uploads: userUploads });
    } catch (error) { res.status(500).render('pages/500'); }
});

app.get('/users/:username', async (req, res) => {
        try {
            const username = req.params.username;
            const user = await User.findOne({ username: username });
            if (!user) return res.status(404).render('pages/404');

            // --- Apply the same avatar logic here for the 'profileUser' ---
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

// ===============================
// 10. FILE UPLOAD & MANAGEMENT
// ===============================

app.get('/upload', ensureAuthenticated, (req, res) => res.render('pages/upload'));

// Step 1 of upload - Client requests a presigned URL
app.post('/generate-presigned-url', ensureAuthenticated, async (req, res) => {
    try {
        const { filename, filetype, folder } = req.body;
        if (!filename || !filetype || !folder) {
            return res.status(400).json({ error: 'Missing required parameters.' });
        }
        
        // Sanitize filename and create a unique key for the object in B2
        const uniqueKey = `${folder}/${Date.now()}-${sanitizeFilename(filename)}`;

        const command = new PutObjectCommand({
            Bucket: process.env.B2_BUCKET_NAME,
            Key: uniqueKey,
            ContentType: filetype
        });

        // Generate the presigned URL, valid for 15 minutes
        const signedUrl = await getSignedUrl(s3Client, command, { expiresIn: 900 });

        res.json({
            presignedUrl: signedUrl,
            fileKey: uniqueKey // The final path of the file in the bucket
        });

    } catch (error) {
        console.error("Error generating presigned URL:", error);
        res.status(500).json({ error: 'Could not prepare upload.' });
    }
});

// --- NEW ROUTE: The Metadata Form Page ---
app.get('/upload-details', ensureAuthenticated, (req, res) => {
    const { fileKey, filename, filesize } = req.query;
    if (!fileKey || !filename || !filesize) {
        return res.redirect('/upload?error=Invalid file details.');
    }
    // Render a new EJS page for the form, passing the file info
    res.render('pages/upload-details', { fileKey, filename, filesize });
});


// =========================================================
// ========= START: UPDATED /upload-finalize ROUTE =========
// =========================================================
app.post('/upload-finalize', ensureAuthenticated, upload.fields([
    { name: 'softwareIcon', maxCount: 1 },
    { name: 'screenshots', maxCount: 4 }
]), async (req, res) => {
    let newFileId = null; // To hold the ID of the newly created file

    try {
        // ... (your existing file validation, destructuring, and icon/screenshot uploads are fine)
        const { fileKey, originalFilename, fileSize, ...formData } = req.body;
        const { softwareIcon, screenshots } = req.files;
        if (!fileKey || !softwareIcon || !screenshots ) return res.status(400).json({ error: 'Missing file key or icon/screenshots.' });
        
        const iconKey = await uploadToB2(softwareIcon[0], 'icons');
        const screenshotKeys = await Promise.all(screenshots.map(shot => uploadToB2(shot, 'screenshots')));
        
        // --- 1. SAVE TO MONGODB FIRST ---
        // The file now has a 'pending' status by default from the model.
        const newFile = new File({
            name: formData.modName,
            version: formData.modVersion,
            developer: formData.developerName,
            modDescription: formData.modDescription,
            modFeatures: formData.modFeatures,
            whatsNew: formData.whatsNew,
            officialDescription: formData.officialDescription,
            videoUrl: formData.videoUrl,
            category: formData.modPlatform,
            platforms: [formData.modCategory],
            tags: formData.tags ? formData.tags.split(',').map(t => t.trim()) : [],
            uploader: req.user.username,
            fileSize: fileSize,
            originalFilename: originalFilename,
            iconKey: iconKey,
            screenshotKeys: screenshotKeys,
            fileKey: fileKey,
            isLatestVersion: true,
        });
        await newFile.save();
        newFileId = newFile._id; // Save the ID for the response

        // --- 2. RESPOND TO THE USER IMMEDIATELY ---
        // The user's upload is complete from their perspective.
        res.status(201).json({ message: 'Upload submitted for review!', fileId: newFileId });

        // --- 3. RUN VIRUSTOTAL SCAN IN THE BACKGROUND (FIRE-AND-FORGET) ---
        // This code will run after the response has been sent to the user.
        console.log(`Starting background VirusTotal scan for file ID: ${newFileId}`);
        const filePublicUrlForScan = `https://${process.env.B2_ENDPOINT}/${process.env.B2_BUCKET_NAME}/${fileKey}`;

        (async () => {
            try {
                const vtUrlScanResponse = await axios.post('https://www.virustotal.com/api/v3/urls',
                    `url=${encodeURIComponent(filePublicUrlForScan)}`,
                    { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY, 'Content-Type': 'application/x-www-form-urlencoded' } }
                );
                const analysisId = vtUrlScanResponse.data.data.id;

                // We won't wait for the final report here. An admin can check the status later,
                // or you could build a more advanced system with webhooks from VirusTotal.
                
                // Update the file in the database with the temporary analysis ID.
                await File.findByIdAndUpdate(newFileId, { virusTotalAnalysisId: analysisId });
                console.log(`VirusTotal analysis ID ${analysisId} saved for file ${newFileId}`);

            } catch (vtError) {
                console.error(`Background VirusTotal scan failed for file ${newFileId}:`, vtError.response?.data);
            }
        })(); // Immediately invoke the async function

    } catch (error) {
        console.error("Finalize upload error:", error);
        // We check if a response has already been sent to avoid crashing
        if (!res.headersSent) {
            res.status(500).json({ error: 'Server failed to finalize upload.' });
        }
    }
});
// =======================================================
// ========= END: UPDATED /upload-finalize ROUTE =========
// =======================================================

// ===================================
// 11. API ROUTES
// ===================================

app.get('/api/search/suggestions', async (req, res) => { 
    // This route was mentioned in the update but was not in the original file.
    // Add your search suggestion logic here. For now, it returns an empty array.
    res.json([]);
});

// --- NEW: Trending Searches API Route ---
app.get('/api/trending-searches', async (req, res) => {
    try {
        // We will fetch the names of the top 5 most downloaded mods
        // that are also the "latest version".
        const trendingFiles = await File.find(
            { isLatestVersion: true },
            { name: 1, _id: 0 } // Projection: only return the 'name' field
        )
        .sort({ downloads: -1 }) // Sort by most downloads
        .limit(5); // Get the top 5

        // Extract just the name strings from the result objects
        const trendingNames = trendingFiles.map(file => file.name);

        res.json(trendingNames); // Send back the array of names

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

// ===============================================
// 14. DATABASE CONNECTION & SERVER STARTUP
// ===============================================

// In-memory store for recent messages
let recentMessages = [];

const startServer = async () => {
    try {
        // --- Step 1: Connect to the Database ---
        await mongoose.connect(process.env.MONGO_URI, {
            // These options are deprecated but leaving them won't hurt for now
            useNewUrlParser: true, 
            useUnifiedTopology: true 
        });
        console.log('Successfully connected to MongoDB Atlas!');

        // --- Step 2: Only start the server AFTER the database is connected ---
        const server = http.createServer(app);
        const io = new Server(server, {
            cors: {
                origin: allowedOrigins, // Use the 'allowedOrigins' array you defined earlier
                methods: ["GET", "POST"]
            }
        });

        // Your existing Socket.IO logic
        io.on('connection', (socket) => {
            console.log('A user connected to chat');

            // --- 1. Send message history to the newly connected user ---
            socket.emit('chat history', recentMessages);

            // --- 2. Listen for new chat messages from a user ---
            socket.on('chat message', (msg) => {
                const messageData = {
                    username: msg.username,
                    avatar: msg.avatar, // 'msg.avatar' from the client is already the signed URL
                    text: msg.text,
                    timestamp: new Date()
                };

                recentMessages.push(messageData);
                if (recentMessages.length > 50) {
                    recentMessages.shift();
                }

                io.emit('chat message', messageData);
            });

            // --- 3. Handle user disconnection ---
            socket.on('disconnect', () => {
                console.log('User disconnected from chat');
            });
        });

        server.listen(PORT, () => {
            console.log(`Server is running on port ${PORT} and connected to the database.`);
        });

    } catch (error) {
        console.error('Failed to connect to the database. Server is not starting.', error);
        process.exit(1); // Exit the process with an error code
    }
};

// --- Call the function to start the entire application ---
startServer();