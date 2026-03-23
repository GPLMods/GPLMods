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
const GitHubStrategy = require('passport-github2').Strategy;
const MicrosoftStrategy = require('passport-microsoft').Strategy;
const MongoDBStore = require('connect-mongodb-session')(session);
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
const UnbanRequest = require('./models/unbanRequest'); 
const DistributorApplication = require('./models/distributorApplication');
const Request = require('./models/request');
const UserNotification = require('./models/userNotification');
const SupportTicket = require('./models/supportTicket');

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

// --- NEW HELPER: FORMAT FILE SIZE DYNAMICALLY ---
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0 || !bytes) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes =['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
// ------------------------------------------------

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
    // Determine if the file is in memory (buffer) or on disk (path)
    let fileBuffer;
    if (file.buffer) {
        fileBuffer = file.buffer;
    } else if (file.path && fs.existsSync(file.path)) {
        fileBuffer = fs.readFileSync(file.path);
    } else {
        throw new Error("File data not found in buffer or disk path.");
    }

    const sanitizedFilename = sanitizeFilename(file.originalname);
    const fileName = `${folder}/${Date.now()}-${sanitizedFilename}`;
    const params = {
        Bucket: process.env.B2_BUCKET_NAME,
        Key: fileName,
        Body: fileBuffer,
        ContentType: file.mimetype
    };
    
    console.log(`Uploading ${fileName} to B2...`);
    await s3Client.send(new PutObjectCommand(params));            
    return fileName;
};

// ===============================
// 4. MIDDLEWARE & CONFIGURATION
// ===============================

// 1. Static Files
app.use(express.static(path.join(__dirname, 'public')));

// 2. Parsers (Crucial for AdminJS and login forms)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// 3. CORS
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

// 4. Maintenance Mode
app.use((req, res, next) => {
    if (process.env.MAINTENANCE_MODE === 'on') {
        // We can't check req.user yet because Passport hasn't run, 
        // so we only allow access to the /admin login path itself
        if (req.path.startsWith('/admin')) {
            return next();
        }
        return res.status(503).render('pages/maintenance');
    }
    next();
});

// 5. DATABASE CONNECTION PROMISE (Needed for session & AdminJS)
const clientPromise = mongoose.connect(process.env.MONGO_URI)
    .then(m => {
        mongoose.Model.count = mongoose.Model.countDocuments; 
        console.log('Successfully connected to MongoDB Atlas!');
        return m.connection.getClient(); 
    })
    .catch(err => console.error('MongoDB connection error:', err));

// 6. SESSION MIDDLEWARE
const store = new MongoDBStore({
    uri: process.env.MONGO_URI,
    collection: 'sessions'
});

store.on('error', function(error) {
    console.error('Session Store Error:', error);
});

app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-key',
    resave: false,
    saveUninitialized: false,
    store: store, 
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 } // Default 7 days
}));

// ===============================
// 5. PASSPORT (AUTHENTICATION)
// ===============================

// 1. Initialize Passport (MUST come right after Session)
app.use(passport.initialize());
app.use(passport.session());

// 2. Passport Serialization
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    try { const user = await User.findById(id); done(null, user); } catch (e) { done(e); }
});

// 3. Dynamic Session Expiration
app.use((req, res, next) => {
    if (req.session) {
        if (req.isAuthenticated()) {
            req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * 3; // 3 Days for logged-in users
        } else {
            req.session.cookie.maxAge = 1000 * 60 * 60 * 1; // 1 Hour for guests
        }
    }
    next();
});

// 4. User Last Seen Updater
app.use(async (req, res, next) => {
    if (req.isAuthenticated()) {
        User.findByIdAndUpdate(req.user.id, { lastSeen: new Date() }).exec();
    }
    next();
});

// 5. Signed Avatar URL Generator
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

// 6. Globals & Notification Cache Middleware
let cachedTotalUpdates = 0;
let lastUpdateCheck = 0;

app.use(async (req, res, next) => {
    // MUST BE SET HERE so every EJS file knows if the user is logged in
    res.locals.user = req.user || null;
    res.locals.timeAgo = timeAgo;
    res.locals.formatBytes = formatBytes; 
    
    try {
        // 1. Check Global Announcements
        if (Date.now() - lastUpdateCheck > 5 * 60 * 1000) {
            cachedTotalUpdates = await Announcement.countDocuments();
            lastUpdateCheck = Date.now();
        }
        res.locals.totalUpdatesCount = cachedTotalUpdates;

        // 2. Check Personal Notifications
        let unreadPersonalCount = 0;
        if (req.isAuthenticated() && req.user) {
            unreadPersonalCount = await UserNotification.countDocuments({ 
                user: req.user._id, 
                isRead: false 
            });
        }
        res.locals.unreadPersonalCount = unreadPersonalCount;
        
        next();
    } catch (e) {
        console.error("Global Middleware Error:", e);
        // Fallback to 0 so the page still loads even if DB fails
        res.locals.totalUpdatesCount = cachedTotalUpdates;
        res.locals.unreadPersonalCount = 0;
        next();
    }
});

// 7. Banned User Trap
app.use((req, res, next) => {
    if (req.isAuthenticated() && req.user && req.user.isBanned) {
        const allowedPaths =['/banned', '/logout', '/unban-request'];
        if (!allowedPaths.includes(req.path)) {
            return res.redirect('/banned');
        }
    }
    next();
});

// 8. Auth Helper Functions (Used by routes)
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}
function ensureAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') return next();
    res.status(403).render('pages/403');
}
function redirectIfAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/'); 
    }
    next();
}
async function verifyRecaptcha(req, res, next) {
    const token = req.body['g-recaptcha-response'];
    const returnUrl = req.path;
    if (!token) return res.redirect(`${returnUrl}?error=Please complete the "I'm not a robot" check.`);
    try {
        const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${token}`);
        if (response.data.success) return next();
        return res.redirect(`${returnUrl}?error=CAPTCHA verification failed. Please try again.`);
    } catch (e) { 
        console.error("reCAPTCHA API Error:", e);
        return res.redirect(`${returnUrl}?error=A server error occurred during CAPTCHA verification.`);
    }
}

// ===============================
// 5.5 PASSPORT STRATEGIES & MULTER
// ===============================

// 1. Disk Storage (For large Mod files)
const diskStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadPath = 'uploads/';
        fs.mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage: diskStorage });

// 2. NEW: Memory Storage (Specifically for Avatars and small images)
const memoryStorage = multer.memoryStorage();
// Limit avatar uploads to 5MB to protect memory
const uploadAvatar = multer({ 
    storage: memoryStorage,
    limits: { fileSize: 5 * 1024 * 1024 } 
});
// Local Strategy
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

// Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.BASE_URL ? `${process.env.BASE_URL}/auth/google/callback` : "https://gplmods.webredirect.org/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
    const googleUserData = { googleId: profile.id, username: profile.displayName, email: profile.emails[0].value, isVerified: true };
    try {
        let user = await User.findOne({ email: googleUserData.email });
        if (user) { user.googleId = googleUserData.googleId; await user.save(); done(null, user); } 
        else {
            if (await User.findOne({ username: googleUserData.username })) googleUserData.username += Math.floor(Math.random() * 1000);
            user = await User.create(googleUserData); done(null, user);
        }
    } catch (err) { done(err, null); }
}));

// GitHub Strategy
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: process.env.BASE_URL ? `${process.env.BASE_URL}/auth/github/callback` : "https://gplmods.webredirect.org/auth/github/callback",
    scope: ['user:email']
}, async (accessToken, refreshToken, profile, done) => {
    const email = (profile.emails && profile.emails.length > 0) ? profile.emails[0].value : `${profile.username}@github.com`;
    const githubUserData = { githubId: profile.id, username: profile.username || profile.displayName, email: email, profileImageKey: profile.photos && profile.photos.length > 0 ? profile.photos[0].value : '', isVerified: true };
    try {
        let user = await User.findOne({ email: githubUserData.email });
        if (user) { user.githubId = githubUserData.githubId; await user.save(); done(null, user); } 
        else {
            if (await User.findOne({ username: githubUserData.username })) githubUserData.username += Math.floor(Math.random() * 1000);
            user = await User.create(githubUserData); done(null, user);
        }
    } catch (err) { done(err, null); }
}));

// Microsoft Strategy
passport.use(new MicrosoftStrategy({
    clientID: process.env.MICROSOFT_CLIENT_ID,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
    callbackURL: process.env.BASE_URL ? `${process.env.BASE_URL}/auth/microsoft/callback` : "https://gplmods.webredirect.org/auth/microsoft/callback",
    scope: ['user.read']
}, async (accessToken, refreshToken, profile, done) => {
    const email = (profile.emails && profile.emails.length > 0) ? profile.emails[0].value : profile.userPrincipalName;
    const microsoftUserData = { microsoftId: profile.id, username: profile.displayName.replace(/\s+/g, '') || `user_${profile.id}`, email: email, isVerified: true };
    try {
        let user = await User.findOne({ email: microsoftUserData.email });
        if (user) { user.microsoftId = microsoftUserData.microsoftId; await user.save(); done(null, user); } 
        else {
            if (await User.findOne({ username: microsoftUserData.username })) microsoftUserData.username += Math.floor(Math.random() * 1000);
            user = await User.create(microsoftUserData); done(null, user);
        }
    } catch (err) { done(err, null); }
}));

// ===============================
// 6. PUBLIC ROUTES
// ===============================

// Health Check Endpoint
app.get('/healthz', (req, res) => {
    res.status(200).json({ status: 'ok', message: 'Server is healthy' });
});

// Home
app.get('/', (req, res, next) => {
    // --- ✅ FIX: ABSOLUTE CACHE PREVENTION ---
    // This forces the browser to re-request the page every single time.
    res.setHeader('Surrogate-Control', 'no-store');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    next();
}, async (req, res) => {
    try {
        const findQuery = { status: 'live', isLatestVersion: true };
        const categories =['android', 'ios-jailed', 'ios-jailbroken', 'wordpress', 'windows'];
        const filesByCategory = {};

        // 1. Fetch all the data
        await Promise.all(categories.map(async (cat) => {
            const workingMods = await File.find({ category: cat, ...findQuery }).sort({ averageRating: -1, downloads: -1 }).limit(4).lean();
            const popularMods = await File.find({ category: cat, ...findQuery }).sort({ downloads: -1 }).limit(4).lean();
            const newUpdates = await File.find({ category: cat, ...findQuery }).sort({ createdAt: -1 }).limit(4).lean();
            
            filesByCategory[cat] = {
                '100-Percent-Working': workingMods,
                'Most-Popular': popularMods,
                'New-Updates': newUpdates,
            };
        }));

        // 2. Process the Image URLs safely
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
                        return { ...file, iconUrl: signedIconUrl };
                    })
                );
            }
        }
        
        // 3. Render the page!
        res.render('pages/index', { filesByCategory });
        
    } catch (error) {
        console.error("CRITICAL Error fetching files for homepage:", error);
        res.status(500).render('pages/500');
    }
});

// ===================================
// NOTIFICATION SYSTEM ROUTES
// ===================================

// 1. The Notification Hub (Category Selection)
// Using lowercase 'app'
app.get('/notifications', ensureAuthenticated, async (req, res) => {
    try {
        // Optimization: Run both database queries at the same time
        const [unreadPersonalCount, totalGlobalUpdates] = await Promise.all([
            UserNotification.countDocuments({ user: req.user._id, isRead: false }),
            Announcement.countDocuments()
        ]);

        res.render('pages/notifications-hub', {
            unreadPersonalCount, // Shorthand for unreadPersonalCount: unreadPersonalCount
            totalGlobalUpdates
        });
    } catch (error) {
        console.error("Error loading notification hub:", error);
        res.status(500).render('pages/500');
    }
});
// 2. Site Updates List (Global Announcements)
app.get('/notifications/site-updates', async (req, res) => {
    try {
        // Fetch all global announcements
        const announcements = await Announcement.find().sort({ createdAt: -1 });
        res.render('pages/updates', { announcements: announcements });
    } catch (error) { 
        console.error("Site Updates page error:", error);
        res.status(500).render('pages/500'); 
    }
});

// 3. Admin Responses List (Personal Direct Messages)
app.get('/notifications/admin-messages', ensureAuthenticated, async (req, res) => {
    try {
        // Fetch only the logged-in user's personal notifications
        const personalNotifications = await UserNotification.find({ user: req.user._id }).sort({ createdAt: -1 });
        
        // Mark them all as read since the user is now viewing them
        if (personalNotifications.length > 0) {
            await UserNotification.updateMany(
                { user: req.user._id, isRead: false }, 
                { $set: { isRead: true } }
            );
        }

        res.render('pages/admin-messages', { personalNotifications: personalNotifications });
    } catch (error) {
        console.error("Admin Messages page error:", error);
        res.status(500).render('pages/500');
    }
});
// --- NEW: 24-Hour "New Uploads" Feed ---
app.get('/notifications/new-uploads', async (req, res) => {
    try {
        // 1. Calculate the timestamp for 24 hours ago
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

        // 2. Find files CREATED within the last 24 hours that are LIVE
        const recentUploads = await File.find({
            createdAt: { $gte: oneDayAgo },
            status: 'live',
            isLatestVersion: true
        }).sort({ createdAt: -1 });

        // 3. Get signed URLs for the icons (using our smart helper)
        const uploadsWithUrls = await Promise.all(recentUploads.map(async (file) => {
            const iconKey = file.iconUrl || file.iconKey;
            const iconUrl = await getSmartImageUrl(iconKey);
            return { ...file.toObject(), iconUrl };
        }));

        res.render('pages/feed-new-uploads', { files: uploadsWithUrls });

    } catch (error) {
        console.error("Error fetching new uploads feed:", error);
        res.status(500).render('pages/500');
    }
});

// --- NEW: 24-Hour "New Updates" Feed ---
app.get('/notifications/new-updates', async (req, res) => {
    try {
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

        // 1. Find files UPDATED within the last 24 hours that are LIVE
        // We use updatedAt instead of createdAt for this feed
        const recentUpdates = await File.find({
            updatedAt: { $gte: oneDayAgo },
            status: 'live',
            isLatestVersion: true
        }).sort({ updatedAt: -1 });

        // 2. Get signed URLs for the icons
        const updatesWithUrls = await Promise.all(recentUpdates.map(async (file) => {
            const iconKey = file.iconUrl || file.iconKey;
            const iconUrl = await getSmartImageUrl(iconKey);
            return { ...file.toObject(), iconUrl };
        }));

        res.render('pages/feed-new-updates', { files: updatesWithUrls });

    } catch (error) {
        console.error("Error fetching new updates feed:", error);
        res.status(500).render('pages/500');
    }
});
// Category / Filter
app.get('/category', async (req, res) => {
    try {
        const { platform, category, sort, page = 1 } = req.query;
        const limit = 12;
        const currentPage = parseInt(page);
        const queryFilter = { isLatestVersion: true };
if (platform && platform !== 'all') {
            // FIX: Search for the exact platform name (e.g., 'ios-jailed')
            queryFilter.category = platform;
        }
        
        // Also, ensure we only show live mods in the category page!
        queryFilter.status = 'live';

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
            totalPages: totalPages,
            currentPage: currentPage,
            
            // THESE THREE LINES ARE THE CRITICAL FIX:
            // They must NOT be wrapped inside a 'currentFilters' object.
            currentPlatform: platform || 'all', 
            currentCategory: category || 'all',
            currentSort: sort || 'latest'
        });  
    } catch (error) { res.status(500).render('pages/500'); }
});

// Search Route
// Helper function to safely escape regex characters
const escapeRegex = (text) => text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&");

app.get('/search', async (req, res) => {
    try {
        // ✅ FIX: The query parsing and escaping MUST happen inside the route!
        const rawQuery = req.query.q || '';
        const query = escapeRegex(rawQuery); // Escape it safely for the database
        
        const platform = req.query.platform || 'all';
        const sort = req.query.sort || 'newest';
        const page = parseInt(req.query.page) || 1;
        const resultsPerPage = 12;

        if (!rawQuery) return res.redirect('/');
        
        let searchQuery = {
            isLatestVersion: true,
            status: 'live', 
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
            query: rawQuery, // We pass the raw (unescaped) query back to the UI so it looks normal to the user!
            totalResults: totalResults,
            totalPages: totalPages,
            currentPage: page,
            currentPlatform: platform,
            currentSort: sort
        });

    } catch (error) {
        console.error("Search Error:", error);
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

        // ======== ADD THIS SECURITY CHECK ========
        // If the mod is NOT live, block access unless it's the Admin or the Uploader
        if (currentFile.status !== 'live') {
            const isUploader = req.user && req.user.username === currentFile.uploader;
            const isAdmin = req.user && req.user.role === 'admin';
            
            if (!isUploader && !isAdmin) {
                return res.status(403).render('pages/403'); // Show Forbidden page
            }
        }

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

// Download Action - UPDATED for External Links & Presigned URLs
app.get('/download-file/:id', async (req, res) => {
    try {
        const file = await File.findByIdAndUpdate(req.params.id, { $inc: { downloads: 1 } });
        if (!file) {
            return res.status(404).render('pages/404');
        }

        // --- 1. CHECK FOR EXTERNAL CLOUD LINK FIRST ---
        if (file.externalDownloadUrl) {
            // If the admin pasted a Mega/Drive/Dropbox link, redirect straight to it!
            return res.redirect(file.externalDownloadUrl);
        }

        // --- 2. FALLBACK TO BACKBLAZE B2 ---
        const fileKey = file.fileKey || file.fileUrl; 

        if (!fileKey) {
            console.error(`File with ID ${file._id} has no fileKey or external URL.`);
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

// ✅ FIX 1: Added redirectIfAuthenticated
app.get('/login', (req, res) => {
    res.render('pages/login', {
        recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY,
        message: req.query.message || null,
        error: req.query.error || null // <--- ADD THIS
    });
});
app.post('/login', verifyRecaptcha, (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        
        // If authentication fails, redirect back with the error message
        if (!user) return res.redirect('/login?error=' + encodeURIComponent(info.message));

        // If authentication succeeds, log them in
        req.logIn(user, (loginErr) => {
            if (loginErr) return next(loginErr);
            
            // --- SECURITY FIX: Generate a brand new Session ID upon login ---
            let tempSession = req.session.passport; // Save their passport data
            req.session.regenerate((regenErr) => {
                if (regenErr) console.error("Session Regen Error:", regenErr);
                
                req.session.passport = tempSession; // Restore the passport data to the new session
                req.session.save((saveErr) => {
                    if (saveErr) console.error("Session Save Error:", saveErr);
                    res.redirect('/?message=Welcome back!');
                });
            });
        });
    })(req, res, next);
});
app.get('/register', redirectIfAuthenticated, (req, res) => {
    res.render('pages/register', { 
        recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY || '', 
        message: req.query.message || null,
        error: req.query.error || null
    });
});
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
            if (err) return res.redirect('/login?error=Verification successful, but login failed. Please log in manually.');
            
            // --- SECURITY FIX: Generate a brand new Session ID upon verification/login ---
            let tempSession = req.session.passport;
            req.session.regenerate((regenErr) => {
                req.session.passport = tempSession;
                req.session.save(() => {
                    return res.redirect('/profile?success=Account verified successfully!');
                });
            });
        });

    } catch (error) {
        res.status(500).render('pages/500');
    }
});

app.get('/forgot-password', (req, res) => {
    // This looks in views/pages/forgot-password.ejs
    res.render('pages/forgot-password'); 
}); // <--- THIS CLOSING BRACKET WAS MISSING!

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
    // 1. Log the user out of Passport
    req.logout(err => { 
        if (err) {
            console.error("Logout Error:", err);
            return next(err); 
        } 
        
        // 2. Destroy the session in the MongoDB store
        req.session.destroy((destroyErr) => {
            if (destroyErr) {
                console.error("Session Destruction Error:", destroyErr);
            }
            
            // 3. Clear the cookie from the user's browser
            // The name 'connect.sid' is the default cookie name used by express-session
            res.clearCookie('connect.sid', { path: '/' });
            
            // 4. Redirect home
            res.redirect('/?message=You have been successfully logged out.'); 
        });
    });
});

// Google Routes (Existing)
app.get('/auth/google', passport.authenticate('google', { scope:['profile', 'email'] }));
// ✅ FIX: Force session save before redirecting to ensure cookies are set
app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }), 
    (req, res, next) => {
        req.session.save((err) => {
            if (err) {
                console.error('Session save error during Google login:', err);
                return next(err);
            }
            res.redirect('/?message=Successfully logged in with Google!');
        });
    }
);

// --- NEW GITHUB ROUTES ---
app.get('/auth/github', passport.authenticate('github', { scope:[ 'user:email' ] }));
app.get('/auth/github/callback', 
    passport.authenticate('github', { failureRedirect: '/login' }), 
    (req, res, next) => {
        req.session.save((err) => {
            if (err) return next(err);
            res.redirect('/?message=Successfully logged in with GitHub!');
        });
    }
);

// --- NEW MICROSOFT ROUTES ---
app.get('/auth/microsoft', passport.authenticate('microsoft', { prompt: 'select_account' }));
app.get('/auth/microsoft/callback', 
    passport.authenticate('microsoft', { failureRedirect: '/login' }), 
    (req, res, next) => {
        req.session.save((err) => {
            if (err) return next(err);
            res.redirect('/?message=Successfully logged in with Microsoft!');
        });
    }
);

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

// --- PUBLIC PROFILE ROUTE ---
app.get('/users/:username', async (req, res) => {
    try {
        const username = req.params.username;
        
        const user = await User.findOne({ username: username })
            .populate('following', 'username profileImageKey role')
            .populate('followers', 'username profileImageKey role');

        if (!user) return res.status(404).render('pages/404');

        if (user.profileImageKey) {
            try {
                user.signedAvatarUrl = await getSignedUrl(s3Client, new GetObjectCommand({
                    Bucket: process.env.B2_BUCKET_NAME, Key: user.profileImageKey
                }), { expiresIn: 3600 });
            } catch (e) { 
                user.signedAvatarUrl = '/images/default-avatar.png'; 
            }
        } else {
            user.signedAvatarUrl = '/images/default-avatar.png';
        }

        const uploads = await File.find({ 
            uploader: username, 
            isLatestVersion: true,
            status: 'live' 
        }).sort({ createdAt: -1 });
        
        const uploadsWithUrls = await Promise.all(uploads.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            const iconUrl = key ? await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 }) : '/images/default-avatar.png';
            return { ...file.toObject(), iconUrl };
        }));

        // --- Follow Logic Check ---
        let isFollowing = false;
        if (req.isAuthenticated()) {
            isFollowing = req.user.following.includes(user._id);
        }

        res.render('pages/public-profile', { 
            profileUser: user, 
            uploads: uploadsWithUrls,
            isFollowing: isFollowing 
        });

    } catch (error) { 
        console.error("Public Profile Error:", error);
        res.status(500).render('pages/500'); 
    }
}); 

// --- ACCOUNT MANAGEMENT ROUTES ---

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

app.post('/account/update-profile-image', ensureAuthenticated, uploadAvatar.single('profileImage'), async (req, res, next) => {
    try {
        if (!req.file) return res.redirect('/profile?error=No image file was selected.');
        if (!req.file.mimetype.startsWith('image/')) return res.redirect('/profile?error=Please upload a valid image file (JPG, PNG).');
        
        const imageKey = await uploadToB2(req.file, 'avatars');
        const updatedUser = await User.findByIdAndUpdate(req.user.id, { profileImageKey: imageKey }, { new: true });
        
        req.login(updatedUser, (err) => {
            if (err) return next(err);
            res.redirect('/profile?success=Profile image updated successfully.');
        });
    } catch (error) { 
        console.error("Error updating profile image:", error);
        res.redirect('/profile?error=' + encodeURIComponent('Could not upload image. Please try a different, smaller file.')); 
    }
});

app.post('/account/change-password', ensureAuthenticated, async (req, res) => {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;
        
        if (newPassword !== confirmPassword) return res.redirect('/profile?error=Passwords do not match.');

        const user = await User.findById(req.user.id);

        if (user.password) {
            const isMatch = await user.comparePassword(currentPassword);
            if (!isMatch) return res.redirect('/profile?error=Current password is incorrect.');
        } else {
            if (currentPassword !== 'social_login_bypass') return res.redirect('/profile?error=Invalid password setup request.');
        }

        user.password = newPassword;
        await user.save();
        res.redirect('/profile?success=Password updated successfully.');
        
    } catch (error) { 
        console.error("Error changing password:", error);
        res.redirect('/profile?error=' + encodeURIComponent(error.message)); 
    }
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

// --- UPDATED ROUTE: Handles both File Uploads and Distributor Links ---
app.post('/upload-initial', ensureAuthenticated, upload.single('modFile'), async (req, res) => {
    
    // --- SCENARIO 1: DISTRIBUTOR UPLOAD (External Link) ---
    // If the user is a distributor and they provided an externalUrl, skip file processing
    if (req.user.role === 'distributor' && req.body.externalUrl) {
        try {
            const { externalUrl, originalFilename } = req.body;

            // Create a "shell" file document for the external link
            const newFile = new File({
                uploader: req.user.username,
                externalDownloadUrl: externalUrl, // Save the external link
                originalFilename: originalFilename,
                
                // We use these placeholders to satisfy the Mongoose schema requirements
                // because there is no actual file in our B2 bucket for this mod.
                fileKey: 'external-link', 
                fileSize: 0, 
                
                name: originalFilename, 
                version: 'Draft',
                category: 'android',         
                platforms: [],
                
                status: 'processing' 
            });
            
            await newFile.save();
            
            console.log(`Distributor ${req.user.username} created external link draft.`);
            // Skip B2 upload and VirusTotal scan, go straight to details page
            return res.redirect(`/upload-details/${newFile._id}`);

        } catch (error) {
            console.error("Distributor initial upload error:", error);
            return res.status(500).render('pages/500');
        }
    }


    // --- SCENARIO 2: STANDARD USER UPLOAD (Physical File Upload) ---
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
            platforms: [],
            
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
// ===================================
// USER FOLLOW SYSTEM
// ===================================
app.post('/users/:id/follow', ensureAuthenticated, async (req, res) => {
    try {
        const targetUserId = req.params.id;
        const currentUserId = req.user._id;

        // You cannot follow yourself
        if (targetUserId === currentUserId.toString()) {
            return res.redirect('back');
        }

        const targetUser = await User.findById(targetUserId);
        if (!targetUser) return res.status(404).send("User not found.");

        // Check if the current user is already following the target user
        const isFollowing = req.user.following.includes(targetUserId);

        if (isFollowing) {
            // UNFOLLOW LOGIC
            await User.findByIdAndUpdate(currentUserId, { $pull: { following: targetUserId } });
            await User.findByIdAndUpdate(targetUserId, { $pull: { followers: currentUserId } });
        } else {
            // FOLLOW LOGIC
            await User.findByIdAndUpdate(currentUserId, { $push: { following: targetUserId } });
            await User.findByIdAndUpdate(targetUserId, { $push: { followers: currentUserId } });
            
            // Optional: Send a notification to the user that they got a new follower
            // await new UserNotification({ user: targetUserId, title: "New Follower", message: `${req.user.username} started following you!`, type: 'info' }).save();
        }

        // Redirect back to the profile page they were just on
        res.redirect(`/users/${targetUser.username}`);

    } catch (error) {
        console.error("Follow User Error:", error);
        res.status(500).send("Server Error");
    }
});

// ===============================
// 13. STATIC PAGES
// ===============================
app.get('/about', (req, res) => res.render('pages/static/about'));
app.get('/faq', (req, res) => res.render('pages/static/faq'));
app.get('/tos', (req, res) => res.render('pages/static/tos'));
app.get('/dmca', (req, res) => res.render('pages/static/dmca'));
app.get('/privacy-policy', (req, res) => res.render('pages/static/privacy-policy'));
app.get('/donate', (req, res) => res.render('pages/static/donate'));
app.get('/leaderboard', (req, res) => res.render('pages/coming-soon'));
app.get('/membership', (req, res) => {
    // If you use Stripe/Cashfree keys in this view, pass them here
    res.render('pages/membership', {
        // e.g., stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY
    });
});

// ======== ADD THE BULLETPROOF SITEMAP HERE ========
app.get('/sitemap.xml', async (req, res) => {
    try {
        // 1. Set the correct XML header so browsers & Google know how to read it
        res.set('Content-Type', 'text/xml');
        
        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
        xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

        // 2. Static Pages
        const staticPages = ['', '/about', '/faq', '/dmca', '/tos', '/privacy-policy'];
        staticPages.forEach(page => {
            xml += `  <url>\n    <loc>${baseUrl}${page}</loc>\n    <changefreq>weekly</changefreq>\n    <priority>0.8</priority>\n  </url>\n`;
        });

        // 3. Category Pages
        const categories = ['android', 'ios-jailed', 'ios-jailbroken', 'windows', 'wordpress'];
        categories.forEach(cat => {
             xml += `  <url>\n    <loc>${baseUrl}/category?platform=${cat}</loc>\n    <changefreq>daily</changefreq>\n    <priority>0.7</priority>\n  </url>\n`;
        });

        // 4. Live Mods (With fallback for missing/corrupted dates)
        const liveMods = await File.find({ 
            showInSitemap: { $ne: false }, 
            isLatestVersion: true 
        }).select('_id updatedAt');

        liveMods.forEach(mod => {
            let lastModDate;
            try {
                // Safely attempt to parse the date. If it fails, use the current date.
                lastModDate = mod.updatedAt ? new Date(mod.updatedAt).toISOString() : new Date().toISOString();
            } catch (e) {
                lastModDate = new Date().toISOString(); 
            }
            
            xml += `  <url>\n    <loc>${baseUrl}/mods/${mod._id}</loc>\n    <lastmod>${lastModDate}</lastmod>\n    <changefreq>daily</changefreq>\n    <priority>0.9</priority>\n  </url>\n`;
        });

        xml += '</urlset>';
        res.send(xml);
        
    } catch (error) {
        console.error("Sitemap generation error:", error);
        res.status(500).send('Error generating sitemap');
    }
});
// ==================================================

app.post('/dmca-request', async (req, res) => {
    try {
        await new Dmca(req.body).save();
        res.redirect('/dmca?success=Request submitted.');
    } catch (e) { res.redirect('/dmca?error=Error.'); }
});
// --- BANNED PAGE ROUTE ---
app.get('/banned', (req, res) => {
    // If they aren't logged in, or aren't banned, send them home
    if (!req.isAuthenticated() || !req.user.isBanned) {
        return res.redirect('/');
    }
    res.render('pages/banned', { 
        banReason: req.user.banReason || 'Violation of Terms of Service',
        message: req.query.message,
        error: req.query.error
    });
});

// --- UNBAN REQUEST SUBMISSION ROUTE ---
app.post('/unban-request', ensureAuthenticated, async (req, res) => {
    if (!req.user.isBanned) return res.redirect('/');
    
    try {
        // Check if they already have a pending request to prevent spam
        const existingRequest = await UnbanRequest.findOne({ user: req.user._id, status: 'pending' });
        if (existingRequest) {
            return res.redirect('/banned?error=You already have a pending unban request. Please wait for an admin to review it.');
        }

        await new UnbanRequest({
            user: req.user._id,
            username: req.user.username,
            email: req.user.email,
            appealMessage: req.body.appealMessage
        }).save();

        res.redirect('/banned?message=Your appeal has been submitted successfully. We will contact you via email.');
    } catch (e) {
        console.error("Unban Request Error:", e);
        res.redirect('/banned?error=An error occurred while submitting your request.');
    }
});
// ===================================
// 14. REQUEST A MOD ROUTES
// ===================================
app.get('/request-mod', ensureAuthenticated, (req, res) => {
    res.render('pages/request-mod', {
        message: req.query.message,
        error: req.query.error
    });
});

app.post('/request-mod', ensureAuthenticated, async (req, res) => {
    try {
        const { requestType, appName, officialLink, existingModLink, platform, requestedVersion, modFeaturesRequested, additionalNotes } = req.body;

        if (!requestType || !appName || !officialLink || !platform || !modFeaturesRequested) {
            return res.redirect('/request-mod?error=Please fill in all required fields.');
        }

        const pendingCount = await Request.countDocuments({ user: req.user._id, status: 'pending' });
        if (pendingCount >= 3) {
            return res.redirect('/request-mod?error=You already have 3 pending requests. Please wait for them to be reviewed.');
        }

        const newRequest = new Request({
            user: req.user._id,
            username: req.user.username,
            requestType, appName, officialLink, existingModLink, platform, requestedVersion, modFeaturesRequested, additionalNotes
        });

        await newRequest.save();
        res.redirect('/request-mod?message=Your request has been submitted successfully! Admins will review it soon.');
    } catch (error) {
        console.error("Error submitting mod request:", error);
        res.redirect('/request-mod?error=An error occurred while submitting your request.');
    }
});

// ===================================
// 14.5 SUPPORT TICKET ROUTES
// ===================================
app.get('/support', ensureAuthenticated, async (req, res) => {
    try {
        const myTickets = await SupportTicket.find({ user: req.user._id }).sort({ createdAt: -1 });
        res.render('pages/support', {
            tickets: myTickets,
            message: req.query.message,
            error: req.query.error
        });
    } catch (error) {
        console.error("Error loading support page:", error);
        res.status(500).render('pages/500');
    }
});

app.post('/support', ensureAuthenticated, async (req, res) => {
    try {
        const { subject, category, message } = req.body;

        if (!subject || !category || !message) {
            return res.redirect('/support?error=Please fill in all required fields.');
        }

        const openCount = await SupportTicket.countDocuments({ user: req.user._id, status: { $in: ['open', 'in-progress'] } });
        if (openCount >= 3) {
            return res.redirect('/support?error=You already have 3 open tickets. Please wait for them to be resolved.');
        }

        const newTicket = new SupportTicket({
            user: req.user._id,
            username: req.user.username,
            email: req.user.email,
            subject, category, message
        });

        await newTicket.save();
        res.redirect('/support?message=Your support ticket has been submitted. We will reply via your Notifications.');
    } catch (error) {
        console.error("Error submitting support ticket:", error);
        res.redirect('/support?error=An error occurred while submitting your ticket.');
    }
});
// ===================================
// 15. DISTRIBUTOR PARTNERSHIP ROUTES
// ===================================
app.get('/partnership', ensureAuthenticated, async (req, res) => {
    try {
        const existingApp = await DistributorApplication.findOne({ user: req.user._id });
        res.render('pages/partnership', {
            existingApplication: existingApp,
            message: req.query.message,
            error: req.query.error
        });
    } catch (error) {
        console.error("Partnership load error:", error);
        res.status(500).render('pages/500');
    }
});

app.post('/partnership/apply', ensureAuthenticated, async (req, res) => {
    try {
        const existingApp = await DistributorApplication.findOne({ user: req.user._id });
        if (existingApp) {
            return res.redirect('/partnership?error=You have already submitted an application.');
        }

        const { organizationName, primaryDistributionPlatform, platformUrl, monetizationMethod, adminContactName, adminSocialLink, socialTelegram, socialDiscord, socialWebsite, socialYoutube, agreedToTerms } = req.body;

        if (!agreedToTerms) {
            return res.redirect('/partnership?error=You must agree to the safety and distribution terms.');
        }

        const newApplication = new DistributorApplication({
            user: req.user._id,
            username: req.user.username,
            email: req.user.email,
            organizationName, primaryDistributionPlatform, platformUrl, monetizationMethod, adminContactName, adminSocialLink, socialTelegram, socialDiscord, socialWebsite, socialYoutube, agreedToTerms: true
        });

        await newApplication.save();
        res.redirect('/partnership?message=Application submitted successfully! Our team will review it shortly.');
    } catch (error) {
        console.error("Partnership Application Error:", error);
        res.redirect('/partnership?error=An error occurred while submitting your application.');
    }
});

// ===============================
// 16. SERVER STARTUP & ADMIN ROUTER
// ===============================
const createAdminRouter = require('./config/admin');

// In-memory store for recent messages
let recentMessages =[];

const startServer = async () => {
    try {
        await clientPromise;
        mongoose.Model.count = mongoose.Model.countDocuments; 

        const adminRouter = await createAdminRouter();
        app.use('/admin', ensureAuthenticated, ensureAdmin, adminRouter);
        
        app.use(express.urlencoded({ extended: true }));
        app.use(express.json());

        // --- DECLARED ONLY ONCE HERE ---
        const server = http.createServer(app);
        const io = new Server(server, {
            cors: {
                origin: allowedOrigins, 
                methods: ["GET", "POST"]
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

        // Error Handlers must remain at the very, very bottom
        app.use((req, res) => res.status(404).render('pages/404'));
        app.use((err, req, res, next) => {
            console.error(err.stack);
            res.status(500).render('pages/500');
        });

       // Finally, listen! Bind to 0.0.0.0 for Render compatibility
        server.listen(PORT, '0.0.0.0', () => {
            console.log(`Server is running on port ${PORT}`);
        });

    } catch (error) {
        console.error('Server failed to start.', error);
    }
};

startServer();