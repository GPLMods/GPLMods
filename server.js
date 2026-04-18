// ===============================
// 1. IMPORTS
// ===============================
if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

// --- ✅ FIX 2: OVERRIDE SYSTEM DNS TO USE GOOGLE DNS (8.8.8.8) ---
// This is crucial for environments that fail to resolve MongoDB Atlas SRV records.
const dns = require('dns');

// Force Node.js to use Google's public DNS servers
dns.setServers([
    '8.8.8.8',
    '8.8.4.4',
    // IPv6 fallbacks (optional but good practice)
    '2001:4860:4860::8888',
    '2001:4860:4860::8844'
]);

console.log(`[DNS] Custom DNS Resolvers configured: ${dns.getServers().join(', ')}`);

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
const { Upload } = require("@aws-sdk/lib-storage");

// Custom Utilities & Config
const { sendVerificationEmail, sendPasswordResetEmail } = require('./utils/mailer');

// AWS SDK v3 Imports (Backblaze B2)
// Add DeleteObjectCommand to this list
const { S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command, DeleteObjectCommand } = require('@aws-sdk/client-s3');
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
const cron = require('node-cron');
const AutomatedCampaign = require('./models/automatedCampaign');
const SiteState = require('./models/siteState');
const Subscriber = require('./models/subscriber');
const DocCategory = require('./models/docCategory');
const DocPage = require('./models/docPage');

// ===============================
// 2. INITIALIZATION & CONFIGURATION
// ===============================
const app = express();
const PORT = process.env.PORT || 3000;
const { Types } = mongoose;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ===============================
// USERNAME & DISCRIMINATOR HELPERS
// ===============================

// 1. Reserved Names List (Lowercase for easy checking)
const RESERVED_NAMES = [
    'admin', 'administrator', 'gplmods', 'gpl community', 'gpl', 
    'moderator', 'system', 'staff', 'support', 'owner'
];

/**
 * Checks if a requested username contains any reserved words.
 * @param {string} requestedName - The name the user wants
 * @returns {boolean} - True if the name is forbidden
 */
function isNameReserved(requestedName) {
    const lowerName = requestedName.toLowerCase();
    // Check if the requested name matches exactly, or contains a reserved word
    return RESERVED_NAMES.some(reserved => lowerName === reserved || lowerName.includes(reserved));
}

/**
 * Generates a unique username by appending a #number if the base name is taken.
 * @param {string} baseName - The desired username (e.g., "Noob")
 * @returns {string} - A guaranteed unique username (e.g., "Noob", "NooB#1", "Noob#2")
 */
async function generateUniqueUsername(baseName) {
    // 1. Clean the base name (remove any existing # numbers the user might have typed)
    const cleanBaseName = baseName.split('#')[0].trim();
    
    // 2. Check if the clean base name is completely available
    const exactMatch = await User.findOne({ username: cleanBaseName });
    if (!exactMatch) {
        return cleanBaseName; // It's available! No # needed.
    }

    // 3. If taken, find the highest discriminator for this base name
    // We search for usernames starting with "BaseName#"
    const regex = new RegExp(`^${cleanBaseName}#(\\d+)$`, 'i');
    const existingUsers = await User.find({ username: regex });

    let maxDiscriminator = 0;

    existingUsers.forEach(user => {
        // Extract the number after the #
        const match = user.username.match(regex);
        if (match && match[1]) {
            const currentNum = parseInt(match[1], 10);
            if (currentNum > maxDiscriminator) {
                maxDiscriminator = currentNum;
            }
        }
    });

    // 4. Return the base name + the next available number
    return `${cleanBaseName}#${maxDiscriminator + 1}`;
}

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

// --- NEW HELPER: CREATE CLEAN URL SLUGS ---
function slugify(text) {
    if (!text) return '';
    return text.toString().toLowerCase()
        .replace(/\s+/g, '-')           // Replace spaces with -
        .replace(/[^\w\-]+/g, '')    // Remove all non-word chars
        .replace(/\-\-+/g, '-')         // Replace multiple - with single -
        .replace(/^-+/, '')             // Trim - from start of text
        .replace(/-+$/, '');            // Trim - from end of text
}
// --- NEW HELPER: SMART VIRUSTOTAL SCANNER ---
// Handles files up to 650MB automatically
async function submitToVirusTotal(fileBuffer, originalName, fileSize) {
    try {
        const vtFormData = new FormData();
        vtFormData.append('file', fileBuffer, originalName);
        
        const THIRTY_TWO_MB = 32 * 1024 * 1024;
        let uploadEndpoint = 'https://www.virustotal.com/api/v3/files';

        // If the file is > 32MB, we MUST request a special upload URL first
        if (fileSize > THIRTY_TWO_MB) {
            console.log(`File is > 32MB (${formatBytes(fileSize)}). Requesting special VT upload URL...`);
            const urlResponse = await axios.get('https://www.virustotal.com/api/v3/files/upload_url', {
                headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
            });
            uploadEndpoint = urlResponse.data.data; // This is the special, one-time URL
            console.log("Special VT upload URL acquired.");
        }

        console.log(`Submitting file to VirusTotal endpoint: ${uploadEndpoint.substring(0, 50)}...`);
        
        // Now, perform the actual upload (using either the standard URL or the special one)
        const vtResponse = await axios.post(uploadEndpoint, vtFormData, {
            headers: { 
                'x-apikey': process.env.VIRUSTOTAL_API_KEY, 
                ...vtFormData.getHeaders() 
            },
            // Prevent axios from timing out on large uploads (e.g., 600MB might take a while)
            maxContentLength: Infinity,
            maxBodyLength: Infinity,
            timeout: 300000 // 5 minutes timeout for VT upload
        });
        
        // Return the Analysis ID
        return vtResponse.data.data.id;

    } catch (vtError) {
        console.error("VirusTotal Submission Error:", vtError.response?.data || vtError.message);
        throw vtError; // Re-throw to be caught by the calling function
    }
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

// --- UPDATED HELPER: Tracks B2 Upload Progress ---

const uploadToB2 = async (file, folder, io = null, uploadId = null) => {
    
    // ✅ FIX: We only expect a buffer now because we switched to memoryStorage
    if (!file || !file.buffer) {
        throw new Error("File data (buffer) not found.");
    }

    const sanitizedFilename = sanitizeFilename(file.originalname);
    const fileName = `${folder}/${Date.now()}-${sanitizedFilename}`;
    
    console.log(`Uploading ${fileName} to B2...`);
    
    // Use lib-storage for chunked uploads and live progress tracking
    const parallelUploads3 = new Upload({
        client: s3Client,
        params: { 
            Bucket: process.env.B2_BUCKET_NAME, 
            Key: fileName, 
            Body: file.buffer, // Use the buffer directly
            ContentType: file.mimetype 
        },
        partSize: 5 * 1024 * 1024, // Uploads in 5MB chunks (faster!)
        queueSize: 4 
    });

    parallelUploads3.on("httpUploadProgress", (progress) => {
        if (progress.total) {
            const percent = Math.round((progress.loaded / progress.total) * 100);
            
            // If we have an active Socket connection, pipe it to the frontend!
            if (io && uploadId) {
                io.emit(`b2_progress_${uploadId}`, {
                    percent: percent,
                    loaded: (progress.loaded / (1024 * 1024)).toFixed(2),
                    total: (progress.total / (1024 * 1024)).toFixed(2)
                });
            }
        }
    });

    await parallelUploads3.done();
    console.log(`Finished uploading ${fileName} to B2.`);
    return fileName;
};

// ===============================
// 4. PRE-ADMIN MIDDLEWARE
// ===============================
// 1. Static Files (Safe to be early)
app.use(express.static(path.join(__dirname, 'public')));

// ✅ NEW: Serve the pre-built AdminJS assets!
app.use('/.adminjs', express.static(path.join(__dirname, '.adminjs')));

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

// --- NEW: PUBLIC HEALTH CHECK & STATUS PAGE ---
// This MUST come before Maintenance Mode and Session/Auth
app.get('/healthz', (req, res) => {
    
    // We do a very fast check to see if Mongoose is connected.
    // 1 = connected. Anything else (0, 2, 3, 99) means there's an issue.
    const isDatabaseConnected = mongoose.connection.readyState === 1;
    
    // You can add more checks here later if needed (e.g., checking B2)
    const isHealthy = isDatabaseConnected;

    // Render relies on the HTTP Status Code (200 = Good, 503 = Bad)
    // We send the correct code, AND render our beautiful UI
    if (isHealthy) {
        res.status(200).render('pages/healthz', { isHealthy: true });
    } else {
        // 503 Service Unavailable
        res.status(503).render('pages/healthz', { isHealthy: false });
    }
});

// --- DYNAMIC SITE STATE ENGINE (Maintenance / Unavailable) ---
let cachedSiteState = null;
let lastStateCheck = 0;

app.use(async (req, res, next) => {
    // 1. Fetch the state from DB, but cache it for 30 seconds for blazing fast performance
    if (Date.now() - lastStateCheck > 30 * 1000) {
        try {
            // Find or create the singleton state document
            cachedSiteState = await SiteState.findOne({ singletonId: 'master-state' });
            if (!cachedSiteState) {
                cachedSiteState = await new SiteState().save();
            }
            lastStateCheck = Date.now();
        } catch (e) {
            console.error("Site State Engine Error:", e);
            return next(); // Fail open if DB is unreachable
        }
    }

    // 2. If the site is online, proceed normally
    if (!cachedSiteState || cachedSiteState.status === 'online') {
        return next();
    }

    // 3. Always allow access to the Admin Panel, regardless of state
    if (req.path.startsWith('/admin') || (req.user && req.user.role === 'admin')) {
        return next();
    }

    // 4. Determine if the current user matches the Target Audience for the lockdown
    const isGuest = !req.isAuthenticated();
    const isMember = req.isAuthenticated();
    let isTargeted = false;

    if (cachedSiteState.targetAudience === 'all-users') {
        isTargeted = true;
    } else if (cachedSiteState.targetAudience === 'guests-only' && isGuest) {
        isTargeted = true;
    } else if (cachedSiteState.targetAudience === 'members-only' && isMember) {
        isTargeted = true;
    } else if (cachedSiteState.targetAudience === 'specific-user' && isMember) {
        if (req.user.username.toLowerCase() === cachedSiteState.targetUsername?.toLowerCase()) {
            isTargeted = true;
        }
    }

    // 5. If the user is targeted, show them the appropriate intercept page
    if (isTargeted) {
        if (cachedSiteState.status === 'maintenance') {
            return res.status(503).render('pages/maintenance', {
                title: cachedSiteState.maintenanceTitle,
                message: cachedSiteState.maintenanceMessage
            });
        } else if (cachedSiteState.status === 'unavailable') {
            return res.status(503).render('pages/unavailable', {
                title: cachedSiteState.unavailableTitle,
                message: cachedSiteState.unavailableMessage
            });
        }
    }

    // If they aren't targeted, let them through
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

// 3. User Last Seen Updater
app.use(async (req, res, next) => {
    if (req.isAuthenticated()) {
        User.findByIdAndUpdate(req.user.id, { lastSeen: new Date() }).exec();
    }
    next();
});

// 4 Signed Avatar URL Generator
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

// 5. Globals & Notification Cache Middleware
let cachedTotalUpdates = 0;
let lastUpdateCheck = 0;

app.use(async (req, res, next) => {
    // 1. Basic Helpers
    res.locals.user = req.user || null;
    res.locals.timeAgo = timeAgo;
    res.locals.formatBytes = formatBytes; 
    res.locals.slugify = slugify;

    // 2. ======== AD DELIVERY LOGIC ========
    let shouldShowAds = true; // Default to true (Guests see ads)
    
    if (req.isAuthenticated() && req.user) {
        const role = req.user.role;
        const membership = req.user.membership;
        // Exempt Admins, Distributors, and Premium users
        if (role === 'admin' || role === 'distributor' || membership === 'premium') {
            shouldShowAds = false; 
        }
    }
    // Pass the boolean to EVERY EJS template
    res.locals.showAds = shouldShowAds;
    // ========================================

    // 3. ======== NOTIFICATIONS LOGIC ========
    try {
        // Check Global Announcements (Cached every 5 mins)
        if (Date.now() - lastUpdateCheck > 5 * 60 * 1000) {
            cachedTotalUpdates = await Announcement.countDocuments();
            lastUpdateCheck = Date.now();
        }
        res.locals.totalUpdatesCount = cachedTotalUpdates;

        // Check Personal Notifications (Real-time per user)
        let unreadPersonalCount = 0;
        if (req.isAuthenticated() && req.user) {
            unreadPersonalCount = await UserNotification.countDocuments({ 
                user: req.user._id, 
                isRead: false 
            });
        }
        res.locals.unreadPersonalCount = unreadPersonalCount;
        
        // Everything succeeded, move to the next route
        next(); 

    } catch (e) {
        console.error("Global Middleware Error:", e);
        // Fallback to 0 so the page still loads even if DB fails
        res.locals.totalUpdatesCount = cachedTotalUpdates;
        res.locals.unreadPersonalCount = 0;
        
        // Still move to the next route even if notifications failed to load
        next(); 
    }
});
// --- End of Globals Middleware ---

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
    if (req.isAuthenticated()) {
        // ✅ NEW: Tell browser NEVER to cache protected pages
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0');
        return next();
    }
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

// ✅ FIX: STRICTLY USE RAM (MEMORY STORAGE)
// We must use memoryStorage so the file streams directly to our code,
// allowing the XMLHttpRequest upload progress bar to be accurate!
const memoryStorage = multer.memoryStorage();

// Main Upload Config (For Mods - 20GB hard limit to prevent multer crash, actual limits enforced in route)
const upload = multer({ 
    storage: memoryStorage, 
    limits: { fileSize: 20 * 1024 * 1024 * 1024 } 
});

// Avatar Upload Config (Strict 5MB limit to protect RAM)
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
            // --- NEW: Security Check & Discriminator ---
            let requestedName = googleUserData.username; // Or githubUserData.username, etc.
            
            // If their social name is reserved, give them a generic safe name
            if (isNameReserved(requestedName)) {
                requestedName = 'Member'; 
            }

            // Generate the unique # number
            const uniqueUsername = await generateUniqueUsername(requestedName);
            googleUserData.username = uniqueUsername; // Update the data object before creating

            user = await User.create(googleUserData);
            done(null, user);
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
            // --- NEW: Security Check & Discriminator ---
            let requestedName = githubUserData.username; // Or microsoftUserData.username, etc.
            
            // If their social name is reserved, give them a generic safe name
            if (isNameReserved(requestedName)) {
                requestedName = 'Member'; 
            }

            // Generate the unique # number
            const uniqueUsername = await generateUniqueUsername(requestedName);
            githubUserData.username = uniqueUsername; // Update the data object before creating

            user = await User.create(githubUserData);
            done(null, user);
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
            // --- NEW: Security Check & Discriminator ---
            let requestedName = microsoftUserData;  // Or googleUserData.username, etc.
            
            // If their social name is reserved, give them a generic safe name
            if (isNameReserved(requestedName)) {
                requestedName = 'Member'; 
            }

            // Generate the unique # number
            const uniqueUsername = await generateUniqueUsername(requestedName);
            microsoftUserData.username = uniqueUsername; // Update the data object before creating

            user = await User.create(microsoftUserData);
            done(null, user);
        }
    } catch (err) { done(err, null); }
}));

// ===============================
// 6. PUBLIC & DIAGNOSTIC ROUTES
// ===============================

// --- ADVANCED DIAGNOSTIC CONSOLE (Admin Only) ---
app.get('/status', ensureAuthenticated, ensureAdmin, async (req, res) => {
    
    // 1. Gather Basic Server Info
    const healthData = {
        status: 'UP',
        timestamp: new Date().toISOString(),
        uptime: formatUptime(process.uptime()),
        nodeVersion: process.version,
        memoryUsage: process.memoryUsage(),
        environment: process.env.NODE_ENV || 'development',
        services: {
            database: { status: 'UNKNOWN', details: null },
            storage: { status: 'UNKNOWN', details: null },
            virustotal: { status: 'UNKNOWN', details: null }
        },
        warnings: []
    };

    // 2. Check MongoDB Connection
    try {
        const dbState = mongoose.connection.readyState;
        // 0 = disconnected, 1 = connected, 2 = connecting, 3 = disconnecting
        if (dbState === 1) {
            healthData.services.database.status = 'CONNECTED';
            healthData.services.database.details = `Connected to ${mongoose.connection.host}`;
        } else {
            healthData.services.database.status = 'DISCONNECTED';
            healthData.warnings.push('MongoDB is currently disconnected.');
            healthData.status = 'DEGRADED';
        }
    } catch (e) {
        healthData.services.database.status = 'ERROR';
        healthData.warnings.push(`MongoDB Error: ${e.message}`);
        healthData.status = 'DEGRADED';
    }

    // 3. Check Backblaze B2 (S3 Client)
    try {
        // We perform a very lightweight operation: listing a single object (or just testing the credentials)
        // If this throws an error, our B2 connection is broken.
        const { ListObjectsV2Command } = require('@aws-sdk/client-s3');
        const command = new ListObjectsV2Command({
            Bucket: process.env.B2_BUCKET_NAME,
            MaxKeys: 1 // Only ask for 1 item to make it fast
        });
        
        await s3Client.send(command);
        healthData.services.storage.status = 'CONNECTED';
        healthData.services.storage.details = `Bucket: ${process.env.B2_BUCKET_NAME} | Region: ${process.env.B2_REGION}`;
    } catch (e) {
        healthData.services.storage.status = 'ERROR';
        healthData.warnings.push(`Backblaze B2 Error: ${e.message}`);
        healthData.status = 'DEGRADED';
    }

    // 4. Check VirusTotal API (Lightweight check)
    try {
        // Just checking if the API key is present and formatted correctly locally
        if (!process.env.VIRUSTOTAL_API_KEY || process.env.VIRUSTOTAL_API_KEY.length < 32) {
            throw new Error("API Key is missing or invalid length.");
        }
        // To do a real live check, you could hit a safe VT endpoint, but that uses quota.
        // Local validation is usually sufficient for a quick health check.
        healthData.services.virustotal.status = 'CONFIGURED';
        healthData.services.virustotal.details = 'API Key is present.';
    } catch (e) {
        healthData.services.virustotal.status = 'ERROR';
        healthData.warnings.push(`VirusTotal Config Error: ${e.message}`);
    }

    // 5. Final Status Calculation
    // If any warnings exist, the server is "DEGRADED", not "UP"
    if (healthData.warnings.length > 0 && healthData.status === 'UP') {
        healthData.status = 'DEGRADED';
    }

    // Instead of sending raw JSON, let's render a beautiful admin page!
    res.render('pages/admin/healthz', { health: healthData });
});

// --- HELPER: Format Uptime ---
function formatUptime(seconds) {
    const d = Math.floor(seconds / (3600*24));
    const h = Math.floor(seconds % (3600*24) / 3600);
    const m = Math.floor(seconds % 3600 / 60);
    const s = Math.floor(seconds % 60);
    return `${d}d ${h}h ${m}m ${s}s`;
}

// --- NEW: Reusable Homepage Logic ---
const renderHomepage = async (req, res) => {
    try {
        const findQuery = { status: 'live', isLatestVersion: true };
        const categories = ['android', 'ios-jailed', 'ios-jailbroken', 'wordpress', 'windows'];
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
                        const signedIconUrl = await getSmartImageUrl(key);
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
};

// 1. The Root Route (Heavily cached by Cloudflare for Guests)
app.get('/', async (req, res) => {
    // If a user happens to hit the root URL but they have a valid session cookie, 
    // redirect them to the un-cached /home route immediately.
    if (req.isAuthenticated()) {
        return res.redirect('/home');
    }
    // Otherwise, render the homepage for the guest
    await renderHomepage(req, res);
});

// 2. The Logged-In Route (Bypasses Cloudflare's strict root cache)
app.get('/home', ensureAuthenticated, async (req, res) => {
    // Render the exact same content, but on a URL that Cloudflare treats differently
    await renderHomepage(req, res);
});
// ===================================
// NOTIFICATION SYSTEM ROUTES
// ===================================
// 1. The Notification Hub (Category Selection)
app.get('/notifications', ensureAuthenticated, async (req, res) => {
    try {
        // 1. Count unread personal messages
        const UserNotification = require('./models/userNotification');
        const unreadPersonalCount = await UserNotification.countDocuments({ 
            user: req.user._id, 
            isRead: false 
        });

        // 2. Count Total Global Announcements
        const totalGlobalUpdates = await Announcement.countDocuments();

        // ✅ FIX 6: Explicitly pass BOTH variables to the EJS template
        res.render('pages/notifications-hub', {
            unreadPersonalCount: unreadPersonalCount || 0,
            totalGlobalUpdates: totalGlobalUpdates || 0
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
// --- NEW: Personalized "Following" Feed ---
app.get('/notifications/following', ensureAuthenticated, async (req, res) => {
    try {
        // 1. Get the current user and populate their 'following' array 
        // to get the actual usernames of the people they follow.
        const userWithFollowing = await User.findById(req.user._id).populate('following', 'username');

        if (!userWithFollowing || !userWithFollowing.following || userWithFollowing.following.length === 0) {
            // If they aren't following anyone, render an empty page
            return res.render('pages/feed-following', { files: [] });
        }

        // 2. Extract just the usernames into an array
        const followedUsernames = userWithFollowing.following.map(u => u.username);

        // 3. Find files where the 'uploader' is in our array of followed usernames
        const followingMods = await File.find({
            uploader: { $in: followedUsernames }, // The magic MongoDB operator!
            status: 'live',
            isLatestVersion: true
        })
        .sort({ updatedAt: -1 }) // Sort by most recently updated/uploaded
        .limit(50); // Reasonable limit for a feed

        // 4. Get signed URLs for the icons (using our smart helper)
        const modsWithUrls = await Promise.all(followingMods.map(async (file) => {
            const iconKey = file.iconUrl || file.iconKey;
            const iconUrl = await getSmartImageUrl(iconKey);
            return { ...file.toObject(), iconUrl };
        }));

        res.render('pages/feed-following', { files: modsWithUrls });

    } catch (error) {
        console.error("Error fetching following feed:", error);
        res.status(500).render('pages/500');
    }
});
// Category / Filter Route
app.get('/category', async (req, res) => {
    try {
        // Grab the queries from the URL (e.g., /category?platform=android&subCategory=game-action)
        const { platform, subCategory, sort, page = 1 } = req.query;
        const limit = 12;
        const currentPage = parseInt(page);
        
        // Base query: Only show live, latest version mods
        const queryFilter = { isLatestVersion: true, status: 'live' };

        // 1. Filter by Main Platform
        if (platform && platform !== 'all') {
            queryFilter.category = platform;
        }

        // 2. NEW: Filter by Sub-Category
        if (subCategory && subCategory !== 'all') {
            // Because we store platforms as an array (e.g., ['game-action']), 
            // we use the $in operator to find mods that have this sub-category.
            queryFilter.platforms = { $in: [subCategory] };
        }

        // 3. Sorting Logic
        const sortOptions = {};
        if (sort === 'popular') {
            sortOptions.downloads = -1; // Sort by most downloads
            sortOptions.averageRating = -1; // Then by rating
        } else {
            sortOptions.createdAt = -1; // Default: Newest first
        }

        // 4. Pagination & Fetching
        const totalMods = await File.countDocuments(queryFilter);
        const totalPages = Math.ceil(totalMods / limit);
        const files = await File.find(queryFilter)
            .sort(sortOptions)
            .skip((currentPage - 1) * limit)
            .limit(limit);

        // 5. Get Signed URLs for images
        const filesWithUrls = await Promise.all(files.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            const iconUrl = key ? await getSmartImageUrl(key) : '/images/default-avatar.png';
            return { ...file.toObject(), iconUrl };
        }));

        res.render('pages/category', {
            files: filesWithUrls,
            totalPages: totalPages,
            currentPage: currentPage,
            
            // Pass the current filters back to the frontend so the dropdowns stay selected
            currentPlatform: platform || 'all', 
            currentSubCategory: subCategory || 'all', // NEW
            currentSort: sort || 'latest'
        });

    } catch (error) { 
        console.error("Category Route Error:", error);
        res.status(500).render('pages/500'); 
    }
});

// Search Route
// Helper function to safely escape regex characters
const escapeRegex = (text) => text.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, "\\$&");

app.get('/search', async (req, res) => {
    try {
        const rawQuery = req.query.q || '';
        const query = escapeRegex(rawQuery); 
        
        // --- NEW: Grab subCategory from the URL query ---
        const platform = req.query.platform || 'all';
        const subCategory = req.query.subCategory || 'all'; 
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

        // 1. Filter by Platform
        if (platform && platform !== 'all') {
            searchQuery.category = platform;
        }

        // 2. --- NEW: Filter by Sub-Category ---
        if (subCategory && subCategory !== 'all') {
            searchQuery.platforms = { $in: [subCategory] };
        }

        // 3. Sorting Logic
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
            query: rawQuery, 
            totalResults: totalResults,
            totalPages: totalPages,
            currentPage: page,
            
            // --- Pass ALL current filters back to the EJS template ---
            currentPlatform: platform,
            currentSubCategory: subCategory, // <--- ADDED THIS
            currentSort: sort
        });

    } catch (error) {
        console.error("Search Error:", error);
        res.status(500).render('pages/500');
    }
});

// Single Mod Page
// --- BUG 1 FIX A: BACKWARD COMPATIBILITY REDIRECT ---
// This catches any old /mods/12345 links (like from your homepage or old bookmarks)
// and instantly forwards them to the new SEO-friendly slug route!
app.get('/mods/:id', async (req, res, next) => {
    try {
        const file = await File.findById(req.params.id);
        if (!file) return next(); // If it really doesn't exist, proceed to 404
        
        // Redirect to the new format: /android/roblox
        return res.redirect(301, `/${file.category}/${file.slug || file._id}`);
    } catch (error) {
        next();
    }
});

// --- ADVANCED: SEO-Friendly "Umbrella" Mod Page Route ---
app.get('/:category/:slug', async (req, res, next) => {
    try {
        const category = req.params.category.toLowerCase();
        const slug = req.params.slug.toLowerCase();
        const variantId = req.query.variant;

        // 1. Prevent this route from capturing system URLs
        // 1. Prevent this route from capturing system URLs
        const reservedPaths =[
            'api', 'admin', 'auth', 'css', 'js', 'images', 'audio', 'animations', 
            'mods', 'users', 'category', 'search', 'updates', 'profile', 'my-uploads', 
            'developer', 'support', 'donate', 'partnership', 'home', 'healthz', 
            'download-file', 'upload-details', 'reset-password' // <--- ✅ ADDED THESE 3
        ];
        
        if (reservedPaths.includes(category)) return next();

        let masterFile = null;

        // 2. PRIMARY SEARCH: Try to find by exact slug
        masterFile = await File.findOne({ 
            category: category, 
            slug: slug,
            isLatestVersion: true,
            isVariant: { $ne: true } // ✅ FIX: Safely catches old mods where this field doesn't exist yet!
        }).populate('variants');

        // 3. FALLBACK SEARCH: If exact slug fails (e.g. old mods without a slug in DB), 
        // use RegEx to search the original 'name' field by turning dashes back into spaces.
        if (!masterFile) {
            const nameSearchPattern = new RegExp(`^${slug.replace(/-/g, '[-\\s]+')}$`, 'i');
            masterFile = await File.findOne({
                category: category,
                name: nameSearchPattern,
                isLatestVersion: true,
                isVariant: { $ne: true } // ✅ FIX: Safely catches old mods here too!
            }).populate('variants');
        }

        // 4. If STILL not found, throw 404
        if (!masterFile) {
            return res.status(404).render('pages/404');
        }

        // --- Security Check for Drafts/Pending ---
        if (masterFile.status !== 'live') {
            const isUploader = req.user && req.user.username === masterFile.uploader;
            const isAdmin = req.user && req.user.role === 'admin';
            if (!isUploader && !isAdmin) return res.status(403).render('pages/403'); 
        }

        let displayFile = masterFile; 
        let isViewingVariant = false;

        if (variantId && Types.ObjectId.isValid(variantId)) {
            const requestedVariant = masterFile.variants.find(v => v._id.toString() === variantId && v.status === 'live');
            if (requestedVariant) {
                // Swap Master data for Variant data seamlessly
                displayFile = {
                    ...(masterFile.toObject ? masterFile.toObject() : masterFile),
                    _id: requestedVariant._id,
                    version: requestedVariant.version,
                    uploader: requestedVariant.uploader,
                    developer: requestedVariant.developer,
                    modDescription: requestedVariant.modDescription,
                    modFeatures: requestedVariant.modFeatures,
                    whatsNew: requestedVariant.whatsNew,
                    importantNote: requestedVariant.importantNote,
                    fileSize: requestedVariant.fileSize,
                    downloads: requestedVariant.downloads,
                    averageRating: requestedVariant.averageRating,
                    workingVoteCount: requestedVariant.workingVoteCount,
                    notWorkingVoteCount: requestedVariant.notWorkingVoteCount,
                    createdAt: requestedVariant.createdAt,
                    updatedAt: requestedVariant.updatedAt,
                    virusTotalAnalysisId: requestedVariant.virusTotalAnalysisId,
                    virusTotalId: requestedVariant.virusTotalId,
                    virusTotalScanDate: requestedVariant.virusTotalScanDate,
                    virusTotalPositiveCount: requestedVariant.virusTotalPositiveCount,
                    virusTotalTotalScans: requestedVariant.virusTotalTotalScans
                };
                isViewingVariant = true;
            }
        }

        const iconKey = masterFile.iconUrl || masterFile.iconKey;
        const iconUrl = await getSmartImageUrl(iconKey);
        
        const screenKeys = (masterFile.screenshotUrls && masterFile.screenshotUrls.length > 0)
            ? masterFile.screenshotUrls : (masterFile.screenshotKeys ||[]);
        const screenshotUrls = await Promise.all(screenKeys.map(key => getSmartImageUrl(key)));

        const reviews = await Review.find({ file: displayFile._id }).sort({ createdAt: -1 }).populate('user', 'profileImageKey'); 
        const reviewsWithAvatars = await Promise.all(reviews.map(async (review) => {
            let avatarUrl = '/images/default-avatar.png';
            if (review.user && review.user.profileImageKey) {
                try { avatarUrl = await getSmartImageUrl(review.user.profileImageKey); } catch (e) {}
            }
            return { ...review.toObject(), user: { ...review.user.toObject(), signedAvatarUrl: avatarUrl } };
        }));

        let versionHistory =[];
        let fileForHistory = await File.findById(displayFile._id).populate('olderVersions');
        if (fileForHistory) {
            versionHistory = [fileForHistory, ...fileForHistory.olderVersions.slice().reverse()];
        }

        const userHasWhitelisted = req.user ? req.user.whitelist.includes(displayFile._id) : false;
        const userHasVotedOnStatus = req.user ? displayFile.votedOnStatusBy.includes(req.user._id) : false;

        res.render('pages/download', {
            file: { ...(displayFile.toObject ? displayFile.toObject() : displayFile), iconUrl, screenshotUrls },
            masterFile: masterFile,
            isViewingVariant: isViewingVariant,
            versionHistory,
            reviews: reviewsWithAvatars,
            userHasWhitelisted,
            userHasVotedOnStatus
        });

    } catch (e) {
        console.error("Error on /:category/:slug route:", e);
        res.status(500).render('pages/500');
    }
});

// --- UPDATED DEVELOPER PAGE ROUTE ---
app.get('/developer', async (req, res) => {
    try {
        const developerSlug = req.query.name;
        if (!developerSlug || developerSlug.trim() === '') return res.redirect('/');
        
        // Create a RegEx to handle the slug
        const searchPattern = new RegExp(developerSlug.replace(/-/g, '[-\\s]+'), 'i');

        const filesByDeveloper = await File.find({
            developer: searchPattern, 
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

        // Pass the actual original developer name to the template if files exist,
        // otherwise pass the slug (or format it nicely)
        const displayName = filesByDeveloper.length > 0 ? filesByDeveloper[0].developer : developerSlug.replace(/-/g, ' ');

        res.render('pages/developer', {
            files: filesWithUrls, 
            developerName: displayName // Pass the clean name
        });

    } catch (error) {
        console.error("Developer page error:", error);
        res.status(500).render('pages/500');
    }
});

// --- GET Add Version Page ---
app.get('/mods/:id/add-version', ensureAuthenticated, async (req, res) => {
    try {
        const parentFile = await File.findById(req.params.id);
        if (!parentFile || req.user.username.toLowerCase() !== parentFile.uploader.toLowerCase()) {
            return res.status(403).render('pages/403');
        }
        res.render('pages/add-version', { parentFile: parentFile });
    } catch (error) {
        res.status(500).render('pages/500');
    }
});
app.post('/mods/:id/add-version', ensureAuthenticated, upload.single('modFile'), async (req, res) => {
    
    try {
        const parentFileId = req.params.id;
        const previousVersion = await File.findById(parentFileId);

        // Security check: Must be uploader or admin
        const isUploader = req.user.username.toLowerCase() === previousVersion.uploader.toLowerCase();
        const isAdmin = req.user.role === 'admin';
        if (!isUploader && !isAdmin) {
            return res.status(403).json({ success: false, message: "Forbidden: You don't have permission to edit this mod." });
        }

        // --- SCENARIO 1: DISTRIBUTOR UPLOAD (External Link / Multi-Part) ---
        if ((req.user.role === 'distributor' || req.user.role === 'admin') && (req.body.externalUrl || req.body.isMultiPart)) {
            const { externalUrl, isMultiPart, partUrls, softwareVersion, whatsNew, originalFilename } = req.body;
            
            const newVersion = new File({
                // Copy details from previous
                name: previousVersion.name,
                developer: previousVersion.developer,
                iconKey: previousVersion.iconKey,
                screenshotKeys: previousVersion.screenshotKeys,
                modDescription: previousVersion.modDescription,
                officialDescription: previousVersion.officialDescription,
                modFeatures: previousVersion.modFeatures,
                category: previousVersion.category,
                platforms: previousVersion.platforms,
                tags: previousVersion.tags,
                uploader: req.user.username,
                
                // New details
                version: softwareVersion,
                whatsNew: whatsNew,
                originalFilename: originalFilename || previousVersion.originalFilename,
                fileKey: 'external-link', 
                fileSize: 0, 
                
                isLatestVersion: false, 
                parentFile: parentFileId,
                status: 'live' 
            });

            if (isMultiPart === 'true' && partUrls && partUrls.length >= 2) {
                newVersion.isMultiPart = true;
                const cleanParts = partUrls.filter(url => url.trim() !== '');
                newVersion.downloadParts = cleanParts.map((url, index) => ({
                    partName: `Part ${index + 1}`,
                    partUrl: url
                }));
            } else {
                newVersion.externalDownloadUrl = externalUrl;
            }
            
            await newVersion.save();
            await File.findByIdAndUpdate(parentFileId, {
                $push: { olderVersions: newVersion._id },
                isLatestVersion: false
            });
            newVersion.isLatestVersion = true;
            await newVersion.save();

            // We use JSON here so the frontend AJAX knows what to do
            return res.json({ success: true, redirectUrl: `/mods/${newVersion._id}` });
        }


        // --- SCENARIO 2: STANDARD UPLOAD (Physical File) ---
        if (!req.file) {
            return res.status(400).json({ success: false, message: "No file uploaded." });
        }

        const fileSize = req.file.size;
        const isPremium = req.user.membership === 'premium';
        const isAdminOrDist = req.user.role === 'admin' || req.user.role === 'distributor';
        
        const limit300MB = 314572800;
        const limit1GB = 1073741824;

        if (!isAdminOrDist) {
            if (!isPremium && fileSize > limit300MB) {
                return res.status(413).json({ success: false, message: "File exceeds your 300MB limit. Please upgrade to Premium." });
            }
            if (isPremium && fileSize > limit1GB) {
                 return res.status(413).json({ success: false, message: "File exceeds the 1GB Premium limit." });
            }
        }

        // Add Socket.IO reporting for B2 upload progress
        const uploadId = req.body.uploadId;
        const io = req.app.get('socketio'); // Assuming you attach `io` to your Express app!
        
        // Custom uploadToB2 with progress tracking (inline for this specific route)
        // Note: For a true live bar here, you need to modify your uploadToB2 helper to accept the 'io' object and 'uploadId'
        // For now, we will do a basic upload and rely on the frontend 50% jump.
        
        console.log("Uploading new version to B2 from memory buffer...");
        const newFileKey = await uploadToB2(req.file, 'mods'); 
        console.log("Upload to B2 complete.");

        // Create new record
        const newVersion = new File({
            name: previousVersion.name,
            developer: previousVersion.developer,
            iconKey: previousVersion.iconKey,
            screenshotKeys: previousVersion.screenshotKeys,
            modDescription: previousVersion.modDescription,
            officialDescription: previousVersion.officialDescription,
            modFeatures: previousVersion.modFeatures,
            category: previousVersion.category,
            platforms: previousVersion.platforms,
            tags: previousVersion.tags,
            uploader: req.user.username,
            version: req.body.softwareVersion,
            whatsNew: req.body.whatsNew,
            fileKey: newFileKey,
            fileSize: req.file.size,
            originalFilename: req.file.originalname,
            isLatestVersion: false, 
            parentFile: parentFileId,
            status: 'live' 
        });
        
        await newVersion.save();
        
        // Update linkage
        await File.findByIdAndUpdate(parentFileId, {
            $push: { olderVersions: newVersion._id },
            isLatestVersion: false 
        });

        newVersion.isLatestVersion = true;
        await newVersion.save();
        
        // Background VT Scan
        (async () => {
            try {
                const vtFormData = new FormData();
                vtFormData.append('file', req.file.buffer, req.file.originalname);
                const vtResponse = await axios.post('https://www.virustotal.com/api/v3/files', vtFormData, {
                    headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY, ...vtFormData.getHeaders() }
                });
                const analysisId = vtResponse.data.data.id;
                await File.findByIdAndUpdate(newVersion._id, { virusTotalAnalysisId: analysisId });
            } catch (vtError) {
                console.error(`VT scan failed for new version:`, vtError.message);
            } 
        })(); 

        // ✅ FIX: Reply with JSON so the AJAX script can redirect cleanly
        return res.json({ success: true, redirectUrl: `/mods/${newVersion._id}` });
        
    } catch (error) {
        console.error("Error adding new version:", error);
        res.status(500).json({ success: false, message: "A server error occurred during upload." });
    }
});
// --- NEW: HELPER TO DELETE FILES FROM BACKBLAZE B2 ---
const deleteFromB2 = async (fileKey) => {
    if (!fileKey || fileKey === 'external-link') return; // Don't try to delete empty or external links

    try {
        const params = {
            Bucket: process.env.B2_BUCKET_NAME,
            Key: fileKey
        };
        console.log(`Deleting ${fileKey} from B2...`);
        await s3Client.send(new DeleteObjectCommand(params));
        console.log(`Successfully deleted ${fileKey} from B2.`);
    } catch (error) {
        // We log the error but don't crash the server. If a file is already gone, that's okay.
        console.error(`Failed to delete ${fileKey} from B2:`, error.message);
    }
};
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

// --- NEW: Multi-Part Download Page Route ---
app.get('/mods/:id/parts', async (req, res) => {
    try {
        const fileId = req.params.id;
        if (!Types.ObjectId.isValid(fileId)) return res.status(404).render('pages/404');

        const file = await File.findById(fileId);
        
        if (!file || !file.isMultiPart) {
            // If it's not a multi-part file, just send them back to the main mod page
            return res.redirect(`/mods/${fileId}`);
        }

        // We still get a signed URL for the icon just to make the page look nice
        const iconKey = file.iconUrl || file.iconKey;
        const iconUrl = await getSmartImageUrl(iconKey);

        res.render('pages/download-parts', { 
            file: { ...file.toObject(), iconUrl }
        });

    } catch (e) {
        console.error("Multi-part page error:", e);
        res.status(500).render('pages/500');
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
            
            let tempSession = req.session.passport;
            req.session.regenerate((regenErr) => {
                req.session.passport = tempSession;
                req.session.save((saveErr) => {
                    // ✅ FIX: Set a readable cookie for the frontend CDN bypass
                    res.cookie('is_logged_in', 'true', { maxAge: 1000 * 60 * 60 * 24 * 3 }); // 3 days
                    res.redirect('/home?message=Welcome back!');
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

        // --- NEW: Security Check (Reserved Names) ---
        if (isNameReserved(username)) {
            return res.status(400).send("That username is reserved and cannot be used.");
        }

        let user = await User.findOne({ email: email.toLowerCase() });

        if (user && user.isVerified) {
            return res.status(400).send("An account with this email already exists.");
        }

        // --- NEW: Generate Unique Username (Discriminator) ---
        // We do this BEFORE creating the new user object
        const uniqueUsername = await generateUniqueUsername(username);

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = Date.now() + 600000; 

        if (user && !user.isVerified) {
            user.verificationOtp = otp;
            user.otpExpires = otpExpires;
            // Update their requested username just in case they changed it
            user.username = uniqueUsername; 
        } else {
            user = new User({
                username: uniqueUsername, // Use the generated name
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
// ======== NEW: AUTOMATED WELCOME MESSAGE ========
        try {
            const UserNotification = require('./models/userNotification');
            
            // Check if we already sent a welcome message (to prevent duplicates on re-verification)
            const existingWelcome = await UserNotification.findOne({ 
                user: user._id, 
                title: 'Welcome to GPL Mods!' 
            });

            if (!existingWelcome) {
                await new UserNotification({
                    user: user._id,
                    title: 'Welcome to GPL Mods!',
                    message: `Hi ${user.username},\n\nWelcome to the community! We're thrilled to have you here. \n\nFeel free to explore our massive library of safe, working mods, or start uploading your own to build your reputation.\n\nIf you need any help, check out the FAQ or submit a Support Ticket.\n\nHappy Modding,\nThe GPL Community Team`,
                    type: 'success' // Green icon
                }).save();
            }
        } catch (notifErr) {
            console.error("Failed to send automated welcome message:", notifErr);
            // We don't want a notification failure to stop the login process
        }
        
        req.login(user, (err) => {
            if (err) return res.redirect('/login?error=Verification successful, but login failed. Please log in manually.');
            
            let tempSession = req.session.passport;
            req.session.regenerate((regenErr) => {
                req.session.passport = tempSession;
                req.session.save(() => {
                    // ✅ FIX: Set a readable cookie for the frontend CDN bypass
                    res.cookie('is_logged_in', 'true', { maxAge: 1000 * 60 * 60 * 24 * 3 });
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
    req.logout(err => { 
        if (err) return next(err); 
        
        req.session.destroy(() => {
            res.clearCookie('connect.sid', { path: '/' });
            // ✅ FIX: Clear the readable cookie on logout
            res.clearCookie('is_logged_in', { path: '/' }); 
            res.redirect('/?message=You have been successfully logged out.'); 
        });
    });
});

// --- GOOGLE ROUTES ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }), 
    (req, res) => {
        // ✅ FIX: Set the CDN bypass cookie on successful social login
        res.cookie('is_logged_in', 'true', { 
            maxAge: 1000 * 60 * 60 * 24 * 3, // 3 Days
            path: '/', // Ensure it's available across the whole site
            secure: process.env.NODE_ENV === 'production', // Use secure cookies on HTTPS
            sameSite: 'lax'
        });
        res.redirect('/home');
    }
);

// --- GITHUB ROUTES ---
app.get('/auth/github', passport.authenticate('github', { scope: [ 'user:email' ] }));

app.get('/auth/github/callback', 
    passport.authenticate('github', { failureRedirect: '/login' }), 
    (req, res) => {
        // ✅ FIX: Set the CDN bypass cookie on successful social login
        res.cookie('is_logged_in', 'true', { 
            maxAge: 1000 * 60 * 60 * 24 * 3, 
            path: '/',
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });
        res.redirect('/home');
    }
);

// --- MICROSOFT ROUTES ---
app.get('/auth/microsoft', passport.authenticate('microsoft', { prompt: 'select_account' }));

app.get('/auth/microsoft/callback', 
    passport.authenticate('microsoft', { failureRedirect: '/login' }), 
    (req, res) => {
        // ✅ FIX: Set the CDN bypass cookie on successful social login
        res.cookie('is_logged_in', 'true', { 
            maxAge: 1000 * 60 * 60 * 24 * 3, 
            path: '/',
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        });
        res.redirect('/home');
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

        // ✅ BUG 2 FIX: Generate Secure Smart URLs for all Whitelisted Mods!
        if (userObj.whitelist && userObj.whitelist.length > 0) {
            userObj.whitelist = await Promise.all(userObj.whitelist.map(async (file) => {
                const iconKey = file.iconUrl || file.iconKey;
                const iconUrl = await getSmartImageUrl(iconKey); // Fetch the secure B2 URL
                return { ...file, iconUrl }; // Attach it to the object
            }));
        }

        const userUploads = await File.find({ uploader: req.user.username, isLatestVersion: true }).sort({ createdAt: -1 });
        
        res.render('pages/profile', { user: userObj, uploads: userUploads });
    } catch (e) { 
        console.error('Profile fetch error:', e);
        res.status(500).send('Profile fetch error.'); 
    }
});

// My Uploads Route
app.get('/my-uploads', ensureAuthenticated, async (req, res) => {
    try {
        // 1. Fetch ONLY the user's LATEST uploads and populate the older versions
        // ✅ FIX: Added `isLatestVersion: true` to prevent duplicates!
                const userUploads = await File.find({ 
            uploader: req.user.username,
            // Ensure we get latest versions OR things still in draft/processing
            $or: [ { isLatestVersion: true }, { status: { $in:['processing', 'draft'] } } ]
        })
        .sort({ createdAt: -1 })
        .populate('olderVersions', 'version fileSize createdAt');
        
        // 2. Map through the uploads to generate signed image URLs
        const uploadsWithUrls = await Promise.all(userUploads.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            let signedIconUrl = '/images/default-avatar.png';
            if (key) {
                try {
                    signedIconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 });
                } catch (urlError) {}
            }
            
            // ✅ FIX: Manually attach the olderVersions array to the new plain object
            const plainFile = file.toObject();
            plainFile.iconUrl = signedIconUrl;
            plainFile.olderVersions = file.olderVersions || []; // Ensure it's an array
            
            return plainFile;
        }));

        res.render('pages/my-uploads', { uploads: uploadsWithUrls }); 
    } catch (error) { 
        console.error("My Uploads Error:", error);
        res.status(500).render('pages/500'); 
    }
});
// --- PUBLIC PROFILE ROUTE ---
app.get('/users/:username', async (req, res) => {
    try {
        const username = req.params.username;
        // 1. Create a RegEx to handle the slug (e.g., 'john-doe' -> matches 'John Doe')
        const searchPattern = new RegExp(`^${username.replace(/-/g, '[-\\s]+')}$`, 'i');

        // 2. Fetch the user and populate the follower/following arrays
        const user = await User.findOne({ username: searchPattern })
            .populate('following', 'username profileImageKey role')
            .populate('followers', 'username profileImageKey role');

        if (!user) return res.status(404).render('pages/404');

        // 3. Get the main user's avatar
        user.signedAvatarUrl = await getSmartImageUrl(user.profileImageKey);

        // 4. Fetch the user's live uploads
        const uploads = await File.find({ 
            uploader: user.username, // Use the real name from DB, not the slug
            isLatestVersion: true,
            status: 'live' 
        }).sort({ createdAt: -1 });
        
        // Get signed URLs for the upload icons
        const uploadsWithUrls = await Promise.all(uploads.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            const iconUrl = await getSmartImageUrl(key);
            return { ...file.toObject(), iconUrl };
        }));

        // 5. --- NEW: Get signed URLs for Followers ---
        const followersWithAvatars = await Promise.all(user.followers.map(async (follower) => {
            const avatarUrl = await getSmartImageUrl(follower.profileImageKey);
            return { ...follower.toObject(), signedAvatarUrl: avatarUrl };
        }));

        // 6. --- NEW: Get signed URLs for Following ---
        const followingWithAvatars = await Promise.all(user.following.map(async (followingUser) => {
            const avatarUrl = await getSmartImageUrl(followingUser.profileImageKey);
            return { ...followingUser.toObject(), signedAvatarUrl: avatarUrl };
        }));

        // 7. Check if current logged-in user is following this profile
        let isFollowing = false;
        if (req.isAuthenticated()) {
            isFollowing = req.user.following.includes(user._id);
        }

        // 8. Render the page, passing the newly processed arrays
        res.render('pages/public-profile', { 
            profileUser: { ...user.toObject(), signedAvatarUrl: user.signedAvatarUrl }, // Pass the main user data
            uploads: uploadsWithUrls,
            followersList: followersWithAvatars, // <--- NEW
            followingList: followingWithAvatars, // <--- NEW
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

        // --- Handle Username Change ---
        if (username && username !== user.username) {
            
            // 1. Security Check
            if (isNameReserved(username)) {
                 return res.redirect('/profile?error=That username is reserved and cannot be used.');
            }

            // 2. Generate the new, unique name (adds # if needed)
            const newUniqueUsername = await generateUniqueUsername(username);

            // 3. CRITICAL: Update the 'uploader' field on all their mods!
            // We must do this BEFORE we change the user's name on their document
            await File.updateMany(
                { uploader: user.username }, // Find mods with the OLD name
                { uploader: newUniqueUsername } // Change to the NEW name
            );

            // 4. Finally, update the user's document
            user.username = newUniqueUsername;
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

// ✅ FIX: Added Multer error catching to prevent 500 errors if image is > 5MB
app.post('/account/update-profile-image', ensureAuthenticated, (req, res, next) => {
    uploadAvatar.single('profileImage')(req, res, function (err) {
        if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
            return res.redirect('/profile?error=Image is too large. Maximum size is 5MB.');
        } else if (err) {
            return res.redirect('/profile?error=An error occurred during upload.');
        }
        next();
    });
}, async (req, res, next) => {
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
        res.redirect('/profile?error=' + encodeURIComponent('Could not upload image. Please try again.')); 
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
// --- INITIAL UPLOAD ROUTE (SERVER-SIDE WITH LIMITS) ---
app.post('/upload-initial', ensureAuthenticated, upload.single('modFile'), async (req, res) => {
    try {
        // ======== DAILY UPLOAD LIMIT CHECK ========
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const recentUploadCount = await File.countDocuments({
            uploader: req.user.username,
            createdAt: { $gte: oneDayAgo }
        });

        let dailyLimit = 5;
        if (req.user.role === 'distributor' || req.user.role === 'admin') dailyLimit = 50;

        if (recentUploadCount >= dailyLimit) {
            const UserNotification = require('./models/userNotification');
            await new UserNotification({
                user: req.user._id,
                title: 'Daily Upload Limit Reached',
                message: `You have reached your limit of ${dailyLimit} uploads in a 24-hour period. \n\nTo ensure quality and prevent spam, we limit how many mods can be submitted daily. Please wait 24 hours before uploading more content.`,
                type: 'warning' 
            }).save();

            if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
            return res.status(429).redirect('/upload?error=Daily upload limit reached. Please check your notifications for details.');
        }

    // ========================================================
    // ✅ FIX: YOU MUST ADD THIS CLOSING BLOCK HERE!
    // This closes the 'try' block that started at the top of the route.
    } catch (limitError) {
        console.error("Upload limit check failed:", limitError);
        return res.status(500).render('pages/500');
    }
    // ========================================================


    // --- SCENARIO 1: DISTRIBUTOR UPLOAD (External Link) ---
    if (req.user.role === 'distributor' && req.body.externalUrl) {
        try {
            const { externalUrl, originalFilename } = req.body;

            const newFile = new File({
                uploader: req.user.username,
                externalDownloadUrl: externalUrl,
                originalFilename: originalFilename,
                fileKey: 'external-link', 
                fileSize: 0, 
                name: originalFilename, 
                version: 'Draft',
                
                // ✅ FIX: Set category to empty string instead of 'android'
                category: 'n/a',         
                platforms: [],
                
                status: 'processing' 
            });
            await newFile.save();
            
            // --- NEW: VIRUSTOTAL v3 URL SCAN ---
            console.log(`Starting VT URL scan for Distributor link: ${externalUrl}`);
            (async () => {
                try {
                    // API v3 requires the URL to be form-urlencoded
                    const urlParams = new URLSearchParams();
                    urlParams.append('url', externalUrl);

                    const vtUrlResponse = await axios.post('https://www.virustotal.com/api/v3/urls', urlParams, {
                        headers: { 
                            'x-apikey': process.env.VIRUSTOTAL_API_KEY,
                            'Content-Type': 'application/x-www-form-urlencoded'
                        }
                    });
                    
                    const analysisId = vtUrlResponse.data.data.id;
                    console.log(`VT URL Scan submitted. Analysis ID: ${analysisId}`);
                    
                    await File.findByIdAndUpdate(newFile._id, { virusTotalAnalysisId: analysisId });
                } catch (vtError) {
                    console.error("VT URL Scan Error:", vtError.response?.data || vtError.message);
                }
            })();
            
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
    
    const fileSize = req.file.size;
    const isPremium = req.user.membership === 'premium';
    const isAdminOrDist = req.user.role === 'admin' || req.user.role === 'distributor';
    
    const limit300MB = 314572800;
    const limit1GB = 1073741824;

    if (!isAdminOrDist) {
        if (!isPremium && fileSize > limit300MB) {
            return res.status(413).redirect('/upload?error=File exceeds your 300MB limit. Please upgrade to Premium.');
        }
        if (isPremium && fileSize > limit1GB) {
             return res.status(413).redirect('/upload?error=File exceeds the 1GB Premium limit.');
        }
    }

    try {
        console.log("Uploading main file to B2 from memory buffer...");
        
        const io = req.app.get('io');
        const uploadId = req.body.uploadId; 
        
        // ✅ CRITICAL FIX: Pass the 'io' object and 'uploadId' into the helper!
        // This is what makes the Socket.IO progress bar work!
        const fileKey = await uploadToB2(req.file, 'mods', io, uploadId);
        
        console.log("Upload to B2 complete.");

        const newFile = new File({
            uploader: req.user.username,
            fileKey: fileKey,
            originalFilename: req.file.originalname,
            fileSize: req.file.size,
            name: req.file.originalname, 
            version: 'Draft',
            
            // ✅ FIX: Set category to empty string instead of 'android'
            category: 'n/a',         
            platforms: [],
            
            status: 'processing' 
        });
        await newFile.save();
        
        // --- VIRUSTOTAL SCAN ---
        (async () => {
            try {
                console.log(`Starting VT Scan for new file ${newFile._id}...`);
                const analysisId = await submitToVirusTotal(req.file.buffer, req.file.originalname, req.file.size);
                await File.findByIdAndUpdate(newFile._id, { virusTotalAnalysisId: analysisId });
                console.log(`VT Scan submitted successfully. Analysis ID: ${analysisId}`);
            } catch (error) {
                console.error(`Background VT scan failed for ${newFile._id}.`);
            } 
        })(); 

        res.redirect(`/upload-details/${newFile._id}`);

    } catch (error) {
        console.error("Initial upload error:", error);
        res.status(500).render('pages/500');
    }
}); // <--- ADD THIS CLOSING BRACE AND PARENTHESIS HERE

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

// --- UPDATED: User Delete Mod Route (Deletes from DB AND Cloud) ---
app.post('/mods/:id/delete', ensureAuthenticated, async (req, res) => {
    try {
        const fileId = req.params.id;
        // Populate older versions so we can delete their files too!
        const file = await File.findById(fileId).populate('olderVersions');

        // Security check: Make sure the file exists and the logged-in user owns it
        if (!file || file.uploader !== req.user.username) {
            return res.status(403).json({ success: false, message: 'Unauthorized' });
        }

        // --- 1. DELETE FILES FROM BACKBLAZE B2 ---
        
        // A. Delete main file, icon, and screenshots
        await deleteFromB2(file.fileKey);
        await deleteFromB2(file.iconKey);
        if (file.screenshotKeys && file.screenshotKeys.length > 0) {
            for (const key of file.screenshotKeys) {
                await deleteFromB2(key);
            }
        }

        // B. Delete all older versions from B2 and the Database
        if (file.olderVersions && file.olderVersions.length > 0) {
            for (const oldVersion of file.olderVersions) {
                await deleteFromB2(oldVersion.fileKey);
                // Icons and screenshots are shared with the parent, so we only need to delete the main fileKey
                await File.findByIdAndDelete(oldVersion._id); 
            }
        }

        // --- 2. DELETE FROM DATABASE ---
        await File.findByIdAndDelete(fileId);
        await Review.deleteMany({ file: fileId });
        await Report.updateMany({ file: fileId }, { status: 'resolved' });

        res.json({ success: true, message: 'Mod and all associated files deleted successfully.' });
    } catch (error) {
        console.error("Error deleting mod:", error);
        res.status(500).json({ success: false });
    }
});
// --- NEW: User Delete Specific Old Version ---
app.post('/mods/:id/delete-version/:versionId', ensureAuthenticated, async (req, res) => {
    try {
        const { id, versionId } = req.params;
        const masterFile = await File.findById(id).populate('olderVersions');

        // Security check
        if (!masterFile || masterFile.uploader !== req.user.username) {
            return res.status(403).json({ success: false, message: 'Unauthorized' });
        }

        // Find the version to delete
        const versionToDelete = masterFile.olderVersions.find(v => v._id.toString() === versionId);
        if (!versionToDelete) {
            return res.status(404).json({ success: false, message: 'Version not found.' });
        }

        // 1. Delete from B2
        await deleteFromB2(versionToDelete.fileKey);

        // 2. Remove from Master File's array
        await File.findByIdAndUpdate(id, { $pull: { olderVersions: versionId } });

        // 3. Delete the version document
        await File.findByIdAndDelete(versionId);

        res.json({ success: true, message: 'Version deleted successfully.' });
    } catch (error) {
        console.error("Error deleting version:", error);
        res.status(500).json({ success: false });
    }
});

// --- NEW: User Delete ALL Old Versions ---
app.post('/mods/:id/delete-all-versions', ensureAuthenticated, async (req, res) => {
    try {
        const fileId = req.params.id;
        const masterFile = await File.findById(fileId).populate('olderVersions');

        // Security check
        if (!masterFile || masterFile.uploader !== req.user.username) {
            return res.status(403).json({ success: false, message: 'Unauthorized' });
        }

        if (masterFile.olderVersions && masterFile.olderVersions.length > 0) {
            for (const oldVersion of masterFile.olderVersions) {
                // 1. Delete from B2
                await deleteFromB2(oldVersion.fileKey);
                // 2. Delete the version document
                await File.findByIdAndDelete(oldVersion._id); 
            }
            
            // 3. Clear the array on the Master File
            masterFile.olderVersions = [];
            await masterFile.save();
        }

        res.json({ success: true, message: 'All older versions deleted successfully.' });
    } catch (error) {
        console.error("Error deleting all versions:", error);
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
        
        // ✅ NEW: Determine if saving as draft or submitting
        const actionType = formData.actionType || 'submit';

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
        // ✅ FIX: Added importantNote to the save logic
        file.importantNote = formData.importantNote || file.importantNote;        
        file.videoUrl = formData.videoUrl || file.videoUrl;
        file.category = formData.modPlatform || file.category;
        file.tags = processedTags;
        if (formData.modCategory) {
            file.platforms = [formData.modCategory];
        }

// 4. IMPORTANT: Status Logic
        if (actionType === 'draft') {
            // If they saved a draft, change the status to processing, taking it offline
            file.status = 'draft'; 
        } else {
            // If they clicked Submit...
            if (file.status === 'rejected' || file.status === 'processing') {
                // If it was rejected or a draft, send it to the admin queue
                file.status = 'pending';
                file.rejectionReason = ''; // Clear old reason
            }
            // If it was already 'live', it stays 'live'. 
            // (Unless you want ALL edits to go through admin review again, in which case set it to 'pending')
        }

        await file.save();
        
        if (actionType === 'draft') {
             res.redirect(`/mods/${file._id}/edit?success=Draft saved successfully. This mod is now hidden from the public until you submit it.`);
        } else {
             res.redirect('/my-uploads?success=Mod updated successfully!');
        }

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

        const { softwareIcon, screenshots } = req.files || {}; // Default to empty object if no files
        const formData = req.body; 
        
        // ✅ NEW: Determine what the user wants to do (Save Draft vs Submit)
        const actionType = formData.actionType || 'submit'; // 'draft' or 'submit'

        // --- 1. THE VARIANT CHECK ---
        const existingMasterFile = await File.findOne({
            name: { $regex: new RegExp(`^${formData.modName}$`, 'i') }, 
            category: formData.modPlatform,
            isLatestVersion: true,
            status: 'live',
            _id: { $ne: fileId } 
        });

        let isVariant = false;
        let masterFileId = null;

        if (existingMasterFile) {
            console.log(`Duplicate upload detected for "${formData.modName}". Converting to Variant.`);
            isVariant = true;
            masterFileId = existingMasterFile._id;
            // No unlinkSync needed here anymore!
        } else {
            if (!softwareIcon || !screenshots) {
                return res.redirect(`/upload-details/${fileId}?error=Icon and screenshots are required for new mods.`);
            }
        }

        let iconKey = fileToUpdate.iconKey; // Keep existing if not updating
        let screenshotKeys = fileToUpdate.screenshotKeys || [];
        const processedTags = formData.tags ? formData.tags.split(',').map(t => t.trim()) : [];

        // --- PROCESS IMAGES ---
        if (!isVariant && softwareIcon && softwareIcon.length > 0) {
            iconKey = await uploadToB2(softwareIcon[0], 'icons');
        }
        if (screenshots && screenshots.length > 0) {
            screenshotKeys = await Promise.all(screenshots.map(f => uploadToB2(f, 'screenshots')));
        }

        // --- VALIDATION FOR SUBMISSION ONLY ---
        // If they are submitting for review, enforce required fields.
        // If they are just saving a draft, allow missing fields.
        if (actionType === 'submit') {
            if (!isVariant && !iconKey) {
                return res.redirect(`/upload-details/${fileId}?error=An icon is required to submit the mod.`);
            }
            if (!formData.modPlatform || !formData.modCategory) {
                return res.redirect(`/upload-details/${fileId}?error=Platform and Category are required to submit.`);
            }
            // Add any other strict requirements here
        }

        // --- GENERATE SLUG ---
        let finalSlug = fileToUpdate.slug; // Keep existing slug if saving a draft
        if (!isVariant && actionType === 'submit' && !finalSlug) {
            let baseSlug = slugify(formData.modName);
            finalSlug = baseSlug;
            let slugCounter = 1;
            while (await File.findOne({ slug: finalSlug, category: formData.modPlatform, isLatestVersion: true, _id: { $ne: fileId } })) {
                finalSlug = `${baseSlug}-${slugCounter}`;
                slugCounter++;
            }
        }

        // --- SET FINAL STATUS ---
        // If saving a draft, keep it in 'processing' mode so it stays in their uploads list
        // but doesn't show up in the Admin's "Pending Review" queue yet.
        const finalStatus = actionType === 'draft' ? 'draft' : 'pending';

        // --- SAVE TO DATABASE ---
        const updateData = {
            name: formData.modName || fileToUpdate.name, 
            version: formData.modVersion || fileToUpdate.version,
            modDescription: formData.modDescription,
            modFeatures: formData.modFeatures,
            whatsNew: formData.whatsNew,
            importantNote: formData.importantNote,
            developer: formData.developerName || 'N/A',
            screenshotKeys: screenshotKeys.length > 0 ? screenshotKeys : fileToUpdate.screenshotKeys,
            videoUrl: formData.videoUrl, 
            
            // Update categories if provided, otherwise keep existing (which might be empty string)
            category: formData.modPlatform || fileToUpdate.category,
            platforms: formData.modCategory ? [formData.modCategory] : fileToUpdate.platforms,
            
            status: finalStatus // 'processing' (draft) or 'pending' (submitted)
        };

        if (isVariant) {
            updateData.isVariant = true;
            updateData.masterFile = masterFileId;
            updateData.isLatestVersion = false;
            
            await File.findByIdAndUpdate(fileId, updateData);
            
            // Only link to master if submitting for real
            if (actionType === 'submit') {
                await File.findByIdAndUpdate(masterFileId, { $push: { variants: fileId } });
            }
        } else {
            updateData.slug = finalSlug;
            updateData.tags = processedTags;
            updateData.iconKey = iconKey;
            updateData.isVariant = false;
            
            await File.findByIdAndUpdate(fileId, updateData);
        }

        // --- REDIRECT BASED ON ACTION ---
        if (actionType === 'draft') {
            res.redirect(`/upload-details/${fileId}?success=Draft saved successfully! You can return to finish it later.`);
        } else {
            res.redirect('/my-uploads?success=Upload complete and submitted for review!');
        }

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

// --- NEW: Username Availability & Suggestion API ---
app.get('/api/check-username', async (req, res) => {
    try {
        const requestedName = req.query.username;

        if (!requestedName || requestedName.trim().length < 3) {
            return res.json({ available: false, message: 'Username too short' });
        }

        // 1. Check against reserved names
        if (isNameReserved(requestedName)) {
            return res.json({ 
                available: false, 
                message: 'This name is reserved.',
                suggestions: [] 
            });
        }

        // 2. Check if the exact name is taken
        const exactMatch = await User.findOne({ 
            username: { $regex: new RegExp(`^${requestedName}$`, 'i') } 
        });

        if (!exactMatch) {
            return res.json({ available: true, message: 'Username is available!' });
        }

        // 3. If taken, generate suggestions using our existing helper logic
        // We'll generate 3 options by appending random numbers or using the next available #
        const suggestions = [];
        
        // Suggestion 1: The next logical # number (using our helper)
        const nextNumberedName = await generateUniqueUsername(requestedName);
        suggestions.push(nextNumberedName);

        // Suggestion 2 & 3: Random suffixes for variety
        suggestions.push(`${requestedName}${Math.floor(Math.random() * 999)}`);
        suggestions.push(`${requestedName}_${Math.floor(Math.random() * 99)}`);

        return res.json({
            available: false,
            message: 'Username is taken.',
            suggestions: suggestions
        });

    } catch (error) {
        console.error("API Username Check Error:", error);
        res.status(500).json({ error: 'Server error during check.' });
    }
});

// --- NEW: Newsletter Subscription API ---
app.post('/api/subscribe', async (req, res) => {
    try {
        const { email, source } = req.body;

        if (!email || !email.includes('@')) {
            return res.status(400).json({ error: 'Please provide a valid email address.' });
        }

        // Check if they are already subscribed
        let subscriber = await Subscriber.findOne({ email: email.toLowerCase() });

        if (subscriber) {
            if (subscriber.isSubscribed) {
                return res.status(400).json({ error: 'You are already subscribed to our newsletter!' });
            } else {
                // If they previously unsubscribed, resubscribe them
                subscriber.isSubscribed = true;
                subscriber.subscribedAt = Date.now();
                await subscriber.save();
                return res.json({ message: 'Welcome back! You have been successfully re-subscribed.' });
            }
        }

        // Create a new subscriber
        const newSubscriber = new Subscriber({
            email: email.toLowerCase(),
            source: source || 'popup',
            user: req.user ? req.user._id : null // Link account if logged in
        });

        await newSubscriber.save();
        
        // Optional: Send a "Welcome to the Newsletter" confirmation email here using your mailer utility
        // await sendNewsletterWelcomeEmail(newSubscriber.email);

        res.json({ message: 'Thank you for subscribing! Check your inbox for the latest updates.' });

    } catch (error) {
        console.error("Newsletter Subscription Error:", error);
        res.status(500).json({ error: 'Server error. Please try again later.' });
    }
});

// ===================================
// 11.5  VIRUSTOTAL REFRESH ROUTE (SMART FIX)
// ===================================
app.post('/api/refresh-vt-scan/:fileId', async (req, res) => {
    try {
        const fileId = req.params.fileId;
        const file = await File.findById(fileId);
        
        // Check both ID fields
        const vtId = file.virusTotalAnalysisId || file.virusTotalId;
        
        if (!file || !vtId) {
            return res.status(404).json({ error: "No VirusTotal ID found for this file." });
        }

        let vtResponse;
        let isCompleted = false;
        let stats = null;
        let trueHash = null;

        // --- SMART CHECK: Is it a File Hash (64 chars) or an Analysis ID (contains '-')? ---
        if (vtId.length === 64 && !vtId.includes('-')) {
            // It's a direct FILE HASH or URL HASH. 
            // We don't know which one yet, but the scan is definitely done.
            // Since we already have the ID, we don't need to fetch the full report just to get the stats
            // if we already have them in the DB.
            if (file.virusTotalScanDate) {
                return res.json({ status: 'completed', stats: { malicious: file.virusTotalPositiveCount } });
            }
            
            // If we don't have stats but we have a hash, we must try to fetch them.
            // We will assume it's a file first. If that 404s, we assume it's a URL.
            try {
                vtResponse = await axios.get(`https://www.virustotal.com/api/v3/files/${vtId}`, {
                    headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
                });
            } catch (err) {
                if (err.response && err.response.status === 404) {
                    // Try URL endpoint instead
                    vtResponse = await axios.get(`https://www.virustotal.com/api/v3/urls/${vtId}`, {
                        headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
                    });
                } else {
                    throw err; // Real error
                }
            }
            
            isCompleted = true;
            stats = vtResponse.data.data.attributes.last_analysis_stats;
            trueHash = vtId; 

        } else {
            // It's an ANALYSIS ID (e.g., from a recent upload or external link submission).
            // We need to check if the background scan is finished.
            vtResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${vtId}`, {
                headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
            });

            if (vtResponse.data.data.attributes.status === 'completed') {
                isCompleted = true;
                stats = vtResponse.data.data.attributes.stats;
                
                // ✅ FIX: Determine if this was a FILE analysis or a URL analysis
                const type = vtResponse.data.meta?.file_info ? 'file' : 'url';

                if (type === 'file') {
                    // Extract the actual File Hash (SHA-256)
                    trueHash = vtResponse.data.meta.file_info.sha256;
                } else {
                    // For URLs, VT provides a URL Identifier (which is just a hash of the URL)
                    // We can extract this from the item_id in the analysis report.
                    // The analysis ID looks like: u-HASH-TIMESTAMP. We want the HASH.
                    const parts = vtId.split('-');
                    if (parts.length >= 2) {
                        trueHash = parts[1]; // The SHA256 of the URL
                    }
                }
            }
        }

        // --- UPDATE DATABASE IF COMPLETED ---
        if (isCompleted && stats) {
            await File.findByIdAndUpdate(fileId, {
                virusTotalScanDate: new Date(), 
                virusTotalPositiveCount: stats.malicious + stats.suspicious,
                virusTotalTotalScans: stats.harmless + stats.malicious + stats.suspicious + stats.undetected,
                // Save the true hash (file or URL) so we link directly to the report next time
                virusTotalId: trueHash || vtId 
            });

            return res.json({ status: 'completed', stats: stats });
        } else {
            // It's still an analysis ID, and it's still 'queued' or 'in-progress'
            return res.json({ status: vtResponse.data.data.attributes.status || 'pending' }); 
        }

    } catch (error) {
        console.error("VT Refresh Error:", error.response?.data || error.message);
        
        if (error.response && error.response.status === 404) {
             return res.status(404).json({ error: "VirusTotal could not find a report for this ID." });
        }
        
        res.status(500).json({ error: "Failed to contact VirusTotal API." });
    }
});
// ===================================
// 11.6 VIRUSTOTAL REFRESH ROUTE (MULTI-PART)
// ===================================
app.post('/api/refresh-vt-scan/:fileId/part/:partId', async (req, res) => {
    try {
        const { fileId, partId } = req.params;
        const file = await File.findById(fileId);
        
        if (!file || !file.downloadParts || file.downloadParts.length === 0) {
            return res.status(404).json({ error: "File or parts not found." });
        }

        // Find the specific part within the array
        const part = file.downloadParts.id(partId);
        
        if (!part || !part.partVirusTotalId) {
             return res.status(404).json({ error: "No VirusTotal ID found for this part." });
        }

        const vtId = part.partVirusTotalId;
        let vtResponse;
        let isCompleted = false;
        let stats = null;
        let trueHash = null;

        // --- SMART CHECK (Same logic as main file refresh) ---
        if (vtId.length === 64 && !vtId.includes('-')) {
            if (part.partVirusTotalScanDate) {
                return res.json({ status: 'completed', stats: { malicious: part.partVirusTotalPositiveCount } });
            }
            try {
                vtResponse = await axios.get(`https://www.virustotal.com/api/v3/files/${vtId}`, { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY } });
            } catch (err) {
                if (err.response && err.response.status === 404) {
                    vtResponse = await axios.get(`https://www.virustotal.com/api/v3/urls/${vtId}`, { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY } });
                } else { throw err; }
            }
            isCompleted = true;
            stats = vtResponse.data.data.attributes.last_analysis_stats;
            trueHash = vtId; 
        } else {
            vtResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${vtId}`, { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY } });
            if (vtResponse.data.data.attributes.status === 'completed') {
                isCompleted = true;
                stats = vtResponse.data.data.attributes.stats;
                const type = vtResponse.data.meta?.file_info ? 'file' : 'url';
                if (type === 'file') {
                    trueHash = vtResponse.data.meta.file_info.sha256;
                } else {
                    const parts = vtId.split('-');
                    if (parts.length >= 2) trueHash = parts[1];
                }
            }
        }

        // --- UPDATE DATABASE IF COMPLETED ---
        if (isCompleted && stats) {
            part.partVirusTotalScanDate = new Date();
            part.partVirusTotalPositiveCount = stats.malicious + stats.suspicious;
            part.partVirusTotalTotalScans = stats.harmless + stats.malicious + stats.suspicious + stats.undetected;
            part.partVirusTotalId = trueHash || vtId;
            
            await file.save(); // Save the parent document to save the nested array changes

            return res.json({ status: 'completed', stats: stats });
        } else {
            return res.json({ status: vtResponse.data.data.attributes.status || 'pending' }); 
        }

    } catch (error) {
        console.error("VT Part Refresh Error:", error.response?.data || error.message);
        res.status(500).json({ error: "Failed to contact VirusTotal API." });
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
app.get('/refund-policy', (req, res) => res.render('pages/static/refund-policy'));
app.get('/donate', (req, res) => res.render('pages/static/donate'));
app.get('/membership', (req, res) => {
    // If you use Stripe/Cashfree keys in this view, pass them here
    res.render('pages/membership', {
        // e.g., stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY
    });
});
// --- NEW: DOCUMENTATION SYSTEM ROUTE ---
app.get('/docs/:slug?', async (req, res) => {
    try {
        const requestedSlug = req.params.slug;

        const allCategories = await DocCategory.find().sort({ order: 1 }).lean();
        const allPages = await DocPage.find().sort({ order: 1 }).populate('category').lean();

        const sidebarStructure = allCategories.map(cat => {
            return {
                ...cat,
                pages: allPages.filter(p => p.category && p.category._id.toString() === cat._id.toString())
            };
        });

        let currentPage = null;

        if (requestedSlug) {
            currentPage = await DocPage.findOne({ slug: requestedSlug }).populate('category');
            if (!currentPage) {
                // If they type a bad slug, render the 404 page
                return res.status(404).render('pages/404');
            }
        } else {
            // If they just visit /docs, find the very first page
            if (sidebarStructure.length > 0 && sidebarStructure[0].pages.length > 0) {
                currentPage = sidebarStructure[0].pages[0];
                return res.redirect(`/docs/${currentPage.slug}`);
            }
        }

        res.render('pages/docs', {
            sidebarStructure: sidebarStructure,
            currentPage: currentPage
        });

    } catch (error) {
        console.error("Docs Engine Error:", error);
        res.status(500).render('pages/500');
    }
});

// ======== THE BULLETPROOF, FULLY AUTOMATED SITEMAP ========
app.get('/sitemap.xml', async (req, res) => {
    try {
        res.set('Content-Type', 'text/xml');
        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
        xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

        // 1. Static Pages
        const staticPages =['', '/login', '/register', '/about', '/faq', '/dmca', '/tos', '/privacy-policy', '/donate', '/docs']; // Added /docs here
        staticPages.forEach(page => {
            xml += `  <url>\n    <loc>${baseUrl}${page}</loc>\n    <changefreq>weekly</changefreq>\n    <priority>0.8</priority>\n  </url>\n`;
        });

        // 2. Category Pages
        const categories =['android', 'ios-jailed', 'ios-jailbroken', 'windows', 'wordpress'];
        categories.forEach(cat => {
             xml += `  <url>\n    <loc>${baseUrl}/category?platform=${cat}</loc>\n    <changefreq>daily</changefreq>\n    <priority>0.7</priority>\n  </url>\n`;
        });

        // 3. Live Mods
        const liveMods = await File.find({ showInSitemap: { $ne: false }, isLatestVersion: true, status: 'live' }).select('_id category slug updatedAt');
        liveMods.forEach(mod => {
            let lastModDate = mod.updatedAt ? new Date(mod.updatedAt).toISOString() : new Date().toISOString();
            const modUrl = `${baseUrl}/${mod.category}/${mod.slug || mod._id}`;
            xml += `  <url>\n    <loc>${modUrl}</loc>\n    <lastmod>${lastModDate}</lastmod>\n    <changefreq>daily</changefreq>\n    <priority>0.9</priority>\n  </url>\n`;
        });

        // 4. Developer Pages
        const uniqueDevelopers = await File.distinct('developer', { status: 'live', isLatestVersion: true });
        uniqueDevelopers.forEach(dev => {
            if (dev && dev !== 'N/A') {
                xml += `  <url>\n    <loc>${baseUrl}/developer?name=${slugify(dev)}</loc>\n    <changefreq>weekly</changefreq>\n    <priority>0.6</priority>\n  </url>\n`;
            }
        });

        // 5. Public User Profiles
        const uniqueUploaders = await File.distinct('uploader', { status: 'live', isLatestVersion: true });
        uniqueUploaders.forEach(uploader => {
             xml += `  <url>\n    <loc>${baseUrl}/users/${slugify(uploader)}</loc>\n    <changefreq>weekly</changefreq>\n    <priority>0.6</priority>\n  </url>\n`;
        });

        // 6. --- NEW: DYNAMIC DOCUMENTATION PAGES ---
        const allDocPages = await DocPage.find().select('slug updatedAt').lean();
        allDocPages.forEach(doc => {
            let lastDocDate = doc.updatedAt ? new Date(doc.updatedAt).toISOString() : new Date().toISOString();
            xml += `  <url>\n    <loc>${baseUrl}/docs/${doc.slug}</loc>\n    <lastmod>${lastDocDate}</lastmod>\n    <changefreq>weekly</changefreq>\n    <priority>0.7</priority>\n  </url>\n`;
        });

        xml += '</urlset>';
        res.send(xml);
        
    } catch (error) {
        console.error("Sitemap generation error:", error);
        res.status(500).send('Error generating sitemap');
    }
});
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
        // Prevent multiple applications
        const existingApp = await DistributorApplication.findOne({ user: req.user._id });
        if (existingApp) {
            return res.redirect('/partnership?error=You have already submitted an application.');
        }

        const { 
            organizationName, primaryDistributionPlatform, platformUrl, 
            monetizationMethod, adminContactName, adminSocialLink,
            socialTelegram, socialDiscord, socialWebsite, socialYoutube,
            agreedToTerms
        } = req.body;

        if (!agreedToTerms) {
            return res.redirect('/partnership?error=You must agree to the safety and distribution terms.');
        }

        const newApplication = new DistributorApplication({
            user: req.user._id,
            username: req.user.username,
            email: req.user.email,
            organizationName,
            primaryDistributionPlatform,
            platformUrl,
            monetizationMethod,
            adminContactName,
            adminSocialLink,
            socialTelegram,
            socialDiscord,
            socialWebsite,
            socialYoutube,
            agreedToTerms: true
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
        
        // ✅ CRITICAL FIX: Make Socket.IO globally accessible HERE, inside the function!
        app.set('io', io); 

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
}; // <-- This correctly closes the startServer() function

// ===================================
// AUTOMATION ENGINE (CRON JOBS)
// ===================================

// This job runs every 1 minute
cron.schedule('* * * * *', async () => {
    try {
        const now = new Date();

        // 1. Find campaigns that are scheduled to run NOW
        const pendingCampaigns = await AutomatedCampaign.find({
            status: 'scheduled',
            scheduledDate: { $lte: now }
        });

        if (pendingCampaigns.length === 0) return;

        for (const campaign of pendingCampaigns) {
            console.log(`Starting automated campaign: ${campaign.title}`);
            
            campaign.status = 'processing';
            await campaign.save();

            let targetUsers = [];

            if (campaign.targetGroup === 'all-users') {
                targetUsers = await User.find({}).select('_id');
            } else if (campaign.targetGroup === 'premium-only') {
                targetUsers = await User.find({ membership: 'premium' }).select('_id');
            } else if (campaign.targetGroup === 'distributors-only') {
                targetUsers = await User.find({ role: 'distributor' }).select('_id');
            } else if (campaign.targetGroup === 'android-uploaders') {
                const uploaders = await File.distinct('uploader', { category: 'android' });
                targetUsers = await User.find({ username: { $in: uploaders } }).select('_id');
            }

            const notificationsToInsert = targetUsers.map(user => ({
                user: user._id,
                title: campaign.notificationTitle,
                message: campaign.notificationMessage,
                type: campaign.notificationType,
                isRead: false,
                createdAt: new Date(),
                updatedAt: new Date()
            }));

            if (notificationsToInsert.length > 0) {
                await UserNotification.insertMany(notificationsToInsert);
            }

            campaign.status = 'completed';
            await campaign.save();
            console.log(`Completed campaign: ${campaign.title}. Sent to ${targetUsers.length} users.`);
        }

    } catch (error) {
        console.error("Cron Job Automation Error:", error);
    }
});

// ✅ START THE SERVER
startServer(); 

// 🛑 MAKE SURE THERE IS ABSOLUTELY NO CODE BELOW THIS LINE! 🛑
