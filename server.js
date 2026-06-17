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
const cookieParser = require('cookie-parser');
const http = require('http');
const { Server } = require("socket.io");
const crypto = require('crypto');
const cors = require('cors');
const fs = require('fs');
const cron = require('node-cron');
const FormData = require('form-data');
const { Upload } = require("@aws-sdk/lib-storage");
const Filter = require('bad-words');
const { isbot } = require('isbot');
const zlib = require('zlib');
const otplib = require('otplib');
const cheerio = require('cheerio');
const AdmZip = require('adm-zip'); 
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { generateRegistrationOptions, verifyRegistrationResponse } = require('@simplewebauthn/server');
const { mirrorToFTP, deleteFromFTP } = require('./utils/ftpSync'); // <--- ADD THIS LINE
const { Translate } = require('@google-cloud/translate').v2;

// Custom Utilities & Config
const { sendVerificationEmail, sendPasswordResetEmail, sendDeletionOtpEmail, send2faEmail, processNewsletterCampaign} = require('./utils/mailer');

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
const AutomatedCampaign = require('./models/automatedCampaign');
const SiteState = require('./models/siteState');
const Subscriber = require('./models/subscriber');
const DocCategory = require('./models/docCategory');
const DocPage = require('./models/docPage');
const Donation = require('./models/donation');
const DailyStat = require('./models/dailyStat');
const PointHistory = require('./models/pointHistory');
const TranslationCache = require('./models/translationCache');
const TranslationQuota = require('./models/translationQuota');

// ===============================
// 1. INITIALIZATION & CONFIGURATION
// ===============================
const app = express();
const PORT = process.env.PORT || 3000;
const { Types } = mongoose;
const translateClient = new Translate({ key: process.env.GOOGLE_TRANSLATE_API_KEY });

// Initialize the profanity filter
const profanityFilter = new Filter();
// You can add custom words that aren't in the default list
// profanityFilter.addWords('custombadword1', 'custombadword2');
// You can also remove words you don't consider bad
// profanityFilter.removeWords('hell');

// Expose it globally so we can use it in Socket.IO and Express routes
global.profanityFilter = profanityFilter;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ===============================
// USERNAME & DISCRIMINATOR HELPERS
// ===============================

// 1. Reserved Names List (Lowercase for easy checking)
const RESERVED_NAMES = ['admin', 'administrator', 'gplmods', 'gpl community', 'gpl', 'moderator', 'system', 'staff', 'support', 'owner', 'gpl hacker', 'destributior', 'mod destrubuter'];

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
// --- NEW HELPER: VALIDATE NAMES (Letters, Numbers, Spaces ONLY) ---
function isValidName(str) {
    if (!str) return false;
    
    const trimmed = str.trim();
    if (trimmed.length === 0) return false; // Prevents "    " (only spaces)

    // Regex: ^ (start) [a-zA-Z0-9 ]+ (one or more letters, numbers, or spaces) $ (end)
    // This strictly forbids emojis, symbols (!@#$), and invisible characters.
    const regex = /^[a-zA-Z0-9 ]+$/;
    return regex.test(trimmed);
}

// --- NEW HELPER: RECORD DAILY STATS ---
async function recordDailyStat(fileId, uploader, type) {
    try {
        const dateString = new Date().toISOString().split('T')[0]; // Gets "YYYY-MM-DD"
        const updateField = type === 'view' ? { views: 1 } : { downloads: 1 };
        
        await DailyStat.findOneAndUpdate(
            { file: fileId, dateString: dateString },
            { $setOnInsert: { uploader: uploader }, $inc: updateField },
            { upsert: true, new: true } // Creates the document if it doesn't exist today
        );
    } catch (e) { console.error("Stat Tracking Error:", e); }
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
// --- NEW HELPER: FORMAT COMPACT NUMBERS (1K, 1.5M) ---
function formatCompactNumber(number) {
    if (!number) return '0';
    // This native JS formatter automatically turns 1500 into 1.5K, 1000000 into 1M, etc.
    return Intl.NumberFormat('en-US', { notation: "compact", maximumFractionDigits: 1 }).format(number);
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
// --- NEW HELPER: TRUNCATE LONG TEXT ---
function truncateText(text, maxLength) {
    if (!text) return '';
    if (text.length <= maxLength) return text;
    // Cut the string and add ellipsis
    return text.substring(0, maxLength).trim() + '...';
}

// --- NEW HELPER: AWARD POINTS WITH HISTORY ---
async function awardPoints(userId, amount, reason, customMessage = '') {
    try {
        if (amount === 0) return; // Ignore 0 point transactions
        
        // 1. Update the user's total points
        await User.findByIdAndUpdate(userId, { $inc: { forumPoints: amount } });
        
        // 2. Log the transaction in the history ledger
        await new PointHistory({
            user: userId,
            amount: amount,
            reason: reason,
            customMessage: customMessage
        }).save();
        
    } catch (err) {
        console.error("Error awarding points:", err);
    }
}

// --- NEW HELPER: GENERATE REFERRAL CODE ---
const generateReferralCode = async (username) => {
    // Create a base code from the username (alphanumeric only, uppercase, max 6 chars)
    let baseCode = username.replace(/[^a-zA-Z0-9]/g, '').substring(0, 6).toUpperCase();
    if (baseCode.length < 3) baseCode = 'GPL' + Math.floor(Math.random() * 999);
    
    let code = baseCode + Math.floor(1000 + Math.random() * 9000); // e.g., NOOB1234
    
    // Ensure uniqueness
    while (await User.findOne({ referralCode: code })) {
        code = baseCode + Math.floor(1000 + Math.random() * 9000);
    }
    return code;
};

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
// --- NEW: ANTI-TEMP MAIL CHECKER ---
/**
 * Checks if an email address is from a known disposable/temporary domain.
 * @param {string} email - The email address to check.
 * @returns {Promise<boolean>} - True if the email is disposable, False if it is safe.
 */
async function isDisposableEmail(email) {
    try {
        // Extract the domain from the email address
        const domain = email.split('@')[1];
        if (!domain) return true; // Invalid email format

        // We use a fast, free, open-source API for disposable domain checking.
        // It returns JSON. If 'disposable' is true, it's a temp mail.
        const response = await axios.get(`https://open.kickbox.com/v1/disposable/${domain}`);
        
        // If the API confirms it is disposable, return true
        if (response.data && response.data.disposable) {
            return true;
        }

        // If it's not listed as disposable, consider it safe
        return false;
    } catch (error) {
        console.error("Temp Mail Checker API Error:", error.message);
        // If the API fails, we fail OPEN (allow the registration) to prevent blocking 
        // legitimate users just because a third-party service is temporarily down.
        // You could also maintain a hardcoded fallback list of domains here.
        return false; 
    }
}
// --- NEW HELPER: Generate 2FA Recovery Codes ---
// Generates an array of 8 random, 8-character alphanumeric codes
function generateRecoveryCodes() {
    const codes = [];
    for (let i = 0; i < 8; i++) {
        codes.push(crypto.randomBytes(4).toString('hex')); 
    }
    return codes;
}
// ===============================
// INDEXNOW SEO PROTOCOL HELPER
// ===============================
const indexNowKey = process.env.INDEXNOW_KEY || 'gplmods-indexnow-key-2026-secure';

// 1. Verification Route: Search engines check this to verify ownership
app.get(`/${indexNowKey}.txt`, (req, res) => {
    res.type('text/plain');
    res.send(indexNowKey);
});

// 2. The Pinger Function
async function notifyIndexNow(urlList) {
    if (!urlList || urlList.length === 0) return;

    // Ensure we only send an array
    const urls = Array.isArray(urlList) ? urlList :[urlList];
    const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
    const host = new URL(baseUrl).hostname; // Extracts just the domain (e.g., gplmods.webredirect.org)

    try {
        console.log(`Pinging IndexNow with ${urls.length} URLs...`);
        const response = await axios.post('https://api.indexnow.org/indexnow', {
            host: host,
            key: indexNowKey,
            keyLocation: `${baseUrl}/${indexNowKey}.txt`,
            urlList: urls
        }, {
            headers: { 'Content-Type': 'application/json; charset=utf-8' }
        });
        
        console.log(`IndexNow Ping Successful! Status: ${response.status}`);
    } catch (error) {
        console.error("IndexNow Ping Failed:", error.response ? error.response.data : error.message);
    }
}
// ===============================
// GOOGLE INDEXING API HELPER
// ===============================
const { google } = require('googleapis');

let jwtClient = null;

try {
    // 1. Read the Base64 string from the environment variable
    if (process.env.GOOGLE_CREDENTIALS_BASE64) {
        
        // 2. Decode the Base64 string back into perfectly formatted JSON text
        const jsonString = Buffer.from(process.env.GOOGLE_CREDENTIALS_BASE64, 'base64').toString('utf-8');
        
        // 3. Parse the clean JSON
        const credentials = JSON.parse(jsonString);
        
        // 4. Setup the JWT authentication client (Official Google Method)
        jwtClient = new google.auth.JWT(
            credentials.client_email,
            null,
            credentials.private_key,['https://www.googleapis.com/auth/indexing'] // Official scope required by the docs
        );
        console.log("[Google Indexing] Credentials successfully decoded and loaded!");
    } else {
        console.warn("[Google Indexing] GOOGLE_CREDENTIALS_BASE64 not found. Google sync skipped.");
    }
} catch (e) {
    console.error("[Google Indexing Error] Failed to decode or parse Base64 credentials.", e.message);
}

/**
 * Pings Google Indexing API to update or remove a URL
 * @param {string} url - The URL to index
 * @param {string} type - 'URL_UPDATED' or 'URL_DELETED'
 */
async function notifyGoogle(url, type = 'URL_UPDATED') {
    if (!jwtClient) {
        console.error(`[Google Error] Skipped ${url}: Missing credentials.`);
        return;
    }

    try {
        await jwtClient.authorize();
        
        // Official API call per Google documentation
        const response = await google.indexing('v3').urlNotifications.publish({
            auth: jwtClient,
            requestBody: {
                url: url,
                type: type 
            }
        });
        console.log(`[Google] Successfully pinged: ${url}`);
    } catch (error) {
        // If Google rejects it (e.g., quota exceeded, domain not verified in Search Console)
        console.error(`[Google Error] Failed for ${url}:`, error.response ? error.response.data : error.message);
        throw error; // Throw the error so the bulk sync loop can count it as a failure
    }
}
// --- NEW GLOBAL DELETE HELPER ---
const deleteCloudFile = async (fileKey) => {
    if (!fileKey || fileKey === 'external-link') return;
    try {
        // 1. Delete from Primary Cloud
        await s3Client.send(new DeleteObjectCommand({ 
            Bucket: process.env.B2_BUCKET_NAME, 
            Key: fileKey 
        }));
        console.log(`Deleted ${fileKey} from B2.`);
        
        // 2. Delete from Backup Cloud
        deleteFromFTP(fileKey).catch(e => console.error("Background FTP delete failed", e));
        
    } catch (error) {
        console.error(`Failed to delete ${fileKey} from B2:`, error.message);
    }
};
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
app.use(cookieParser());

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
// --- NEW: KICKED OUT SESSION MIDDLEWARE ---
// If the user's session has been flagged by a new login, log them out instantly!
app.use(async (req, res, next) => {
    // Check in-memory flag first
    if (req.session && req.session.kickedOut) {
        req.logout((err) => {
            req.session.destroy(() => {
                res.clearCookie('connect.sid', { path: '/' });
                return res.redirect('/login?error=' + encodeURIComponent('Your session got expired because you logged in from another device. Please relogin again.'));
            });
        });
        return;
    }
    
    // Also check MongoDB directly in case the flag was just set by another login
    if (req.sessionID) {
        try {
            const sessionsCollection = mongoose.connection.collection('sessions');
            const sessionDoc = await sessionsCollection.findOne({ _id: req.sessionID });
            if (sessionDoc && sessionDoc.kickedOut) {
                console.log(`[Session] Detected kickedOut flag in MongoDB for session ${req.sessionID}`);
                req.logout((err) => {
                    req.session.destroy(() => {
                        res.clearCookie('connect.sid', { path: '/' });
                        return res.redirect('/login?error=' + encodeURIComponent('Your session got expired because you logged in from another device. Please relogin again.'));
                    });
                });
                return;
            }
        } catch (err) {
            console.error(`[Session] Error checking kickedOut flag: ${err.message}`);
        }
    }
    
    next();
});

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

// =========================================================
// CRITICAL FIX: ISOLATED REQUEST GLOBALS & CACHE
// =========================================================

let cachedTotalUpdates = 0;
let cachedNewUploads = 0;
let cachedNewUpdates = 0;
let lastUpdateCheck = 0;

app.use(async (req, res, next) => {
    try {
        // 1. ======== BASIC LOCALS & HELPERS ========
        res.locals.user = req.user || null;
        res.locals.timeAgo = timeAgo;
        res.locals.formatCompactNumber = formatCompactNumber;
        res.locals.formatBytes = formatBytes;
        res.locals.slugify = slugify;
        res.locals.cdnUrl = process.env.CDN_URL || ''; 
        // Make sure truncateText is defined as a helper function elsewhere in your server.js!
        res.locals.truncateText = typeof truncateText === 'function' ? truncateText : (str, len) => str.length > len ? str.substring(0, len) + '...' : str;
        res.locals.baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org'; 

        // 2. ======== CRAWLER DETECTION LOGIC ========
        // Safely grab the User-Agent header (fallback to empty string if undefined)
        const userAgent = req.get('User-Agent') || '';
        const isCrawler = isbot(userAgent);
        res.locals.isCrawler = isCrawler;

        // 3. ======== AD DELIVERY & MODAL LOGIC ========
        let shouldShowAds = true; 
        let shouldShowModals = true; 

        // If it's a bot (Google, Discord, etc.), turn OFF ads and modals for perfect SEO
        if (isCrawler) {
            shouldShowAds = false;
            shouldShowModals = false;
        } else if (req.isAuthenticated() && req.user) {
            // If real user, check privileges
            const role = req.user.role;
            const membership = req.user.membership;
            if (role === 'admin' || role === 'distributor' || membership === 'premium') {
                shouldShowAds = false; 
            }
        }
        res.locals.showAds = shouldShowAds;
        res.locals.showModals = shouldShowModals;

        // 4. ======== LINKVERTISE & AD MONETIZATION ========
        let linkvId = process.env.LINKVERTISE_ID || '5373913'; 
        let adBaseUrl = null;
        res.locals.linkvertiseEnabled = false;

        // Safely pull from SiteState if you created that feature
        if (typeof cachedSiteState !== 'undefined' && cachedSiteState) {
            res.locals.linkvertiseEnabled = cachedSiteState.enableLinkvertise || false;
            if (cachedSiteState.linkvertiseId) linkvId = cachedSiteState.linkvertiseId;
            if (cachedSiteState.adNetworkBaseUrl) adBaseUrl = cachedSiteState.adNetworkBaseUrl;
        }
        res.locals.linkvertiseId = linkvId;

        res.locals.generateAdLink = (targetUrl) => {
            if (!targetUrl) return '';
            
            const encodedUri = encodeURI(targetUrl);
            const base64Str = Buffer.from(encodedUri, "binary").toString("base64");
            
            if (adBaseUrl && !adBaseUrl.includes('link-to.net')) {
                 return adBaseUrl.replace('{{ID}}', linkvId).replace('{{URL}}', base64Str);
            }

            // Fix: Math.random() converted to an integer using Math.floor
            const randomNum = Math.floor(Math.random() * 1000);
            return `https://link-to.net/${linkvId}/${randomNum}/dynamic?r=${base64Str}`;
        };

        // 5. ======== NOTIFICATIONS LOGIC (CACHED) ========
        if (Date.now() - lastUpdateCheck > 5 * 60 * 1000) {
            const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
            
            cachedTotalUpdates = await Announcement.countDocuments();
            cachedNewUploads = await File.countDocuments({ status: 'live', isLatestVersion: true, createdAt: { $gte: oneDayAgo } });
            cachedNewUpdates = await File.countDocuments({ status: 'live', isLatestVersion: true, updatedAt: { $gte: oneDayAgo } });
            
            lastUpdateCheck = Date.now();
        }
        res.locals.totalUpdatesCount = cachedTotalUpdates;
        res.locals.newUploadsCount = cachedNewUploads;
        res.locals.newUpdatesCount = cachedNewUpdates;

        let unreadPersonalCount = 0;
        if (req.isAuthenticated() && req.user) {
            const UserNotification = require('./models/userNotification');
            unreadPersonalCount = await UserNotification.countDocuments({ user: req.user._id, isRead: false });
        }
        res.locals.unreadPersonalCount = unreadPersonalCount;
        
        next(); 
        
    } catch (e) {
        console.error("Global Middleware Error:", e);
        
        // Fallbacks: If the DB crashes, the EJS templates still get data so the site doesn't crash completely!
        res.locals.totalUpdatesCount = cachedTotalUpdates || 0;
        res.locals.newUploadsCount = cachedNewUploads || 0;
        res.locals.newUpdatesCount = cachedNewUpdates || 0;
        res.locals.unreadPersonalCount = 0;
        res.locals.showAds = false;
        res.locals.showModals = false;
        res.locals.generateAdLink = (url) => url; // Return normal url if Ad Generator fails
        
        next(); 
    }
});
// =========================================================
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
    
    // Use the universal error template
    res.status(403).render('pages/error', {
        errorCode: '403',
        errorTitle: 'Access <span>Denied</span>',
        errorMessage: 'You do not have the necessary permissions to view this page.'
    });
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
// 1 PASSPORT STRATEGIES & MULTER
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
            let requestedName = googleUserData.username; // Or githubUserData / microsoftUserData
            
            // ======== SANITIZE SOCIAL NAME ========
            // Strip out anything that isn't a letter, number, or space
            requestedName = requestedName.replace(/[^a-zA-Z0-9 ]/g, '').trim();
            // If the name was 100% emojis, it will now be empty. Give a fallback name:
            if (!requestedName || requestedName.length === 0) {
                requestedName = 'Member';
            }
            // ======================================

            // If their social name is reserved, give them a generic safe name
            if (isNameReserved(requestedName)) {
                requestedName = 'Member'; 
            }

            // Generate the unique # number
            const uniqueUsername = await generateUniqueUsername(requestedName);
            googleUserData.username = uniqueUsername; // Update the data object before creating
            googleUserData.referralCode = await generateReferralCode(uniqueUsername);

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
            let requestedName = githubUserData.username; // Or githubUserData / microsoftUserData
            
            // ======== SANITIZE SOCIAL NAME ========
            // Strip out anything that isn't a letter, number, or space
            requestedName = requestedName.replace(/[^a-zA-Z0-9 ]/g, '').trim();
            // If the name was 100% emojis, it will now be empty. Give a fallback name:
            if (!requestedName || requestedName.length === 0) {
                requestedName = 'Member';
            }
            // ======================================

            // If their social name is reserved, give them a generic safe name
            if (isNameReserved(requestedName)) {
                requestedName = 'Member'; 
            }

            // Generate the unique # number
            const uniqueUsername = await generateUniqueUsername(requestedName);
            githubUserData.username = uniqueUsername; // Update the data object before creating
            githubUserData.referralCode = await generateReferralCode(uniqueUsername);

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
            let requestedName = microsoftUserData.username; // Or githubUserData / microsoftUserData
            
            // ======== SANITIZE SOCIAL NAME ========
            // Strip out anything that isn't a letter, number, or space
            requestedName = requestedName.replace(/[^a-zA-Z0-9 ]/g, '').trim();
            // If the name was 100% emojis, it will now be empty. Give a fallback name:
            if (!requestedName || requestedName.length === 0) {
                requestedName = 'Member';
            }
            // ======================================

            // If their social name is reserved, give them a generic safe name
            if (isNameReserved(requestedName)) {
                requestedName = 'Member'; 
            }
            // Generate the unique # number
            const uniqueUsername = await generateUniqueUsername(requestedName);
            microsoftUserData.username = uniqueUsername; // Update the data object before creating
            microsoftUserData.referralCode = await generateReferralCode(uniqueUsername);

            user = await User.create(microsoftUserData);
            done(null, user);
        }
    } catch (err) { done(err, null); }
}));

// ===============================
// 1.5. PUBLIC & DIAGNOSTIC ROUTES
// ===============================

// --- ADVANCED DIAGNOSTIC CONSOLE (Admin Only) ---
app.get('/status', ensureAuthenticated, ensureAdmin, async (req, res) => {
    
        // 1. Gather Basic Server Info
    const memUsage = process.memoryUsage();
    const totalMem = os.totalmem();
    
    const healthData = {
        status: 'UP',
        timestamp: new Date().toISOString(),
        uptime: formatUptime(process.uptime()),
        nodeVersion: process.version,
        // ✅ NEW: Detailed Memory Metrics
        memoryUsage: {
            rss: memUsage.rss,             // Total RAM allocated
            heapTotal: memUsage.heapTotal, // V8 engine memory
            heapUsed: memUsage.heapUsed,   // Actual active JS objects
            systemTotal: totalMem,         // Server total RAM
            percentage: ((memUsage.rss / totalMem) * 100).toFixed(2) + '%'
        },
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
    res.render('pages/admin/status', { health: healthData });
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
        // --- NEW: Fetch Editor's Choice Mods for Homepage ---
        const editorsChoiceModsRaw = await File.find({ ...findQuery, isEditorsChoice: true }).sort({ updatedAt: -1 }).limit(10);
        
        // Process URLs for Editor's Choice
        const editorsChoiceMods = await Promise.all(editorsChoiceModsRaw.map(async (file) => {
            const iconKey = file.iconUrl || file.iconKey;
            let signedIconUrl = '/images/default-app-icon.png';
            if (iconKey) {
                try { signedIconUrl = await getSmartImageUrl(iconKey); } catch (e) {}
            }
            return { ...file.toObject(), iconUrl: signedIconUrl };
        }));
        // ---------------------------------------------------
        const categories = ['android', 'ios-jailed', 'ios-jailbroken', 'wordpress', 'windows'];
        const filesByCategory = {};

                await Promise.all(categories.map(async (cat) => {
            // ✅ OPTIMIZATION: Added .lean() to prevent memory spikes on homepage load
            const workingMods = await File.find({ category: cat, ...findQuery }).sort({ averageRating: -1, downloads: -1 }).limit(4).lean();
            const popularMods = await File.find({ category: cat, ...findQuery }).sort({ downloads: -1 }).limit(4).lean();
            const newUpdates = await File.find({ category: cat, ...findQuery }).sort({ createdAt: -1 }).limit(4).lean();
            
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
                        return { ...file, iconUrl: signedIconUrl };
                    })
                );
            }
        }
        res.render('pages/index', { filesByCategory, editorsChoiceMods });
    } catch (error) {
        console.error("Error fetching files for homepage:", error);
        return next(error);
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
// 2 NOTIFICATION SYSTEM ROUTES
// ===================================
// 1. The Notification Hub (Category Selection)
app.get('/notifications', async (req, res) => {
    try {
        let followingCount = 0;

        // If the user is logged in, calculate their personalized "Following" updates
        if (req.isAuthenticated() && req.user) {
            const userWithFollowing = await User.findById(req.user._id).populate('following', 'username');
            if (userWithFollowing && userWithFollowing.following && userWithFollowing.following.length > 0) {
                const followedUsernames = userWithFollowing.following.map(u => u.username);
                const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
                
                followingCount = await File.countDocuments({
                    uploader: { $in: followedUsernames },
                    status: 'live',
                    isLatestVersion: true,
                    updatedAt: { $gte: oneDayAgo }
                });
            }
        }

        res.render('pages/notifications-hub', {
            // Unread Personal and Global Counts are already provided by res.locals
            followingCount: followingCount
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
        return next(error); 
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
        return next(error);
    }
});
// --- NEW: 24-Hour "New Uploads" Feed ---
app.get('/notifications/new-uploads', async (req, res) => {
    try {
        // 1. Calculate the timestamp for 24 hours ago
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

        // ✅ RAM OPTIMIZATION: Added .lean()
        const recentUploads = await File.find({
            createdAt: { $gte: oneDayAgo },
            status: 'live',
            isLatestVersion: true
        })
        .sort({ createdAt: -1 })
        .lean(); 
           

        // 3. Get signed URLs for the icons (using our smart helper)
        const uploadsWithUrls = await Promise.all(recentUploads.map(async (file) => {
            const iconKey = file.iconUrl || file.iconKey;
            const iconUrl = await getSmartImageUrl(iconKey);
            return { ...file, iconUrl };
        }));

        res.render('pages/feed-new-uploads', { files: uploadsWithUrls });

    } catch (error) {
        console.error("Error fetching new uploads feed:", error);
        return next(error);
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
        })        
        .sort({ updatedAt: -1 })
        .lean();  

        // 2. Get signed URLs for the icons
        const updatesWithUrls = await Promise.all(recentUpdates.map(async (file) => {
            const iconKey = file.iconUrl || file.iconKey;
            const iconUrl = await getSmartImageUrl(iconKey);
            return { ...file, iconUrl };
        }));

        res.render('pages/feed-new-updates', { files: updatesWithUrls });

    } catch (error) {
        console.error("Error fetching new updates feed:", error);
        return next(error);
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
        .limit(50) // Reasonable limit for a feed
        .lean();

        // 4. Get signed URLs for the icons (using our smart helper)
        const modsWithUrls = await Promise.all(followingMods.map(async (file) => {
            const iconKey = file.iconUrl || file.iconKey;
            const iconUrl = await getSmartImageUrl(iconKey);
            return { ...file, iconUrl };
        }));

        res.render('pages/feed-following', { files: modsWithUrls });

    } catch (error) {
        console.error("Error fetching following feed:", error);
        return next(error);
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
        // --- NEW: Fetch Editor's Choice Mods for this specific platform ---
        let editorQuery = { isLatestVersion: true, status: 'live', isEditorsChoice: true };
        if (platform && platform !== 'all') {
            editorQuery.category = platform;
        }
        
        const editorsChoiceModsRaw = await File.find(editorQuery).sort({ updatedAt: -1 }).limit(10);
        
        // Process URLs
        const editorsChoiceMods = await Promise.all(editorsChoiceModsRaw.map(async (file) => {
            const iconKey = file.iconUrl || file.iconKey;
            let signedIconUrl = '/images/icon.png';
            if (iconKey) {
                try { signedIconUrl = await getSmartImageUrl(iconKey); } catch (e) {}
            }
            return { ...file.toObject(), iconUrl: signedIconUrl };
        }));
        // -----------------------------------------------------------------

        // 4. Pagination & Fetching
        const totalMods = await File.countDocuments(queryFilter);
        const totalPages = Math.ceil(totalMods / limit);
        const files = await File.find(queryFilter)
            .sort(sortOptions)
            .skip((currentPage - 1) * limit)
            .limit(limit)
            .lean();

        // 5. Get Signed URLs for images
                const filesWithUrls = await Promise.all(files.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            const iconUrl = key ? await getSmartImageUrl(key) : '/images/default-app-icon.png';
            return { ...file, iconUrl }; // No need for toObject() when using .lean()
        }));

        res.render('pages/category', {
            files: filesWithUrls,
            totalPages: totalPages,
            editorsChoiceMods: editorsChoiceMods,
            currentPage: currentPage,
            
            // Pass the current filters back to the frontend so the dropdowns stay selected
            currentPlatform: platform || 'all', 
            currentSubCategory: subCategory || 'all', // NEW
            currentSort: sort || 'latest'
        });

    } catch (error) { 
        console.error("Category Route Error:", error);
        return next(error); 
    }
});

// ===================================
// SEARCH ROUTE
// ===================================

// ✅ FIX: Removed \s so it completely ignores spaces!
const escapeRegex = (text) => text.replace(/[-[\]{}()*+?.,\\^$|#]/g, "\\$&");

app.get('/search', async (req, res, next) => {
    try {
        const rawQuery = req.query.q || '';
        const query = escapeRegex(rawQuery); // We use this strictly for the DB search
        
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

        // 2. Filter by Sub-Category
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
            .limit(resultsPerPage)
            .lean();

        const resultsWithUrls = await Promise.all(searchResults.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            let signedIconUrl = '/images/default-app-icon.png'; 
            if (key) {
                try {
                    signedIconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 });
                } catch (urlError) {}
            }
            return { ...file, iconUrl: signedIconUrl };
        }));

        // Search for Users
        const userResultsRaw = await User.find({
            username: { $regex: query, $options: 'i' }
        })
        .select('username role profileImageKey followers following lastSeen')
        .limit(4);

        const usersWithAvatars = await Promise.all(userResultsRaw.map(async (u) => {
            let avatarUrl = '/images/default-avatar.png';
            if (u.profileImageKey) {
                try { avatarUrl = await getSmartImageUrl(u.profileImageKey); } catch (e) {}
            }
            return { ...u.toObject(), signedAvatarUrl: avatarUrl };
        }));

        const processedUsers = usersWithAvatars.map(u => {
            let isFollowing = false;
            if (req.user && req.user.following) {
                isFollowing = req.user.following.includes(u._id.toString());
            }
            return { ...u, isFollowing };
        });

        // --- RENDER THE PAGE ---
        res.render('pages/search', {
            results: resultsWithUrls, 
            userResults: processedUsers, 
            query: rawQuery, // <--- ✅ FIX: We pass rawQuery back to the EJS template so it shows perfectly normal spaces!
            totalResults: totalResults,
            totalPages: totalPages,
            currentPage: page,
            currentPlatform: platform,
            currentSubCategory: subCategory, 
            currentSort: sort
        });

    } catch (error) {
        console.error("Search Error:", error);
        return next(error);
    }
});
// ===================================
// COMMUNITY FORUM ROUTES (PHASE 3)
// ===================================
const Issue = require('./models/issue');
const Reply = require('./models/reply');

// 1. Forum Hub (View all issues with search/filter)
app.get('/community', async (req, res) => {
    try {
        const { category, status, sort, q, page = 1 } = req.query;
        const limit = 15;
        
        let queryFilter = {};
        if (category && category !== 'all') queryFilter.category = category;
        if (status && status !== 'all') queryFilter.status = status;
        if (q) queryFilter.title = { $regex: q, $options: 'i' };

        let sortOptions = { createdAt: -1 }; // Default: Newest
        if (sort === 'views') sortOptions = { views: -1 };
        if (sort === 'oldest') sortOptions = { createdAt: 1 };

        const totalIssues = await Issue.countDocuments(queryFilter);
        const totalPages = Math.ceil(totalIssues / limit);

        const issues = await Issue.find(queryFilter)
            .populate('author', 'username profileImageKey role forumPoints') // Populate author details
            .sort(sortOptions)
            .skip((page - 1) * limit)
            .limit(limit);

        // Get reply counts for each issue
        const issuesWithCounts = await Promise.all(issues.map(async (issue) => {
            const replyCount = await Reply.countDocuments({ issue: issue._id });
            const authorObj = issue.author ? issue.author.toObject() : { username: 'Deleted User', forumRank: { color: 'var(--silver)' } };
            // Ensure avatar URL is attached safely
            if (issue.author && issue.author.profileImageKey) {
                authorObj.signedAvatarUrl = await getSmartImageUrl(issue.author.profileImageKey);
            } else {
                authorObj.signedAvatarUrl = '/images/default-avatar.png';
            }
            return { ...issue.toObject(), author: authorObj, replyCount };
        }));

        res.render('pages/forum-index', {
            issues: issuesWithCounts,
            totalPages,
            currentPage: parseInt(page),
            currentCategory: category || 'all',
            currentStatus: status || 'all',
            currentSort: sort || 'newest',
            searchQuery: q || ''
        });

    } catch (error) {
        console.error("Forum Index Error:", error);
        res.status(500).render('pages/500');
    }
});

// 2. GET: Ask a Question Page
app.get('/community/ask', ensureAuthenticated, (req, res) => {
    res.render('pages/forum-ask');
});

// 3. POST: Submit a Question
app.post('/community/ask', ensureAuthenticated, async (req, res) => {
    try {
        const { title, category, content } = req.body;
        if (!title || !category || !content) return res.redirect('/community/ask?error=All fields are required.');

        // Generate a unique slug: slugify title + random 5 char string
        const baseSlug = slugify(title);
        const uniqueSlug = `${baseSlug}-${Math.random().toString(36).substr(2, 5)}`;

        const newIssue = new Issue({
            title,
            slug: uniqueSlug,
            content,
            author: req.user._id,
            category
        });

        await newIssue.save();
        
        // Award 5 points for asking a question
        await User.adjustForumPoints(req.user._id, 5, "Asked a community question");

        res.redirect(`/community/${uniqueSlug}`);
    } catch (error) {
        console.error("Ask Issue Error:", error);
        res.status(500).render('pages/500');
    }
});

// 4. GET: View a Single Issue Thread
app.get('/community/:slug', async (req, res) => {
    try {
        const issue = await Issue.findOneAndUpdate(
            { slug: req.params.slug },
            { $inc: { views: 1 } }, // Automatically increment views!
            { new: true }
        ).populate('author', 'username profileImageKey role forumPoints');

        if (!issue) return res.status(404).render('pages/404');

        // Fetch Author Avatar
        const issueAuthor = issue.author ? issue.author.toObject() : { username: 'Deleted User' };
        issueAuthor.signedAvatarUrl = issue.author?.profileImageKey ? await getSmartImageUrl(issue.author.profileImageKey) : '/images/default-avatar.png';

        // Fetch Replies
        const rawReplies = await Reply.find({ issue: issue._id })
            .populate('author', 'username profileImageKey role forumPoints')
            .sort({ isSolution: -1, createdAt: 1 }); // Solutions float to the top!

        const replies = await Promise.all(rawReplies.map(async (reply) => {
            const repAuth = reply.author ? reply.author.toObject() : { username: 'Deleted User' };
            repAuth.signedAvatarUrl = reply.author?.profileImageKey ? await getSmartImageUrl(reply.author.profileImageKey) : '/images/default-avatar.png';
            return { ...reply.toObject(), author: repAuth };
        }));

        res.render('pages/forum-issue', {
            issue: { ...issue.toObject(), author: issueAuthor },
            replies
        });
    } catch (error) {
        console.error("View Issue Error:", error);
        res.status(500).render('pages/500');
    }
});

// 5. POST: Reply to an Issue
app.post('/community/:slug/reply', ensureAuthenticated, async (req, res) => {
    try {
        const issue = await Issue.findOne({ slug: req.params.slug });
        if (!issue || issue.status === 'closed') return res.redirect('/community');

        const newReply = new Reply({
            issue: issue._id,
            author: req.user._id,
            content: req.body.content,
            isAdminReply: req.user.role === 'admin'
        });

        await newReply.save();

        // Award 2 points for helping by replying
        await User.adjustForumPoints(req.user._id, 2, "Helped a user with a reply");

        res.redirect(`/community/${issue.slug}`);
    } catch (error) {
        console.error("Reply Error:", error);
        res.status(500).render('pages/500');
    }
});

// 6. POST: Mark Reply as Solution (Author or Admin only)
app.post('/community/:slug/resolve/:replyId', ensureAuthenticated, async (req, res) => {
    try {
        const issue = await Issue.findOne({ slug: req.params.slug });
        const reply = await Reply.findById(req.params.replyId);

        if (!issue || !reply) return res.status(404).send("Not found");

        // Verify permissions (Must be Author of the issue or an Admin)
        const isAuthor = issue.author.toString() === req.user._id.toString();
        const isAdmin = req.user.role === 'admin';

        if (!isAuthor && !isAdmin) return res.status(403).render('pages/403');

        // Mark Reply as solution
        reply.isSolution = true;
        await reply.save();

        // Mark Issue as resolved
        issue.status = 'resolved';
        await issue.save();

        // ==== GAMIFICATION: Massive 25 Point Reward for the Solution Provider! ====
        if (reply.author.toString() !== req.user._id.toString()) { // Don't reward if solving own issue
            await User.adjustForumPoints(reply.author, 25, "Provided an Accepted Solution!");
        }

        res.redirect(`/community/${issue.slug}`);
    } catch (error) {
        console.error("Resolve Error:", error);
        res.status(500).render('pages/500');
    }
});

// ==========================================
// LEGACY MOD PAGE ROUTE (REDIRECT ONLY)
// ==========================================
// This catches any old /mods/12345 links and instantly forwards them 
// to the new SEO-friendly slug route! No other logic is needed here.
app.get('/mods/:id', async (req, res, next) => {
    try {
        const file = await File.findById(req.params.id);
        if (!file) return next(); // If it really doesn't exist, proceed to 404
        
        // Redirect to the new format: /android/roblox
        return res.redirect(301, `/${file.category}/${file.slug || file._id}`);
    } catch (error) {
        return next();
    }
});

// ==========================================
// ADVANCED: SEO-Friendly "Umbrella" Mod Page Route
// ==========================================
app.get('/:category/:slug', async (req, res, next) => {
    try {
        const category = req.params.category.toLowerCase();
        const slug = req.params.slug.toLowerCase();
        const variantId = req.query.variant;

        // 1. Prevent this route from capturing system URLs
        const reservedPaths = [
            'api', 'admin', 'auth', 'css', 'js', 'images', 'audio', 'animations', 
            'mods', 'users', 'category', 'search', 'updates', 'profile', 'my-uploads', 
            'developer', 'support', 'donate', 'partnership', 'home', 'healthz', 
            'download-file', 'upload-details', 'reset-password', 'docs'
        ];
        
        if (reservedPaths.includes(category)) return next();

        let masterFile = null;

        // 2. PRIMARY SEARCH: Try to find by exact slug
        masterFile = await File.findOne({ 
            category: category, 
            slug: slug,
            isLatestVersion: true,
            isVariant: { $ne: true } 
        }).populate('variants');

        // 3. FALLBACK SEARCH: If exact slug fails, use RegEx on the name field
        if (!masterFile) {
            const nameSearchPattern = new RegExp(`^${slug.replace(/-/g, '[-\\s]+')}$`, 'i');
            masterFile = await File.findOne({
                category: category,
                name: nameSearchPattern,
                isLatestVersion: true,
                isVariant: { $ne: true } 
            }).populate('variants');
        }

        // 4. If STILL not found, throw 404
        if (!masterFile) {
            return next(); 
        }

        // --- Security Check for Drafts/Pending ---
        if (masterFile.status !== 'live') {
            const isUploader = req.user && req.user.username === masterFile.uploader;
            const isAdmin = req.user && req.user.role === 'admin';
            if (!isUploader && !isAdmin) return res.status(403).render('pages/403'); 
        }

        let displayFile = masterFile; 
        let isViewingVariant = false;

        // --- VARIANT HANDLING ---
        if (variantId && Types.ObjectId.isValid(variantId)) {
            const requestedVariant = masterFile.variants.find(v => v._id.toString() === variantId && v.status === 'live');
            if (requestedVariant) {
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

        // ==========================================
        // ✅ BUG 1 & 2 FIXED: VIEW TRACKING MOVED HERE
        // ==========================================
        let shouldIncrementView = false;
        // We use masterFile._id so all variants share the same view count pool
        const trackingId = masterFile._id.toString(); 

        if (req.isAuthenticated()) {
            if (!masterFile.viewedBy.includes(req.user._id)) {
                shouldIncrementView = true;
                masterFile.viewedBy.push(req.user._id);
            }
        } else {
            const cookieName = `viewed_mod_${trackingId}`;
            if (!req.cookies[cookieName]) {
                shouldIncrementView = true;
                res.cookie(cookieName, 'true', { maxAge: 30 * 60 * 1000, httpOnly: true });
            }
        }

        if (shouldIncrementView) {
            masterFile.views += 1;
            // Since we updated masterFile, we must save it
            await masterFile.save();
            
            // If we are viewing a variant, ensure the view count displays correctly on the page right now
            if (isViewingVariant) {
                displayFile.views = masterFile.views;
            }
        }
        // ==========================================


        // --- IMAGE HANDLING ---
        const iconKey = masterFile.iconUrl || masterFile.iconKey;
        const iconUrl = await getSmartImageUrl(iconKey);
        
        const screenKeys = (masterFile.screenshotUrls && masterFile.screenshotUrls.length > 0)
            ? masterFile.screenshotUrls : (masterFile.screenshotKeys || []);
        const screenshotUrls = await Promise.all(screenKeys.map(key => getSmartImageUrl(key)));

        // --- REVIEWS HANDLING ---
        const reviews = await Review.find({ file: displayFile._id }).sort({ createdAt: -1 }).populate('user', 'profileImageKey'); 
        
        let reviewsWithAvatars = await Promise.all(reviews.map(async (review) => {
            let avatarUrl = '/images/default-avatar.png';
            if (review.user && review.user.profileImageKey) {
                try { avatarUrl = await getSmartImageUrl(review.user.profileImageKey); } catch (e) {}
            }
            return { ...review.toObject(), user: { ...review.user.toObject(), signedAvatarUrl: avatarUrl } };
        }));

        // ✅ BUG 3 FIXED: SORT REVIEWS *AFTER* MAPPING
        if (req.user) {
            reviewsWithAvatars.sort((a, b) => {
                const isA = a.user._id.toString() === req.user._id.toString();
                const isB = b.user._id.toString() === req.user._id.toString();
                if (isA && !isB) return -1; // Push A to top
                if (!isA && isB) return 1;  // Push B to top
                return 0; 
            });
        }
        // ----------------------------------------------------

        let versionHistory = [];
        let fileForHistory = await File.findById(displayFile._id).populate('olderVersions');
        if (fileForHistory) {
            versionHistory = [fileForHistory, ...fileForHistory.olderVersions.slice().reverse()];
        }

        // --- USER INTERACTIONS ---
        const userHasWhitelisted = req.user ? req.user.whitelist.includes(displayFile._id) : false;
        
        let userVotedWorking = false;
        let userVotedNotWorking = false;
        if (req.user) {
            // Check displayFile instead of currentFile to support variant voting
            userVotedWorking = (displayFile.votedWorkingBy || []).includes(req.user._id);
            userVotedNotWorking = (displayFile.votedNotWorkingBy || []).includes(req.user._id);
        }

        // --- UPLOADER ROLE CHECK ---
        let isUploaderDistributor = false;
        const uploaderUser = await User.findOne({ username: displayFile.uploader }).lean();
        
        if (uploaderUser && uploaderUser.role === 'distributor') {
            isUploaderDistributor = true;
        }

        // --- RENDER ---
        res.render('pages/download', {
            file: { ...(displayFile.toObject ? displayFile.toObject() : displayFile), iconUrl, screenshotUrls },
            masterFile: masterFile,
            isViewingVariant: isViewingVariant,
            versionHistory,
            reviews: reviewsWithAvatars,
            userHasWhitelisted,
            userVotedWorking,
            userVotedNotWorking,
            isUploaderDistributor
        });

    } catch (e) {
        console.error("Error on /:category/:slug route:", e);
        return next(e); 
    }
});
// ===================================
// FRONTEND REPOSITORY HUB ROUTES 
// (The visual pages users click buttons on)
// ===================================

function getBaseUrl(req) {
    if (process.env.BASE_URL) {
        return process.env.BASE_URL.replace(/\/*$/, '');
    }
    const forwardedProto = req.headers['x-forwarded-proto'];
    const protocol = forwardedProto ? forwardedProto.split(',')[0].trim() : req.protocol;
    const host = req.get('host');
    return `${protocol}://${host}`.replace(/\/*$/, '');
}

const REPO_BASE_URL = process.env.BASE_URL ? process.env.BASE_URL.replace(/\/*$/, '') : null;
function getRepoBaseUrl(req) {
    return REPO_BASE_URL || getBaseUrl(req);
}

// --- 1. Jailbreak Repo Hub Route ---
app.get('/jailbreak-repos', async (req, res) => {
    try {
        // Fetch all live Jailbreak tweaks
        const jbMods = await File.find({ 
            category: 'ios-jailbroken', 
            status: 'live', 
            isLatestVersion: true,
            showInRepo: { $ne: false } // Only show mods allowed in repo
        }).sort({ createdAt: -1 });

        // Filter them into their specific architecture buckets
        const rootless = [];
        const rootful = [];
        const roothide =[];
        const other =[];

        for (let file of jbMods) {
            // We use the new architectures array if it exists, otherwise fallback to subcategory
            const archs = file.architectures || [];
            const subcat = file.platforms[0] || '';
            const isRootless = archs.includes('arm64') || subcat.includes('Rootless');
            
            const iconKey = file.iconUrl || file.iconKey;
            const iconUrl = await getSmartImageUrl(iconKey);
            const fileObj = { ...file.toObject(), iconUrl };

            // Sort them based on platform/arch
            if (isRootless) rootless.push(fileObj);
            else if (subcat.includes('Rootful')) rootful.push(fileObj);
            else if (subcat.includes('Roothide')) roothide.push(fileObj);
            else other.push(fileObj);
        }

        const baseUrl = getBaseUrl(req);
        res.render('pages/jailbreak-repos', { 
            rootless, rootful, roothide, other,
            baseUrl: baseUrl // <-- Pass baseUrl to EJS
        });


    } catch (e) {
        console.error("Jailbreak repo error:", e);
        res.status(500).render('pages/500');
    }
});

// --- 2. Jailed iOS & Android Repo Route ---
app.get('/repos', async (req, res) => {
    try {
        // --- Fetch Android F-Droid Candidates ---
        const androidRepoMods = await File.find({ 
            category: 'android',
            status: 'live',
            isLatestVersion: true,
            showInRepo: { $ne: false },
            // ✅ FIX: Looking for the new 'directDownloadUrl' field OR 'externalDownloadUrl'
            $or:[
                { directDownloadUrl: { $exists: true, $ne: '' } },
                { externalDownloadUrl: { $exists: true, $ne: '' } }
            ]
        }).sort({ createdAt: -1 });

        const androidFiles = await Promise.all(androidRepoMods.map(async (file) => {
            const iconKey = file.iconUrl || file.iconKey;
            const iconUrl = await getSmartImageUrl(iconKey);
            return { ...file.toObject(), iconUrl };
        }));

        // --- Fetch iOS Jailed (Sideloading) Candidates ---
        const iosJailedRepoMods = await File.find({ 
            category: 'ios-jailed',
            status: 'live',
            isLatestVersion: true,
            showInRepo: { $ne: false },
            // ✅ FIX: Looking for the new 'directDownloadUrl' field OR 'externalDownloadUrl'
            $or:[
                { directDownloadUrl: { $exists: true, $ne: '' } },
                { externalDownloadUrl: { $exists: true, $ne: '' } }
            ]
        }).sort({ createdAt: -1 });

        const iosFiles = await Promise.all(iosJailedRepoMods.map(async (file) => {
            const iconKey = file.iconUrl || file.iconKey;
            const iconUrl = await getSmartImageUrl(iconKey);
            return { ...file.toObject(), iconUrl };
        }));

        const baseUrl = getBaseUrl(req);

        res.render('pages/repos', { 
            androidFiles: androidFiles,
            iosFiles: iosFiles,
            baseUrl: baseUrl // <-- Pass baseUrl to EJS
        });

    } catch (e) {
        console.error("Repository Hub Error:", e);
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

        // ✅ RAM OPTIMIZATION: Added .lean()
        const filesByDeveloper = await File.find({
            developer: searchPattern, 
            isLatestVersion: true,
            status: 'live'
        })
        .sort({ createdAt: -1 })
        .lean();
        // --- FIX: GENERATE SIGNED URLS FOR IMAGES ---
        const filesWithUrls = await Promise.all(filesByDeveloper.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            let signedIconUrl = '/images/default-app-icon.png';
            if (key) {
                try { signedIconUrl = await getSmartImageUrl(key); } catch (e) {}
            }
            // ✅ REMOVED: .toObject() is no longer needed
            return { ...file, iconUrl: signedIconUrl }; 
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
        return next(error);
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
        return next(error);
    }
});
app.post('/mods/:id/add-version', ensureAuthenticated, upload.single('modFile'), async (req, res) => {
    try {
        const parentFileId = req.params.id;
        const previousVersion = await File.findById(parentFileId);
        if (!previousVersion) {
            return res.status(404).json({ success: false, message: 'Parent file not found.' });
        }

        const isUploader = req.user.username.toLowerCase() === previousVersion.uploader.toLowerCase();
        const isAdmin = req.user.role === 'admin';
        if (!isUploader && !isAdmin) {
            return res.status(403).json({ success: false, message: "Forbidden: You don't have permission to edit this mod." });
        }

        const formData = req.body;
        let isMultiPart = formData.isMultiPart === 'true' || formData.isMultiPart === true;
        let downloadParts = [];
        let newFileKey = 'external-link';
        let actualFileSize = 0;
        let originalFilename = formData.originalFilename || req.file?.originalname || 'Update';

        if (isMultiPart && (formData.partUrls || formData.partNames)) {
            const pNames = formData.partNames
                ? (Array.isArray(formData.partNames) ? formData.partNames : [formData.partNames])
                : [];
            const pUrls = formData.partUrls
                ? (Array.isArray(formData.partUrls) ? formData.partUrls : [formData.partUrls])
                : [];
            const m1Prov = formData.mirror1Provider
                ? (Array.isArray(formData.mirror1Provider) ? formData.mirror1Provider : [formData.mirror1Provider])
                : [];
            const m1Url = formData.mirror1Url
                ? (Array.isArray(formData.mirror1Url) ? formData.mirror1Url : [formData.mirror1Url])
                : [];
            const m2Prov = formData.mirror2Provider
                ? (Array.isArray(formData.mirror2Provider) ? formData.mirror2Provider : [formData.mirror2Provider])
                : [];
            const m2Url = formData.mirror2Url
                ? (Array.isArray(formData.mirror2Url) ? formData.mirror2Url : [formData.mirror2Url])
                : [];
            const daLink = formData.directAdminLink
                ? (Array.isArray(formData.directAdminLink) ? formData.directAdminLink : [formData.directAdminLink])
                : [];
            const mfScan = formData.partManualFileScanUrl
                ? (Array.isArray(formData.partManualFileScanUrl) ? formData.partManualFileScanUrl : [formData.partManualFileScanUrl])
                : [];
            const msScan = formData.partManualSiteScanUrl
                ? (Array.isArray(formData.partManualSiteScanUrl) ? formData.partManualSiteScanUrl : [formData.partManualSiteScanUrl])
                : [];

            for (let i = 0; i < pUrls.length; i++) {
                const partUrl = pUrls[i] ? pUrls[i].trim() : '';
                if (!partUrl) continue;

                downloadParts.push({
                    partName: pNames[i] && pNames[i].trim() !== '' ? pNames[i].trim() : `Part ${downloadParts.length + 1}`,
                    partUrl,
                    mirror1Provider: m1Prov[i] ? m1Prov[i].trim() : '',
                    mirror1Url: m1Url[i] ? m1Url[i].trim() : '',
                    mirror2Provider: m2Prov[i] ? m2Prov[i].trim() : '',
                    mirror2Url: m2Url[i] ? m2Url[i].trim() : '',
                    directAdminLink: daLink[i] ? daLink[i].trim() : '',
                    manualFileScanUrl: mfScan[i] ? mfScan[i].trim() : '',
                    manualSiteScanUrl: msScan[i] ? msScan[i].trim() : ''
                });
            }
        } else if (req.file && req.file.size > 100) {
            const fileSize = req.file.size;
            actualFileSize = fileSize;
            const isPremium = req.user.membership === 'premium';
            const isAdminOrDist = req.user.role === 'admin' || req.user.role === 'distributor';

            if (!isAdminOrDist) {
                if (!isPremium && fileSize > 314572800) {
                    return res.status(413).json({ success: false, message: 'File exceeds 300MB limit.' });
                }
                if (isPremium && fileSize > 1073741824) {
                    return res.status(413).json({ success: false, message: 'File exceeds 1GB limit.' });
                }
            }

            const io = req.app.get('io');
            newFileKey = await uploadToB2(req.file, 'mods', io, formData.uploadId);
        }

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
            architectures: previousVersion.architectures,
            minOsVersion: previousVersion.minOsVersion,
            ageRating: previousVersion.ageRating,
            importantNote: formData.importantNote || previousVersion.importantNote,
            uploader: req.user.username,
            version: req.body.softwareVersion,
            whatsNew: req.body.whatsNew,
            fileKey: newFileKey,
            fileSize: actualFileSize,
            originalFilename: originalFilename,
            isMultiPart: isMultiPart,
            downloadParts: downloadParts,
            externalDownloadUrl: !isMultiPart ? (formData.externalDownloadUrl || '') : '',
            directDownloadUrl: formData.directDownloadUrl || '',
            ipaDirectDownloadUrl: formData.ipaDirectDownloadUrl || '',
            manualFileScanUrl: !isMultiPart ? (formData.manualFileScanUrl || '') : '',
            manualSiteScanUrl: !isMultiPart ? (formData.manualSiteScanUrl || '') : '',
            isLatestVersion: false,
            parentFile: parentFileId,
            status: 'live'
        });

        await newVersion.save();
        await File.findByIdAndUpdate(parentFileId, {
            $push: { olderVersions: newVersion._id },
            isLatestVersion: false
        });

        newVersion.isLatestVersion = true;
        await newVersion.save();

        if (req.file && req.file.size > 100) {
            (async () => {
                try {
                    const analysisId = await submitToVirusTotal(req.file.buffer, req.file.originalname, req.file.size);
                    await File.findByIdAndUpdate(newVersion._id, { virusTotalAnalysisId: analysisId });
                } catch (error) {
                    console.error('VirusTotal submission failed for new version:', error.message || error);
                }
            })();
        }

        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        const modUrl = `${baseUrl}/${encodeURIComponent(newVersion.category)}/${encodeURIComponent(newVersion.slug || newVersion._id.toString())}`;
        notifyIndexNow([modUrl]);
        notifyGoogle(modUrl, 'URL_UPDATED');

        return res.json({ success: true, redirectUrl: `/mods/${newVersion._id}` });
    } catch (error) {
        console.error('Error adding new version:', error);
        return res.status(500).json({ success: false, message: 'A server error occurred during upload.' });
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
// Download Action - UPDATED for Anti-Spam & Universal Link Tracking
app.get('/download-file/:id', async (req, res) => {
    try {
        const fileId = req.params.id;
        const file = await File.findById(fileId);
        if (!file) return res.status(404).render('pages/404');

        // ==========================================
        // DOWNLOAD TRACKING LOGIC (Anti-Spam)
        // ==========================================
        let shouldIncrementDownload = false;

        if (req.isAuthenticated()) {
            if (!file.downloadedBy.includes(req.user._id)) {
                shouldIncrementDownload = true;
                file.downloadedBy.push(req.user._id);
            }
        } else {
            const cookieName = `download_mod_${fileId}`;
            if (!req.cookies[cookieName]) {
                shouldIncrementDownload = true;
                res.cookie(cookieName, 'true', { maxAge: 30 * 60 * 1000, httpOnly: true });
            }
        }

        if (shouldIncrementDownload) {
            file.downloads += 1;
            await file.save();
            await recordDailyStat(file._id, file.uploader, 'download'); // For the graph!
        }
        // ==========================================

        // --- 1. MULTI-PART / ALTERNATIVE URL PASSTHROUGH ---
        // If a mirror URL was passed in the query, count the download and redirect only to an approved mirror URL.
        if (req.query.url) {
            const requestedUrl = req.query.url;
            const allowedMirrorUrls = [];

            if (file.alternativeLinks && file.alternativeLinks.length > 0) {
                file.alternativeLinks.forEach(mirror => {
                    allowedMirrorUrls.push(mirror.url);
                    if (res.locals.showAds && res.locals.linkvertiseEnabled && !isUploaderDistributor) {
                        allowedMirrorUrls.push(res.locals.generateAdLink(mirror.url));
                    }
                });
            }

            if (!allowedMirrorUrls.includes(requestedUrl)) {
                console.warn(`Rejected invalid mirror redirect for file ${fileId}: ${requestedUrl}`);
                return res.status(400).send("Invalid download URL.");
            }

            return res.redirect(requestedUrl);
        }

        // --- 2. EXTERNAL CLOUD LINK FIRST ---
        if (file.externalDownloadUrl) {
            return res.redirect(file.externalDownloadUrl);
        }

        // --- 3. FALLBACK TO BACKBLAZE B2 ---
        const fileKey = file.fileKey || file.fileUrl; 
        if (!fileKey) return res.status(500).send("File record incomplete.");

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
        if (!Types.ObjectId.isValid(fileId)) return next(error);

        const file = await File.findById(fileId);
        
        if (!file || !file.isMultiPart) {
            // If it's not a multi-part file, just send them back to the main mod page
            return res.redirect(`/mods/${fileId}`);
        }

        // We still get a signed URL for the icon just to make the page look nice
        const iconKey = file.iconUrl || file.iconKey;
        const iconUrl = await getSmartImageUrl(iconKey);

        // ======== NEW: FIND UPLOADER ROLE ========
        let isUploaderDistributor = false;
        const uploaderUser = await User.findOne({ username: file.uploader }).lean();
        
        if (uploaderUser && uploaderUser.role === 'distributor') {
            isUploaderDistributor = true;
        }
        // =========================================


        res.render('pages/download-parts', { 
            file: { ...file.toObject(), iconUrl },
            isUploaderDistributor
        });

    } catch (e) {
        console.error("Multi-part page error:", e);
        return next(error);
    }
});

// ===============================
// 3.5. AUTH ROUTES & 2FA SYSTEM
// ===============================

// --- 1. SINGLE SESSION CONCURRENCY HELPER ---
async function finalizeLogin(req, res, user, redirectUrl) {
    let tempSession = req.session.passport;
    if (req.session.pending2faUserId) {
        req.session.pending2faUserId = null;
    }
    if (req.session.currentChallenge) {
        req.session.currentChallenge = null;
    }
    
    // Generate a brand new, secure Session ID for this device
    req.session.regenerate(async (err) => {
        if (err) console.error("Session Regen Error:", err);
        
        req.session.passport = tempSession; // Restore login state
        
        // Check if the user already has an active session on another device
        if (user.currentSessionId && user.currentSessionId !== req.sessionID) {
            try {
                // ✅ FIX: Directly update MongoDB to mark the old session as kicked out
                // This ensures persistence before we continue
                const sessionsCollection = mongoose.connection.collection('sessions');
                await sessionsCollection.updateOne(
                    { _id: user.currentSessionId },
                    { $set: { kickedOut: true } }
                );
                console.log(`[Session] Marked old session ${user.currentSessionId} as kickedOut for user ${user.username}`);
            } catch (err) {
                console.error(`[Session] Failed to invalidate old session: ${err.message}`);
            }
        }
        
        // Save the new Session ID
        user.currentSessionId = req.sessionID;
        await user.save();

        // Save the cookie and redirect
        req.session.save((saveErr) => {
            if (saveErr) console.error("Session save error:", saveErr);
            // Set the CDN bypass cookie
            res.cookie('is_logged_in', 'true', { 
                maxAge: 1000 * 60 * 60 * 24 * 3, // 3 Days
                path: '/', 
                secure: process.env.NODE_ENV === 'production', 
                sameSite: 'lax'
            });
            res.redirect(redirectUrl);
        });
    });
}

// --- 2. CENTRALIZED LOGIN SUCCESS HANDLER (INTERCEPTS FOR 2FA) ---
const processSuccessfulLogin = async (req, res, next, user) => {
    if (user.twoFactorEnabled) {
        // Place user in 2FA limbo
        req.session.pending2faUserId = user._id.toString();
        
        if (user.twoFactorMethod === 'email') {
            try {
                const otp = Math.floor(100000 + Math.random() * 900000).toString();
                user.verificationOtp = otp;
                user.otpExpires = Date.now() + 600000;
                await user.save();
                await send2faEmail(user, otp); 
            } catch (e) { console.error("2FA Email Error:", e); }
        }
        
        // Explicitly SAVE the session to MongoDB before redirecting!
        req.session.save((err) => {
            if (err) console.error("Session save error:", err);
            return res.redirect('/login/2fa');
        });
        
    } else {
        // Standard Login (No 2FA required)
        req.logIn(user, (loginErr) => {
            if (loginErr) return next(loginErr);
            finalizeLogin(req, res, user, '/home?message=Welcome back!');
        });
    }
};

// --- 3. LOCAL LOGIN ROUTE ---
app.get('/login', (req, res) => {
    res.render('pages/login', {
        recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY,
        message: req.query.message || null,
        error: req.query.error || null 
    });
});

app.post('/login', verifyRecaptcha, (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.redirect('/login?error=' + encodeURIComponent(info.message));
        
        processSuccessfulLogin(req, res, next, user); 
    })(req, res, next);
});

// --- 4. SOCIAL CALLBACK HANDLER (Handles Fresh Logins AND Social 2FA) ---
const handleSocialCallback = (provider) => {
    return (req, res, next) => {
        passport.authenticate(provider, async (err, user, info) => {
            if (err) return next(err);
            if (!user) return res.redirect('/login');

            // Is the user currently trying to pass a Social 2FA Challenge?
            if (req.session.pending2faUserId) {
                const pendingUser = await User.findById(req.session.pending2faUserId);
                
                // Check if the social account matches the pending account
                if (pendingUser && pendingUser._id.toString() === user._id.toString()) {
                    // Match! 2FA is successful!
                    req.logIn(pendingUser, (loginErr) => {
                        if (loginErr) return next(loginErr);
                        req.session.pending2faUserId = null;
                        
                        finalizeLogin(req, res, pendingUser, '/home?message=2FA Verified via Social Login!');
                    });
                    return;
                } else {
                    // Imposter detected
                    return res.redirect('/login/2fa?error=The social account does not match the linked 2FA account.');
                }
            }

            // If not in 2FA limbo, process as a normal login
            processSuccessfulLogin(req, res, next, user);
        })(req, res, next);
    };
};

// --- SOCIAL ROUTES ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', handleSocialCallback('google'));

app.get('/auth/github', passport.authenticate('github', { scope: [ 'user:email' ] }));
app.get('/auth/github/callback', handleSocialCallback('github'));

app.get('/auth/microsoft', passport.authenticate('microsoft', { prompt: 'select_account' }));
app.get('/auth/microsoft/callback', handleSocialCallback('microsoft'));


// --- 5. REGISTRATION ROUTES ---
app.get('/register', redirectIfAuthenticated, (req, res) => {
    res.render('pages/register', { 
        recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY || '', 
        message: req.query.message || null,
        error: req.query.error || null
    });
});

app.post('/register', verifyRecaptcha, async (req, res, next) => {
    try {
        const { username, email, password, dateOfBirth, referralCode} = req.body;
        if (!username || !email || !password || !dateOfBirth) {
            return res.status(400).send("All fields are required, including Date of Birth.");
        }
        
        // Validation Check
        if (!isValidName(username)) {
            return res.status(400).send("Username can only contain letters, numbers, and spaces. No emojis.");
        }

        // Security Check (Reserved Names)
        if (isNameReserved(username)) {
            return res.status(400).send("That username is reserved and cannot be used.");
        }

        // Profanity Check
        if (global.profanityFilter.isProfane(username)) {
             return res.status(400).send("That username contains inappropriate language.");
        }

        // Anti-Temp Mail Check
        const isTempMail = await isDisposableEmail(email.toLowerCase());
        if (isTempMail) {
            return res.status(400).render('pages/register', { 
                recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY, 
                message: null,
                error: "Registration failed. Disposable or temporary email addresses are not allowed. Please use a valid, permanent email." 
            });
        }

        let user = await User.findOne({ email: email.toLowerCase() });
        if (user && user.isVerified) {
            return res.status(400).send("An account with this email already exists.");
        }

        // Generate Unique Username (Discriminator)
        const uniqueUsername = await generateUniqueUsername(username);

        // Generate a referral code for this NEW user
        const newReferralCode = await generateReferralCode(uniqueUsername);

        // Process the incoming referral code (if provided)
        let referrerId = null;
        if (referralCode && referralCode.trim() !== '') {
            const referrer = await User.findOne({ referralCode: referralCode.trim().toUpperCase() });
            if (referrer) {
                referrerId = referrer._id;
            }
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const otpExpires = Date.now() + 600000; 

        if (user && !user.isVerified) {
            // Update unverified user
            user.verificationOtp = otp;
            user.otpExpires = otpExpires;
            user.username = uniqueUsername;
            user.dateOfBirth = new Date(dateOfBirth); 
        } else {
            // Create new user
            user = new User({
                username: uniqueUsername,
                email: email.toLowerCase(),
                password,
                referralCode: newReferralCode, 
                referredBy: referrerId,        
                dateOfBirth: new Date(dateOfBirth), 
                verificationOtp: otp,
                otpExpires: otpExpires
            });
        }
        
        await user.save();
        await sendVerificationEmail(user);
        
        res.render('pages/please-verify', { email: user.email, error: null });

    } catch (e) {
        console.error("Registration error:", e);
        return next(e);
    }
});


// --- 6. OTP VERIFICATION (Used for Registration) ---
app.post('/verify-otp', async (req, res, next) => {
    try {
        const { otp, email } = req.body; 

        const user = await User.findOne({
            email: email.toLowerCase(),
            verificationOtp: otp,
            otpExpires: { $gt: Date.now() }
        });

        if (!user) {
            return res.render('pages/please-verify', { 
                email: email, 
                error: 'Invalid or expired verification code. Please try again.' 
            });
        }

        user.isVerified = true;
        user.verificationOtp = undefined; 
        user.otpExpires = undefined;
        await user.save();

        // REWARD THE REFERRER
        if (user.referredBy) {
            await awardPoints(user.referredBy, 5, "Successful Referral", `You referred ${user.username}!`);
            await User.findByIdAndUpdate(user.referredBy, { $inc: { referralCount: 1 } });
            
            try {
                const UserNotification = require('./models/userNotification');
                await new UserNotification({
                    user: user.referredBy,
                    title: 'New Referral!',
                    message: `Awesome! ${user.username} just signed up using your referral code. You earned 5 points!`,
                    type: 'success'
                }).save();
            } catch (err) { console.error("Referral Notif Error:", err); }
        }

        // AUTOMATED WELCOME MESSAGE
        try {
            const UserNotification = require('./models/userNotification');
            const existingWelcome = await UserNotification.findOne({ user: user._id, title: 'Welcome to GPL Mods!' });

            if (!existingWelcome) {
                await new UserNotification({
                    user: user._id,
                    title: 'Welcome to GPL Mods!',
                    message: `Hi ${user.username},\n\nWelcome to the community! We're thrilled to have you here. \n\nFeel free to explore our massive library of safe, working mods, or start uploading your own to build your reputation.\n\nIf you need any help, check out the FAQ or submit a Support Ticket.\n\nHappy Modding,\nThe GPL Community Team`,
                    type: 'success' 
                }).save();
            }
        } catch (notifErr) { console.error("Welcome message error:", notifErr); }
        
        // Log them in and finalize session
        req.login(user, (err) => {
            if (err) return res.redirect('/login?error=Verification successful, but login failed. Please log in manually.');
            finalizeLogin(req, res, user, '/profile?success=Account verified successfully!');
        });

    } catch (error) {
        return next(error);
    }
});


// --- 7. PASSWORD RESET ROUTES ---
app.get('/forgot-password', (req, res) => {
    res.render('pages/forgot-password'); 
});

app.post('/resend-otp', async (req, res) => {
    try {
        const { email } = req.body;
        // ANTI-TEMP MAIL CHECK 
        const isTempMail = await isDisposableEmail(email.toLowerCase());
        if (isTempMail) {
            return res.redirect('/forgot-password?error=Invalid email domain.');
        }
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
            return res.redirect('/forgot-password?success=If an account exists, a link has been sent.');
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        user.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
        user.passwordResetExpires = Date.now() + 3600000; // 1 hour
        await user.save();
        
        const resetURL = `https://${req.get('host')}/reset-password/${resetToken}`;
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
            finalizeLogin(req, res, user, '/home?message=Password has been reset successfully!');
        });
    } catch (e) { res.redirect('/forgot-password?error=An error occurred.'); }
});

// --- 8. LOGOUT ROUTE ---
app.get('/logout', async (req, res, next) => {
    if (req.user) {
        // Clear the active session from the database
        await User.findByIdAndUpdate(req.user._id, { $unset: { currentSessionId: "" } });
    }
    req.logout(err => { 
        if (err) return next(err); 
        
        req.session.destroy(() => {
            res.clearCookie('connect.sid', { path: '/' });
            // Clear the readable cookie on logout
            res.clearCookie('is_logged_in', { path: '/' }); 
            res.redirect('/?message=You have been successfully logged out.'); 
        });
    });
});

// --- GOOGLE ROUTES ---
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    processSuccessfulLogin,
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
    processSuccessfulLogin,
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
    processSuccessfulLogin,
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
// 4. PROFILE & DASHBOARD ROUTES
// ===============================

// --- 1. Main User Dashboard Hub ---
app.get('/dashboard', ensureAuthenticated, async (req, res) => {
    try {
        // 1. Fetch the user and fully populate their followers and following lists
        const userWithCommunity = await User.findById(req.user._id)
            .populate('following', 'username profileImageKey role')
            .populate('followers', 'username profileImageKey role');

        // 2. Helper function to generate signed Avatar URLs for the lists
        const mapCommunityUsers = async (usersArray) => {
            return await Promise.all(usersArray.map(async (u) => {
                let avatarUrl = '/images/default-avatar.png';
                if (u.profileImageKey) {
                    try {
                        avatarUrl = await getSmartImageUrl(u.profileImageKey);
                    } catch (e) { console.error("Avatar sign error", e); }
                }
                return { 
                    _id: u._id, 
                    username: u.username, 
                    role: u.role, 
                    signedAvatarUrl: avatarUrl 
                };
            }));
        };

        // 3. Process the lists
        const followersList = await mapCommunityUsers(userWithCommunity.followers);
        const followingList = await mapCommunityUsers(userWithCommunity.following);

        // 4. Render the page with the new data
        res.render('pages/dashboard', { 
            user: req.user,
            followers: followersList,
            following: followingList
        });

    } catch (error) {
        console.error("Dashboard community fetch error:", error);
        res.status(500).render('pages/500');
    }
});

// --- 2. Edit Profile Page (Avatar, Bio, Username, Passwords) ---
app.get('/profile', ensureAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        
        // Ensure virtuals (like forumRank) are passed to the frontend
        const userObj = user.toObject({ virtuals: true });
        userObj.signedAvatarUrl = req.user.signedAvatarUrl; 

        res.render('pages/profile', { user: userObj });
    } catch (e) { 
        console.error('Profile fetch error:', e);
        res.status(500).render('pages/500'); 
    }
});

// --- 3. Dedicated Wishlist Page ---
app.get('/wishlist', ensureAuthenticated, async (req, res) => {
    try {
        // Fetch the user and populate the whitelist with FULL file details
        const userWithWhitelist = await User.findById(req.user._id)
            .populate({
                path: 'whitelist',
                match: { isLatestVersion: true, status: 'live' } // Only show live, latest mods
            });
            
        // We need to get signed URLs for the icons in the whitelist
        const populatedWhitelist = await Promise.all((userWithWhitelist.whitelist || []).map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            const signedIconUrl = await getSmartImageUrl(key);
            return { ...file.toObject(), iconUrl: signedIconUrl };
        }));

        res.render('pages/wishlist', { whitelistedMods: populatedWhitelist });

    } catch (error) {
        console.error("Wishlist Error:", error);
        res.status(500).render('pages/500');
    }
});

// --- 4. Additional Settings Page (2FA, Delete Account, Newsletter) ---
app.get('/settings', ensureAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        
        // Convert to object so we can append custom properties
        const userObj = user.toObject();
        // Crucial: Attach the signed avatar URL generated by your global middleware!
        userObj.signedAvatarUrl = req.user.signedAvatarUrl;

        res.render('pages/settings', { user: userObj });
    } catch (error) {
        console.error("Settings page error:", error);
        res.status(500).render('pages/500');
    }
});

// --- 5. Newsletter Toggle Route ---
app.post('/account/newsletter', ensureAuthenticated, async (req, res) => {
    try {
        const { subscribe } = req.body;
        const user = await User.findById(req.user._id);
        
        user.isSubscribedToNewsletter = (subscribe === 'true');
        await user.save();
        
        res.redirect('/settings?success=Newsletter preferences updated.');
    } catch (e) {
        console.error("Newsletter update error:", e);
        res.redirect('/settings?error=Error updating newsletter preferences.');
    }
});

// --- 6. 2FA Recovery Codes Display ---
app.get('/account/2fa/recovery-codes', ensureAuthenticated, (req, res) => {
    // Grab the codes from the session
    const codes = req.session.tempRecoveryCodes;
    
    if (!codes || codes.length === 0) {
        // If they try to go to this page later, kick them back to Settings
        return res.redirect('/settings'); 
    }

    // IMMEDIATELY delete the codes from the session so they can never be viewed again
    req.session.tempRecoveryCodes = null;

    res.render('pages/2fa-recovery-codes', { codes: codes });
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
        .populate('olderVersions', 'version fileSize createdAt')
        .lean();
        
        // 2. Map through the uploads to generate signed image URLs
        const uploadsWithUrls = await Promise.all(userUploads.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            let signedIconUrl = '/images/default-app-icon.png';
            if (key) {
                try {
                    signedIconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: key }), { expiresIn: 3600 });
                } catch (urlError) {}
            }
            
            // ✅ FIX: Because of .lean(), 'file' is already a plain object! No .toObject() needed.
            file.iconUrl = signedIconUrl;
            file.olderVersions = file.olderVersions ||[]; 
            
            return file; 
        }));

        res.render('pages/my-uploads', { uploads: uploadsWithUrls }); 
    } catch (error) { 
        console.error("My Uploads Error:", error);
        return next(error); 
    }
});
// --- NEW: Analytics Dashboard Route ---
app.get('/my-stats', ensureAuthenticated, async (req, res) => {
    try {
        // 1. Get all files by this user
        const myFiles = await File.find({ uploader: req.user.username, isLatestVersion: true }).sort({ createdAt: -1 });
        
        // 2. Get the daily time-series data for this user
        const myDailyStats = await DailyStat.find({ uploader: req.user.username }).sort({ dateString: 1 });

        // 3. Calculate Totals
        let totalViews = 0;
        let totalDownloads = 0;
        myFiles.forEach(f => {
            totalViews += f.views || 0;
            totalDownloads += f.downloads || 0;
        });

        res.render('pages/my-stats', {
            files: myFiles,
            dailyStatsJson: JSON.stringify(myDailyStats), // Stringify for Chart.js
            totalViews,
            totalDownloads
        });
    } catch (e) {
        console.error("Stats Error:", e);
        res.status(500).render('pages/500');
    }
});
// ===================================
// 6.5 PUBLIC PROFILE ROUTE
// ===================================
app.get('/users/:username', async (req, res, next) => {
    try {
        const slug = req.params.username;
        const searchPattern = new RegExp(`^${slug.replace(/-/g, '[-\\s]+')}$`, 'i');

        // --- 1. FETCH USER WITH POPULATES ---
        const targetUser = await User.findOne({ username: searchPattern })
            .populate('following', 'username profileImageKey role')
            .populate('followers', 'username profileImageKey role');

        // --- 2. HANDLE USER NOT FOUND ---
        if (!targetUser) {
            return res.status(404).render('pages/error', {
                errorCode: '404',
                errorTitle: 'User <span>Not Found</span>',
                errorMessage: `We couldn't find a user named "${slug}". They may have changed their name or deleted their account.`
            });
        }

        // --- 3. USE STORED FORUM POINTS AND RANK ---
        // The public profile should match the same persisted point totals
        // and computed rank used on /profile and /rewards.
        if (targetUser.forumPoints == null) {
            const userUploadsForPoints = await File.countDocuments({ uploader: targetUser.username, isLatestVersion: true, status: 'live' });
            const userReviewsForPoints = await Review.countDocuments({ user: targetUser._id });
            const userFollowersForPoints = targetUser.followers.length;
            targetUser.forumPoints = (userUploadsForPoints * 10) + (userReviewsForPoints * 2) + (userFollowersForPoints * 5);
        }

        const targetUserObj = targetUser.toObject({ virtuals: true });

        // --- 3. HANDLE BANNED USERS ---
        if (targetUser.isBanned) {
            return res.status(403).render('pages/error', {
                errorCode: '403',
                errorTitle: 'Account <span>Suspended</span>',
                errorMessage: `The account for "${targetUser.username}" has been suspended due to a violation of our Terms of Service.`
            });
        }

        // --- 4. GET AVATAR URL ---
        if (targetUserObj.profileImageKey) {
            try {
                targetUserObj.signedAvatarUrl = await getSmartImageUrl(targetUserObj.profileImageKey);
            } catch (e) {
                targetUserObj.signedAvatarUrl = '/images/default-avatar.png';
            }
        } else {
            targetUserObj.signedAvatarUrl = '/images/default-avatar.png';
        }

        // --- 5. GET LATEST UPLOADS ---
        const uploads = await File.find({ 
            uploader: targetUserObj.username, 
            isLatestVersion: true,
            status: 'live' 
        })
        .sort({ createdAt: -1 })
        .lean(); 

        const uploadsWithUrls = await Promise.all(uploads.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            const iconUrl = await getSmartImageUrl(key);
            return { ...file, iconUrl }; 
        }));

        // --- 6. OPTIMIZED FOLLOWERS & FOLLOWING ---
        const followersWithAvatars = await Promise.all(targetUserObj.followers.map(async (follower) => {
            const avatarUrl = await getSmartImageUrl(follower.profileImageKey);
            return { ...follower, signedAvatarUrl: avatarUrl }; 
        }));

        const followingWithAvatars = await Promise.all(targetUserObj.following.map(async (followingUser) => {
            const avatarUrl = await getSmartImageUrl(followingUser.profileImageKey);
            return { ...followingUser, signedAvatarUrl: avatarUrl };
        }));        

        // --- 7. CHECK FOLLOW STATUS ---
        let isFollowing = false;
        if (req.isAuthenticated() && req.user && req.user.following) {
            isFollowing = req.user.following.some((id) => id.toString() === targetUser._id.toString());
        }

        // --- 8. RENDER PAGE ---
        res.render('pages/public-profile', { 
            profileUser: targetUserObj, 
            uploads: uploadsWithUrls,
            followersList: followersWithAvatars, 
            followingList: followingWithAvatars,
            isFollowing: isFollowing 
        });

    } catch (error) { 
        console.error("Public Profile Error:", error);
        next(error); 
    }
});

// --- ACCOUNT MANAGEMENT ROUTES ---

app.post('/account/update-details', ensureAuthenticated, async (req, res, next) => {
    try {
        const { username, email, bio, dateOfBirth, country } = req.body; 
        const user = await User.findById(req.user.id);
        if (bio !== undefined) user.bio = bio;
        if (country !== undefined) user.country = country;
        // 2. Save Date of Birth
        if (dateOfBirth) {
            user.dateOfBirth = new Date(dateOfBirth);
        }

        // --- Handle Username Change ---
        if (username && username !== user.username) {
            // ======== VALIDATION CHECK ========
            if (!isValidName(username)) {
                 return res.redirect('/profile?error=Username can only contain letters, numbers, and spaces.');
            }
            // ===========================================
            
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
            // ======== NEW: ANTI-TEMP MAIL CHECK ========
            const isTempMail = await isDisposableEmail(email.toLowerCase());
            if (isTempMail) {
                return res.redirect('/profile?error=Disposable or temporary email addresses are not allowed. Please use a permanent email.');
            }
            // ===========================================
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
// ===================================
// SECURITY: DELETION & 2FA ROUTES
// ===================================

// --- 1. Account Deletion with OTP ---
app.post('/account/delete-request', ensureAuthenticated, async (req, res) => {
    try {
        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        const user = await User.findById(req.user._id);
        user.deletionOtp = otp;
        user.deletionOtpExpires = Date.now() + 600000; // 10 mins
        await user.save();
        await sendDeletionOtpEmail(user, otp);
        res.json({ success: true });
    } catch (e) { res.json({ success: false }); }
});

app.post('/account/delete-confirm', ensureAuthenticated, async (req, res, next) => {
    try {
        const { otp, preserveMods } = req.body;
        const user = await User.findById(req.user._id);

        if (!user.deletionOtp || user.deletionOtp !== otp || user.deletionOtpExpires < Date.now()) {
            return res.json({ success: false, message: 'Invalid or expired code.' });
        }

        const username = user.username;
        if (preserveMods) {
            await File.updateMany({ uploader: username }, { uploader: 'GPL Community' });
        } else {
            await File.deleteMany({ uploader: username });
        }
        await Review.deleteMany({ user: user._id });
        await User.findByIdAndDelete(user._id);

        req.logout(function(err) {
            if (err) return next(err);
            res.json({ success: true, redirect: '/?message=Account deleted permanently.' });
        });
    } catch (error) { res.status(500).json({ success: false }); }
});

// ✅ KEEP THIS ROUTE ✅
app.get('/account/2fa/setup', ensureAuthenticated, (req, res) => {
    res.render('pages/2fa-setup', { error: req.query.error, message: req.query.message });
});

// ==========================================
// 2FA SETUP GENERATION ROUTES
// ==========================================

// 1. Generate TOTP (QR Code & Secret)
app.post('/account/2fa/generate-totp', ensureAuthenticated, async (req, res) => {
    try {
        const secret = speakeasy.generateSecret({ 
            name: `GPLMods (${req.user.username})` 
        });
        
        req.session.tempTwoFactorSecret = secret.base32;
        const dataURL = await QRCode.toDataURL(secret.otpauth_url);
        
        // Force session to save BEFORE responding
        req.session.save((err) => {
            if (err) throw err;
            res.json({ success: true, qrCodeUrl: dataURL, manualCode: secret.base32 });
        });
    } catch (e) {
        console.error("TOTP Gen Error:", e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// 2. Generate Passkey Options
app.get('/account/2fa/passkey/generate-options', ensureAuthenticated, async (req, res) => {
    try {
        const stringId = req.user._id.toString();
        const uint8UserId = new Uint8Array(Buffer.from(stringId, 'utf8'));

        const options = await generateRegistrationOptions({
            rpName: 'GPL Mods',
            rpID: req.hostname, // Matches your dynamic domain
            userID: uint8UserId,
            userName: req.user.username,
            attestationType: 'none',
            authenticatorSelection: { userVerification: 'preferred' },
        });
        
        req.session.currentChallenge = options.challenge;
        
        req.session.save((err) => {
            if (err) throw err;
            res.json(options);
        });
    } catch (e) {
        console.error("Passkey Options Error:", e);
        res.status(500).json({ error: e.message });
    }
});

// 3. Verify Passkey Setup
app.post('/account/2fa/passkey/verify', ensureAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        const expectedChallenge = req.session.currentChallenge;

        if (!expectedChallenge) {
            return res.status(400).json({ success: false, error: 'Session expired. Please try again.' });
        }

        const verification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: req.headers.origin || (process.env.BASE_URL ? process.env.BASE_URL : `http://${req.headers.host}`), 
            expectedRPID: req.hostname,         
        });

        if (verification.verified) {
            const { registrationInfo } = verification;
            
            // --- NEW: Handle SimpleWebAuthn Registration Info Safely ---
            // The library returns these as Uint8Arrays or similar structures in newer versions.
            // We need to convert them to base64url strings to store them safely in MongoDB.
            
            // Function to safely convert Uint8Array/Buffer to base64url
            const toBase64Url = (buffer) => {
                if (!buffer) return '';
                // If it's already a string, assume it's base64url or similar and use it
                if (typeof buffer === 'string') return buffer;
                // Otherwise, convert the Uint8Array/Buffer to a standard buffer then to base64url
                return Buffer.from(buffer).toString('base64url');
            };

            const credentialIDStr = toBase64Url(registrationInfo.credentialID || registrationInfo.credential.id);
            const publicKeyStr = toBase64Url(registrationInfo.credentialPublicKey || registrationInfo.credential.publicKey);
            const counter = registrationInfo.counter || 0;
            const transports = registrationInfo.credentialDeviceType === 'singleDevice' ? ['internal'] : []; // Optional, but good practice

            if (!credentialIDStr || !publicKeyStr) {
                throw new Error("Missing credential data from authenticator.");
            }

            // Push to your Schema's 'passkeys' array
            user.passkeys.push({
                credentialID: credentialIDStr,
                credentialPublicKey: publicKeyStr,
                counter: counter,
                transports: transports
            });
            
            user.twoFactorMethod = 'passkey';

            const rawCodes = generateRecoveryCodes();
            user.twoFactorRecoveryCodes = await Promise.all(rawCodes.map(code => bcrypt.hash(code, 10)));
            
            user.twoFactorEnabled = true;

            await user.save();

            req.session.currentChallenge = null;
            req.session.tempRecoveryCodes = rawCodes;
            
            req.session.save(() => {
                res.json({ success: true }); 
            });
        } else {
            res.json({ success: false, error: 'Verification failed' });
        }
    } catch (err) {
        console.error("Passkey Verify Error:", err);
        res.status(500).json({ success: false, error: err.message });
    }
});

// 4. Enable TOTP or Email Verification
app.post('/account/2fa/enable', ensureAuthenticated, async (req, res) => {
    try {
        const { method, token } = req.body;
        const user = await User.findById(req.user._id);

        // ✅ FIX 1: Strip accidental spaces from the token
        const cleanToken = token ? token.replace(/\s+/g, '') : '';

        if (method === 'email') {
            user.twoFactorMethod = 'email';
        } else if (method === 'totp') {
            
            const verified = speakeasy.totp.verify({
                secret: req.session.tempTwoFactorSecret,
                encoding: 'base32',
                token: cleanToken // <-- Use the sanitized token here
            });

            if (!verified) {
                return res.redirect('/account/2fa/setup?error=Invalid TOTP code. Please try again.');
            }
            
            user.twoFactorMethod = 'totp';
            user.twoFactorSecret = req.session.tempTwoFactorSecret;
            req.session.tempTwoFactorSecret = null; // Clean up
        }

        const rawCodes = generateRecoveryCodes();
        user.twoFactorRecoveryCodes = await Promise.all(rawCodes.map(code => bcrypt.hash(code, 10)));
        
        // Use your Schema's exact boolean name
        user.twoFactorEnabled = true;
        
        await user.save();

        req.session.tempRecoveryCodes = rawCodes; 
        
        // ✅ FIX 2: Wait for session to save BEFORE redirecting to avoid a blank recovery codes page
        req.session.save((err) => {
            if (err) console.error("Session save error:", err);
            res.redirect('/account/2fa/recovery-codes');
        });

    } catch (err) {
        console.error("2FA Enable Error:", err);
        res.redirect('/account/2fa/setup?error=An error occurred.');
    }
});

// --- Update 2FA Login Challenge to Accept Backup Codes ---
app.post('/login/2fa/verify', async (req, res, next) => {
    if (!req.session.pending2faUserId) return res.redirect('/login');
    try {
        // ✅ FIX: Extract token and strip any accidental whitespace immediately
        const token = req.body.token ? req.body.token.replace(/\s+/g, '') : '';
        
        const user = await User.findById(req.session.pending2faUserId);

        let isValid = false;
        let usedRecoveryCodeIndex = -1;

        // 1. Check if it's an 8-character Backup Code
        if (token.length === 8 && user.twoFactorRecoveryCodes && user.twoFactorRecoveryCodes.length > 0) {
            for (let i = 0; i < user.twoFactorRecoveryCodes.length; i++) {
                if (await bcrypt.compare(token, user.twoFactorRecoveryCodes[i])) {
                    isValid = true;
                    usedRecoveryCodeIndex = i;
                    break;
                }
            }
        } 
        // 2. Otherwise, check TOTP
        else if (user.twoFactorMethod === 'totp') {
            // Make sure you use speakeasy here to verify the login!
            isValid = speakeasy.totp.verify({
                secret: user.twoFactorSecret,
                encoding: 'base32',
                token: token // Using the clean token
            });
        }
        // 3. Otherwise, check Email OTP
        else if (user.twoFactorMethod === 'email') {
            isValid = (user.verificationOtp === token && user.otpExpires > Date.now());
        }

        if (!isValid) return res.redirect('/login/2fa?error=Invalid code. Please try again.');

        // Cleanup: Remove used recovery code or email OTP
        if (usedRecoveryCodeIndex !== -1) {
            user.twoFactorRecoveryCodes.splice(usedRecoveryCodeIndex, 1);
        }
        if (user.twoFactorMethod === 'email') {
            user.verificationOtp = undefined;
            user.otpExpires = undefined;
        }
        await user.save();

        // Finalize Login!
        req.logIn(user, (err) => {
            if (err) return next(err);
            finalizeLogin(req, res, user, '/home?message=Login successful!');
        });
    } catch (e) { res.redirect('/login/2fa?error=Server error.'); }
});

app.post('/account/2fa/disable', ensureAuthenticated, async (req, res) => {
    await User.findByIdAndUpdate(req.user._id, { twoFactorEnabled: false, twoFactorMethod: 'none', twoFactorSecret: '' });
    res.redirect('/dashboard?success=2FA Disabled.');
});
app.post('/account/2fa/enable-social', ensureAuthenticated, async (req, res) => {
    try {
        const { provider } = req.body;
        const user = await User.findById(req.user._id);

        if (!['google', 'github', 'microsoft'].includes(provider)) {
            return res.redirect('/account/2fa/setup?error=Invalid provider.');
        }

        // Ensure they actually have that provider linked
        if (!user[`${provider}Id`]) {
             return res.redirect(`/account/2fa/setup?error=You must link a ${provider} account first.`);
        }

        user.twoFactorMethod = 'social';
        user.twoFactorProvider = provider; // Save which one they want to use

        // --- THE CRITICAL FIX: GENERATE RECOVERY CODES HERE ---
        const rawCodes = generateRecoveryCodes();
        user.twoFactorRecoveryCodes = await Promise.all(rawCodes.map(code => bcrypt.hash(code, 10)));
        user.isTwoFactorEnabled = true;
        
        await user.save();

        req.session.tempRecoveryCodes = rawCodes;
        res.redirect('/account/2fa/recovery-codes'); // Redirect to codes page

    } catch (err) {
        console.error("Social 2FA Enable Error:", err);
        res.redirect('/account/2fa/setup?error=An error occurred.');
    }
});


// ==========================================
// PASSKEY LOGIN CHALLENGE ROUTES
// ==========================================

// 1. Generate the challenge for the user trying to log in
app.get('/login/2fa/passkey/options', async (req, res) => {
    if (!req.session.pending2faUserId) return res.status(400).json({error: 'No pending login session'});
    const user = await User.findById(req.session.pending2faUserId);
    
    if (!user || !user.passkey) return res.status(400).json({error: 'No passkey found for user'});

    try {
        const options = await generateAuthenticationOptions({
            rpID: process.env.BASE_URL ? new URL(process.env.BASE_URL).hostname : 'localhost',
            allowCredentials: [{
                id: Buffer.from(user.passkey.credentialID, 'base64url'),
                type: 'public-key',
                transports: ['internal'],
            }],
            userVerification: 'preferred',
        });
        
        // Save the challenge to the session
        req.session.currentChallenge = options.challenge;
        res.json(options);
    } catch (e) {
        console.error("Passkey Login Options Error:", e);
        res.status(500).json({ error: e.message });
    }
});

// 2. Verify the biometric response from the user's device
app.post('/login/2fa/passkey/verify', async (req, res, next) => {
    if (!req.session.pending2faUserId) return res.status(400).json({error: 'No pending login session'});
    const user = await User.findById(req.session.pending2faUserId);
    
    try {
        const verification = await verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge: req.session.currentChallenge,
            expectedOrigin: process.env.BASE_URL || `http://${req.headers.host}`,
            expectedRPID: process.env.BASE_URL ? new URL(process.env.BASE_URL).hostname : 'localhost',
            authenticator: {
                credentialPublicKey: Buffer.from(user.passkey.credentialPublicKey, 'base64url'),
                credentialID: Buffer.from(user.passkey.credentialID, 'base64url'),
                counter: user.passkey.counter,
            },
        });

        if (verification.verified) {
            // Update the counter to prevent replay attacks
            user.passkey.counter = verification.authenticationInfo.newCounter;
            await user.save();
            
            // Clean up session vars
            req.session.pending2faUserId = null;
            req.session.currentChallenge = null;
            
            // Login successful! Use centralized session finalization with JSON callback
            req.logIn(user, (err) => {
                if (err) return res.status(500).json({ success: false, error: err.message });
                
                // ✅ FIX: For passkey (JSON response), use a custom finalization
                let tempSession = req.session.passport;
                
                // Invalidate old session if exists
                if (user.currentSessionId && user.currentSessionId !== req.sessionID) {
                    try {
                        const sessionsCollection = mongoose.connection.collection('sessions');
                        sessionsCollection.updateOne(
                            { _id: user.currentSessionId },
                            { $set: { kickedOut: true } }
                        ).catch(err => console.error(`[Session] Failed to invalidate old session: ${err.message}`));
                        console.log(`[Session] Marked old session ${user.currentSessionId} as kickedOut for user ${user.username}`);
                    } catch (err) {
                        console.error(`[Session] Error invalidating old session: ${err.message}`);
                    }
                }
                
                // Regenerate session for new device
                req.session.regenerate((rErr) => {
                    if (rErr) return res.status(500).json({ success: false, error: 'Session error' });
                    
                    req.session.passport = tempSession;
                    user.currentSessionId = req.sessionID;
                    user.save().catch(err => console.error('User save error:', err));
                    
                    req.session.save((sErr) => {
                        if (sErr) console.error('Session save error:', sErr);
                        res.cookie('is_logged_in', 'true', { 
                            maxAge: 1000 * 60 * 60 * 24 * 3,
                            path: '/', 
                            secure: process.env.NODE_ENV === 'production', 
                            sameSite: 'lax'
                        });
                        res.json({ success: true, redirect: '/home?message=Login successful!' });
                    });
                });
            });
        } else {
            res.status(400).json({ success: false, error: 'Biometric verification failed' });
        }
    } catch (e) {
        console.error("Passkey Login Verify Error:", e);
        res.status(400).json({ success: false, error: e.message });
    }
});

// --- 3. 2FA Login Challenge ---
app.get('/login/2fa', async (req, res) => {
    if (!req.session.pending2faUserId) return res.redirect('/login');
    const user = await User.findById(req.session.pending2faUserId);
    res.render('pages/2fa-challenge', { method: user.twoFactorMethod, error: req.query.error });
});

app.post('/account/delete', ensureAuthenticated, async (req, res, next) => {
    try {
        const userId = req.user._id;
        const username = req.user.username;
        const preserveMods = req.body.preserveMods === 'true';

        // 1. DELETE AVATAR FROM CLOUD (Uses new dual-cloud helper)
        if (req.user.profileImageKey) {
            await deleteCloudFile(req.user.profileImageKey);
        }

        // 2. WIPE MODS & MOD DATA
        if (preserveMods) {
            // Keep the files, but anonymize the uploader
            await File.updateMany({ uploader: username }, { uploader: 'GPL Community' });
            
            // If they preserve mods, we must unset their "Uploader Replies" on comments
            const userFiles = await File.find({ uploader: 'GPL Community' }); 
            const fileIds = userFiles.map(f => f._id);
            await Review.updateMany({ file: { $in: fileIds } }, { $unset: { uploaderReply: 1 } });
            
        } else {
            // Delete EVERYTHING related to their mods from the Cloud and DB
            const userFiles = await File.find({ uploader: username }).populate('olderVersions');
            
            for (const f of userFiles) {
                // Delete main mod files from Cloud (B2 + FTP)
                await deleteCloudFile(f.fileKey);
                await deleteCloudFile(f.iconKey);
                
                if (f.screenshotKeys) {
                    for (const sk of f.screenshotKeys) {
                        await deleteCloudFile(sk);
                    }
                }
                
                // Delete older versions from Cloud and DB
                if (f.olderVersions) {
                    for (const ov of f.olderVersions) {
                        await deleteCloudFile(ov.fileKey);
                        await File.findByIdAndDelete(ov._id);
                    }
                }
                
                // Delete the file entry and its associated data
                await File.findByIdAndDelete(f._id);
                await Review.deleteMany({ file: f._id }); // Delete all reviews on their mods
                await Report.updateMany({ file: f._id }, { status: 'resolved' }); // Resolve reports
            }
        }

        // 3. DELETE THEIR PERSONAL REVIEWS/COMMENTS
        await Review.deleteMany({ user: userId });

        // 4. DELETE THEIR CHAT HISTORY FROM MEMORY
        recentMessages = recentMessages.filter(msg => msg.username !== username);

        // 5. NEWSLETTER UNSUBSCRIBE (Custom Local DB)
        try {
            const SubscriberModel = mongoose.models.Subscriber || require('./models/subscriber');
            if (SubscriberModel) {
                await SubscriberModel.deleteOne({ email: req.user.email.toLowerCase() });
                console.log(`Unsubscribed ${req.user.email} from newsletter during account deletion.`);
            }
        } catch (subErr) {
            console.error("Failed to delete subscriber record:", subErr);
        }

        // 6. DELETE THE USER ACCOUNT
        await User.findByIdAndDelete(userId);

        // 7. SECURE LOGOUT & COOKIE CLEAR
        req.logout(function(err) {
            if (err) return next(err);
            res.clearCookie('connect.sid', { path: '/' }); // Securely clear the session cookie
            res.redirect('/?message=Your account and all associated data have been permanently wiped.');
        });
        
    } catch (error) { 
        console.error("Deep Wipe Deletion Error:", error);
        return next(error); 
    }
});

// ===================================
// USER REWARDS & POINT HISTORY ROUTE
// ===================================
app.get('/rewards', ensureAuthenticated, async (req, res) => {
    try {
        // --- NEW: SILENT REFERRAL CODE BACKFILL ---
        // If an old user visits this page and doesn't have a code, generate one now.
        if (!req.user.referralCode) {
            console.log(`Backfilling referral code for old user: ${req.user.username}`);
            const newCode = await generateReferralCode(req.user.username);
            
            // Save it to the database
            await User.findByIdAndUpdate(req.user._id, { referralCode: newCode });
            
            // Crucial: Update the session object so the page renders correctly immediately
            req.user.referralCode = newCode;
            
            // Re-save the session to ensure it persists
            req.session.passport.user = req.user; 
            req.session.save();
        }
        // ------------------------------------------

        const currentPoints = req.user.forumPoints || 0;
        const history = await PointHistory.find({ user: req.user._id }).sort({ createdAt: -1 });

        // Define our Ranks and their thresholds
        const ranks = [
            { name: 'Novice', threshold: 0, color: '#FFFFFF', lottie: null },
            { name: 'Bronze Member', threshold: 25, color: '#cd7f32', lottie: 'level-1.json' },
            { name: 'Silver Expert', threshold: 100, color: '#c0c0c0', lottie: 'level-2.json' },
            { name: 'Gold Expert', threshold: 250, color: '#FFD700', lottie: 'level-3.json' },
            { name: 'Platinum Expert', threshold: 500, color: '#770087', lottie: 'level-4.json' },
            { name: 'Diamond Expert', threshold: 1000, color: '#003e54', lottie: 'level-5.json' }
        ];

        // Figure out current rank and the NEXT rank
        let currentRank = ranks[0];
        let nextRank = null;

        for (let i = ranks.length - 1; i >= 0; i--) {
            if (currentPoints >= ranks[i].threshold) {
                currentRank = ranks[i];
                nextRank = ranks[i + 1] || null; // Will be null if they are max rank
                break;
            }
        }

        // Calculate Progress Percentage for the Progress Bar
        let progressPercent = 100;
        let pointsNeeded = 0;

        if (nextRank) {
            const pointsRequiredForThisTier = nextRank.threshold - currentRank.threshold;
            const pointsEarnedInThisTier = currentPoints - currentRank.threshold;
            progressPercent = Math.floor((pointsEarnedInThisTier / pointsRequiredForThisTier) * 100);
            pointsNeeded = nextRank.threshold - currentPoints;
        }

        res.render('pages/rewards', { 
            history, 
            currentRank, 
            nextRank, 
            progressPercent, 
            pointsNeeded, 
            currentPoints 
        });

    } catch (error) {
        console.error("Rewards Page Error:", error);
        res.status(500).render('pages/500');
    }
});

// ===================================
// 7. FILE UPLOAD & MANAGEMENT
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
        return next(error);
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
            return next(error);
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
        return next(error);
    }
}); // <--- ADD THIS CLOSING BRACE AND PARENTHESIS HERE

app.get('/upload-details/:fileId', ensureAuthenticated, async (req, res) => {
    try {
        const fileId = req.params.fileId;
        const pendingFile = await File.findById(fileId);

        if (!pendingFile) return next(error);
        if (pendingFile.uploader !== req.user.username) return res.status(403).render('pages/403');

        const filename = pendingFile.originalFilename || "";
        
        const ext = filename.split('.').pop().toLowerCase();
        let defaultPlatform = "";
        if (ext === 'apk' || ext === 'xapk' || ext === 'apks') defaultPlatform = 'android';
        else if (ext === 'exe' || ext === 'msi') defaultPlatform = 'windows';
        else if (ext === 'ipa') defaultPlatform = 'ios-jailed';
        else if (ext === 'deb') defaultPlatform = 'ios-jailbroken';
        else if (ext === 'zip') defaultPlatform = 'wordpress'; 
        // ======== NEW: AUTO-DETECT DROPBOX LINK ========
        if (pendingFile.externalDownloadUrl && pendingFile.externalDownloadUrl.toLowerCase().includes('dropbox.com')) {
            defaultPlatform = 'ios-jailed';
        }

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
            defaultPlatform: defaultPlatform,
            file: pendingFile
        });

    } catch (error) {
        console.error("Error loading upload details:", error);
        return next(error);
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
        // ✅ ADDED: Delete images from BOTH clouds before deleting DB record
        await deleteCloudFile(file.iconKey);
        if (file.screenshotKeys) {
            for (const key of file.screenshotKeys) {
                await deleteCloudFile(key);
            }
        }

        // Delete the file and its associated reviews/reports from the database
        await File.findByIdAndDelete(fileId);

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

        // --- INDEXNOW PING (DELETION) ---
        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        const deadUrl = `${baseUrl}/${encodeURIComponent(file.category)}/${encodeURIComponent(file.slug || file._id.toString())}`;
        notifyIndexNow([deadUrl]); // Tell Google this link is dead now
        notifyGoogle(deadUrl, 'URL_DELETED'); // Tell Google to REMOVE this from search results!

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
        return next(error);
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
        // ======== VALIDATION CHECK ========
        if (formData.modName && !isValidName(formData.modName)) {
            return res.redirect(`/mods/${file._id}/edit?error=Mod Name can only contain letters, numbers, and spaces.`);
        }
        // ===========================================

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
        // --- NEW: Update dependencies on edit ---
        file.minOsVersion = formData.minOsVersion !== undefined ? formData.minOsVersion : file.minOsVersion;
        if (formData.architectures !== undefined) {
            file.architectures = Array.isArray(formData.architectures) ? formData.architectures : [formData.architectures];
        }
        if (formData.directDownloadUrl !== undefined) {
            file.directDownloadUrl = formData.directDownloadUrl;
        }
        // ✅ ADDED: Update the Package ID on edit
        if (formData.iosPackageId !== undefined) {
            file.iosPackageId = formData.iosPackageId;
        }
        file.tags = processedTags;
        // --- NEW: UPDATE MANUAL SCANS (allow clearing them) ---
        if (formData.manualFileScanUrl !== undefined) file.manualFileScanUrl = formData.manualFileScanUrl;
        if (formData.manualSiteScanUrl !== undefined) file.manualSiteScanUrl = formData.manualSiteScanUrl;
        
        // ✅ FIX: Added "file." to save it properly, and replaced the comma with a semicolon!
        file.ageRating = req.body.ageRating || file.ageRating; 
        
        if (formData.modCategory) {
            file.platforms =[formData.modCategory];
        }

        // --- MULTI-PART ARRAY PARSING LOGIC (Edit Route) ---
        try {
            const editIsMultiPart = (formData.isMultiPart === 'true' || formData.isMultiPart === true);
            const editDownloadParts = [];

            if (editIsMultiPart && (formData.partUrls || formData.partNames)) {
                const pNames = Array.isArray(formData.partNames) ? formData.partNames : (formData.partNames ? [formData.partNames] : []);
                const pUrls = Array.isArray(formData.partUrls) ? formData.partUrls : (formData.partUrls ? [formData.partUrls] : []);
                const m1Prov = Array.isArray(formData.mirror1Providers) ? formData.mirror1Providers : (formData.mirror1Providers ? [formData.mirror1Providers] : []);
                const m1Url = Array.isArray(formData.mirror1Urls) ? formData.mirror1Urls : (formData.mirror1Urls ? [formData.mirror1Urls] : []);
                const m2Prov = Array.isArray(formData.mirror2Providers) ? formData.mirror2Providers : (formData.mirror2Providers ? [formData.mirror2Providers] : []);
                const m2Url = Array.isArray(formData.mirror2Urls) ? formData.mirror2Urls : (formData.mirror2Urls ? [formData.mirror2Urls] : []);
                const daLink = Array.isArray(formData.directAdminLinks) ? formData.directAdminLinks : (formData.directAdminLinks ? [formData.directAdminLinks] : []);
                const mfScan = Array.isArray(formData.manualFileScanUrls) ? formData.manualFileScanUrls : (formData.manualFileScanUrls ? [formData.manualFileScanUrls] : []);
                const msScan = Array.isArray(formData.manualSiteScanUrls) ? formData.manualSiteScanUrls : (formData.manualSiteScanUrls ? [formData.manualSiteScanUrls] : []);

                const len = Math.max(pUrls.length, pNames.length);
                for (let i = 0; i < len; i++) {
                    if (!pUrls[i]) continue;
                    editDownloadParts.push({
                        partName: pNames[i] || `Part ${i + 1}`,
                        partUrl: pUrls[i],
                        mirror1Provider: m1Prov[i] || '',
                        mirror1Url: m1Url[i] || '',
                        mirror2Provider: m2Prov[i] || '',
                        mirror2Url: m2Url[i] || '',
                        directAdminLink: daLink[i] || '',
                        manualFileScanUrl: mfScan[i] || '',
                        manualSiteScanUrl: msScan[i] || '',
                        partVirusTotalId: '',
                        partVirusTotalScanDate: null,
                        partVirusTotalPositiveCount: 0,
                        partVirusTotalTotalScans: 0
                    });
                }
            }

            // Apply parsed multipart data to the file model
            file.isMultiPart = editIsMultiPart;
            if (editDownloadParts.length > 0) file.downloadParts = editDownloadParts;
        } catch (e) {
            console.error('Multipart parsing error (edit):', e);
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
        // --- INDEXNOW PING ---
        // Tell search engines the mod has been updated!
        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        const modUrl = `${baseUrl}/${encodeURIComponent(file.category)}/${encodeURIComponent(file.slug || file._id.toString())}`;
        // Fire and forget (don't await it so it doesn't slow down the user's redirect)
        notifyIndexNow([modUrl]);
        notifyGoogle(modUrl, 'URL_UPDATED'); // Tell Google the page changed!
        
        if (actionType === 'draft') {
             res.redirect(`/mods/${file._id}/edit?success=Draft saved successfully. This mod is now hidden from the public until you submit it.`);
        } else {
             res.redirect('/my-uploads?success=Mod updated successfully!');
        }

    } catch (error) {
        console.error("Error updating mod:", error);
        return next(error);
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
        // ======== ADD THIS VALIDATION CHECK ========
        if (!isValidName(formData.modName)) {
            return res.redirect(`/upload-details/${fileId}?error=Mod Name can only contain letters, numbers, and spaces. No emojis.`);
        }
        // ===========================================

        let iconKey = fileToUpdate.iconKey; // Keep existing if not updating
        let screenshotKeys = fileToUpdate.screenshotKeys || [];
        const processedTags = formData.tags ? formData.tags.split(',').map(t => t.trim()) : [];
        // --- NEW: Parse architectures safely (can be string or array) ---
        const archData = formData.architectures ? (Array.isArray(formData.architectures) ? formData.architectures : [formData.architectures]) :[];

        // --- PROCESS IMAGES ---
        if (!isVariant && softwareIcon && softwareIcon.length > 0) {
            iconKey = await uploadToB2(softwareIcon[0], 'icons');
        }
        if (screenshots && screenshots.length > 0) {
            screenshotKeys = await Promise.all(screenshots.map(f => uploadToB2(f, 'screenshots')));
        }

        // --- MULTI-PART ARRAY PARSING LOGIC ---
        let isMultiPart = (formData.isMultiPart === 'true' || formData.isMultiPart === true);
        let downloadParts = [];

        if (isMultiPart && (formData.partUrls || formData.partNames)) {
            const pNames = Array.isArray(formData.partNames) ? formData.partNames : (formData.partNames ? [formData.partNames] : []);
            const pUrls = Array.isArray(formData.partUrls) ? formData.partUrls : (formData.partUrls ? [formData.partUrls] : []);
            const m1Prov = Array.isArray(formData.mirror1Providers) ? formData.mirror1Providers : (formData.mirror1Providers ? [formData.mirror1Providers] : []);
            const m1Url = Array.isArray(formData.mirror1Urls) ? formData.mirror1Urls : (formData.mirror1Urls ? [formData.mirror1Urls] : []);
            const m2Prov = Array.isArray(formData.mirror2Providers) ? formData.mirror2Providers : (formData.mirror2Providers ? [formData.mirror2Providers] : []);
            const m2Url = Array.isArray(formData.mirror2Urls) ? formData.mirror2Urls : (formData.mirror2Urls ? [formData.mirror2Urls] : []);
            const daLink = Array.isArray(formData.directAdminLinks) ? formData.directAdminLinks : (formData.directAdminLinks ? [formData.directAdminLinks] : []);
            const mfScan = Array.isArray(formData.manualFileScanUrls) ? formData.manualFileScanUrls : (formData.manualFileScanUrls ? [formData.manualFileScanUrls] : []);
            const msScan = Array.isArray(formData.manualSiteScanUrls) ? formData.manualSiteScanUrls : (formData.manualSiteScanUrls ? [formData.manualSiteScanUrls] : []);

            const len = Math.max(pUrls.length, pNames.length);
            for (let i = 0; i < len; i++) {
                if (!pUrls[i]) continue; // skip empty parts
                downloadParts.push({
                    partName: pNames[i] || `Part ${i + 1}`,
                    partUrl: pUrls[i],
                    mirror1Provider: m1Prov[i] || '',
                    mirror1Url: m1Url[i] || '',
                    mirror2Provider: m2Prov[i] || '',
                    mirror2Url: m2Url[i] || '',
                    directAdminLink: daLink[i] || '',
                    manualFileScanUrl: mfScan[i] || '',
                    manualSiteScanUrl: msScan[i] || '',
                    partVirusTotalId: '',
                    partVirusTotalScanDate: null,
                    partVirusTotalPositiveCount: 0,
                    partVirusTotalTotalScans: 0
                });
            }
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
            let baseSlug = slugify(cleanName);
            finalSlug = baseSlug;
            let slugCounter = 1;
            while (await File.findOne({ slug: finalSlug, category: formData.modPlatform, isLatestVersion: true, _id: { $ne: fileId } })) {
                finalSlug = `${baseSlug}-${slugCounter}`;
                slugCounter++;
            }
        }

        // --- NEW: Sanitize Mod Details ---
        const cleanName = global.profanityFilter.clean(formData.modName);
        const cleanDescription = global.profanityFilter.clean(formData.modDescription);
        const cleanFeatures = global.profanityFilter.clean(formData.modFeatures || '');
        const cleanWhatsNew = global.profanityFilter.clean(formData.whatsNew || '');
        // --- SET FINAL STATUS ---
        // If saving a draft, keep it in 'processing' mode so it stays in their uploads list
        // but doesn't show up in the Admin's "Pending Review" queue yet.
        const finalStatus = actionType === 'draft' ? 'draft' : 'pending';

        // --- SAVE TO DATABASE ---
        const updateData = {
            name: cleanName, // Use clean name || fileToUpdate.name, 
            version: formData.modVersion || fileToUpdate.version,
            modFeatures: formData.modFeatures,
            modDescription: cleanDescription, // Use clean description
            modFeatures: cleanFeatures,       // Use clean features
            whatsNew: cleanWhatsNew,          // Use clean what's new
            developer: formData.developerName || 'N/A',
            screenshotKeys: screenshotKeys.length > 0 ? screenshotKeys : fileToUpdate.screenshotKeys,
            videoUrl: formData.videoUrl, 
            tags: processedTags,
            ageRating: req.body.ageRating,
            // --- NEW: SAVE MANUAL SCANS ---
            manualFileScanUrl: formData.manualFileScanUrl,
            manualSiteScanUrl: formData.manualSiteScanUrl,

            
            // Update categories if provided, otherwise keep existing (which might be empty string)
            category: formData.modPlatform || fileToUpdate.category,
            platforms: formData.modCategory ? [formData.modCategory] : fileToUpdate.platforms,
            directDownloadUrl: formData.directDownloadUrl || '',
            // --- NEW: Save dependencies ---
            architectures: archData,
            minOsVersion: formData.minOsVersion || '',
            // ✅ ADDED: Save the Package ID
            iosPackageId: formData.iosPackageId || '',
            // ------------------------------          
            status: finalStatus // 'processing' (draft) or 'pending' (submitted)
        };

        // Attach multipart fields when present
        updateData.isMultiPart = isMultiPart;
        if (downloadParts && downloadParts.length > 0) updateData.downloadParts = downloadParts;

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
        // ======== NEW: AWARD POINTS FOR UPLOADING ========
        // Give the user 50 points for contributing a mod!
        await User.adjustForumPoints(req.user._id, 50, "Uploaded a new mod");
            res.redirect('/my-uploads?success=Upload complete and submitted for review!');
        }

    } catch (error) {
        console.error("Finalize upload error:", error);
        return next(error);
    }
});

// ===================================
// 8. API ROUTES
// ===================================
// --- SMART TRANSLATION API WITH CACHING & FREE-TIER SAFEGUARDS ---
app.post('/api/translate', async (req, res) => {
    try {
        const { texts, targetLanguage } = req.body;

        if (!texts || !Array.isArray(texts) || texts.length === 0 || !targetLanguage) {
            return res.status(400).json({ error: "Invalid request payload." });
        }

        if (targetLanguage === 'en') {
            return res.json({ translations: texts });
        }

        const finalTranslations = [];
        const textsToTranslate = [];
        const indicesToTranslate = [];

        // 1. Check the Database Cache First (Costs $0)
        for (let i = 0; i < texts.length; i++) {
            const text = texts[i];
            
            if (!text.trim() || !isNaN(text.trim())) {
                finalTranslations[i] = text;
                continue;
            }

            const cached = await TranslationCache.findOne({ originalText: text, targetLanguage: targetLanguage });

            if (cached) {
                finalTranslations[i] = cached.translatedText; // Use free cached translation
            } else {
                textsToTranslate.push(text);
                indicesToTranslate.push(i);
            }
        }

        // 2. Safely Call Google API for missing texts
        if (textsToTranslate.length > 0) {
            // Count exactly how many characters we are about to ask Google to translate
            const newCharsLength = textsToTranslate.join('').length;
            
            // Get current month string (e.g., "2026-06")
            const currentMonthYear = new Date().toISOString().slice(0, 7);
            
            // Find or create the quota record for this month
            let quota = await TranslationQuota.findOne({ monthYear: currentMonthYear });
            if (!quota) {
                quota = new TranslationQuota({ monthYear: currentMonthYear, characterCount: 0 });
            }

            const FREE_TIER_LIMIT = 500000; // 500,000 characters

            // --- THE FAILSAFE CHECK ---
            if (quota.characterCount + newCharsLength <= FREE_TIER_LIMIT) {
                // We have enough free quota! Send to Google.
                const [apiTranslations] = await translateClient.translate(textsToTranslate, targetLanguage);
                
                const newCacheEntries = [];

                for (let j = 0; j < apiTranslations.length; j++) {
                    const original = textsToTranslate[j];
                    const translated = apiTranslations[j];
                    
                    finalTranslations[indicesToTranslate[j]] = translated;

                    newCacheEntries.push({
                        originalText: original,
                        targetLanguage: targetLanguage,
                        translatedText: translated
                    });
                }

                // Save to cache so we never pay for these words again
                if (newCacheEntries.length > 0) {
                    await TranslationCache.insertMany(newCacheEntries, { ordered: false }).catch(e => {});
                }

                // Update the monthly usage counter
                quota.characterCount += newCharsLength;
                await quota.save();

            } else {
                // --- LIMIT REACHED: FAIL GRACEFULLY ---
                console.warn(`[TRANSLATION LIMIT] Stopped API call. Used: ${quota.characterCount}/${FREE_TIER_LIMIT}. Tried to add: ${newCharsLength}`);
                
                // Instead of crashing, just return the original English text for the missing chunks
                for (let j = 0; j < textsToTranslate.length; j++) {
                    finalTranslations[indicesToTranslate[j]] = textsToTranslate[j];
                }
            }
        }

        res.json({ translations: finalTranslations });

    } catch (error) {
        console.error("Translation API Error:", error);
        res.status(500).json({ error: "Translation failed." });
    }
});
// --- NEW: SMART TRANSLATION API WITH DB CACHING ---
app.post('/api/translate', async (req, res) => {
    try {
        const { texts, targetLanguage } = req.body;

        if (!texts || !Array.isArray(texts) || texts.length === 0 || !targetLanguage) {
            return res.status(400).json({ error: "Invalid request payload." });
        }

        if (targetLanguage === 'en') {
            return res.json({ translations: texts }); // No translation needed for default
        }

        const finalTranslations = [];
        const textsToTranslate = [];
        const indicesToTranslate = [];

        // 1. Check the Database Cache First
        for (let i = 0; i < texts.length; i++) {
            const text = texts[i];
            
            // Skip empty or purely numeric strings
            if (!text.trim() || !isNaN(text.trim())) {
                finalTranslations[i] = text;
                continue;
            }

            const cached = await TranslationCache.findOne({ 
                originalText: text, 
                targetLanguage: targetLanguage 
            });

            if (cached) {
                // We have it in the DB! Free translation!
                finalTranslations[i] = cached.translatedText;
            } else {
                // We need to ask Google for this one
                textsToTranslate.push(text);
                indicesToTranslate.push(i);
            }
        }

        // 2. Call Google API for missing texts
        if (textsToTranslate.length > 0) {
            // Google Translate accepts an array of strings
            const [apiTranslations] = await translateClient.translate(textsToTranslate, targetLanguage);
            
            const newCacheEntries = [];

            for (let j = 0; j < apiTranslations.length; j++) {
                const original = textsToTranslate[j];
                const translated = apiTranslations[j];
                
                // Map the new translation back to its correct index in the final array
                finalTranslations[indicesToTranslate[j]] = translated;

                // Prepare to save to database
                newCacheEntries.push({
                    originalText: original,
                    targetLanguage: targetLanguage,
                    translatedText: translated
                });
            }

            // 3. Save new translations to Database Cache in bulk
            if (newCacheEntries.length > 0) {
                // Use insertMany with ordered:false to silently ignore accidental duplicates
                await TranslationCache.insertMany(newCacheEntries, { ordered: false }).catch(e => {
                    // Ignore duplicate key errors, it just means another request cached it first
                });
            }
        }

        // Return the fully translated array
        res.json({ translations: finalTranslations });

    } catch (error) {
        console.error("Translation API Error:", error);
        res.status(500).json({ error: "Translation failed." });
    }
});
// --- NEW: AUTO-FETCH METADATA SCRAPER API ---
app.post('/api/fetch-metadata', ensureAuthenticated, async (req, res) => {
    try {
        const { url, platform } = req.body;
        
        if (!url || !platform) {
            return res.status(400).json({ error: "URL and platform are required." });
        }

        // We use a generic browser User-Agent so stores don't block the request
        const axiosConfig = {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' },
            timeout: 8000 // 8 second timeout
        };

        const response = await axios.get(url, axiosConfig);
        const $ = cheerio.load(response.data);

        let data = {
            description: '',
            whatsNew: '',
            minOsVersion: '',
            ageRating: '',
            developer: ''
        };

        // --- SCRAPING LOGIC BASED ON PLATFORM ---
        if (platform === 'playstore') {
            // Google Play Store
            data.description = $('meta[name="description"]').attr('content') || '';
            data.developer = $('a.LkLjBd span').first().text() || '';
            
            // "What's New" is tricky on Play Store, usually in a specific div
            $("div").each((i, el) => {
                const text = $(el).text();
                if (text.includes("Requires Android")) data.minOs = text.replace("Requires Android", "").trim();
                if (text.includes("Content Rating")) data.ageRating = $(el).next().text().trim() || 'Everyone';
            });

        } else if (platform === 'appstore') {
            // Apple App Store
            data.description = $('.section__description p').text() || $('meta[name="description"]').attr('content') || '';
            data.whatsNew = $('.whats-new__content p').text() || '';
            data.developer = $('h2.product-header__identity a').text().trim() || '';
            data.minOsVersion = $('dt:contains("Compatibility")').next('dd').text().trim().replace(/Requires iOS|Requires iPadOS/, 'iOS ') || 'iOS 11.0 or later';
            data.ageRating = $('dt:contains("Age Rating")').next('dd').text().trim() || '4+';

        } else if (platform === 'steam') {
            // Steam
            data.description = $('.game_description_snippet').text().trim() || $('meta[name="description"]').attr('content') || '';
            data.developer = $('#developers_list a').first().text().trim() || '';
            data.minOsVersion = $('.sysreq_contents .bb_ul li:contains("OS:")').text().replace("OS:", "").trim() || 'Windows 10';

        } else {
            // Fallback for Epic Games, WordPress, etc (Rely on meta tags)
            data.description = $('meta[property="og:description"]').attr('content') || $('meta[name="description"]').attr('content') || '';
            data.developer = $('meta[property="og:site_name"]').attr('content') || '';
        }

        // Clean up the data
        Object.keys(data).forEach(key => {
            if (data[key]) data[key] = data[key].trim().replace(/\s{2,}/g, ' ');
        });

        res.json({ success: true, data });

    } catch (error) {
        console.error("Scraping Error:", error.message);
        res.status(500).json({ error: "Failed to fetch data. Make sure the URL is correct and public." });
    }
});
// ===================================
// 9.2 ADMIN: BULK INDEXNOW & GOOGLE SYNC
// ===================================
app.get('/api/admin/indexnow-sync', ensureAuthenticated, ensureAdmin, async (req, res) => {
    try {
        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        let urlsToPing =[];

        // 1. Static Pages
        const staticPages =['', '/login', '/register', '/about', '/faq', '/dmca', '/tos', '/privacy-policy', '/donate'];
        staticPages.forEach(page => {
            urlsToPing.push(`${baseUrl}${page}`);
        });

        // 2. Category Pages
        const categories =['android', 'ios-jailed', 'ios-jailbroken', 'windows', 'wordpress'];
        categories.forEach(cat => {
             urlsToPing.push(`${baseUrl}/category?platform=${encodeURIComponent(cat)}`);
        });

        // 3. Live Mods
        const liveMods = await File.find({ showInSitemap: { $ne: false }, isLatestVersion: true, status: 'live' }).select('category slug _id').lean();
        liveMods.forEach(mod => {
            const safeCategory = encodeURIComponent(mod.category);
            const safeSlug = encodeURIComponent(mod.slug || mod._id.toString());
            urlsToPing.push(`${baseUrl}/${safeCategory}/${safeSlug}`);
        });

        // 4. Developer Pages
        const uniqueDevelopers = await File.distinct('developer', { status: 'live', isLatestVersion: true }).lean();
        uniqueDevelopers.forEach(dev => {
            if (dev && dev !== 'N/A') {
                urlsToPing.push(`${baseUrl}/developer?name=${encodeURIComponent(dev)}`);
            }
        });

        // 5. Public User Profiles
        const uniqueUploaders = await File.distinct('uploader', { status: 'live', isLatestVersion: true }).lean();
        uniqueUploaders.forEach(uploader => {
             urlsToPing.push(`${baseUrl}/users/${encodeURIComponent(uploader)}`);
        });

        // --- Execute IndexNow Ping (Bulk) ---
        // IndexNow can handle thousands of URLs at once
        const CHUNK_SIZE = 9500; 
        for (let i = 0; i < urlsToPing.length; i += CHUNK_SIZE) {
            const chunk = urlsToPing.slice(i, i + CHUNK_SIZE);
            await notifyIndexNow(chunk);
        }

        // --- Execute Google Indexing Ping (Sequential) ---
        // WARNING: DO NOT RUN THIS IF YOU HAVE > 200 URLS
        // --- Execute Google Indexing Ping (Sequential) ---
        let googleSuccessCount = 0;
        let googleFailCount = 0;

        (async () => {
            console.log(`[Google Sync] Starting bulk sync of ${urlsToPing.length} URLs...`);
            for (let i = 0; i < urlsToPing.length; i++) {
                try {
                    // Safety check: ensure jwtClient is configured before attempting
                    if (!jwtClient) {
                        throw new Error("No key or keyFile set.");
                    }
                    
                    await jwtClient.authorize();
                    await google.indexing('v3').urlNotifications.publish({
                        auth: jwtClient,
                        requestBody: { url: urlsToPing[i], type: 'URL_UPDATED' }
                    });
                    
                    console.log(`[Google] Successfully pinged: ${urlsToPing[i]}`);
                    googleSuccessCount++;
                    await new Promise(resolve => setTimeout(resolve, 250));
                    
                } catch (err) {
                    // Track the failure!
                    googleFailCount++;
                    console.error(`[Google Error] Failed for ${urlsToPing[i]}:`, err.message);
                    
                    if (err.response && err.response.status === 429) {
                        console.error("[Google Sync] HALTED: Daily Quota Exceeded (200 requests/day).");
                        break; 
                    }
                }
            }
            console.log(`[Google Sync] Finished. Success: ${googleSuccessCount}, Failed: ${googleFailCount}`);
        })();

        res.json({ 
            success: true, 
            message: `Successfully pushed ${urlsToPing.length} URLs to IndexNow. Google sync has started in the background (Warning: Google limits to 200 requests/day).`,
            totalUrls: urlsToPing.length,
            urls: urlsToPing 
        });

    } catch (error) {
        console.error("Bulk Sync Error:", error);
        res.status(500).json({ success: false, error: 'Failed to sync with search engines.' });
    }
});

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
        // ======== VALIDATION CHECK ========
        if (!isValidName(requestedName)) {
            return res.json({ 
                available: false, 
                message: 'Letters, numbers, and spaces only. No emojis.' 
            });
        }
        // ===========================================

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
                return res.json({ message: 'Welcome back! You have been successfully re subscribed.' });
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
// 9.5  VIRUSTOTAL REFRESH ROUTE (SMART FIX)
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
// 9.6 VIRUSTOTAL REFRESH ROUTE (MULTI-PART)
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
// 10. SOCIAL & ADMIN INTERACTION
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

        // Sanitize the comment
        const cleanComment = global.profanityFilter.clean(req.body.comment);
        const newReview = new Review({ file: req.params.fileId, user: req.user._id, username: req.user.username, rating: parseInt(rating), comment: cleanComment });
        await newReview.save();
        // ======== NEW: AWARD POINTS FOR WRITING A REVIEW ========
        await User.adjustForumPoints(req.user._id, 20, "Wrote a detailed review");
        // ========================================================
        
        const stats = await Review.aggregate([{ $match: { file: new Types.ObjectId(req.params.fileId) } }, { $group: { _id: '$file', avg: { $avg: '$rating' }, count: { $sum: 1 } } }]);
        if (stats.length > 0) {
            await File.findByIdAndUpdate(req.params.fileId, { averageRating: stats[0].avg.toFixed(1), ratingCount: stats[0].count });
        }
        res.redirect(`/mods/${req.params.fileId}`);
    } catch (e) { res.status(500).send("Error."); }
});
// --- HELPER to recalculate ratings ---
async function recalculateRating(fileId) {
    const stats = await Review.aggregate([{ $match: { file: new Types.ObjectId(fileId) } }, { $group: { _id: '$file', avg: { $avg: '$rating' }, count: { $sum: 1 } } }]);
    if (stats.length > 0) {
        await File.findByIdAndUpdate(fileId, { averageRating: stats[0].avg.toFixed(1), ratingCount: stats[0].count });
    } else {
        await File.findByIdAndUpdate(fileId, { averageRating: 0, ratingCount: 0 });
    }
}

// 1. User Deletes their own comment
app.post('/reviews/:id/delete', ensureAuthenticated, async (req, res) => {
    try {
        const review = await Review.findById(req.params.id);
        if (!review || review.user.toString() !== req.user._id.toString()) return res.status(403).send("Unauthorized");
        
        await Review.findByIdAndDelete(review._id);
        await recalculateRating(review.file);
        await User.adjustForumPoints(review.user, -20, "Deleted your mod review");
        res.redirect('back');
    } catch (e) { res.status(500).send("Error"); }
});

// 2. User Edits their own comment
app.post('/reviews/:id/edit', ensureAuthenticated, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        const review = await Review.findById(req.params.id);
        if (!review || review.user.toString() !== req.user._id.toString()) return res.status(403).send("Unauthorized");
        
        review.rating = parseInt(rating);
        review.comment = comment;
        await review.save();
        await recalculateRating(review.file);
        res.redirect('back');
    } catch (e) { res.status(500).send("Error"); }
});

// 3. Uploader Replies to a comment
app.post('/reviews/:id/reply', ensureAuthenticated, async (req, res) => {
    try {
        const review = await Review.findById(req.params.id).populate('file');
        if (!review || review.file.uploader !== req.user.username) return res.status(403).send("Unauthorized");

        const hadReply = review.uploaderReply && review.uploaderReply.text;
        review.uploaderReply = { text: req.body.replyText, createdAt: new Date() };
        await review.save();
        if (!hadReply) {
            await User.adjustForumPoints(req.user._id, 10, "Replay to a community member");
        }
        res.redirect('back');
    } catch (e) { res.status(500).send("Error"); }
});

// 4. Uploader Deletes their reply
app.post('/reviews/:id/reply/delete', ensureAuthenticated, async (req, res) => {
    try {
        const review = await Review.findById(req.params.id).populate('file');
        if (!review || review.file.uploader !== req.user.username) return res.status(403).send("Unauthorized");

        review.uploaderReply = undefined; // Unset the reply
        await review.save();
        res.redirect('back');
    } catch (e) { res.status(500).send("Error"); }
});
app.post('/reviews/:reviewId/vote', ensureAuthenticated, async (req, res) => {
    try {
        const reviewId = req.params.reviewId;
        const userId = req.user._id;

        const review = await Review.findById(reviewId);
        if (!review) return res.status(404).send("Review not found.");

        if (review.votedBy.includes(userId)) {
            return res.redirect(`/mods/${review.file}`);
        }

        review.votedBy.push(userId);
        review.isHelpfulCount += 1;
        await review.save();

        // ======== NEW: REWARD THE AUTHOR OF THE HELPFUL REVIEW ========
        // Notice we are updating 'review.user', NOT 'req.user._id'
        await User.adjustForumPoints(review.user, 10, "Vote a mod");
        res.redirect(`/mods/${review.file}`);

    } catch (error) {
        console.error('Error processing review vote:', error);
        res.status(500).send("Server Error");
    }
});

// ===================================
// FILE STATUS VOTING ROUTE (SMART TOGGLE)
// ===================================
app.post('/files/:fileId/vote-status', ensureAuthenticated, async (req, res) => {
    try {
        const fileId = req.params.fileId;
        const userId = req.user._id;
        const { voteType } = req.body; // 'working' or 'not-working'

        if (!['working', 'not-working'].includes(voteType)) {
            return res.status(400).send("Invalid vote type.");
        }
        
        const file = await File.findById(fileId);
        if (!file) return res.status(404).send("File not found.");
        
        // Check current voting status
        const votedWorkingBy = Array.isArray(file.votedWorkingBy) ? file.votedWorkingBy : [];
        const votedNotWorkingBy = Array.isArray(file.votedNotWorkingBy) ? file.votedNotWorkingBy : [];

        const hasVotedWorking = votedWorkingBy.includes(userId);
        const hasVotedNotWorking = votedNotWorkingBy.includes(userId);
        const hasPreviouslyVotedStatus = hasVotedWorking || hasVotedNotWorking;

        let updateQuery = {};

        // SCENARIO 1: User clicked "Working"
        if (voteType === 'working') {
            if (hasVotedWorking) {
                // TOGGLE OFF: They already voted working, so remove their vote
                updateQuery = {
                    $pull: { votedWorkingBy: userId },
                    $inc: { workingVoteCount: -1 }
                };
            } else {
                // ADD VOTE: Add to working, and if they previously voted not-working, remove that
                updateQuery = {
                    $push: { votedWorkingBy: userId },
                    $inc: { workingVoteCount: 1 }
                };
                if (hasVotedNotWorking) {
                    updateQuery.$pull = { votedNotWorkingBy: userId };
                    updateQuery.$inc.notWorkingVoteCount = -1;
                }
            }
        }

        // SCENARIO 2: User clicked "Not Working"
        else if (voteType === 'not-working') {
            if (hasVotedNotWorking) {
                // TOGGLE OFF: They already voted not-working, so remove their vote
                updateQuery = {
                    $pull: { votedNotWorkingBy: userId },
                    $inc: { notWorkingVoteCount: -1 }
                };
            } else {
                // ADD VOTE: Add to not-working, and if they previously voted working, remove that
                updateQuery = {
                    $push: { votedNotWorkingBy: userId },
                    $inc: { notWorkingVoteCount: 1 }
                };
                if (hasVotedWorking) {
                    updateQuery.$pull = { votedWorkingBy: userId };
                    updateQuery.$inc.workingVoteCount = -1;
                }
            }
        }

        // Execute the smart update
        await File.findByIdAndUpdate(fileId, updateQuery);

        const isVoteRemoval = (voteType === 'working' && hasVotedWorking) || (voteType === 'not-working' && hasVotedNotWorking);
        const isVoteAdd = (voteType === 'working' && !hasVotedWorking) || (voteType === 'not-working' && !hasVotedNotWorking);

        if (isVoteRemoval) {
            await User.adjustForumPoints(req.user._id, -5, "Remove your vote from a mod");
        } else if (isVoteAdd && !hasPreviouslyVotedStatus) {
            await User.adjustForumPoints(req.user._id, 5, "Voted a mod");
        }

        return res.redirect(`/mods/${fileId}`);
    } catch (error) {
        console.error("Error processing file status vote:", error);
        return res.status(500).send("Server Error");
    }
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
// --- NEW: Secure Signed URL Generator for AdminJS ---
// Only accessible by Admins. Used by custom React components to view private images.
app.get('/api/admin/signed-url', ensureAuthenticated, ensureAdmin, async (req, res) => {
    try {
        const key = req.query.key;
        if (!key) {
            return res.status(400).json({ error: 'No key provided.' });
        }

        // Use our existing smart helper! It already knows how to handle external URLs vs B2 keys.
        const signedUrl = await getSmartImageUrl(key);
        
        res.json({ url: signedUrl });
    } catch (error) {
        console.error("Error generating signed URL for AdminJS:", error);
        res.status(500).json({ error: 'Failed to generate URL.' });
    }
});

app.post('/admin/reports/delete-file/:fileId', ensureAuthenticated, ensureAdmin, async (req, res) => {
    await File.findByIdAndDelete(req.params.fileId);
    await Review.deleteMany({ file: req.params.fileId });
    await Report.updateMany({ file: req.params.fileId }, { status: 'resolved' });
    res.redirect('/admin/reports');
});

app.get('/community-chat', ensureAuthenticated, (req, res) => res.render('pages/community-chat'));
// ===================================
// 11 USER FOLLOW SYSTEM
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
            await User.adjustForumPoints(targetUserId, -10, "Unfollow user");
        } else {
            // FOLLOW LOGIC
            await User.findByIdAndUpdate(currentUserId, { $push: { following: targetUserId } });
            await User.findByIdAndUpdate(targetUserId, { $push: { followers: currentUserId } });
            await User.adjustForumPoints(targetUserId, 10, "Follow a new user");
            
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
// ===================================
// 12 LEADERBOARD ROUTE (UPDATED)
// ===================================
app.get('/leaderboard', async (req, res) => {
    try {
        const category = req.query.category || 'uploaders'; 
        const timeframe = req.query.timeframe || 'all-time'; 

        let dateFilter = {};
        const now = new Date();
        if (timeframe === 'daily') {
            dateFilter = { createdAt: { $gte: new Date(now.setDate(now.getDate() - 1)) } };
        } else if (timeframe === 'weekly') {
            dateFilter = { createdAt: { $gte: new Date(now.setDate(now.getDate() - 7)) } };
        } else if (timeframe === 'monthly') {
            dateFilter = { createdAt: { $gte: new Date(now.setMonth(now.getMonth() - 1)) } };
        }

        let results =[];
        let totalCount = 0; // NEW: To store the total number of participants
        let totalLabel = ""; // NEW: To label the count (e.g., "Total Uploaders")

        if (category === 'uploaders') {
            const pipeline =[
                { $match: { status: 'live', ...dateFilter } },
                { $group: { _id: '$uploader', count: { $sum: 1 } } },
                { $sort: { count: -1 } }
            ];
            const rawUploaders = await File.aggregate(pipeline);
            
            totalCount = rawUploaders.length; // Count unique uploaders in this timeframe
            totalLabel = "Total Uploaders";

            // Only take top 100 for the actual list
            const top100 = rawUploaders.slice(0, 100);
            
            results = await Promise.all(top100.map(async (u) => {
                const user = await User.findOne({ username: u._id });
                const avatarUrl = user && user.profileImageKey ? await getSmartImageUrl(user.profileImageKey) : '/images/default-avatar.png';
                return { name: u._id, score: u.count, avatar: avatarUrl, role: user ? user.role : 'member' };
            }));

        } else if (category === 'downloaded') {
            totalCount = await File.countDocuments({ status: 'live', isLatestVersion: true, ...dateFilter });
            totalLabel = "Total Files Uploaded";

            const files = await File.find({ status: 'live', isLatestVersion: true, ...dateFilter })
                .sort({ downloads: -1 })
                .limit(100);
                
            results = await Promise.all(files.map(async (f) => {
                const iconUrl = await getSmartImageUrl(f.iconKey || f.iconUrl);
                return { name: f.name, score: f.downloads, subtext: `By ${f.uploader}`, avatar: iconUrl, link: `/${f.category}/${f.slug || f._id}` };
            }));

        } else if (category === 'followed') {
            totalCount = await User.countDocuments();
            totalLabel = "Total Registered Users";

            const rawUsers = await User.aggregate([
                { $project: { username: 1, profileImageKey: 1, role: 1, followerCount: { $size: { $ifNull:["$followers", []] } } } },
                { $sort: { followerCount: -1 } },
                { $limit: 100 }
            ]);
            
            results = await Promise.all(rawUsers.map(async (u) => {
                const avatarUrl = u.profileImageKey ? await getSmartImageUrl(u.profileImageKey) : '/images/default-avatar.png';
                return { name: u.username, score: u.followerCount, avatar: avatarUrl, role: u.role };
            }));

        } else if (category === 'donators') {
            // Count unique donators
            const donatorsCountPipeline =[
                { $match: { status: 'successful', user: { $ne: null }, ...dateFilter } },
                { $group: { _id: '$user' } }
            ];
            const uniqueDonators = await Donation.aggregate(donatorsCountPipeline);
            totalCount = uniqueDonators.length;
            totalLabel = "Total Donators";

            const pipeline =[
                { $match: { status: 'successful', user: { $ne: null }, ...dateFilter } },
                { $group: { _id: '$user', totalAmount: { $sum: '$amount' }, username: { $first: '$username' } } },
                { $sort: { totalAmount: -1 } },
                { $limit: 100 }
            ];
            const rawDonators = await Donation.aggregate(pipeline);
            
            results = await Promise.all(rawDonators.map(async (d) => {
                const user = await User.findById(d._id);
                const avatarUrl = user && user.profileImageKey ? await getSmartImageUrl(user.profileImageKey) : '/images/default-avatar.png';
                // Convert currency to string, dividing by 100 if you store in cents/paise
                return { name: d.username, score: `₹${(d.totalAmount / 100).toLocaleString()}`, isCurrency: true, avatar: avatarUrl, role: user ? user.role : 'member' };
            }));
        }

        res.render('pages/leaderboard', {
            results,
            currentCategory: category,
            currentTimeframe: timeframe,
            totalCount, // NEW
            totalLabel  // NEW
        });

    } catch (error) {
        console.error("Leaderboard Error:", error);
        res.status(500).render('pages/500');
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
app.get('/partnership-policy', (req, res) => res.render('pages/static/partnership-policy'));
app.get('/distributor-features', (req, res) => res.render('pages/static/distributor-features'));
app.get('/why-choose-us', (req, res) => res.render('pages/static/why-choose-us'));
app.get('/understanding-scans', (req, res) => res.render('pages/static/understanding-scans'));
app.get('/membership', (req, res) => {
    // If you use Stripe/Cashfree keys in this view, pass them here
    res.render('pages/membership', {
        // e.g., stripePublishableKey: process.env.STRIPE_PUBLISHABLE_KEY
    });
});

// --- UPDATED: DOCUMENTATION SYSTEM ROUTE ---
app.get(['/docs', '/docs/:slug'], async (req, res, next) => {
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
            currentPage = await DocPage.findOne({ slug: requestedSlug }).populate('category').lean(); // Use lean() to allow editing the object
            
            if (!currentPage) {
                return res.status(404).render('pages/404'); // Using your standard 404
            }
        } else {
            if (sidebarStructure.length > 0 && sidebarStructure[0].pages.length > 0) {
                currentPage = sidebarStructure[0].pages[0];
                return res.redirect(`/docs/${currentPage.slug}`);
            }
        }

        // ======== NEW: PROCESS THE FEATURED IMAGE ========
        if (currentPage && currentPage.featuredImageKey) {
            // Assuming getSmartImageUrl is available in this file. 
            // If this is in a separate router file, make sure to import the helper!
            currentPage.featuredImageUrl = await getSmartImageUrl(currentPage.featuredImageKey);
        }
        // =================================================

        res.render('pages/docs', {
            sidebarStructure: sidebarStructure,
            currentPage: currentPage
        });

    } catch (error) {
        console.error("Docs Engine Error:", error);
        return next(error);
    }
});

// ======== THE BULLETPROOF, SEO-OPTIMIZED SITEMAP ========

// 1. Helper function to ensure XML strictness
const escapeXML = (str) => {
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&apos;');
};

app.get('/sitemap.xml', async (req, res) => {
    try {
        // Set the correct XML header so browsers & Google know how to read it
        res.set('Content-Type', 'text/xml');
        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
        xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

        // 1. Static Pages
        const staticPages =['', '/login', '/register', '/about', '/faq', '/dmca', '/tos', '/privacy-policy', '/donate', '/docs'];
        staticPages.forEach(page => {
            const pageUrl = `${baseUrl}${page}`;
            xml += `  <url>\n    <loc>${escapeXML(pageUrl)}</loc>\n    <changefreq>weekly</changefreq>\n    <priority>0.8</priority>\n  </url>\n`;
        });

        // 2. Category Pages
        const categories = ['android', 'ios-jailed', 'ios-jailbroken', 'windows', 'wordpress'];
        categories.forEach(cat => {
             // encodeURIComponent ensures special chars in categories are handled safely
             const catUrl = `${baseUrl}/category?platform=${encodeURIComponent(cat)}`;
             xml += `  <url>\n    <loc>${escapeXML(catUrl)}</loc>\n    <changefreq>daily</changefreq>\n    <priority>0.7</priority>\n  </url>\n`;
        });

        // 3. Live Mods
        const liveMods = await File.find({ showInSitemap: { $ne: false }, isLatestVersion: true, status: 'live' })
            .select('_id category slug updatedAt')
            .lean(); 
            
        liveMods.forEach(mod => {
            let lastModDate = mod.updatedAt ? new Date(mod.updatedAt).toISOString() : new Date().toISOString();
            
            // encodeURIComponent safely converts emojis, +, @, and # to be URL-safe!
            const safeCategory = encodeURIComponent(mod.category);
            const safeSlug = encodeURIComponent(mod.slug || mod._id.toString());
            const modUrl = `${baseUrl}/${safeCategory}/${safeSlug}`;
            
            xml += `  <url>\n    <loc>${escapeXML(modUrl)}</loc>\n    <lastmod>${lastModDate}</lastmod>\n    <changefreq>daily</changefreq>\n    <priority>0.9</priority>\n  </url>\n`;
        });

        // 4. Developer Pages
        const uniqueDevelopers = await File.distinct('developer', { status: 'live', isLatestVersion: true }).lean();
        uniqueDevelopers.forEach(dev => {
            if (dev && dev !== 'N/A') {
                // Using encodeURIComponent instead of slugify ensures emojis and special characters 
                // in company names (like "DevGroup #1 🚀") are properly indexed by Google!
                const devUrl = `${baseUrl}/developer?name=${encodeURIComponent(dev)}`;
                xml += `  <url>\n    <loc>${escapeXML(devUrl)}</loc>\n    <changefreq>weekly</changefreq>\n    <priority>0.6</priority>\n  </url>\n`;
            }
        });

        // 5. Public User Profiles
        const uniqueUploaders = await File.distinct('uploader', { status: 'live', isLatestVersion: true }).lean();
        uniqueUploaders.forEach(uploader => {
             // This fixes the Noob#1 bug! The # is safely converted to %23 so the URL doesn't break.
             const userUrl = `${baseUrl}/users/${encodeURIComponent(uploader)}`;
             xml += `  <url>\n    <loc>${escapeXML(userUrl)}</loc>\n    <changefreq>weekly</changefreq>\n    <priority>0.6</priority>\n  </url>\n`;
        });

        // 6. Dynamic Documentation Pages
        const allDocPages = await DocPage.find().select('slug updatedAt').lean();
        allDocPages.forEach(doc => {
            let lastDocDate = doc.updatedAt ? new Date(doc.updatedAt).toISOString() : new Date().toISOString();
            const docUrl = `${baseUrl}/docs/${encodeURIComponent(doc.slug)}`;
            xml += `  <url>\n    <loc>${escapeXML(docUrl)}</loc>\n    <lastmod>${lastDocDate}</lastmod>\n    <changefreq>weekly</changefreq>\n    <priority>0.7</priority>\n  </url>\n`;
        });

        xml += '</urlset>';
        res.send(xml);
        
    } catch (error) {
        console.error("Sitemap generation error:", error);
        res.status(500).send('Error generating sitemap');
    }
});
// ======== HTML SITEMAP (FOR TIDIO LYRO & AI CRAWLERS) ========
app.get('/ai-directory', async (req, res) => {
    try {
        // Fetch all active, latest version mods. 
        // We only need the fields required to build the URL and title.
        const liveMods = await File.find({ 
            status: 'live', 
            isLatestVersion: true,
            showInSitemap: { $ne: false }
        })
        .select('name category slug developer') // Only grab what we need to make it fast
        .sort({ category: 1, name: 1 }); // Sort alphabetically by category, then name

        // Group mods by category so the AI understands the site structure better
        const modsByCategory = {};
        liveMods.forEach(mod => {
            if (!modsByCategory[mod.category]) {
                modsByCategory[mod.category] = [];
            }
            modsByCategory[mod.category].push(mod);
        });

        res.render('pages/ai-directory', { 
            modsByCategory: modsByCategory 
        });

    } catch (error) {
        console.error("AI Directory generation error:", error);
        res.status(500).send('Error generating AI directory');
    }
});
// ===============================================
// 15. UNIVERSAL REPOSITORY ENGINE (Automatic, Manual & JSON)
// ===============================================

// If a user pastes the base URL into a web browser, redirect them to the actual data 
app.get('/ios-repo', (req, res) => res.redirect('/ios-repo/Packages'));
app.get('/fdroid/repo', (req, res) => res.redirect('/fdroid/repo/index-v2.json'));

function getBaseUrl(req) {
    if (process.env.BASE_URL) {
        return process.env.BASE_URL.replace(/\/*$/, '');
    }
    const forwardedProto = req.headers['x-forwarded-proto'];
    const protocol = forwardedProto ? forwardedProto.split(',')[0].trim() : req.protocol;
    const host = req.get('host');
    return `${protocol}://${host}`.replace(/\/*$/, '');
}

// ======== ✅ FIX 1: PERMANENT IMAGE REDIRECTS ========
// Prevents 404 crashes in Droid-ify, Sileo, and AltStore caused by expired B2 URLs.
app.get('/api/icon/:id', async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        if (!file) return res.redirect('/images/default-avatar.png');
        const key = file.iconUrl || file.iconKey;
        const signedUrl = await getSmartImageUrl(key);
        res.redirect(signedUrl);
    } catch(e) { res.redirect('/images/default-avatar.png'); }
});

app.get('/api/screenshot/:id/:index', async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        if (!file || !file.screenshotKeys || !file.screenshotKeys[req.params.index]) return res.status(404).send('Not found');
        const key = file.screenshotKeys[req.params.index];
        const signedUrl = await getSmartImageUrl(key);
        res.redirect(signedUrl);
    } catch(e) { res.status(404).send('Not found'); }
});

// Catch-all Repo Logos (Clients request these specific paths blindly)
app.get('/fdroid/repo/icon-512x512.png', (req, res) => res.redirect('/images/icon-512x512.png'));
app.get('/ios-repo/CydiaIcon.png', (req, res) => res.redirect('/images/icon-512x512.png'));
app.get('/ios-repo/Icon.png', (req, res) => res.redirect('/images/icon-512x512.png'));
// =====================================================


// -----------------------------------------------
// A. iOS JAILBREAK REPO ENGINE (APT & Sileo Native)
// -----------------------------------------------

async function generateIosPackages(req) {
    const repoBaseUrl = getBaseUrl(req);
    const jbMods = await File.find({ 
        category: 'ios-jailbroken', 
        status: 'live', 
        isLatestVersion: true,
        showInRepo: { $ne: false } 
    }).sort({ createdAt: -1 });

    let packagesText = '';

    for (const mod of jbMods) {
        const downloadUrl = mod.directDownloadUrl || mod.externalDownloadUrl || (mod.fileKey ? `${REPO_BASE_URL}/download-file/${mod._id}` : null);
        if (!downloadUrl) continue;

        let aptArch = 'iphoneos-arm';
        if (mod.architectures && mod.architectures.includes('arm64')) aptArch = 'iphoneos-arm64';

        const bundleId = `com.gplmods.${(mod.slug || mod.name).toLowerCase().replace(/[^a-z0-9]/g, '')}`;
        const cleanDesc = (mod.modDescription || 'No description').replace(/<[^>]*>?/gm, '').substring(0, 150).replace(/\n/g, ' ');

        packagesText += `Package: ${bundleId}\n`;
        packagesText += `Name: ${mod.name}\n`;
        packagesText += `Version: ${mod.version}\n`;
        packagesText += `Architecture: ${aptArch}\n`;
        packagesText += `Maintainer: ${mod.developer || 'GPL Mods Team'} <admin@gplmods.webredirect.org>\n`;
        packagesText += `Author: ${mod.uploader}\n`;
        packagesText += `Section: Tweaks\n`;
        packagesText += `Description: ${cleanDesc}...\n`;
        // ✅ FIX 2: Added the Icon URL so tweaks show logos in Sileo/Zebra lists
        packagesText += `Icon: ${repoBaseUrl}/api/icon/${mod._id}\n`;
        packagesText += `Depiction: ${repoBaseUrl}/ios-jailbroken/${mod.slug || mod._id}\n`;
        packagesText += `SileoDepiction: ${repoBaseUrl}/ios-repo/depiction/${mod._id}.json\n`;
        packagesText += `Filename: ${downloadUrl}\n`; 
        packagesText += `Size: ${mod.fileSize || 1024}\n\n`;
    }
    return packagesText;
}

app.get('/ios-repo/Release', (req, res) => {
    // ✅ FIX 3: Added Icon to Release file for Cydia/Zebra Repo Header
    const releaseText = `Origin: GPL Mods\nLabel: GPL Mods\nSuite: stable\nVersion: 1.0\nCodename: ios\nArchitectures: iphoneos-arm iphoneos-arm64\nComponents: main\nDescription: 100% Safe & Working Mods For All Your Devices!\nIcon: ${getBaseUrl(req)}/images/icon-512x512.png\n`;
    res.set('Content-Type', 'text/plain');
    res.send(releaseText);
});

app.get('/ios-repo/Packages', async (req, res) => {
    try {
        const packagesText = await generateIosPackages(req);
        res.set('Content-Type', 'text/plain');
        res.send(packagesText);
    } catch (e) { res.status(500).send("Error generating Packages file."); }
});

app.get('/ios-repo/Packages.bz2', async (req, res) => {
    try {
        const packagesText = await generateIosPackages(req);
        res.set('Content-Type', 'application/x-bzip2');
        res.set('Content-Disposition', 'attachment; filename="Packages.bz2"');
        res.send(packagesText); 
    } catch (e) { res.status(500).send("Error generating Packages.bz2 file."); }
});

app.get('/ios-repo/sileo-info.json', (req, res) => {
    const repoBaseUrl = getRepoBaseUrl(req);
    res.json({
        name: "GPL Mods",
        icon: `${repoBaseUrl}/images/icon-512x512.png`,
        description: "100% Safe & Working Mods For All Your Devices!",
        authentication_banner: {
            message: "Support us by upgrading to Premium!",
            button: "Go Premium"
        }
    });
});

app.get('/ios-repo/depiction/:id.json', async (req, res) => {
    try {
        const mod = await File.findById(req.params.id);
        if (!mod) return res.status(404).json({});

        const repoBaseUrl = getRepoBaseUrl(req);
        const cleanDesc = (mod.modDescription || 'No description').replace(/<[^>]*>?/gm, '');
        const cleanFeatures = (mod.modFeatures || '').replace(/<[^>]*>?/gm, '');
        const cleanWhatsNew = (mod.whatsNew || 'Bug fixes.').replace(/<[^>]*>?/gm, '');
        const cleanImportantNote = (mod.importantNote || '').replace(/<[^>]*>?/gm, '');

        let screenshots = [];
        if (mod.screenshotKeys && mod.screenshotKeys.length > 0) {
            screenshots = mod.screenshotKeys.map((_, index) => {
                return { url: `${repoBaseUrl}/api/screenshot/${mod._id}/${index}`, accessibilityText: "Screenshot" };
            });
        }

        let detailsViews = [
            { class: "DepictionHeaderView", title: mod.name },
            { class: "DepictionSubheaderView", title: `Version ${mod.version}` }
        ];

        if (screenshots.length > 0) {
            detailsViews.push({ class: "DepictionScreenshotsView", itemCornerRadius: 8, itemSize: "{160, 346}", screenshots: screenshots });
            detailsViews.push({ class: "DepictionSeparatorView" });
        }

        detailsViews.push({ class: "DepictionMarkdownView", markdown: `**Description**\n\n${cleanDesc}` });
        detailsViews.push({ class: "DepictionSeparatorView" });

        if (cleanImportantNote) {
            detailsViews.push({ class: "DepictionMarkdownView", markdown: `**🚨 IMPORTANT NOTE:**\n\n${cleanImportantNote}` });
            detailsViews.push({ class: "DepictionSeparatorView" });
        }
        if (cleanFeatures) {
            detailsViews.push({ class: "DepictionMarkdownView", markdown: `**Features**\n\n${cleanFeatures}` });
            detailsViews.push({ class: "DepictionSeparatorView" });
        }

        detailsViews.push(
            { class: "DepictionTableTextView", title: "Developer", text: mod.developer || "GPL Mods" },
            { class: "DepictionTableTextView", title: "Uploader", text: mod.uploader },
            { class: "DepictionTableTextView", title: "Updated", text: new Date(mod.updatedAt).toLocaleDateString() }
        );

        res.json({
            minVersion: "0.1",
            class: "DepictionTabView",
            tintColor: "#FFD700",
            headerImage: `${repoBaseUrl}/images/icon-512x512.png`,
            tabs: [
                { tabname: "Details", class: "DepictionStackView", views: detailsViews },
                { tabname: "Changelog", class: "DepictionStackView", views: [{ class: "DepictionMarkdownView", markdown: `**Version ${mod.version}**\n\n${cleanWhatsNew}` }] }
            ]
        });
    } catch (e) { res.status(500).json({}); }
});

// --- B. iOS SIDELOADING REPO ENGINE (AltStore / Scarlet / Feather JSON) ---
app.get('/ios-repo/apps.json', async (req, res) => {
    try {
        const repoBaseUrl = getRepoBaseUrl(req);
        const ipaMods = await File.find({ 
            category: 'ios-jailed',
            status: 'live',
            isLatestVersion: true,
            showInRepo: { $ne: false },
            $or:[ { directDownloadUrl: { $exists: true, $ne: '' } }, { externalDownloadUrl: { $exists: true, $ne: '' } } ]
        }).sort({ createdAt: -1 });

        const sourceJson = {
            name: "GPL Mods",
            identifier: "org.webredirect.gplmods.ios",
            subtitle: "100% Safe & Working iOS Mods",
            description: "The ultimate source for tweaked and modded iOS apps and games.",
            iconURL: `${repoBaseUrl}/images/icon-512x512.png`,
            headerURL: `${repoBaseUrl}/images/icon-512x512.png`,
            website: repoBaseUrl,
            tintColor: "#FFD700",
            apps: [], news: []
        };

        for (const mod of ipaMods) {
            const downloadUrl = mod.directDownloadUrl || mod.externalDownloadUrl || (mod.fileKey ? `${repoBaseUrl}/download-file/${mod._id}` : null);
            if (!downloadUrl) continue;

            const cleanDesc = (mod.modDescription || '').replace(/<[^>]*>?/gm, '');
            const cleanFeatures = (mod.modFeatures || '').replace(/<[^>]*>?/gm, '');
            const cleanNotes = (mod.officialDescription || '').replace(/<[^>]*>?/gm, '');
            const cleanWhatsNew = (mod.whatsNew || 'New update available.').replace(/<[^>]*>?/gm, '');
            const cleanImportantNote = (mod.importantNote || '').replace(/<[^>]*>?/gm, '');
            
            let fullMarkdownDesc = `${cleanDesc}\n\n`;
            if (cleanImportantNote) fullMarkdownDesc += `**🚨 IMPORTANT NOTE:**\n${cleanImportantNote}\n\n`;
            if (cleanFeatures) fullMarkdownDesc += `**Mod Features:**\n${cleanFeatures}\n\n`;
            if (cleanNotes) fullMarkdownDesc += `**App Store Info:**\n${cleanNotes}\n\n`;

            const bundleId = `com.gplmods.${(mod.slug || mod.name).toLowerCase().replace(/[^a-z0-9]/g, '')}`;

            // ✅ FIX 4: Implemented Permanent Image APIs
            const iconUrl = `${repoBaseUrl}/api/icon/${mod._id}`;
            const screenshotUrls = (mod.screenshotKeys || []).map((_, i) => `${repoBaseUrl}/api/screenshot/${mod._id}/${i}`);

            sourceJson.apps.push({
                name: mod.name,
                bundleIdentifier: bundleId,
                developerName: mod.developer || mod.uploader,
                subtitle: `Version ${mod.version} by ${mod.uploader}`,
                localizedDescription: fullMarkdownDesc, 
                iconURL: iconUrl,
                tintColor: "#FFD700",
                size: mod.fileSize || 1048576,
                screenshotURLs: screenshotUrls,
                versions: [{
                    version: mod.version,
                    date: new Date(mod.updatedAt).toISOString(),
                    localizedDescription: cleanWhatsNew, 
                    downloadURL: downloadUrl,
                    size: mod.fileSize || 1048576
                }]
            });
        }
        res.set('Content-Type', 'application/json');
        res.send(JSON.stringify(sourceJson, null, 2));
    } catch (e) { res.status(500).json({ error: "Error generating Source JSON." }); }
});

// --- C. ANDROID F-DROID REPO ENGINE ---

// Helper function to safely escape XML characters
function escapeXml(unsafe) {
    if (!unsafe) return '';
    return unsafe.toString().replace(/[<>&'"]/g, function (c) {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
        }
    });
}

// Helper to generate the core XML data
async function generateFDroidXml(req) {
    const repoBaseUrl = getRepoBaseUrl(req);
    const androidMods = await File.find({ 
        category: 'android', status: 'live', isLatestVersion: true, showInRepo: { $ne: false } 
    }).sort({ createdAt: -1 });

    const formatDate = (date) => new Date(date).toISOString().split('T')[0];

    let xml = '<?xml version="1.0" encoding="utf-8"?>\n';
    xml += '<fdroid>\n';
    xml += `  <repo icon="icon-512x512.png" name="GPL Mods Android" pubkey="" timestamp="${Date.now()}" url="${escapeXml(repoBaseUrl)}/fdroid/repo" version="17">\n`;
    xml += `    <description>The ultimate source for safe and working Android mods.</description>\n`;
    xml += `  </repo>\n`;

    for (const mod of androidMods) {
        const downloadUrl = mod.directDownloadUrl || mod.externalDownloadUrl || (mod.fileKey ? `${repoBaseUrl}/download-file/${mod._id}` : null);
        if (!downloadUrl) continue;

        const bundleId = `com.gplmods.${(mod.slug || mod.name).toLowerCase().replace(/[^a-z0-9]/g, '')}`;
        const cleanDesc = (mod.modDescription || '').replace(/<[^>]*>?/gm, '');

        xml += `  <application id="${escapeXml(bundleId)}">\n`;
        xml += `    <id>${escapeXml(bundleId)}</id>\n`;
        xml += `    <name>${escapeXml(mod.name)}</name>\n`;
        xml += `    <summary>${escapeXml(mod.version)} Mod by ${escapeXml(mod.uploader)}</summary>\n`;
        xml += `    <desc>${escapeXml(cleanDesc)}</desc>\n`;
        xml += `    <license>GNU/GPL</license>\n`;
        xml += `    <categories><category>Mods</category></categories>\n`;
        xml += `    <added>${formatDate(mod.createdAt)}</added>\n`;
        xml += `    <lastupdated>${formatDate(mod.updatedAt)}</lastupdated>\n`;
        xml += `    <marketversion>${escapeXml(mod.version)}</marketversion>\n`;
        xml += `    <marketvercode>1</marketvercode>\n`;
        xml += `    <package>\n`;
        xml += `      <version>${escapeXml(mod.version)}</version>\n`;
        xml += `      <versioncode>1</versioncode>\n`;
        xml += `      <apkname>${escapeXml(downloadUrl)}</apkname>\n`;
        
        if (mod.virusTotalId && mod.virusTotalId.length === 64) {
            xml += `      <hash type="sha256">${mod.virusTotalId}</hash>\n`;
        }
        
        xml += `      <size>${mod.fileSize || 1048576}</size>\n`;
        xml += `      <added>${formatDate(mod.createdAt)}</added>\n`;
        xml += `    </package>\n`;
        xml += `  </application>\n`;
    }

    xml += '</fdroid>';
    return xml;
}

// ✅ 1. Classic XML Route
app.get('/fdroid/repo/index.xml', async (req, res) => {
    try {
        const xmlContent = await generateFDroidXml(req);
        res.set('Content-Type', 'application/xml');
        res.send(xmlContent);
    } catch (e) { 
        console.error("XML Error:", e);
        res.status(500).send("Error generating index.xml"); 
    }
});

// ✅ 2. Classic JAR Route (Zips the XML file dynamically)
app.get('/fdroid/repo/index.jar', async (req, res) => {
    try {
        const xmlContent = await generateFDroidXml(req);
        
        // Create an archive in memory
        const zip = new AdmZip();
        // Add the XML file into the archive
        zip.addFile("index.xml", Buffer.from(xmlContent, "utf8"));
        
        // Convert to a buffer and send
        const jarBuffer = zip.toBuffer();

        res.set('Content-Type', 'application/java-archive');
        res.set('Content-Disposition', 'attachment; filename="index.jar"');
        res.send(jarBuffer);
    } catch (e) { 
        console.error("JAR Error:", e);
        res.status(500).send("Error generating index.jar"); 
    }
});

// ✅ 3. Legacy compatibility endpoint for JSON-based Android clients (index-v1.json)
app.get('/fdroid/repo/index-v1.json', async (req, res) => {
    try {
        const repoBaseUrl = getRepoBaseUrl(req);
        const androidMods = await File.find({ 
            category: 'android', status: 'live', isLatestVersion: true, showInRepo: { $ne: false } 
        }).sort({ createdAt: -1 });

        const repoJson = {
            repo: { name: "GPL Mods Android", description: "Safe and working Android mods.", address: `${repoBaseUrl}/fdroid/repo`, icon: "icon-512x512.png", timestamp: Date.now(), version: 1 },
            requests: { install: [], uninstall: [] },
            apps:[], packages: {}
        };

        for (const mod of androidMods) {
            const downloadUrl = mod.directDownloadUrl || mod.externalDownloadUrl || (mod.fileKey ? `${repoBaseUrl}/download-file/${mod._id}` : null);
            if (!downloadUrl) continue;

            const bundleId = `com.gplmods.${(mod.slug || mod.name).toLowerCase().replace(/[^a-z0-9]/g, '')}`;
            const cleanDesc = (mod.modDescription || '').replace(/<[^>]*>?/gm, '');

            repoJson.apps.push({
                packageName: bundleId, name: mod.name, summary: `${mod.version} Mod by ${mod.uploader}`,
                description: cleanDesc, license: "GNU/GPL", categories:["Mods", "Games", "Apps"],
                icon: `${repoBaseUrl}/api/icon/${mod._id}`, 
                added: new Date(mod.createdAt).getTime(), lastUpdated: new Date(mod.updatedAt).getTime()
            });

            repoJson.packages[bundleId] =[{
                versionName: mod.version, versionCode: 1, apkName: downloadUrl,
                hash: mod.virusTotalId && mod.virusTotalId.length === 64 ? mod.virusTotalId : "",
                hashType: "sha256", size: mod.fileSize || 1048576, added: new Date(mod.createdAt).getTime()
            }];
        }
        res.set('Content-Type', 'application/json');
        res.send(JSON.stringify(repoJson, null, 2));
    } catch (e) { res.status(500).json({ error: "Error generating F-Droid JSON index." }); }
});

// ✅ 4. Current default endpoint for Neo Store / Droid-ify (index-v2.json)
app.get('/fdroid/repo/index-v2.json', async (req, res) => {
    try {
        const repoBaseUrl = getRepoBaseUrl(req);
        const androidMods = await File.find({ 
            category: 'android', status: 'live', isLatestVersion: true, showInRepo: { $ne: false } 
        }).sort({ createdAt: -1 });

        const repoJson = {
            repo: {
                name: "GPL Mods Android",
                description: "The ultimate source for safe and working Android mods.",
                address: `${repoBaseUrl}/fdroid/repo`,
                icon: { "en-US": { name: "icon-512x512.png" } }, 
                timestamp: Date.now(),
                version: 2
            },
            requests: { install: [], uninstall: [] },
            packages: {}
        };

        for (const mod of androidMods) {
            const downloadUrl = mod.directDownloadUrl || mod.externalDownloadUrl || (mod.fileKey ? `${repoBaseUrl}/download-file/${mod._id}` : null);
            if (!downloadUrl) continue;

            const bundleId = `com.gplmods.${(mod.slug || mod.name).toLowerCase().replace(/[^a-z0-9]/g, '')}`;
            
            const cleanDesc = (mod.modDescription || '').replace(/<[^>]*>?/gm, '');
            const cleanFeatures = (mod.modFeatures || '').replace(/<[^>]*>?/gm, '');
            const cleanNotes = (mod.officialDescription || '').replace(/<[^>]*>?/gm, '');
            const cleanWhatsNew = (mod.whatsNew || 'Bug fixes.').replace(/<[^>]*>?/gm, '');
            const cleanImportantNote = (mod.importantNote || '').replace(/<[^>]*>?/gm, '');

            let fullMarkdownDesc = `${cleanDesc}\n\n`;
            if (cleanImportantNote) fullMarkdownDesc += `**🚨 IMPORTANT NOTE:**\n${cleanImportantNote}\n\n`;
            if (cleanFeatures) fullMarkdownDesc += `**Features:**\n${cleanFeatures}\n\n`;
            if (cleanNotes) fullMarkdownDesc += `**App Store Info:**\n${cleanNotes}\n\n`;

            const screenshotArray = [];
            if (mod.screenshotKeys && mod.screenshotKeys.length > 0) {
                mod.screenshotKeys.forEach((_, i) => {
                    screenshotArray.push({ name: `${repoBaseUrl}/api/screenshot/${mod._id}/${i}` });
                });
            }

            repoJson.packages[bundleId] = {
                metadata: {
                    name: { "en-US": mod.name },
                    summary: { "en-US": `${mod.version} Mod by ${mod.uploader}` },
                    description: { "en-US": fullMarkdownDesc },
                    license: "GNU/GPL",
                    categories: ["Mods", "Games", "Apps"],
                    developerName: mod.developer || "GPL Mods",
                    authorName: mod.uploader,
                    icon: { "en-US": { name: `${repoBaseUrl}/api/icon/${mod._id}` } }, 
                    phoneScreenshots: { "en-US": screenshotArray }, 
                    added: new Date(mod.createdAt).getTime(),
                    lastUpdated: new Date(mod.updatedAt).getTime()
                },
                versions: {
                    [mod.version]: {
                        added: new Date(mod.updatedAt).getTime(),
                        file: {
                            name: downloadUrl,
                            sha256: mod.virusTotalId && mod.virusTotalId.length === 64 ? mod.virusTotalId : "",
                            size: mod.fileSize || 1048576
                        },
                        releaseNotes: { "en-US": cleanWhatsNew }
                    }
                }
            };
        }

        res.set('Content-Type', 'application/json');
        res.send(JSON.stringify(repoJson, null, 2));

    } catch (e) {
        console.error("F-Droid JSON Error:", e);
        res.status(500).json({ error: "Error generating F-Droid JSON index." });
    }
});

// --- DMCA PAGE ROUTE ---
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
        const myTickets = await SupportTicket.find({ user: req.user._id }).sort({ createdAt: -1 }).lean();
        res.render('pages/support', {
            tickets: myTickets,
            message: req.query.message,
            error: req.query.error
        });
    } catch (error) {
        console.error("Error loading support page:", error);
        return next(error);
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
        return next(error);
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
                // --- FIXED: Sanitize chat messages with Try/Catch ---
                let finalSafeText = msg.text; // Default to original text

                try {
                    // Try to clean it. If it's just emojis, this might fail.
                    finalSafeText = global.profanityFilter.clean(msg.text);
                } catch (error) {
                    // If the filter crashes (because of emojis), do nothing!
                    // finalSafeText remains the original emoji string.
                }

                const messageData = {
                    username: msg.username,
                    avatar: msg.avatar, 
                    
                    // ✅ FIXED: We are now passing the SAFE text, not the dirty text!
                    text: finalSafeText, 
                    
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

// ===============================================
// 17. GLOBAL ERROR HANDLERS (MUST BE LAST)
// ===============================================

// 404 Handler - Catch all unhandled routes
app.use((req, res) => {
    res.status(404).render('pages/error', {
        errorCode: '404',
        errorTitle: 'Page <span>Not Found</span>',
        errorMessage: "Oops! The page you're looking for doesn't exist. It might have been moved or deleted."
    });
});

// 500 Handler - Catch all server crashes/exceptions
app.use((err, req, res, next) => {
    console.error(err.stack); // Still log the error for you to debug!
    res.status(500).render('pages/error', {
        errorCode: '500',
        errorTitle: 'Server <span>Error</span>',
        errorMessage: "Something went wrong on our end. Our team has been notified and we're working to fix it."
    });
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
// 18 AUTOMATION ENGINE & RAM MANAGER
// ===================================
const os = require('os');

// --- 1. THE RAM OPTIMIZER (Runs every 30 minutes) ---
cron.schedule('*/30 * * * *', () => {
    try {
        // Get current memory usage in MB
        const usedMemory = process.memoryUsage().rss / 1024 / 1024;
        const totalMem = os.totalmem() / 1024 / 1024;
        const memoryPercentage = (usedMemory / totalMem) * 100;

        console.log(`[RAM Monitor] Current Usage: ${usedMemory.toFixed(2)} MB (${memoryPercentage.toFixed(1)}%)`);

        // If we are approaching Render's 512MB limit (e.g., hitting 350MB+)
        if (usedMemory > 350) {
            console.warn(`[RAM Warning] Memory high (${usedMemory.toFixed(2)} MB). Initiating aggressive cleanup...`);

            // 1. Clear our custom in-memory caches
            cachedTotalUpdates = 0; 
            recentMessages = recentMessages.slice(-10); // Keep only last 10 chat messages in RAM instead of 50

            // 2. Force V8 Garbage Collection (if the flag is enabled)
            if (global.gc) {
                global.gc();
                const newMem = process.memoryUsage().rss / 1024 / 1024;
                console.log(`[RAM Monitor] Garbage collection forced. Memory reduced to: ${newMem.toFixed(2)} MB`);
            } else {
                console.warn("[RAM Monitor] Cannot force GC. Start server with 'node --expose-gc server.js'");
            }
        }
    } catch (e) {
        console.error("RAM Manager Error:", e);
    }
});

// --- 2. THE CHAT HISTORY CLEANER (Runs every hour) ---
// Prevents the recentMessages array from slowly growing and causing a memory leak
cron.schedule('0 * * * *', () => {
    if (recentMessages.length > 20) {
        recentMessages = recentMessages.slice(-20); // Trim to last 20 every hour
        console.log("[Maintenance] Chat history array pruned to prevent memory leak.");
    }
});

// ===================================
// AUTOMATION ENGINE (CRON JOBS)
// ===================================

cron.schedule('* * * * *', async () => {
    try {
        // --- 1. Check if the engine is enabled in SiteState ---
        const SiteState = require('./models/siteState'); // Ensure this is imported
        const siteState = await SiteState.findOne({ singletonId: 'master-state' });
        
        // If the state document doesn't exist, or the toggle is false, DO NOTHING.
        if (!siteState || siteState.enableAutomationEngine !== true) {
            return; // Exit silently
        }

        // --- 2. Proceed with normal checks ---
        const now = new Date();
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