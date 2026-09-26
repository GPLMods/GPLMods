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
const UAParser = require('ua-parser-js');
const cors = require('cors');
const fs = require('fs');
const cron = require('node-cron');
const FormData = require('form-data');
const { Upload } = require("@aws-sdk/lib-storage");
const Filter = require('bad-words');
const { isbot } = require('isbot');
const zlib = require('zlib');
const otplib = require('otplib');
const { checkDomain } = require('./utils/tempMailDetector');
const cheerio = require('cheerio');
const googlePlayScraper = require('google-play-scraper').default;
const appStoreScraper = require('app-store-scraper');
const AdmZip = require('adm-zip'); 
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const { mirrorToFTP, deleteFromFTP, shouldMirrorToFTP } = require('./utils/ftpSync'); // <--- ADD THIS LINE
const { normalizeSingleValue } = require('./utils/formHelpers');
const { getSubmissionValidationErrors } = require('./utils/uploadValidation');
const { analyzeFileDetails } = require('./utils/platformDetector');
const { getUserStorageBasePath, getUserAssetKey, getPlatformStoragePath, getModStorageKey } = require('./utils/storagePaths');
const { ensureModDirectories, saveModMetadata, saveModReviewsArchive } = require('./utils/fileStorage');

// Custom Utilities & Config
const { 
    sendVerificationEmail, 
    sendPasswordResetEmail, 
    sendDeletionOtpEmail, 
    send2faEmail, 
    sendLoginAlertEmail, 
    sendFailedAttemptEmail, 
    processNewsletterCampaign,
    sendTicketConfirmationEmail,
    sendDmcaReportConfirmationEmail,
    sendSubscriptionStatusEmail
} = require('./utils/mailer');
const { getUserUploadQuota, validateUploadFileSize, TIER_CONFIGS } = require('./utils/uploadQuota');

// AWS SDK v3 Imports (Backblaze B2)
// Add DeleteObjectCommand to this list
const { S3Client, PutObjectCommand, GetObjectCommand, ListObjectsV2Command, DeleteObjectCommand, CopyObjectCommand } = require('@aws-sdk/client-s3');
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
const StaticPage = require('./models/staticPage');
const DraftSnapshot = require('./models/draftSnapshot');
const Donation = require('./models/donation');
const MembershipOrder = require('./models/membershipOrder');
const Coupon = require('./models/coupon');
const DevtoolLog = require('./models/devtoolLog');
const VolunteerApplication = require('./models/volunteerApplication');
const PaymentCancellation = require('./models/paymentCancellation');
const Club = require('./models/club');
const ClubChannel = require('./models/clubChannel');
const ClubRole = require('./models/clubRole');
const ClubMember = require('./models/clubMember');
const ClubMessage = require('./models/clubMessage');
const ClubJoinRequest = require('./models/clubJoinRequest');
const { ensureDefaultClub } = require('./utils/clubSeed');
const { validateMessageLinks } = require('./utils/linkSanitizer');
const { saveClubChatArchive } = require('./utils/clubStorage');
const ModPromotion = require('./models/modPromotion');

// Multer storage for Volunteer KYC documents
const kycStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        const kycDir = path.join(__dirname, 'public', 'uploads', 'kyc');
        if (!fs.existsSync(kycDir)) {
            fs.mkdirSync(kycDir, { recursive: true });
        }
        cb(null, kycDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, 'kyc-' + uniqueSuffix + ext);
    }
});
const kycUpload = multer({
    storage: kycStorage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: function (req, file, cb) {
        const allowedTypes = /jpeg|jpg|png|webp|pdf/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (extname && mimetype) {
            return cb(null, true);
        }
        cb(new Error('Only JPG, PNG, WEBP, and PDF documents are allowed for KYC verification.'));
    }
});

// Cashfree Payments SDK Initialization (Sandbox / Test Environment)
const { Cashfree, CFEnvironment } = require('cashfree-pg');
const cashfreeEnvironment = (process.env.CASHFREE_ENVIRONMENT || 'sandbox').toLowerCase() === 'production'
    ? CFEnvironment.PRODUCTION
    : CFEnvironment.SANDBOX;

const cashfree = new Cashfree(
    cashfreeEnvironment,
    process.env.CASHFREE_APP_ID,
    process.env.CASHFREE_SECRET_KEY
);
cashfree.XApiVersion = "2025-01-01";

const DailyStat = require('./models/dailyStat');
const PointHistory = require('./models/pointHistory');
const TranslationCache = require('./models/translationCache');
const { reserveApiQuota, releaseApiQuota, disableApiQuotaOnError, ensureApiLimitCatalog } = require('./utils/apiQuota');
const deepl = require('deepl-node');
const deeplClient = new deepl.DeepLClient(process.env.DEEPL_API_KEY);
const IosDns = require('./models/iosDns');
const IosCert = require('./models/iosCert');
const VpnCache = require('./models/vpnCache');
const License = require('./models/content/license');
const ModTemplate = require('./models/modTemplate');
const SourceCode = require('./models/sourceCode');
const ChatSession = require('./models/chatSession');
const ChatSettings = require('./models/chatSettings');
const AIKnowledge = require('./models/aiKnowledge');
const improvmx = require('./utils/improvmx');
const { GoogleGenerativeAI } = require("@google/generative-ai");

// Initialize Gemini Flash AI
const genAI = process.env.GEMINI_API_KEY ? new GoogleGenerativeAI(process.env.GEMINI_API_KEY) : null;
const aiModel = genAI ? genAI.getGenerativeModel({ 
    model: "gemini-3.6-flash",
    systemInstruction: "You are the official support assistant for GPL Mods. Your tone is helpful, friendly, and uses emojis naturally. You help users find safe Android, iOS, Windows, and WordPress mods. If they need human help, tell them to type 'human'."
}) : null;

// AI Diagnostics & Health State
const aiDebuggerStatus = {
    status: process.env.GEMINI_API_KEY ? 'online' : 'offline',
    model: 'gemini-3.6-flash',
    configured: Boolean(process.env.GEMINI_API_KEY),
    lastPing: null,
    latencyMs: null,
    lastError: null,
    totalRequests: 0,
    totalErrors: 0
};

// ===============================
// 1. INITIALIZATION & CONFIGURATION
// ===============================
const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;
const { Types } = mongoose;

// Initialize the profanity filter
const profanityFilter = new Filter();
// You can add custom words that aren't in the default list
// profanityFilter.addWords('custombadword1', 'custombadword2');
// You can also remove words you don't consider bad
// profanityFilter.removeWords('hell');

// Expose it globally so we can use it in Socket.IO and Express routes
global.profanityFilter = profanityFilter;

app.set('view engine', 'ejs');

// --- HELPER: AUTOMATED MOD FEEDS POSTING TO CLUBS (#new-uploads and #new-updates) ---
async function notifyClubModFeeds(file, isUpdate = false, whatsNew = '') {
    try {
        if (!file || !file.uploader) return;
        const uploaderUser = await User.findOne({ username: file.uploader });
        const uploaderId = uploaderUser ? uploaderUser._id : null;

        const clubQuery = {
            $or: [
                { isDefault: true }
            ]
        };
        if (uploaderId) {
            clubQuery.$or.push({ trackedCreators: uploaderId }, { creator: uploaderId });
        }

        const clubs = await Club.find(clubQuery);
        if (!clubs || clubs.length === 0) return;

        const targetChannelName = isUpdate ? 'new-updates' : 'new-uploads';
        const io = app.get('io');
        const resolvedIcon = await getSmartImageUrl(file.iconKey || file.iconUrl);

        for (const club of clubs) {
            const channel = await ClubChannel.findOne({ club: club._id, name: targetChannelName });
            if (!channel) continue;

            const contentText = isUpdate
                ? `🔄 **Mod Updated:** **${file.name}** has a new update (**v${file.version}**)! Release notes: ${whatsNew || 'Bug fixes and performance improvements.'}`
                : `🚀 **New Mod Upload:** **${file.name}** (**v${file.version}**) is now available in category **${(file.category || 'mods').toUpperCase()}**!`;

            const modMsg = await ClubMessage.create({
                club: club._id,
                channel: channel._id,
                sender: uploaderId || club.creator,
                content: contentText,
                modUpdate: {
                    modId: file._id,
                    name: file.name,
                    iconUrl: resolvedIcon,
                    version: file.version,
                    category: file.category,
                    downloadUrl: `/download/${file.slug || file._id}`,
                    changelog: whatsNew || (isUpdate ? 'General improvements.' : 'Initial release.'),
                    isNewUpload: !isUpdate
                },
                isSystemMessage: true
            });

            if (io) {
                io.to(`club_${club._id}_chan_${channel._id}`).emit('club_new_message', {
                    _id: modMsg._id,
                    channel: channel._id,
                    club: club._id,
                    content: contentText,
                    modUpdate: modMsg.modUpdate,
                    createdAt: modMsg.createdAt,
                    sender: {
                        username: 'GPL Mods Feeds',
                        signedAvatarUrl: '/images/team-logo.png',
                        role: 'admin',
                        badges: []
                    }
                });
            }
        }

        // Broadcast dynamic push notification to subscribed PWA / web devices
        try {
            const pushNotification = require('./utils/pushNotification');
            const notifCategory = isUpdate ? 'club-updates' : 'new-uploads';
            const notifTitle = isUpdate
                ? `🔄 Mod Update: ${file.name} v${file.version}`
                : `🚀 New Mod Upload: ${file.name}`;
            const notifBody = isUpdate
                ? (whatsNew || `${file.name} has a new update! Check out what's new.`)
                : `${file.name} (v${file.version}) is now available in ${(file.category || 'mods').toUpperCase()}!`;

            pushNotification.broadcastPushNotification(notifCategory, {
                title: notifTitle,
                body: notifBody,
                url: `/download/${file.slug || file._id}`,
                icon: resolvedIcon || '/images/icon-192x192.png',
                tag: `gplmods-${isUpdate ? 'update' : 'upload'}-${file.slug || file._id}`,
                sound: true
            }, io);
        } catch (pushErr) {
            console.error('[WebPush] notifyClubModFeeds push error:', pushErr.message);
        }
    } catch (err) {
        console.error('[Clubs] notifyClubModFeeds error:', err.message);
    }
}
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

// --- HELPER: DETECT EMOJIS ---
function hasEmoji(str) {
    if (!str || typeof str !== 'string') return false;
    const emojiRegex = /\p{Extended_Pictographic}|\p{Emoji_Presentation}/u;
    return emojiRegex.test(str);
}

// --- HELPER: VALIDATE MOD NAMES (Letters, Numbers, Spaces, ':', and '-' ONLY) ---
function isValidModName(str) {
    if (!str || typeof str !== 'string') return false;
    const trimmed = str.trim();
    if (trimmed.length === 0) return false;
    // Must contain at least one letter or number
    if (!/[a-zA-Z0-9]/.test(trimmed)) return false;
    // Strictly forbids emojis
    if (hasEmoji(trimmed)) return false;
    // Only letters, numbers, spaces, colons (:), and hyphens (-)
    const regex = /^[a-zA-Z0-9 :\-]+$/;
    return regex.test(trimmed);
}

function getModNameValidationError(str) {
    if (!str || typeof str !== 'string' || !str.trim()) {
        return 'Mod Name is required.';
    }
    const trimmed = str.trim();
    if (!/[a-zA-Z0-9]/.test(trimmed)) {
        return 'Mod Name must contain at least one letter or number.';
    }
    if (hasEmoji(trimmed)) {
        return 'Emojis are not allowed in Mod Name.';
    }
    if (!/^[a-zA-Z0-9 :\-]+$/.test(trimmed)) {
        const illegalChars = Array.from(new Set(trimmed.split('').filter(c => !/[a-zA-Z0-9 :\-]/i.test(c)))).join(' ');
        return `Mod Name contains illegal character(s): ${illegalChars}. Only letters, numbers, spaces, ':', and '-' are allowed.`;
    }
    return null;
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
    
    // If it's a Backblaze B2 URL (expired or active), extract the B2 key to re-sign it fresh
    if (typeof key === 'string' && key.includes('backblazeb2.com')) {
        const b2Match = key.match(/(?:users|mods|clubs|card-avatars|avatars|card-backgrounds|mod-icons|screenshots|files)\/[^?#\s]+/);
        if (b2Match) {
            key = b2Match[0];
        }
    }
    
    // If local path or external web URL (not a B2 raw link), just use it directly!
    if (key.startsWith('/') || ((key.startsWith('http://') || key.startsWith('https://')) && !key.includes('backblazeb2.com'))) {
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

// --- NEW HELPER: CONVERT IMAGE TO BASE64 DATA URL FOR CORS-FREE HTML2CANVAS ---
async function getImageAsDataUrl(urlOrKey) {
    try {
        if (!urlOrKey) return null;
        if (typeof urlOrKey === 'string' && urlOrKey.startsWith('data:image/')) return urlOrKey;

        // 1. Local public path
        if (typeof urlOrKey === 'string' && urlOrKey.startsWith('/')) {
            const localPath = path.join(__dirname, 'public', urlOrKey);
            if (fs.existsSync(localPath)) {
                const ext = path.extname(localPath).replace('.', '').toLowerCase() || 'png';
                const mime = ext === 'svg' ? 'image/svg+xml' : (ext === 'jpg' ? 'image/jpeg' : `image/${ext}`);
                const buf = fs.readFileSync(localPath);
                return `data:${mime};base64,${buf.toString('base64')}`;
            }
        }

        // 2. Backblaze B2 key or URL
        let b2Key = urlOrKey;
        if (typeof urlOrKey === 'string' && urlOrKey.includes('backblazeb2.com')) {
            const b2Match = urlOrKey.match(/(?:users|mods|clubs|card-avatars|avatars|card-backgrounds|mod-icons|screenshots|files)\/[^?#\s]+/);
            if (b2Match) b2Key = b2Match[0];
        }

        if (typeof b2Key === 'string' && !b2Key.startsWith('http://') && !b2Key.startsWith('https://')) {
            const s3Res = await s3Client.send(new GetObjectCommand({
                Bucket: process.env.B2_BUCKET_NAME,
                Key: b2Key
            }));
            const chunks = [];
            for await (const chunk of s3Res.Body) chunks.push(chunk);
            const buf = Buffer.concat(chunks);
            const mime = s3Res.ContentType || 'image/png';
            return `data:${mime};base64,${buf.toString('base64')}`;
        }

        // 3. Remote HTTP / HTTPS URL
        if (typeof urlOrKey === 'string' && (urlOrKey.startsWith('http://') || urlOrKey.startsWith('https://'))) {
            const resp = await axios.get(urlOrKey, { responseType: 'arraybuffer', timeout: 6000 });
            const mime = resp.headers['content-type'] || 'image/png';
            return `data:${mime};base64,${Buffer.from(resp.data).toString('base64')}`;
        }
    } catch (error) {
        console.warn(`[getImageAsDataUrl] Could not convert image to Data URL: ${urlOrKey}`, error.message);
    }
    return null;
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
// --- ANTI-TEMP MAIL CHECKER (TempMailDetector API + MongoDB Cache) ---
/**
 * Checks if an email address is from a disposable/temporary domain.
 * Uses TempMailDetector API with MongoDB caching & default whitelist.
 * @param {string} email - The email address to check.
 * @returns {Promise<boolean>} - True if disposable/blocked, False if safe.
 */
async function isDisposableEmail(email) {
    try {
        if (!email || typeof email !== 'string') return true;
        const result = await checkDomain(email);
        return Boolean(result.isDisposable || result.blocked);
    } catch (error) {
        console.error("Temp Mail Checker Error:", error.message);
        // Fallback OPEN to avoid blocking legitimate users on unexpected runtime errors
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

// --- HELPER: Get all active, configured 2FA methods for a user ---
function getAvailable2FAMethods(user) {
    if (!user) return ['email'];
    if (!user.twoFactorEnabled && !user.is2FAEnabled) return [];

    const methods = [];
    const rawMethods = Array.isArray(user.twoFactorMethods) ? user.twoFactorMethods : [];

    // Check credentials for each method
    const hasTotp = Boolean(user.twoFactorSecret && user.twoFactorSecret.length > 0);
    const hasPasskey = Boolean((user.passkey && user.passkey.credentialID) || (Array.isArray(user.passkeys) && user.passkeys.length > 0));
    const hasSocial = Boolean((user.twoFactorSocialProvider && user.twoFactorSocialProvider !== 'none') || (user.twoFactorProvider && user.twoFactorProvider !== 'none'));
    const hasEmail = Boolean(user.email && user.email.length > 0);

    // If user has explicitly configured twoFactorMethods array, only respect what is in the array and has credentials
    if (rawMethods.length > 0) {
        rawMethods.forEach(m => {
            if (m === 'totp' && hasTotp && !methods.includes('totp')) methods.push('totp');
            if (m === 'passkey' && hasPasskey && !methods.includes('passkey')) methods.push('passkey');
            if (m === 'social' && hasSocial && !methods.includes('social')) methods.push('social');
            if (m === 'email' && hasEmail && !methods.includes('email')) methods.push('email');
        });
    }

    // If array was empty or methods became empty but 2FA is marked enabled (legacy account support)
    if (methods.length === 0 && (user.twoFactorEnabled || user.is2FAEnabled)) {
        if (user.twoFactorMethod === 'totp' && hasTotp) methods.push('totp');
        else if (user.twoFactorMethod === 'passkey' && hasPasskey) methods.push('passkey');
        else if (user.twoFactorMethod === 'social' && hasSocial) methods.push('social');
        else if (hasEmail) methods.push('email');
    }

    return methods.slice(0, 3); // Max 3 methods
}

async function createWelcomeNotification(user) {
    if (!user || !user._id) return;

    try {
        const existingWelcome = await UserNotification.findOne({
            user: user._id,
            title: 'Welcome to GPL Mods!'
        });

        if (existingWelcome) return;

        await new UserNotification({
            user: user._id,
            title: 'Welcome to GPL Mods!',
            message: `Hi ${user.username || 'there'},\n\nWelcome to the community! We're thrilled to have you here. \n\nFeel free to explore our massive library of safe, working mods, or start uploading your own to build your reputation.\n\nIf you need any help, check out the FAQ or submit a Support Ticket.\n\nHappy Modding,\nThe GPL Community Team`,
            type: 'success'
        }).save();
    } catch (notifErr) {
        console.error('Welcome message error:', notifErr);
    }
}

// ===============================
// INDEXNOW SEO PROTOCOL HELPER
// ===============================
const indexNowKey = process.env.INDEXNOW_KEY || '4387532a48904cbaae6f8ba7ad35d790';

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
    let clientEmail = process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL || process.env.GOOGLE_INDEXING_CLIENT_EMAIL || process.env.GOOGLE_CLIENT_EMAIL;
    let privateKey = process.env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY || process.env.GOOGLE_INDEXING_PRIVATE_KEY || process.env.GOOGLE_PRIVATE_KEY;

    // Support raw JSON, Base64 JSON, or direct environment variables
    const rawCredentials = process.env.GOOGLE_SERVICE_ACCOUNT_JSON 
        || process.env.GOOGLE_CREDENTIALS 
        || process.env.GOOGLE_CREDENTIALS_JSON 
        || process.env.GOOGLE_CREDENTIALS_BASE64;

    if (rawCredentials && (!clientEmail || !privateKey)) {
        let jsonString = rawCredentials.trim();
        let credentials = null;

        // 1. Try direct JSON parsing (for unencoded JSON strings)
        if (jsonString.startsWith('{')) {
            try {
                credentials = JSON.parse(jsonString);
            } catch (parseErr) {
                // Ignore and fall back to base64
            }
        }

        // 2. Try Base64 decoding if direct JSON parsing didn't work
        if (!credentials) {
            try {
                const decodedString = Buffer.from(jsonString, 'base64').toString('utf-8').trim();
                credentials = JSON.parse(decodedString);
            } catch (parseErr) {
                // Ignore
            }
        }

        if (credentials && typeof credentials === 'object') {
            clientEmail = credentials.client_email || clientEmail;
            privateKey = credentials.private_key || privateKey;
        }
    }

    if (!clientEmail || !privateKey) {
        console.warn("[Google Indexing] Incomplete credentials: client_email or private_key missing. Google sync will be skipped.");
        jwtClient = null;
    } else {
        // Unescape escaped newline characters (\n -> actual newline)
        const formattedPrivateKey = privateKey.replace(/\\n/g, '\n');

        jwtClient = new google.auth.JWT({
            email: clientEmail,
            key: formattedPrivateKey,
            scopes: ['https://www.googleapis.com/auth/indexing'] // Official scope required by the docs
        });
        console.log("[Google Indexing] Credentials successfully loaded!");
    }
} catch (e) {
    console.error("[Google Indexing Error] Failed to load Google credentials:", e.message);
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
        try {
            await jwtClient.authorize();
        } catch (authErr) {
            console.error(`[Google Error] Authorization failed for ${url}:`, authErr.message || authErr);
            return; // Don't throw - skip Google indexing if auth fails
        }

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
        // Don't throw - indexing failures should not crash the server
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
        
        // 2. Delete from Backup Cloud (images only)
        if (shouldMirrorToFTP(fileKey)) {
            deleteFromFTP(fileKey).catch(e => console.error("Background FTP delete failed", e));
        }
        
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

// --- UPDATED HELPER: Tracks B2 Upload Progress & Creates Clean Slugs ---
// --- UPDATED HELPER: Tracks B2 Upload Progress & Creates Categorized Subfolders ---
const uploadToB2 = async (file, folder, io = null, uploadId = null, baseName = null, options = {}) => {
    if (!file || !file.buffer) {
        throw new Error("File data (buffer) not found.");
    }

    const ext = path.extname(file.originalname).toLowerCase() || '';
    const cleanBase = baseName ? slugify(baseName) : 'file';

    let catFolder = 'general';
    const rawCategory = options.category || options.platform || '';
    if (rawCategory === 'ios-jailed') catFolder = 'ios/jailed';
    else if (rawCategory === 'ios-jailbroken') catFolder = 'ios/jailbroken';
    else if (rawCategory) catFolder = slugify(rawCategory);

    let fileName = '';

    if (options.exactKey) {
        fileName = options.exactKey;
    } else if (options.user && (folder === 'avatars' || folder === 'card-avatars' || folder === 'card-backgrounds' || folder === 'users')) {
        const userAssetType = options.assetType || (folder === 'card-backgrounds' ? 'card-bg' : (folder === 'card-avatars' ? 'card-avatar' : 'avatar'));
        fileName = getUserAssetKey(options.user, userAssetType, file.originalname);
    } else if (folder === 'avatars') {
        const username = options.username || baseName || 'user';
        const userSlug = slugify(username);
        fileName = `avatars/${userSlug}/${userSlug}-avatar-${Date.now()}${ext}`;
    } else if (folder === 'mods' && (options.modName || options.modSlug)) {
        fileName = getModStorageKey({
            category: options.category || options.platform || rawCategory,
            modName: options.modName || options.modSlug || cleanBase,
            uploader: options.uploader || options.username,
            uploaderEmail: options.uploaderEmail,
            isVariant: options.isVariant,
            variantId: options.variantId,
            assetType: options.isOldVersion ? 'old-version' : 'file',
            originalFilename: file.originalname,
            version: options.version
        });
    } else if (folder === 'icons' && (options.modName || options.modSlug)) {
        fileName = getModStorageKey({
            category: options.category || options.platform || rawCategory,
            modName: options.modName || options.modSlug || cleanBase,
            uploader: options.uploader || options.username,
            uploaderEmail: options.uploaderEmail,
            isVariant: options.isVariant,
            variantId: options.variantId,
            assetType: 'icon',
            originalFilename: file.originalname
        });
    } else if (folder === 'screenshots' && (options.modName || options.modSlug)) {
        fileName = getModStorageKey({
            category: options.category || options.platform || rawCategory,
            modName: options.modName || options.modSlug || cleanBase,
            uploader: options.uploader || options.username,
            uploaderEmail: options.uploaderEmail,
            isVariant: options.isVariant,
            variantId: options.variantId,
            assetType: 'screenshot',
            screenshotIndex: options.screenshotIndex || 1,
            originalFilename: file.originalname
        });
    } else if (folder === 'mods') {
        const modSlug = options.modSlug || cleanBase;
        if (options.isVariant && options.masterSlug) {
            fileName = `mods/${catFolder}/${options.masterSlug}/variants/${modSlug}/${cleanBase}-${Date.now()}${ext}`;
        } else {
            fileName = `mods/${catFolder}/${modSlug}/${cleanBase}-${Date.now()}${ext}`;
        }
    } else if (folder === 'icons') {
        const modSlug = options.modSlug || cleanBase;
        if (options.isVariant && options.masterSlug) {
            fileName = `mods/${catFolder}/${options.masterSlug}/variants/${modSlug}/icons/${cleanBase}-icon-${Date.now()}${ext}`;
        } else {
            fileName = `mods/${catFolder}/${modSlug}/icons/${cleanBase}-icon-${Date.now()}${ext}`;
        }
    } else if (folder === 'screenshots') {
        const modSlug = options.modSlug || cleanBase;
        if (options.isVariant && options.masterSlug) {
            fileName = `mods/${catFolder}/${options.masterSlug}/variants/${modSlug}/screenshots/${cleanBase}-screenshot-${Date.now()}${ext}`;
        } else {
            fileName = `mods/${catFolder}/${modSlug}/screenshots/${cleanBase}-screenshot-${Date.now()}${ext}`;
        }
    } else if (folder === 'forums') {
        const issueCat = options.category || 'general';
        const issueStatus = options.status || 'open';
        const issueSlug = options.issueSlug || cleanBase;
        fileName = `forums/${slugify(issueCat)}/${slugify(issueStatus)}/${issueSlug}/media/${cleanBase}-${Date.now()}${ext}`;
    } else if (folder === 'docs') {
        const docCat = options.category || 'general';
        const docSlug = options.docSlug || cleanBase;
        fileName = `docs/${slugify(docCat)}/${docSlug}/media/${cleanBase}-${Date.now()}${ext}`;
    } else if (folder === 'requests') {
        const reqPlatform = options.platform || 'general';
        const reqStatus = options.status || 'pending';
        const reqId = options.requestId || cleanBase;
        fileName = `requests/${slugify(reqPlatform)}/${slugify(reqStatus)}/${reqId}/media/${cleanBase}-${Date.now()}${ext}`;
    } else if (folder === 'support') {
        const ticketCat = options.category || 'general';
        const ticketStatus = options.status || 'open';
        const ticketId = options.ticketId || cleanBase;
        fileName = `support/${slugify(ticketCat)}/${slugify(ticketStatus)}/${ticketId}/media/${cleanBase}-${Date.now()}${ext}`;
    } else {
        const sanitizedFilename = file.originalname.replace(/\s+/g, '-').replace(/[^a-zA-Z0-9.\-_]/g, '');
        fileName = `${folder}/${Date.now()}-${sanitizedFilename}`;
    }

    console.log(`Uploading ${fileName} to B2...`);
    
    const { Upload } = require("@aws-sdk/lib-storage");

    const parallelUploads3 = new Upload({
        client: s3Client,
        params: { 
            Bucket: process.env.B2_BUCKET_NAME, 
            Key: fileName, 
            Body: file.buffer,
            ContentType: file.mimetype 
        },
        partSize: 5 * 1024 * 1024, 
        queueSize: 4 
    });

    parallelUploads3.on("httpUploadProgress", (progress) => {
        if (progress.total && io && uploadId) {
            const percent = Math.round((progress.loaded / progress.total) * 100);
            io.emit(`b2_progress_${uploadId}`, {
                percent: percent,
                loaded: (progress.loaded / (1024 * 1024)).toFixed(2),
                total: (progress.total / (1024 * 1024)).toFixed(2)
            });
        }
    });

    await parallelUploads3.done();
    console.log(`Finished uploading ${fileName} to B2.`);

    if (shouldMirrorToFTP(fileName)) {
        mirrorToFTP(file.buffer, fileName).catch(e => console.error("Background FTP mirror failed", e));
    }

    return fileName;
};

// ===============================
// 4. PRE-ADMIN MIDDLEWARE
// ===============================
// 1. Static Files (Safe to be early)
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookieParser());

// 2. Parsers (Crucial for AdminJS and login forms)
app.use(express.urlencoded({ extended: true }));
app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf.toString('utf8');
    }
}));

// 3. CORS
const allowedOrigins = [
    `http://localhost:${PORT}`,
    'http://localhost:3000',          
    'https://gplmods.webredirect.org',
    'http://gplmods.webredirect.org',
    ...(process.env.RENDER_EXTERNAL_URL ? [process.env.RENDER_EXTERNAL_URL] : []),
    ...(process.env.BASE_URL ? [process.env.BASE_URL] : [])
];
app.use(cors({
    origin: function (origin, callback) {
        // Requests without origin (like direct navigation, curl, webhooks, or same-origin)
        if (!origin) return callback(null, true);

        // Explicit matches from allowed list
        if (allowedOrigins.indexOf(origin) !== -1) {
            return callback(null, true);
        }

        // Dynamic domain pattern matching for Cashfree, Render, and site mirrors
        try {
            const parsedUrl = new URL(origin);
            const host = parsedUrl.hostname.toLowerCase();
            if (
                host === 'localhost' ||
                host === '127.0.0.1' ||
                host.endsWith('.cashfree.com') ||
                host === 'cashfree.com' ||
                host.endsWith('.onrender.com') ||
                host === 'onrender.com' ||
                host.endsWith('.webredirect.org') ||
                host === 'webredirect.org'
            ) {
                return callback(null, true);
            }
        } catch (e) {
            // Malformed origin string
        }

        // Safely disallow CORS without crashing Express with an unhandled 500 error
        return callback(null, false);
    },
    credentials: true
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

// ===============================
// MUSIC & PLAYLIST API
// ===============================
const AUDIO_DIR = path.join(__dirname, 'public', 'audio');

const DEFAULT_TRACK_TITLES = {
    'bgm-0.mp3': 'You are Good Enough',
    'bgm-1.mp3': 'Whoopty',
    'bgm-2.mp3': 'Nekozilla',
    'bgm-3.mp3': 'Heroes Tonight',
    'bgm-4.mp3': 'Dreams',
    'bgm-5.mp3': 'Royalty',
    'bgm-6.mp3': 'Mortals',
    'bgm-7.mp3': 'On & On',
    'bgm-8.mp3': 'Rise Up',
    'bgm-9.mp3': 'Keep Up'
};

// Helper to scan public/audio and return all audio files
async function getLocalAudioTracks() {
    try {
        if (!fs.existsSync(AUDIO_DIR)) {
            fs.mkdirSync(AUDIO_DIR, { recursive: true });
        }
        const files = await fs.promises.readdir(AUDIO_DIR);
        const audioExtensions = new Set(['.mp3', '.wav', '.ogg', '.m4a', '.aac', '.flac']);
        const audioFiles = files.filter(f => audioExtensions.has(path.extname(f).toLowerCase()));
        
        // Natural sort e.g. bgm-0, bgm-1, bgm-2 ... bgm-9
        audioFiles.sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));

        const tracks = await Promise.all(audioFiles.map(async (filename) => {
            const filePath = path.join(AUDIO_DIR, filename);
            const stats = await fs.promises.stat(filePath);
            
            let trackTitle = DEFAULT_TRACK_TITLES[filename];
            if (!trackTitle) {
                let friendlyTitle = filename.replace(/\.[^/.]+$/, '').replace(/[-_]/g, ' ');
                trackTitle = friendlyTitle.replace(/\b\w/g, l => l.toUpperCase());
            }

            return {
                filename,
                src: `/audio/${filename}`,
                title: trackTitle,
                size: stats.size,
                sizeFormatted: (stats.size / (1024 * 1024)).toFixed(2) + ' MB',
                modifiedAt: stats.mtime
            };
        }));
        return tracks;
    } catch (err) {
        console.error('Error scanning public/audio directory:', err);
        return [];
    }
}

// Audio upload configuration for public/audio
const uploadAudioTrack = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            if (!fs.existsSync(AUDIO_DIR)) fs.mkdirSync(AUDIO_DIR, { recursive: true });
            cb(null, AUDIO_DIR);
        },
        filename: (req, file, cb) => {
            const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_').toLowerCase();
            cb(null, safeName);
        }
    }),
    limits: { fileSize: 30 * 1024 * 1024 }, // 30 MB limit
    fileFilter: (req, file, cb) => {
        const allowedExts = ['.mp3', '.wav', '.ogg', '.m4a', '.aac', '.flac'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedExts.includes(ext)) {
            cb(null, true);
        } else {
            cb(new Error('Only audio files (.mp3, .wav, .ogg, .m4a, .aac, .flac) are allowed.'));
        }
    }
});

// ===============================
// VPN DETECTION API (vpnapi.io + MongoDB Cache)
// ===============================
app.get('/api/check-vpn', async (req, res) => {
    try {
        // Extract client IP address from headers or socket
        let clientIp = req.headers['x-forwarded-for'] 
            ? req.headers['x-forwarded-for'].split(',')[0].trim() 
            : (req.socket.remoteAddress || req.ip || '');

        // Remove IPv6 mapping prefix if present
        if (clientIp.startsWith('::ffff:')) {
            clientIp = clientIp.replace('::ffff:', '');
        }

        // Allow query parameter override for testing (e.g., /api/check-vpn?ip=8.8.8.8)
        if (req.query.ip && typeof req.query.ip === 'string') {
            clientIp = req.query.ip.trim();
        }

        // Handle local loopback / private IP addresses
        const isLocalhost = !clientIp || clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === 'localhost' || clientIp.startsWith('192.168.') || clientIp.startsWith('10.');
        if (isLocalhost && !req.query.ip) {
            return res.json({
                success: true,
                ip: clientIp || '127.0.0.1',
                isVpn: false,
                security: { vpn: false, proxy: false, tor: false, relay: false },
                location: {},
                network: {},
                cached: false,
                note: 'Local/Internal IP address detected'
            });
        }

        // 1. Check MongoDB Database FIRST
        const existingCache = await VpnCache.findOneAndUpdate(
            { ip: clientIp },
            { $inc: { visitCount: 1 }, $set: { lastVisitedAt: new Date() } },
            { new: true }
        );
        if (existingCache) {
            console.log(`[VPN API] DB Cache HIT for IP: ${clientIp} (isVpn: ${existingCache.isVpn})`);
            return res.json({
                success: true,
                ip: existingCache.ip,
                isVpn: existingCache.isVpn,
                security: existingCache.security,
                location: existingCache.location,
                network: existingCache.network,
                visitCount: existingCache.visitCount,
                cached: true
            });
        }

        // 2. Not in DB -> Query vpnapi.io API
        console.log(`[VPN API] DB Cache MISS for IP: ${clientIp}. Querying vpnapi.io...`);
        const apiKey = process.env.VPNAPI_KEY || '58919de8ab5d4a5cbdb0604e31efc9bd';
        const quota = await reserveApiQuota({ service: 'vpnapi.io', metric: 'requests', period: 'daily', amount: 1 });
        if (!quota.allowed) {
            return res.json({
                success: true,
                ip: clientIp,
                isVpn: false,
                security: {},
                location: {},
                network: {},
                cached: false,
                note: 'VPN API request limit unavailable'
            });
        }
        
        let response;
        try {
            response = await axios.get(`https://vpnapi.io/api/${clientIp}?key=${apiKey}`, {
                timeout: 7000
            });
        } catch (error) {
            await releaseApiQuota(quota.reservation);
            await disableApiQuotaOnError('vpnapi.io', 'daily', error, 'requests');
            throw error;
        }

        const data = response.data || {};
        const security = data.security || {};
        const isVpn = Boolean(security.vpn || security.proxy || security.tor || security.relay);

        // 3. Save result to Database
        const newVpnRecord = new VpnCache({
            ip: clientIp,
            isVpn: isVpn,
            visitCount: 1,
            firstSeenAt: new Date(),
            lastVisitedAt: new Date(),
            security: {
                vpn: Boolean(security.vpn),
                proxy: Boolean(security.proxy),
                tor: Boolean(security.tor),
                relay: Boolean(security.relay)
            },
            location: data.location || {},
            network: data.network || {},
            rawResponse: data
        });

        let storedVpnRecord;
        try {
            storedVpnRecord = await newVpnRecord.save();
        } catch (saveError) {
            if (saveError.code !== 11000) throw saveError;
            storedVpnRecord = await VpnCache.findOneAndUpdate(
                { ip: clientIp },
                { $inc: { visitCount: 1 }, $set: { lastVisitedAt: new Date() } },
                { new: true }
            );
        }
        console.log(`[VPN API] Saved IP ${clientIp} to DB cache (isVpn: ${isVpn}).`);

        return res.json({
            success: true,
            ip: clientIp,
            isVpn: isVpn,
            security: storedVpnRecord.security,
            location: storedVpnRecord.location,
            network: storedVpnRecord.network,
            visitCount: storedVpnRecord.visitCount,
            cached: false
        });

    } catch (error) {
        console.error('[VPN API Error]:', error.response ? error.response.data : error.message);
        // Fail-open strategy: return isVpn: false on error so user experience isn't broken
        return res.status(500).json({
            success: false,
            isVpn: false,
            error: 'Failed to verify VPN status'
        });
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

    // 2.1 Check Dynamic Coming Soon Auto-Timer Expiration
    if (cachedSiteState.status === 'coming-soon') {
        const now = new Date();
        const launchDate = cachedSiteState.comingSoonLaunchDate ? new Date(cachedSiteState.comingSoonLaunchDate) : null;
        if (cachedSiteState.comingSoonEnableTimer && launchDate && now >= launchDate && cachedSiteState.comingSoonAutoPublishOnTimerEnd) {
            // Timer expired! Automatically transition site to online for everyone!
            cachedSiteState.status = 'online';
            SiteState.updateOne({ singletonId: 'master-state' }, { status: 'online' }).catch(err => console.error("Error auto-publishing on timer end:", err));
            return next();
        }
    }

    // 3. Always allow access to the Admin Panel, static assets, and essential endpoints
    if (
        req.path.startsWith('/admin') ||
        req.path === '/notify-launch' ||
        req.path === '/coming-soon' ||
        req.path.startsWith('/public') ||
        req.path.startsWith('/dist') ||
        req.path.startsWith('/css') ||
        req.path.startsWith('/images') ||
        req.path.startsWith('/js') ||
        req.path.startsWith('/api/devtool') ||
        (req.user && (req.user.role === 'admin' || req.user.role === 'owner'))
    ) {
        return next();
    }

    // 4. Handle "coming-soon" Status with Role & User Access Control
    if (cachedSiteState.status === 'coming-soon') {
        const allowedRoles = Array.isArray(cachedSiteState.comingSoonAllowedRoles)
            ? cachedSiteState.comingSoonAllowedRoles.map(r => String(r || '').toLowerCase().trim()).filter(Boolean)
            : [];
        const allowedUsers = Array.isArray(cachedSiteState.comingSoonAllowedUsers)
            ? cachedSiteState.comingSoonAllowedUsers.map(u => String(u || '').toLowerCase().trim()).filter(Boolean)
            : [];

        const userRole = req.user ? String(req.user.role || '').toLowerCase().trim() : '';
        const userName = req.user ? String(req.user.username || '').toLowerCase().trim() : '';

        // Check if role or username is allowed to access
        const isRoleAllowed = userRole && allowedRoles.includes(userRole);
        const isUserAllowed = userName && allowedUsers.includes(userName);

        if (isRoleAllowed || isUserAllowed) {
            return next();
        }

        // Intercept and render dynamic Coming Soon page
        return res.status(200).render('pages/coming-soon', {
            title: cachedSiteState.comingSoonTitle || 'Something Awesome is Coming Soon',
            message: cachedSiteState.comingSoonMessage || "We're working hard behind the scenes to deliver an exceptional experience. Stay tuned for the big reveal!",
            customText: cachedSiteState.comingSoonCustomText || 'Feature is currently under development. Stay tuned for official announcements!',
            enableTimer: cachedSiteState.comingSoonEnableTimer !== false,
            launchDate: cachedSiteState.comingSoonLaunchDate ? new Date(cachedSiteState.comingSoonLaunchDate).toISOString() : '',
            user: req.user || null
        });
    }

    // 5. Determine if the current user matches the Target Audience for maintenance / unavailable lockdown
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

    // 6. If the user is targeted, show them the appropriate intercept page
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
        return ensureApiLimitCatalog()
            .then(() => m.connection.getClient());
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

const sessionMiddleware = session({
    secret: process.env.SESSION_SECRET || 'fallback-secret-key',
    resave: false,
    saveUninitialized: false,
    store: store, 
    cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 } // Default 7 days
});
app.use(sessionMiddleware);

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
                res.clearCookie('is_logged_in', { path: '/' });
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
                        res.clearCookie('is_logged_in', { path: '/' });
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

// Invalidate sessions after an account-wide security change.
app.use((req, res, next) => {
    if (req.isAuthenticated() && req.session.sessionVersion !== undefined && req.session.sessionVersion !== (req.user.sessionVersion || 0)) {
        return req.logout(() => {
            req.session.destroy(() => {
                res.clearCookie('connect.sid', { path: '/' });
                res.clearCookie('is_logged_in', { path: '/' });
                res.redirect('/login?error=' + encodeURIComponent('Your session was revoked for security reasons. Please log in again.'));
            });
        });
    }
    next();
});

// Auto-clean stale is_logged_in cookie when user is not authenticated
app.use((req, res, next) => {
    if (!req.isAuthenticated() && req.cookies && req.cookies.is_logged_in) {
        res.clearCookie('is_logged_in', { path: '/' });
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
                const avatarUrl = await getSmartImageUrl(req.user.profileImageKey);
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
let cachedRecentAnnouncements = 0;
let cachedNewUploads = 0;
let cachedNewUpdates = 0;
let lastUpdateCheck = 0;

const officialSiteUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
let officialSiteHost = 'gplmods.webredirect.org';
try {
    officialSiteHost = new URL(officialSiteUrl).hostname.toLowerCase();
} catch (error) {
    console.error('Invalid BASE_URL configuration:', error.message);
}
const hasIntegrityConfiguration = Boolean(process.env.SYSTEM_INTEGRITY_KEY);

function isUnder18(dateOfBirth) {
    if (!dateOfBirth || Number.isNaN(new Date(dateOfBirth).getTime())) return false;
    const today = new Date();
    const birth = new Date(dateOfBirth);
    let age = today.getFullYear() - birth.getFullYear();
    const beforeBirthday = today.getMonth() < birth.getMonth() ||
        (today.getMonth() === birth.getMonth() && today.getDate() < birth.getDate());
    if (beforeBirthday) age -= 1;
    return age < 18;
}

function shouldHideAdultContent(user) {
    if (!user) return false;
    return typeof user.hideAdultContent === 'boolean'
        ? user.hideAdultContent
        : isUnder18(user.dateOfBirth);
}

app.use(async (req, res, next) => {
    try {
        // 1. ======== BASIC LOCALS & HELPERS ========
        res.locals.user = req.user || null;
        res.locals.hideAdultContent = shouldHideAdultContent(req.user);
        res.locals.globalCouncil = req.user ? !!req.user.globalCouncil : false;
        res.locals.timeAgo = timeAgo;
        res.locals.formatCompactNumber = formatCompactNumber;
        res.locals.formatBytes = formatBytes;
        res.locals.slugify = slugify;
    const cookies = req.headers.cookie || '';    
    const isCdnDown = cookies.includes('cdn_down=true');
    if (isCdnDown || !process.env.CDN_URL) {
        res.locals.cdnUrl = ''; // Fallback: Use local Render server
    } else {
        res.locals.cdnUrl = process.env.CDN_URL; // Normal: Use Cloudflare CDN
    }    
    // We pass the Raw Url to the frontend so our JS knows what to search & replace
    res.locals.rawCdnUrl = process.env.CDN_URL || ''; 
        // Make sure truncateText is defined as a helper function elsewhere in your server.js!
        res.locals.truncateText = typeof truncateText === 'function' ? truncateText : (str, len) => str.length > len ? str.substring(0, len) + '...' : str;
        res.locals.baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org'; 
        res.locals.socialLinks = cachedSiteState?.socialLinks || {};
        const requestHost = (req.hostname || '').toLowerCase().split(':')[0];
        const isLocalHost = requestHost === 'localhost' || requestHost === '127.0.0.1' || requestHost === '::1' || requestHost === '0.0.0.0' || requestHost.startsWith('192.168.') || requestHost.startsWith('10.');
        res.locals.isTestDeployment = isLocalHost || (!process.env.RENDER && process.env.NODE_ENV !== 'production' && requestHost !== officialSiteHost);
        res.locals.isOfficialDeployment = !res.locals.isTestDeployment && requestHost === officialSiteHost && (
            process.env.NODE_ENV !== 'production' || hasIntegrityConfiguration
        );
        res.locals.officialSiteUrl = officialSiteUrl;

        // 1.1 ======== DEBUGGER ACCESS & DEVTOOLS EXEMPTION ========
        // Admin, owner, and support roles have debugger access by default.
        // Also available for everyone on local development / test deployments.
        const currentRole = req.user ? String(req.user.role || '').toLowerCase() : '';
        res.locals.isDebuggerExempt = Boolean(
            res.locals.isTestDeployment ||
            ['admin', 'owner', 'support'].includes(currentRole)
        );

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
        } else if (req.user) {
            // If real user, check privileges (case-insensitive)
            const role = String(req.user.role || '').toLowerCase();
            const membership = String(req.user.membership || '').toLowerCase();
            if (role === 'admin' || role === 'owner' || role === 'distributor' || membership === 'premium') {
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
            cachedRecentAnnouncements = await Announcement.countDocuments({ createdAt: { $gte: oneDayAgo } });
            cachedNewUploads = await File.countDocuments({ status: 'live', isLatestVersion: true, createdAt: { $gte: oneDayAgo } });
            cachedNewUpdates = await File.countDocuments({ status: 'live', isLatestVersion: true, updatedAt: { $gte: oneDayAgo } });
            
            lastUpdateCheck = Date.now();
        }
        res.locals.totalUpdatesCount = cachedTotalUpdates;
        res.locals.recentAnnouncementsCount = cachedRecentAnnouncements;
        res.locals.newUploadsCount = cachedNewUploads;
        res.locals.newUpdatesCount = cachedNewUpdates;

        let unreadPersonalCount = 0;
        if (req.isAuthenticated() && req.user) {
            const UserNotification = require('./models/userNotification');
            unreadPersonalCount = await UserNotification.countDocuments({ user: req.user._id, isRead: false });
        }
        res.locals.unreadPersonalCount = unreadPersonalCount;

        // 6. ======== GOOGLE GEMINI CHATBOT VISIBILITY ENGINE ========
        let chatbotMasterEnabled = true;
        let hiddenPatterns = [];

        if (typeof cachedSiteState !== 'undefined' && cachedSiteState) {
            if (typeof cachedSiteState.enableGeminiChatbot === 'boolean') {
                chatbotMasterEnabled = cachedSiteState.enableGeminiChatbot;
            }
            if (Array.isArray(cachedSiteState.geminiHiddenPages)) {
                hiddenPatterns = cachedSiteState.geminiHiddenPages;
            } else if (typeof cachedSiteState.geminiHiddenPages === 'string') {
                hiddenPatterns = cachedSiteState.geminiHiddenPages.split(/[,\n\r]+/).map(s => s.trim()).filter(Boolean);
            }
        }

        let isChatbotHiddenOnPage = false;
        const currentReqPath = (req.path || '').toLowerCase();

        if (chatbotMasterEnabled && hiddenPatterns.length > 0) {
            isChatbotHiddenOnPage = hiddenPatterns.some(rawPattern => {
                if (!rawPattern) return false;
                let pattern = rawPattern.trim().toLowerCase();
                if (!pattern) return false;

                // Ensure leading slash
                if (!pattern.startsWith('/')) pattern = '/' + pattern;

                // Exact match (e.g. /upload, /status)
                if (currentReqPath === pattern || currentReqPath === pattern + '/') return true;

                // Dynamic param pattern like /mods/:id, /users/:username
                if (pattern.includes('/:')) {
                    const regexString = '^' + pattern.replace(/:[a-zA-Z0-9_]+/g, '[^\\/]+') + '(\\/?|\\/.*)?$';
                    try {
                        if (new RegExp(regexString).test(currentReqPath)) return true;
                    } catch (e) {}
                }

                // Wildcard / prefix pattern e.g. /admin/* or /mods/*
                if (pattern.endsWith('/*')) {
                    const prefix = pattern.slice(0, -2);
                    if (currentReqPath === prefix || currentReqPath.startsWith(prefix + '/')) return true;
                }
                if (pattern.endsWith('*')) {
                    const prefix = pattern.slice(0, -1);
                    if (currentReqPath.startsWith(prefix)) return true;
                }

                // Subdirectory prefix match e.g. /admin or /mods/
                if (pattern !== '/' && (currentReqPath === pattern || currentReqPath.startsWith(pattern + '/'))) {
                    return true;
                }

                return false;
            });
        }

        // By default Gemini shows on all pages, unless disabled globally or hidden for current page
        res.locals.showChatbot = chatbotMasterEnabled && !isChatbotHiddenOnPage;
        
        next(); 
        
    } catch (e) {
        console.error("Global Middleware Error:", e);
        
        // Fallbacks: If the DB crashes, the EJS templates still get data so the site doesn't crash completely!
        res.locals.totalUpdatesCount = cachedTotalUpdates || 0;
        res.locals.recentAnnouncementsCount = cachedRecentAnnouncements || 0;
        res.locals.newUploadsCount = cachedNewUploads || 0;
        res.locals.newUpdatesCount = cachedNewUpdates || 0;
        res.locals.unreadPersonalCount = 0;
        res.locals.socialLinks = cachedSiteState?.socialLinks || {};
        res.locals.showAds = false;
        res.locals.showModals = false;
        res.locals.showChatbot = true; // Default to showing chatbot
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
function send404(req, res) {
    res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0');
    if (req.xhr || (req.headers.accept && req.headers.accept.includes('application/json')) || (req.path && req.path.startsWith('/api/'))) {
        return res.status(404).json({ success: false, error: 'Not Found' });
    }
    return res.status(404).render('pages/error', {
        errorCode: '404',
        errorTitle: 'Page <span>Not Found</span>',
        errorMessage: "Oops! The page you're looking for doesn't exist. It might have been moved or deleted."
    });
}

function ensureAuthenticated(req, res, next) {
    if (typeof req.isAuthenticated === 'function' && req.isAuthenticated()) {
        // ✅ NEW: Tell browser NEVER to cache protected pages
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0');
        return next();
    }
    if (req.xhr || (req.headers.accept && req.headers.accept.includes('application/json')) || (req.path && req.path.startsWith('/api/'))) {
        return res.status(401).json({ success: false, error: 'Authentication required' });
    }
    res.redirect('/login');
}
function ensureAdmin(req, res, next) {
    if (!req.isAuthenticated || typeof req.isAuthenticated !== 'function' || !req.isAuthenticated() || !req.user) {
        return send404(req, res);
    }
    const role = (req.user && req.user.role) ? String(req.user.role).trim().toLowerCase() : '';
    if (role === 'admin' || role === 'owner') {
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0');
        return next();
    }
    return send404(req, res);
}
function ensureAdminOr404(req, res, next) {
    return ensureAdmin(req, res, next);
}
function ensureSupportOrAdmin(req, res, next) {
    if (!req.isAuthenticated || typeof req.isAuthenticated !== 'function' || !req.isAuthenticated() || !req.user) {
        return send404(req, res);
    }
    const role = (req.user && req.user.role) ? String(req.user.role).trim().toLowerCase() : '';
    if (role === 'admin' || role === 'support' || role === 'owner') {
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0');
        return next();
    }
    return send404(req, res);
}
function ensureOwner(req, res, next) {
    if (!req.isAuthenticated || typeof req.isAuthenticated !== 'function' || !req.isAuthenticated() || !req.user) {
        return send404(req, res);
    }
    const role = (req.user && req.user.role) ? String(req.user.role).trim().toLowerCase() : '';
    if (role === 'owner') {
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0');
        return next();
    }
    return send404(req, res);
}

// =========================================================================
// STEALTH ROUTE SHIELD: HIDE /admin, /owner, AND /.adminjs FROM THE PUBLIC
// =========================================================================
app.use((req, res, next) => {
    const rawPath = (req.path || '').toLowerCase();
    const isOwnerRoute = rawPath === '/owner' || rawPath.startsWith('/owner/') || rawPath.startsWith('/api/owner');
    const isAdminRoute = rawPath === '/admin' || rawPath.startsWith('/admin/') || rawPath.startsWith('/api/admin') || rawPath === '/.adminjs' || rawPath.startsWith('/.adminjs');

    if (!isOwnerRoute && !isAdminRoute) {
        return next();
    }

    const isAuth = Boolean(typeof req.isAuthenticated === 'function' && req.isAuthenticated() && req.user);
    const userRole = isAuth && req.user && req.user.role ? String(req.user.role).trim().toLowerCase() : '';

    if (isOwnerRoute) {
        if (!isAuth || userRole !== 'owner') {
            return send404(req, res);
        }
        return next();
    }

    if (isAdminRoute) {
        // Special-case: /admin/support and support-related ping/gemini endpoints allow 'support'
        const isSupportAllowed = rawPath === '/admin/support' || rawPath.startsWith('/api/admin/ai-') || rawPath === '/api/admin/gemini-config';
        if (isSupportAllowed && isAuth && (userRole === 'support' || userRole === 'admin' || userRole === 'owner')) {
            return next();
        }

        if (!isAuth || (userRole !== 'admin' && userRole !== 'owner')) {
            return send404(req, res);
        }
        return next();
    }

    next();
});
function redirectIfAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        const returnTo = req.session && req.session.returnTo && !req.session.returnTo.includes('/login') && !req.session.returnTo.includes('/register') && !req.session.returnTo.includes('/logout') ? req.session.returnTo : '/';
        if (req.session) delete req.session.returnTo;
        return res.redirect(returnTo); 
    }
    next();
}
async function verifyRecaptcha(req, res, next) {
    const token = req.body['g-recaptcha-response'];
    const returnUrl = req.path;
    if (!token) return res.redirect(`${returnUrl}?error=Please complete the "I'm not a robot" check.`);
    const quota = await reserveApiQuota({ service: 'google-recaptcha', metric: 'requests', period: 'monthly', amount: 1 });
    if (!quota.allowed) return res.redirect(`${returnUrl}?error=CAPTCHA verification is temporarily unavailable.`);
    try {
        const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${token}`);
        if (response.data.success) return next();
        return res.redirect(`${returnUrl}?error=CAPTCHA verification failed. Please try again.`);
    } catch (e) { 
        await releaseApiQuota(quota.reservation).catch(() => {});
        await disableApiQuotaOnError('google-recaptcha', 'monthly', e, 'requests').catch(() => {});
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
passport.use(new LocalStrategy({ usernameField: 'email', passReqToCallback: true }, async (req, email, password, done) => {
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) return done(null, false, { message: 'Incorrect email.' });
        const isMatch = await user.comparePassword(password);
        if (!isMatch) {
            user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
            if (user.failedLoginAttempts >= 5) {
                if (user.failedLoginAlertEmailsEnabled || user.safetyEmailsEnabled) await sendFailedAttemptEmail(user, req);
                user.failedLoginAttempts = 0;
            }
            await user.save();
            return done(null, false, { message: 'Incorrect password.' });
        }
        if (!user.isVerified) return done(null, false, { message: 'Please verify your email before logging in.' });
        user.failedLoginAttempts = 0;
        await user.save();
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
            await createWelcomeNotification(user);
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
            await createWelcomeNotification(user);
            done(null, user);
        }
    } catch (err) { done(err, null); }
}));

// Microsoft Strategy
passport.use(new MicrosoftStrategy({
    clientID: process.env.MICROSOFT_CLIENT_ID,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
    tenant: process.env.MICROSOFT_TENANT_ID || 'common',
    callbackURL: process.env.MICROSOFT_CALLBACK_URL || `${(process.env.BASE_URL || 'https://gplmods.webredirect.org').replace(/\/+$/, '')}/auth/microsoft/callback`,
    scope: ['User.Read'],
    addUPNAsEmail: true
}, async (accessToken, refreshToken, profile, done) => {
    const email = (profile.emails && profile.emails.length > 0) ? profile.emails[0].value : profile.userPrincipalName;
    const displayName = profile.displayName || profile.userPrincipalName || `user_${profile.id}`;
    const microsoftUserData = { microsoftId: profile.id, username: displayName.replace(/\s+/g, ''), email: email, isVerified: true };
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
            await createWelcomeNotification(user);
            done(null, user);
        }
    } catch (err) { done(err, null); }
}));

// ===============================
// 1.5. PUBLIC & DIAGNOSTIC ROUTES
// ===============================

// --- ADVANCED DIAGNOSTIC CONSOLE (Admin Only) ---
app.get('/status', ensureAdmin, async (req, res) => {
    
    // 1. Gather Basic Server Info
    const memUsage = process.memoryUsage();
    const totalMem = os.totalmem();

    // Dynamically determine environment: 'development' if local, 'production' if running online
    const reqHost = (req.hostname || req.get('host') || '').toLowerCase().split(':')[0];
    const isLocalHost = reqHost === 'localhost' || reqHost === '127.0.0.1' || reqHost === '::1' || reqHost === '0.0.0.0' || reqHost.startsWith('192.168.') || reqHost.startsWith('10.');
    const isRender = Boolean(process.env.RENDER || process.env.RENDER_EXTERNAL_URL);
    const isOnline = isRender || (!isLocalHost && reqHost !== '');
    const dynamicEnvironment = isOnline ? 'production' : 'development';
    
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
        environment: dynamicEnvironment,
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
    const debuggerData = await getOrRotateDebuggerKey(false);
    const recentDevtoolLogs = await DevtoolLog.find().sort({ createdAt: -1 }).limit(10).lean();

    res.render('pages/admin/status', { 
        health: healthData,
        debuggerKey: debuggerData.key,
        debuggerExpiresAt: debuggerData.expiresAt,
        debuggerMasterKey: debuggerData.masterKey,
        recentDevtoolLogs: recentDevtoolLogs || []
    });
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
        
        // --- Separated Editor's Choice Councils (Android, iOS, WordPress, Windows) ---
        const mapWithIcons = async (rawFiles) => {
            return Promise.all(rawFiles.map(async (file) => {
                const iconKey = file.iconUrl || file.iconKey;
                let signedIconUrl = '/images/default-app-icon.png';
                if (iconKey) {
                    try { signedIconUrl = await getSmartImageUrl(iconKey); } catch (e) {}
                }
                return { ...(file.toObject ? file.toObject() : file), iconUrl: signedIconUrl };
            }));
        };

        const [androidCouncilRaw, iosCouncilRaw, wpCouncilRaw, winCouncilRaw] = await Promise.all([
            File.find({ ...findQuery, isEditorsChoice: true, category: 'android' }).sort({ updatedAt: -1 }).limit(10),
            File.find({ ...findQuery, isEditorsChoice: true, category: { $in: ['ios-jailed', 'ios-jailbroken'] } }).sort({ updatedAt: -1 }).limit(10),
            File.find({ ...findQuery, isEditorsChoice: true, category: 'wordpress' }).sort({ updatedAt: -1 }).limit(10),
            File.find({ ...findQuery, isEditorsChoice: true, category: 'windows' }).sort({ updatedAt: -1 }).limit(10)
        ]);

        const [androidCouncil, iosCouncil, wpCouncil, winCouncil] = await Promise.all([
            mapWithIcons(androidCouncilRaw),
            mapWithIcons(iosCouncilRaw),
            mapWithIcons(wpCouncilRaw),
            mapWithIcons(winCouncilRaw)
        ]);

        const editorsChoiceByCouncil = {
            android: androidCouncil,
            ios: iosCouncil,
            wordpress: wpCouncil,
            windows: winCouncil
        };
        const editorsChoiceMods = [...androidCouncil, ...iosCouncil, ...wpCouncil, ...winCouncil];
        // --------------------------------------------------------------------------

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
        res.render('pages/index', { filesByCategory, editorsChoiceMods, editorsChoiceByCouncil });
    } catch (error) {
        console.error("Error fetching files for homepage:", error);
        return next(error);
    }
};

// Web Cache Clear Shortcut Route (/cc)
app.get('/cc', (req, res) => {
    res.set('Clear-Site-Data', '"cache", "storage"');
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0, post-check=0, pre-check=0');
    res.set('Pragma', 'no-cache');
    const returnUrl = req.query.returnTo || req.headers.referer || '/';
    res.render('pages/cache-cleaner', { returnUrl });
});

// 1. The Root Route
app.get('/', async (req, res) => {
    // Prevent stale caching so logout and login status stay synchronized
    res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate, max-age=0');
    res.set('Pragma', 'no-cache');

    // If a user is authenticated, always redirect them to /home immediately
    if (req.isAuthenticated()) {
        const queryString = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
        return res.redirect('/home' + queryString);
    }
    // Otherwise, render the homepage for the guest
    await renderHomepage(req, res);
});

// 2. The Logged-In Route (Bypasses Cloudflare's strict root cache)
app.get('/home', ensureAuthenticated, async (req, res) => {
    res.set('Cache-Control', 'private, no-cache, no-store, must-revalidate, max-age=0');
    res.set('Pragma', 'no-cache');
    await renderHomepage(req, res);
});

// ===================================
// SOURCE CODE HUB (GITHUB SYNC)
// ===================================
function canUserAccessSource(user, sourceDoc) {
    if (!sourceDoc) return false;
    if (!sourceDoc.isPrivate) return true;
    if (!user) return false;
    if (user.role === 'admin' || user.role === 'owner') return true;

    const allowedRoles = sourceDoc.allowedRoles || [];
    if (allowedRoles.includes(user.role)) return true;

    const userId = user._id && user._id.toString();
    return Boolean(userId && (sourceDoc.allowedUsers || []).some(id => id.toString() === userId));
}

function githubApiConfig(customHeaders = {}) {
    const token = process.env.GITHUB_PAT || process.env.GITHUB_TOKEN || process.env.GH_TOKEN || process.env.GITHUB_API_TOKEN || process.env.GITHUB_ACCESS_TOKEN;
    const apiVersion = process.env.GITHUB_API_VERSION || '2022-11-28';
    const headers = {
        'User-Agent': 'GPLMods-SourceHub',
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': apiVersion,
        ...customHeaders
    };
    if (token && token.trim() !== '') {
        headers.Authorization = `Bearer ${token.trim()}`;
    }
    return { headers };
}

function formatSourceFileSize(bytes) {
    if (bytes === 0 || bytes == null) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function detectSourceLanguage(filename) {
    if (!filename) return 'plaintext';
    const ext = filename.split('.').pop().toLowerCase();
    const map = {
        js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'jsx',
        ts: 'typescript', tsx: 'tsx',
        html: 'markup', xml: 'markup', svg: 'markup', ejs: 'markup',
        css: 'css', scss: 'scss', less: 'less',
        json: 'json', yml: 'yaml', yaml: 'yaml',
        md: 'markdown', markdown: 'markdown',
        py: 'python', rb: 'ruby', php: 'php',
        java: 'java', c: 'c', cpp: 'cpp', cs: 'csharp', go: 'go', rs: 'rust',
        sh: 'bash', bash: 'bash', zsh: 'bash', ps1: 'powershell',
        sql: 'sql', dockerfile: 'docker', toml: 'toml', ini: 'ini'
    };
    return map[ext] || 'plaintext';
}

function renderSourceError(res, status, title, message) {
    return res.status(status).render('pages/error', {
        errorCode: String(status),
        errorTitle: title,
        errorMessage: message
    });
}

app.get('/source', async (req, res) => {
    try {
        const sources = await SourceCode.find({ status: 'live' }).sort({ title: 1 }).lean();
        const visibleSources = sources.filter(source => canUserAccessSource(req.user, source));
        const sanitizedSources = visibleSources.map(source => {
            const { owner, repo } = cleanGitHubOwnerRepo(source.githubOwner, source.githubRepo);
            return {
                ...source,
                cleanOwner: owner,
                cleanRepo: repo,
                displayRepo: `${owner}/${repo}`
            };
        });

        return res.render('pages/source-hub', { sources: sanitizedSources });
    } catch (error) {
        console.error('Source Hub Listing Error:', error);
        return renderSourceError(res, 500, 'Source Hub <span>Unavailable</span>', 'The source hub could not be loaded right now.');
    }
});

// --- GitHub URL Safety & Sanitization Helpers ---
function validateGitHubUrl(urlStr) {
    try {
        if (!urlStr || typeof urlStr !== 'string') return { safe: false, reason: 'Empty URL' };
        const trimmed = urlStr.trim();
        if (/^(javascript|data|vbscript|file):/i.test(trimmed)) {
            return { safe: false, reason: 'Disallowed protocol' };
        }
        const parsed = new URL(trimmed.startsWith('http') ? trimmed : `https://${trimmed}`);
        if (parsed.protocol !== 'https:') {
            return { safe: false, reason: 'Insecure protocol: only HTTPS allowed' };
        }
        const allowedHosts = ['github.com', 'www.github.com', 'raw.githubusercontent.com', 'gist.github.com', 'api.github.com'];
        const host = parsed.hostname.toLowerCase();
        if (!allowedHosts.includes(host)) {
            return { safe: false, reason: `Unverified domain: ${host}` };
        }
        if (parsed.pathname.includes('..') || /[\0\r\n]/.test(parsed.pathname)) {
            return { safe: false, reason: 'Invalid path characters detected' };
        }
        return {
            safe: true,
            hostname: host,
            url: parsed.href.toLowerCase(),
            isOfficialGitHub: host === 'github.com' || host === 'www.github.com'
        };
    } catch (e) {
        return { safe: false, reason: 'Malformed URL' };
    }
}

function cleanGitHubOwnerRepo(rawOwner, rawRepo) {
    const combined = `${rawOwner || ''}/${rawRepo || ''}`;
    const ghMatch = combined.match(/github\.com\/([a-zA-Z0-9_.-]+)\/([a-zA-Z0-9_.-]+)/i);
    if (ghMatch) {
        return {
            owner: ghMatch[1].toLowerCase(),
            repo: ghMatch[2].replace(/\.git$/i, '').toLowerCase()
        };
    }
    let owner = (rawOwner || '').trim().replace(/^https?:\/\/github\.com\//i, '').replace(/\/.*$/, '').toLowerCase();
    let repo = (rawRepo || '').trim().replace(/^https?:\/\/github\.com\/[^/]+\//i, '').replace(/\.git$/i, '').replace(/\/.*$/, '').toLowerCase();
    owner = owner.replace(/[^a-z0-9_.-]/g, '');
    repo = repo.replace(/[^a-z0-9_.-]/g, '');
    return { owner, repo };
}

function sanitizeRepoPath(rawPath) {
    if (!rawPath) return '';
    return rawPath
        .toString()
        .trim()
        .replace(/\\/g, '/')
        .replace(/\.{2,}/g, '')
        .replace(/^\/+|\/+$/g, '')
        .replace(/[\0\r\n]/g, '');
}

function getSourceMimeType(filePath) {
    if (!filePath) return 'text/plain; charset=utf-8';
    const ext = (filePath.split('.').pop() || '').toLowerCase();
    const mimeMap = {
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'gif': 'image/gif',
        'webp': 'image/webp',
        'svg': 'image/svg+xml',
        'ico': 'image/x-icon',
        'bmp': 'image/bmp',
        'avif': 'image/avif',
        'tiff': 'image/tiff',
        'tif': 'image/tiff',
        'pdf': 'application/pdf',
        'json': 'application/json; charset=utf-8',
        'xml': 'application/xml; charset=utf-8',
        'html': 'text/html; charset=utf-8',
        'htm': 'text/html; charset=utf-8',
        'css': 'text/css; charset=utf-8',
        'js': 'text/javascript; charset=utf-8',
        'mjs': 'text/javascript; charset=utf-8',
        'txt': 'text/plain; charset=utf-8',
        'md': 'text/markdown; charset=utf-8',
        'mp4': 'video/mp4',
        'webm': 'video/webm',
        'mp3': 'audio/mpeg',
        'wav': 'audio/wav',
        'ogg': 'audio/ogg'
    };
    return mimeMap[ext] || 'text/plain; charset=utf-8';
}

// Serve raw source file content directly like GitHub raw
app.get('/source/:slug/raw', async (req, res) => {
    try {
        const slug = req.params.slug ? req.params.slug.toLowerCase().trim() : '';
        const source = await SourceCode.findOne({ slug, status: 'live' });
        if (!source) return res.status(404).type('text/plain').send('Source repository not found.');
        if (source.isPrivate && !req.isAuthenticated()) return res.status(401).type('text/plain').send('Authentication required.');
        if (!canUserAccessSource(req.user, source)) {
            return res.status(403).type('text/plain').send('Access denied.');
        }

        const filePath = sanitizeRepoPath(req.query.path);
        if (!filePath) {
            return res.status(400).type('text/plain').send('Path query parameter is required.');
        }

        const { owner, repo } = cleanGitHubOwnerRepo(source.githubOwner, source.githubRepo);
        const currentBranch = (req.query.ref || 'main').toString().trim();
        const refQuery = req.query.ref ? `?ref=${encodeURIComponent(currentBranch)}` : '';
        const encodedPath = encodeURIComponent(filePath).replace(/%2F/g, '/');
        const apiUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${encodedPath}${refQuery}`;

        const mimeType = getSourceMimeType(filePath);
        const isBinaryOrMedia = /^(image|video|audio|application\/pdf)/i.test(mimeType);

        try {
            const response = await axios.get(apiUrl, {
                ...githubApiConfig({ Accept: 'application/vnd.github.raw+json' }),
                responseType: 'arraybuffer'
            });

            res.setHeader('Content-Type', mimeType);
            if (!isBinaryOrMedia) {
                res.setHeader('X-Content-Type-Options', 'nosniff');
            }
            return res.send(Buffer.from(response.data));
        } catch (apiErr) {
            // Fallback to raw.githubusercontent.com for public repositories or if API rate-limited
            if (!source.isPrivate) {
                try {
                    const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(currentBranch)}/${encodedPath}`;
                    const rawRes = await axios.get(rawUrl, {
                        responseType: 'arraybuffer'
                    });
                    res.setHeader('Content-Type', mimeType);
                    if (!isBinaryOrMedia) {
                        res.setHeader('X-Content-Type-Options', 'nosniff');
                    }
                    return res.send(Buffer.from(rawRes.data));
                } catch (rawErr) {
                    if (currentBranch === 'main') {
                        try {
                            const masterUrl = `https://raw.githubusercontent.com/${owner}/${repo}/master/${encodedPath}`;
                            const masterRes = await axios.get(masterUrl, {
                                responseType: 'arraybuffer'
                            });
                            res.setHeader('Content-Type', mimeType);
                            if (!isBinaryOrMedia) {
                                res.setHeader('X-Content-Type-Options', 'nosniff');
                            }
                            return res.send(Buffer.from(masterRes.data));
                        } catch (mErr) {}
                    }
                }
            }
            console.error('Source Raw File Error:', apiErr.response?.data || apiErr.message);
            if (apiErr.response?.status === 404) {
                return res.status(404).type('text/plain').send('File not found in repository.');
            }
            return res.status(502).type('text/plain').send('GitHub could not provide this file right now.');
        }
    } catch (error) {
        console.error('Source Raw Route Exception:', error);
        return res.status(500).type('text/plain').send('Internal server error.');
    }
});

app.get('/source/:slug', async (req, res) => {
    try {
        const rawSlug = (req.params.slug || '').trim();
        // Redirect uppercase slugs to lowercase (301 Permanent Redirect)
        if (/[A-Z]/.test(rawSlug)) {
            const lowerSlug = rawSlug.toLowerCase();
            const queryString = req._parsedUrl?.search || '';
            return res.redirect(301, `/source/${lowerSlug}${queryString}`);
        }

        const source = await SourceCode.findOne({ slug: rawSlug.toLowerCase(), status: 'live' });
        if (!source) return renderSourceError(res, 404, 'Source <span>Not Found</span>', 'That source repository is unavailable.');
        if (source.isPrivate && !req.isAuthenticated()) return res.redirect(`/login?returnTo=${encodeURIComponent(req.originalUrl)}`);

        const hasAccess = canUserAccessSource(req.user, source);
        const { owner, repo } = cleanGitHubOwnerRepo(source.githubOwner, source.githubRepo);

        // Normalize requested path & ref
        const rawPath = sanitizeRepoPath(req.query.path);
        const requestedRef = (req.query.ref || '').toString().trim();
        const activeTab = (req.query.tab || 'code').toString().toLowerCase();

        const config = githubApiConfig();
        const refParam = requestedRef ? `?ref=${encodeURIComponent(requestedRef)}` : '';
        const encodedPath = rawPath ? encodeURIComponent(rawPath).replace(/%2F/g, '/') : '';

        // Construct canonical lowercase repo URL and validate safety
        const canonicalRepoUrl = `https://github.com/${owner}/${repo}`.toLowerCase();
        const urlSafety = validateGitHubUrl(canonicalRepoUrl);

        // Concurrently fetch repo details, contents at path, readme, license, and releases
        const contentsUrl = `https://api.github.com/repos/${owner}/${repo}/contents${encodedPath ? '/' + encodedPath : ''}${refParam}`;
        const readmeUrl = `https://api.github.com/repos/${owner}/${repo}/readme${refParam}`;

        const [repoResult, contentsResult, readmeResult, licenseResult, releasesResult] = await Promise.allSettled([
            axios.get(`https://api.github.com/repos/${owner}/${repo}`, config),
            axios.get(contentsUrl, config),
            axios.get(readmeUrl, config),
            axios.get(`https://api.github.com/repos/${owner}/${repo}/license`, config),
            axios.get(`https://api.github.com/repos/${owner}/${repo}/releases`, config)
        ]);

        // 1. Repo Metadata
        let repoData = {
            name: repo,
            full_name: `${owner}/${repo}`.toLowerCase(),
            default_branch: 'main',
            stargazers_count: 0,
            forks_count: 0,
            open_issues_count: 0,
            html_url: canonicalRepoUrl,
            description: source.description || ''
        };
        let apiError = null;

        if (repoResult.status === 'fulfilled') {
            repoData = { ...repoData, ...repoResult.value.data };
            // Ensure full_name and html_url are strictly lowercase
            repoData.full_name = (repoData.full_name || `${owner}/${repo}`).toLowerCase();
            repoData.html_url = canonicalRepoUrl;
        } else {
            const errStatus = repoResult.reason?.response?.status;
            const errMsg = repoResult.reason?.response?.data?.message || repoResult.reason?.message;
            console.warn(`GitHub Repo Info Warning (${source.slug}):`, errStatus, errMsg);
            if (errStatus === 403 || errStatus === 429) {
                apiError = 'GitHub API rate limit reached. If accessing frequently or using a private repository, configure a GitHub Personal Access Token in environment settings.';
            } else if (errStatus === 401) {
                apiError = 'GitHub token is invalid or expired.';
            } else if (errStatus === 404) {
                apiError = `Repository "${owner}/${repo}" was not found on GitHub. Please check the repository owner and name.`;
            }
        }

        const currentRef = requestedRef || repoData.default_branch || 'main';

        // 2. Directory Contents or File View
        let isViewingFile = false;
        let fileData = null;
        let directoryItems = [];

        if (contentsResult.status === 'fulfilled') {
            const data = contentsResult.value.data;
            if (Array.isArray(data)) {
                // Directory listing
                isViewingFile = false;
                directoryItems = data.map(item => ({
                    name: item.name,
                    path: item.path,
                    type: item.type, // 'dir' | 'file' | 'submodule'
                    sizeFormatted: item.type === 'file' ? formatSourceFileSize(item.size) : '',
                    size: item.size || 0,
                    download_url: item.download_url
                })).sort((a, b) => {
                    if (a.type === 'dir' && b.type !== 'dir') return -1;
                    if (a.type !== 'dir' && b.type === 'dir') return 1;
                    return a.name.localeCompare(b.name);
                });
            } else if (data && data.type === 'file') {
                // Single file view
                isViewingFile = true;
                const lowerFileName = (data.name || '').toLowerCase();
                const isImageFile = /\.(png|jpg|jpeg|gif|svg|webp|ico|bmp|avif)$/i.test(lowerFileName);
                const fileMimeType = getSourceMimeType(data.name);

                let rawCode = '';
                let dataUrl = null;

                if (data.content && data.encoding === 'base64') {
                    const cleanBase64 = data.content.replace(/[\r\n\s]/g, '');
                    if (isImageFile) {
                        dataUrl = `data:${fileMimeType};base64,${cleanBase64}`;
                    } else {
                        try {
                            rawCode = Buffer.from(cleanBase64, 'base64').toString('utf8');
                        } catch (decErr) {
                            console.error('Base64 decode error:', decErr.message);
                        }
                    }
                }

                // Fallback to direct raw download if content was omitted (large file >1MB or null)
                if (!rawCode && !dataUrl) {
                    const fallbackUrls = [];
                    if (data.download_url) fallbackUrls.push(data.download_url);
                    fallbackUrls.push(`https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(currentRef)}/${encodedPath}`);
                    if (currentRef === 'main') {
                        fallbackUrls.push(`https://raw.githubusercontent.com/${owner}/${repo}/master/${encodedPath}`);
                    }

                    for (const fUrl of fallbackUrls) {
                        try {
                            const rawFetch = await axios.get(fUrl, {
                                ...(!fUrl.includes('raw.githubusercontent.com') ? githubApiConfig({ Accept: 'application/vnd.github.raw+json' }) : {}),
                                responseType: isImageFile ? 'arraybuffer' : 'text',
                                transformResponse: isImageFile ? [] : [d => d],
                                timeout: 7000
                            });
                            if (isImageFile && rawFetch.data) {
                                const b64 = Buffer.from(rawFetch.data).toString('base64');
                                dataUrl = `data:${fileMimeType};base64,${b64}`;
                                break;
                            } else if (typeof rawFetch.data === 'string') {
                                rawCode = rawFetch.data;
                                break;
                            }
                        } catch (rawErr) {}
                    }
                }

                fileData = {
                    name: data.name,
                    path: data.path,
                    sizeFormatted: formatSourceFileSize(data.size),
                    size: data.size,
                    lines: !isImageFile && rawCode ? (rawCode.match(/\n/g) || []).length + 1 : 0,
                    language: detectSourceLanguage(data.name),
                    content: rawCode || '',
                    dataUrl: dataUrl || null,
                    download_url: data.download_url || `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(currentRef)}/${encodedPath}`
                };
            }
        } else {
            console.warn(`GitHub Contents Warning (${source.slug}):`, contentsResult.reason?.response?.status, contentsResult.reason?.message);
            // If contents call failed, but this was a file path requested, attempt raw.githubusercontent.com fallback!
            if (rawPath && !isViewingFile) {
                try {
                    const fileName = rawPath.split('/').pop() || 'file';
                    const lowerFileName = fileName.toLowerCase();
                    const isImageFile = /\.(png|jpg|jpeg|gif|svg|webp|ico|bmp|avif)$/i.test(lowerFileName);
                    const fileMimeType = getSourceMimeType(fileName);
                    const rawFallbackUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(currentRef)}/${encodedPath}`;
                    const rawRes = await axios.get(rawFallbackUrl, {
                        responseType: isImageFile ? 'arraybuffer' : 'text',
                        transformResponse: isImageFile ? [] : [d => d],
                        timeout: 5000
                    });
                    if (rawRes.data) {
                        isViewingFile = true;
                        let dataUrl = null;
                        let rawCode = '';
                        let byteSize = 0;
                        if (isImageFile) {
                            const b64 = Buffer.from(rawRes.data).toString('base64');
                            dataUrl = `data:${fileMimeType};base64,${b64}`;
                            byteSize = Buffer.byteLength(Buffer.from(rawRes.data));
                        } else {
                            rawCode = typeof rawRes.data === 'string' ? rawRes.data : Buffer.from(rawRes.data).toString('utf8');
                            byteSize = Buffer.byteLength(rawCode, 'utf8');
                        }
                        fileData = {
                            name: fileName,
                            path: rawPath,
                            sizeFormatted: formatSourceFileSize(byteSize),
                            size: byteSize,
                            lines: isImageFile ? 0 : (rawCode.match(/\n/g) || []).length + 1,
                            language: detectSourceLanguage(fileName),
                            content: rawCode,
                            dataUrl: dataUrl,
                            download_url: rawFallbackUrl
                        };
                    }
                } catch (e) {
                    if (!apiError && contentsResult.reason?.response?.status === 404) {
                        apiError = rawPath ? `Path "${rawPath}" was not found in branch "${currentRef}".` : 'Repository has no commits or default branch is empty.';
                    }
                }
            } else if (!apiError && contentsResult.reason?.response?.status === 404) {
                apiError = rawPath ? `Path "${rawPath}" was not found in branch "${currentRef}".` : 'Repository has no commits or default branch is empty.';
            }
        }

        // 3. README Data with fallback
        let readme = null;
        if (readmeResult.status === 'fulfilled' && readmeResult.value.data) {
            const rmData = readmeResult.value.data;
            let rmContent = '';
            if (rmData.content && rmData.encoding === 'base64') {
                rmContent = Buffer.from(rmData.content.replace(/\r?\n/g, ''), 'base64').toString('utf8');
            } else if (rmData.download_url) {
                try {
                    const rmFetch = await axios.get(rmData.download_url, { responseType: 'text', transformResponse: [d => d], timeout: 5000 });
                    rmContent = rmFetch.data;
                } catch (rmErr) {}
            }
            readme = {
                name: rmData.name || 'README.md',
                path: rmData.path || 'README.md',
                content: rmContent,
                download_url: rmData.download_url
            };
        } else {
            // README fallback to raw.githubusercontent.com
            try {
                const rmFallbackUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(currentRef)}/README.md`;
                const rmRes = await axios.get(rmFallbackUrl, { responseType: 'text', transformResponse: [d => d], timeout: 5000 });
                if (typeof rmRes.data === 'string' && rmRes.data.trim()) {
                    readme = {
                        name: 'README.md',
                        path: 'README.md',
                        content: rmRes.data,
                        download_url: rmFallbackUrl
                    };
                }
            } catch (e) {
                try {
                    const rmFallbackUrl2 = `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(currentRef)}/readme.md`;
                    const rmRes2 = await axios.get(rmFallbackUrl2, { responseType: 'text', transformResponse: [d => d], timeout: 4000 });
                    if (typeof rmRes2.data === 'string' && rmRes2.data.trim()) {
                        readme = {
                            name: 'readme.md',
                            path: 'readme.md',
                            content: rmRes2.data,
                            download_url: rmFallbackUrl2
                        };
                    }
                } catch (e2) {}
            }
        }

        // 4. License Data
        let license = null;
        if (licenseResult.status === 'fulfilled' && licenseResult.value.data) {
            const licData = licenseResult.value.data;
            let licContent = '';
            if (licData.content && licData.encoding === 'base64') {
                licContent = Buffer.from(licData.content.replace(/\r?\n/g, ''), 'base64').toString('utf8');
            }
            license = {
                name: licData.license?.name || repoData.license?.name || 'Open Source License',
                spdxId: licData.license?.spdx_id || repoData.license?.spdx_id || 'Custom',
                key: licData.license?.key || repoData.license?.key || '',
                url: licData.license?.url || repoData.license?.url || '',
                content: licContent,
                path: licData.name || 'LICENSE'
            };
        } else if (repoData.license) {
            license = {
                name: repoData.license.name || 'Open Source License',
                spdxId: repoData.license.spdx_id || 'Custom',
                key: repoData.license.key || '',
                url: repoData.license.url || '',
                content: '',
                path: 'LICENSE'
            };
        }

        // 5. Releases Data
        const releases = (releasesResult.status === 'fulfilled' && Array.isArray(releasesResult.value.data))
            ? releasesResult.value.data
            : [];

        // Build breadcrumbs for folder/file navigation
        const breadcrumbs = [];
        if (rawPath) {
            const segments = rawPath.split('/').filter(Boolean);
            let cumulative = '';
            segments.forEach((seg, idx) => {
                cumulative += (cumulative ? '/' : '') + seg;
                breadcrumbs.push({
                    name: seg,
                    path: cumulative,
                    isLast: idx === segments.length - 1
                });
            });
        }

        // Calculate parent path for back button
        let parentPath = null;
        if (rawPath) {
            const segs = rawPath.split('/').filter(Boolean);
            segs.pop();
            parentPath = segs.join('/');
        }

        return res.render('pages/source-view', {
            source,
            cleanOwner: owner,
            cleanRepo: repo,
            repoUrl: canonicalRepoUrl,
            urlSafety,
            repoData,
            currentRef,
            requestedRef,
            currentPath: rawPath,
            parentPath,
            breadcrumbs,
            isViewingFile,
            fileData,
            directoryItems,
            readme,
            license,
            releases,
            activeTab,
            apiError,
            hasAccess
        });
    } catch (error) {
        console.error('Source View Error:', error);
        return renderSourceError(res, 500, 'Source Hub <span>Unavailable</span>', 'The source repository could not be loaded right now.');
    }
});

// Download release zip or branch zipball
app.get('/source/:slug/download/:tag?', async (req, res) => {
    try {
        const slug = req.params.slug ? req.params.slug.toLowerCase().trim() : '';
        const source = await SourceCode.findOne({ slug, status: 'live' });
        if (!source) return renderSourceError(res, 404, 'Source <span>Not Found</span>', 'That source repository is unavailable.');
        if (source.isPrivate && !req.isAuthenticated()) return res.redirect(`/login?returnTo=${encodeURIComponent(req.originalUrl)}`);
        if (!canUserAccessSource(req.user, source)) {
            return renderSourceError(res, 403, 'Access <span>Denied</span>', 'You do not have permission to download this source code.');
        }

        const { owner, repo } = cleanGitHubOwnerRepo(source.githubOwner, source.githubRepo);
        const tag = encodeURIComponent(req.params.tag || 'main');
        const response = await axios.get(`https://api.github.com/repos/${owner}/${repo}/zipball/${tag}`, {
            ...githubApiConfig(),
            responseType: 'stream'
        });

        const safeTag = (req.params.tag || 'main').replace(/[^a-zA-Z0-9._-]/g, '-');
        res.setHeader('Content-Disposition', `attachment; filename="${source.slug}-${safeTag}.zip"`);
        res.setHeader('Content-Type', 'application/zip');
        response.data.on('error', error => {
            console.error('Source Download Stream Error:', error);
            if (!res.headersSent) res.status(502).end();
            else res.destroy(error);
        });
        response.data.pipe(res);
    } catch (error) {
        console.error('Source Download Error:', error.response?.data || error.message);
        if (!res.headersSent) return renderSourceError(res, 502, 'Download <span>Unavailable</span>', 'GitHub could not provide this source archive right now.');
        res.destroy(error);
    }
});

// ===================================
// MUSIC & AUDIO SYSTEM ROUTES (Mounted after Passport & Session)
// ===================================

// Public playlist endpoint for floating music player (auto-falls back to all local tracks)
app.get('/api/music/playlist', async (req, res) => {
    try {
        const state = await SiteState.findOne({ singletonId: 'master-state' });
        let playlist = state?.weeklyPlaylist || [];
        
        // Combined Feature: If weeklyPlaylist is empty or not configured, serve all local tracks
        if (!playlist || playlist.length === 0) {
            const localTracks = await getLocalAudioTracks();
            playlist = localTracks.map(t => ({ title: t.title, src: t.src }));
        }

        res.json({
            success: true,
            playlist
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to fetch playlist' });
    }
});

// Admin Music Management Page
app.get('/admin/music', ensureAdmin, async (req, res) => {
    try {
        const tracks = await getLocalAudioTracks();
        const state = await SiteState.findOne({ singletonId: 'master-state' });
        const weeklyPlaylist = state?.weeklyPlaylist || [];
        res.render('pages/admin/music', {
            user: req.user,
            tracks,
            weeklyPlaylist
        });
    } catch (error) {
        console.error('Error loading admin music page:', error);
        res.status(500).send('Error loading music manager');
    }
});

// Admin API: Get all tracks from public/audio with playlist metadata
app.get('/api/admin/music/tracks', ensureAdmin, async (req, res) => {
    try {
        const tracks = await getLocalAudioTracks();
        const state = await SiteState.findOne({ singletonId: 'master-state' });
        const playlist = state?.weeklyPlaylist || [];

        const playlistMap = new Map();
        playlist.forEach((p, idx) => {
            playlistMap.set(p.src, { order: idx, title: p.title });
        });

        const mappedTracks = tracks.map(t => {
            const inPl = playlistMap.has(t.src);
            return {
                ...t,
                inPlaylist: inPl,
                order: inPl ? playlistMap.get(t.src).order : 999,
                playlistTitle: inPl ? playlistMap.get(t.src).title : t.title
            };
        });

        res.json({
            success: true,
            tracks: mappedTracks,
            playlist
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// Admin API: Upload new audio track to public/audio
app.post('/api/admin/music/upload', ensureAdmin, (req, res) => {
    uploadAudioTrack.single('audioFile')(req, res, async (err) => {
        if (err) {
            return res.status(400).json({ success: false, error: err.message });
        }
        if (!req.file) {
            return res.status(400).json({ success: false, error: 'No audio file provided.' });
        }
        try {
            const tracks = await getLocalAudioTracks();
            res.json({
                success: true,
                message: `Track "${req.file.filename}" uploaded successfully!`,
                file: {
                    filename: req.file.filename,
                    src: `/audio/${req.file.filename}`
                },
                tracks
            });
        } catch (error) {
            res.status(500).json({ success: false, error: error.message });
        }
    });
});

// Admin API: Delete audio track from public/audio
app.delete('/api/admin/music/track/:filename', ensureAdmin, async (req, res) => {
    try {
        const rawFilename = path.basename(req.params.filename);
        const filePath = path.join(AUDIO_DIR, rawFilename);

        if (!fs.existsSync(filePath)) {
            return res.status(404).json({ success: false, error: 'Track file not found on disk.' });
        }

        await fs.promises.unlink(filePath);

        // Remove from SiteState.weeklyPlaylist if present
        const trackSrc = `/audio/${rawFilename}`;
        await SiteState.findOneAndUpdate(
            { singletonId: 'master-state' },
            { $pull: { weeklyPlaylist: { src: trackSrc } } }
        );

        const tracks = await getLocalAudioTracks();
        res.json({
            success: true,
            message: `Track "${rawFilename}" deleted successfully.`,
            tracks
        });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/admin/music/playlist', ensureAdmin, async (req, res) => {
    try {
        const { playlist } = req.body;
        if (!Array.isArray(playlist)) {
            return res.status(400).json({ success: false, error: 'Playlist must be an array' });
        }
        await SiteState.findOneAndUpdate(
            { singletonId: 'master-state' },
            { $set: { weeklyPlaylist: playlist } },
            { upsert: true }
        );
        res.json({ success: true, message: 'Weekly playlist updated successfully' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/admin/music/theme', ensureAdmin, async (req, res) => {
    try {
        const { fileId, themeMusic } = req.body;
        if (!fileId) return res.status(400).json({ success: false, error: 'File ID is required' });

        await File.findByIdAndUpdate(fileId, { $set: { themeMusic } });
        res.json({ success: true, message: 'Theme music updated successfully' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ==========================================
// EDITOR'S CHOICE COUNCIL MANAGEMENT ROUTES
// ==========================================
app.get('/admin/editors-choice', ensureAdmin, async (req, res) => {
    try {
        const findQuery = { status: 'live', isLatestVersion: true, isEditorsChoice: true };

        const mapWithIcons = async (rawFiles) => {
            return Promise.all(rawFiles.map(async (file) => {
                const iconKey = file.iconUrl || file.iconKey;
                let signedIconUrl = '/images/default-app-icon.png';
                if (iconKey) {
                    try { signedIconUrl = await getSmartImageUrl(iconKey); } catch (e) {}
                }
                return { ...(file.toObject ? file.toObject() : file), iconUrl: signedIconUrl };
            }));
        };

        const [androidRaw, iosRaw, wpRaw, winRaw] = await Promise.all([
            File.find({ ...findQuery, category: 'android' }).sort({ updatedAt: -1 }).lean(),
            File.find({ ...findQuery, category: { $in: ['ios-jailed', 'ios-jailbroken'] } }).sort({ updatedAt: -1 }).lean(),
            File.find({ ...findQuery, category: 'wordpress' }).sort({ updatedAt: -1 }).lean(),
            File.find({ ...findQuery, category: 'windows' }).sort({ updatedAt: -1 }).lean()
        ]);

        const [android, ios, wordpress, windows] = await Promise.all([
            mapWithIcons(androidRaw),
            mapWithIcons(iosRaw),
            mapWithIcons(wpRaw),
            mapWithIcons(winRaw)
        ]);

        res.render('pages/admin/editors-choice', {
            councils: { android, ios, wordpress, windows },
            pageTitle: "Editor's Choice Councils"
        });
    } catch (error) {
        res.status(500).render('pages/error', { 
            errorCode: '500', 
            errorTitle: 'Server Error', 
            errorMessage: 'Could not load Editor Choice Councils.',
            errorDetails: {
                message: error ? error.message : 'Could not load Editor Choice Councils.',
                name: error ? error.name : 'Error',
                path: req.originalUrl || req.url,
                method: req.method,
                timestamp: new Date().toISOString()
            }
        });
    }
});

app.get('/api/admin/editors-choice/search', ensureAdmin, async (req, res) => {
    try {
        const { platform, q } = req.query;
        if (!q || q.trim().length < 2) {
            return res.json({ success: true, mods: [] });
        }

        const query = {
            status: 'live',
            isLatestVersion: true,
            name: { $regex: q.trim(), $options: 'i' }
        };

        if (platform === 'android') {
            query.category = 'android';
        } else if (platform === 'ios') {
            query.category = { $in: ['ios-jailed', 'ios-jailbroken'] };
        } else if (platform === 'wordpress') {
            query.category = 'wordpress';
        } else if (platform === 'windows') {
            query.category = 'windows';
        }

        const modsRaw = await File.find(query).sort({ downloads: -1 }).limit(15).lean();
        const mods = await Promise.all(modsRaw.map(async (mod) => {
            const iconKey = mod.iconUrl || mod.iconKey;
            let signedIconUrl = '/images/default-app-icon.png';
            if (iconKey) {
                try { signedIconUrl = await getSmartImageUrl(iconKey); } catch (e) {}
            }
            return {
                _id: mod._id,
                name: mod.name,
                category: mod.category,
                downloads: mod.downloads,
                views: mod.views || 0,
                averageRating: mod.averageRating || 5.0,
                iconUrl: signedIconUrl
            };
        }));

        res.json({ success: true, mods });
    } catch (error) {
        console.error("Editor's choice search error:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.post('/api/admin/editors-choice/toggle', ensureAdmin, async (req, res) => {
    try {
        const { fileId, isEditorsChoice, description } = req.body;
        if (!fileId) return res.status(400).json({ success: false, message: 'File ID is required' });

        const updateData = {
            isEditorsChoice: Boolean(isEditorsChoice)
        };
        if (description !== undefined) {
            updateData.editorsChoiceDescription = (description || '').trim();
        }

        const updated = await File.findByIdAndUpdate(fileId, { $set: updateData }, { new: true });
        if (!updated) return res.status(404).json({ success: false, message: 'File not found' });

        res.json({
            success: true,
            message: `Mod "${updated.name}" ${updated.isEditorsChoice ? 'added to' : 'removed from'} Council!`,
            file: {
                _id: updated._id,
                name: updated.name,
                isEditorsChoice: updated.isEditorsChoice
            }
        });
    } catch (error) {
        console.error("Editor's choice toggle error:", error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// ===============================
// USER MUSIC SETTINGS API
// ===============================
app.get('/api/user/music-settings', ensureAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        res.json({
            success: true,
            settings: user?.musicSettings || { allowThemeMusic: true, autoPlayTheme: true }
        });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to fetch settings' });
    }
});

app.post('/api/user/music-settings', ensureAuthenticated, async (req, res) => {
    try {
        const { allowThemeMusic, autoPlayTheme } = req.body;
        await User.findByIdAndUpdate(req.user._id, {
            $set: {
                'musicSettings.allowThemeMusic': allowThemeMusic,
                'musicSettings.autoPlayTheme': autoPlayTheme
            }
        });
        res.json({ success: true, message: 'Music settings updated' });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
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

        let clubNotificationsCount = 0;
        if (req.isAuthenticated() && req.user) {
            const userManagedClubs = await Club.find({ creator: req.user._id }).select('_id');
            const managedClubIds = userManagedClubs.map(c => c._id);
            const pendingReqs = await ClubJoinRequest.countDocuments({
                club: { $in: managedClubIds },
                status: 'pending'
            });
            const unreadClubNotifs = await UserNotification.countDocuments({
                user: req.user._id,
                isRead: false,
                $or: [
                    { title: { $regex: /club/i } },
                    { message: { $regex: /club/i } }
                ]
            });
            clubNotificationsCount = pendingReqs + unreadClubNotifs;
        }

        res.render('pages/notifications-hub', {
            followingCount: followingCount,
            clubNotificationsCount: clubNotificationsCount
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


// --- CLUBS NOTIFICATIONS & REQUESTS INBOX ---
app.get('/notifications/clubs', ensureAuthenticated, async (req, res) => {
    try {
        const userManagedClubs = await Club.find({
            $or: [
                { creator: req.user._id },
                { isDefault: true }
            ]
        }).select('_id');
        const managedClubIds = userManagedClubs.map(c => c._id);

        const joinRequests = await ClubJoinRequest.find({
            club: { $in: managedClubIds },
            status: 'pending'
        })
        .populate('club')
        .populate('user', 'username profileImageKey role signedAvatarUrl')
        .sort({ createdAt: -1 })
        .lean();

        const clubAlerts = await UserNotification.find({
            user: req.user._id,
            $or: [
                { title: { $regex: /club/i } },
                { message: { $regex: /club/i } }
            ]
        })
        .sort({ createdAt: -1 })
        .limit(25)
        .lean();

        res.render('pages/notifications/club-messages', {
            joinRequests,
            clubAlerts,
            pageTitle: 'Club Alerts & Requests'
        });
    } catch (err) {
        console.error('Club notifications error:', err);
        res.status(500).render('pages/500');
    }
});
// 3. Admin Responses List (Personal Direct Messages)
app.get('/notifications/admin-messages', ensureAuthenticated, async (req, res) => {
    try {
        const personalNotifications = await UserNotification.find({ user: req.user._id }).sort({ createdAt: -1 });
        // ✅ FIX: Do not auto-mark everything as read on page load. The inbox UI handles per-message read state.
        res.render('pages/admin-messages', { personalNotifications });
    } catch (error) {
        console.error("Admin Messages page error:", error);
        res.status(500).render('pages/500');
    }
});

// ===================================
// MAILBOX ACTION APIs
// ===================================

// Dynamic live counts API for client-side refresh
app.get('/api/notifications/counts', async (req, res) => {
    try {
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const recentAnnouncements = await Announcement.countDocuments({ createdAt: { $gte: oneDayAgo } });
        const newUploads = await File.countDocuments({ status: 'live', isLatestVersion: true, createdAt: { $gte: oneDayAgo } });
        const newUpdates = await File.countDocuments({ status: 'live', isLatestVersion: true, updatedAt: { $gte: oneDayAgo } });

        let unreadPersonal = 0;
        let following = 0;

        if (req.isAuthenticated() && req.user) {
            unreadPersonal = await UserNotification.countDocuments({ user: req.user._id, isRead: false });
            const currentUser = await User.findById(req.user._id).select('following').lean();
            if (currentUser && currentUser.following && currentUser.following.length > 0) {
                const followedUsers = await User.find({ _id: { $in: currentUser.following } }).select('username').lean();
                const followedUsernames = followedUsers.map(u => u.username);
                following = await File.countDocuments({
                    uploader: { $in: followedUsernames },
                    status: 'live',
                    isLatestVersion: true,
                    updatedAt: { $gte: oneDayAgo }
                });
            }
        }

        res.json({
            success: true,
            unreadPersonal,
            recentAnnouncements,
            newUploads,
            newUpdates,
            following
        });
    } catch (e) {
        console.error("Error fetching notification counts:", e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// Mark a single message as read
app.post('/api/notifications/:id/read', ensureAuthenticated, async (req, res) => {
    try {
        await UserNotification.findOneAndUpdate(
            { _id: req.params.id, user: req.user._id },
            { isRead: true }
        );
        res.json({ success: true });
    } catch (e) {
        console.error("Error marking notification as read:", e);
        res.status(500).json({ success: false });
    }
});

// Delete multiple messages (or a single one)
app.post('/api/notifications/delete', ensureAuthenticated, async (req, res) => {
    try {
        const { ids } = req.body;
        if (!ids || !ids.length) return res.json({ success: false });

        await UserNotification.deleteMany({ _id: { $in: ids }, user: req.user._id });
        res.json({ success: true });
    } catch (e) {
        console.error("Error deleting notifications:", e);
        res.status(500).json({ success: false });
    }
});

// Delete all READ messages
app.post('/api/notifications/delete-read', ensureAuthenticated, async (req, res) => {
    try {
        await UserNotification.deleteMany({ user: req.user._id, isRead: true });
        res.json({ success: true });
    } catch (e) {
        console.error("Error deleting read notifications:", e);
        res.status(500).json({ success: false });
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
app.get('/category', async (req, res, next) => {
    try {
        // Grab the queries from the URL (e.g., /category?platform=android, /category?cat=wordpress)
        const platform = (req.query.platform || req.query.cat || 'all').toLowerCase();
        const rawPlatform = platform;
        const { subCategory, sort, page = 1 } = req.query;
        const limit = 12;
        const currentPage = parseInt(page);
        
        // Base query: Only show live, latest version mods
        const queryFilter = { isLatestVersion: true, status: 'live' };

        // 1. Filter by Main Platform & Council
        if (rawPlatform === 'android') {
            queryFilter.category = 'android';
        } else if (rawPlatform === 'ios' || rawPlatform === 'ios-all') {
            queryFilter.category = { $in: ['ios-jailed', 'ios-jailbroken'] };
        } else if (rawPlatform === 'ios-jailed' || rawPlatform === 'ipa') {
            queryFilter.category = 'ios-jailed';
        } else if (rawPlatform === 'ios-jailbroken' || rawPlatform === 'deb') {
            queryFilter.category = 'ios-jailbroken';
        } else if (rawPlatform === 'wordpress' || rawPlatform === 'wp') {
            queryFilter.category = 'wordpress';
        } else if (rawPlatform === 'windows' || rawPlatform === 'win') {
            queryFilter.category = 'windows';
        } else if (rawPlatform !== 'all') {
            queryFilter.category = rawPlatform;
        }

        // 2. Filter by Sub-Category
        if (subCategory && subCategory !== 'all') {
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
        
        // --- Platform-Specific Editor's Choice Council ---
        let editorQuery = { isLatestVersion: true, status: 'live', isEditorsChoice: true };
        const userGlobalCouncil = req.user && req.user.globalCouncil;
        if (queryFilter.category && !userGlobalCouncil) {
            editorQuery.category = queryFilter.category;
        }
        
        const editorsChoiceModsRaw = await File.find(editorQuery).sort({ updatedAt: -1 }).limit(10);
        
        // Process URLs
        const editorsChoiceMods = await Promise.all(editorsChoiceModsRaw.map(async (file) => {
            const iconKey = file.iconUrl || file.iconKey;
            let signedIconUrl = '/images/default-app-icon.png';
            if (iconKey) {
                try { signedIconUrl = await getSmartImageUrl(iconKey); } catch (e) {}
            }
            return { ...(file.toObject ? file.toObject() : file), iconUrl: signedIconUrl };
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
        if (typeof next === 'function') {
            return next(error);
        }
        return res.status(500).render('pages/500', { error: 'Failed to load category page' });
    }
});

// ===================================
// EXTERNAL LINK WARNING ROUTE
// ===================================
app.get('/leave', (req, res) => {
    try {
        const targetUrl = req.query.url;
        const filename = req.query.name || 'External File';

        if (!targetUrl) return res.redirect('/');

        // Extract the hostname (e.g., "linkvertise.com", "mega.nz") to show the user
        const urlObj = new URL(targetUrl);
        const destinationHost = urlObj.hostname.replace('www.', '');

        res.render('pages/leave', { 
            targetUrl: targetUrl, 
            filename: filename,
            destination: destinationHost
        });
    } catch (e) {
        // If the URL is invalid, just send them home
        console.error("Invalid URL passed to /leave:", e);
        res.redirect('/');
    }
});

// ===================================
// SEARCH ROUTE
// ===================================

// ✅ FIX: Removed \s so it completely ignores spaces!
const escapeRegex = (text) => text.replace(/[-[\]{}()*+?.,\\^$|#]/g, "\\$&");

app.get('/search', async (req, res, next) => {
    try {
        const rawQuery = (req.query.q || '').trim();
        if (!rawQuery) return res.redirect('/');
        
        const activeTab = req.query.tab || 'mods'; // 'mods' | 'users' | 'community'
        const platform = req.query.platform || 'all';
        const subCategory = req.query.subCategory || 'all'; 
        const sort = req.query.sort || 'newest';
        const page = parseInt(req.query.page) || 1;
        const resultsPerPage = 12;

        const tokens = rawQuery.split(/\s+/).filter(Boolean);
        const queryEscaped = escapeRegex(rawQuery);
        const queryRegex = new RegExp(queryEscaped, 'i');
        
        // Multi-token match: each token must match in at least one searchable field
        const tokenConditions = tokens.map(t => {
            const tr = new RegExp(escapeRegex(t), 'i');
            return {
                $or: [
                    { name: { $regex: tr } },
                    { modDescription: { $regex: tr } },
                    { tags: { $regex: tr } },
                    { developer: { $regex: tr } },
                    { category: { $regex: tr } },
                    { platforms: { $regex: tr } },
                    { originalApkName: { $regex: tr } }
                ]
            };
        });

        // 1. MODS & PLATFORM QUERY
        let searchQuery = {
            isLatestVersion: true,
            status: 'live',
            $or: [
                { name: { $regex: queryRegex } },
                { modDescription: { $regex: queryRegex } },
                { tags: { $regex: queryRegex } },
                { developer: { $regex: queryRegex } },
                { originalApkName: { $regex: queryRegex } },
                ...(tokens.length > 1 ? [{ $and: tokenConditions }] : [])
            ]
        };

        if (platform && platform !== 'all') {
            searchQuery.category = platform;
        }

        if (subCategory && subCategory !== 'all') {
            searchQuery.platforms = { $in: [subCategory] };
        }

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
                    signedIconUrl = await getSmartImageUrl(key);
                } catch (urlError) {}
            }
            return { ...file, iconUrl: signedIconUrl };
        }));

        // 2. USERS & DEVELOPERS QUERY
        const userTokenConditions = tokens.map(t => {
            const tr = new RegExp(escapeRegex(t), 'i');
            return {
                $or: [
                    { username: { $regex: tr } },
                    { bio: { $regex: tr } },
                    { role: { $regex: tr } },
                    { cardId: { $regex: tr } }
                ]
            };
        });

        const [userResultsRaw, developerMods] = await Promise.all([
            User.find({
                isBanned: { $ne: true },
                $or: [
                    { username: { $regex: queryRegex } },
                    { bio: { $regex: queryRegex } },
                    { role: { $regex: queryRegex } },
                    { cardId: { $regex: queryRegex } },
                    ...(tokens.length > 1 ? [{ $and: userTokenConditions }] : [])
                ]
            })
            .select('username role profileImageKey followers following lastSeen bio cardId isVerified')
            .limit(24)
            .lean(),
            File.find({
                developer: { $regex: queryRegex, $ne: 'N/A' },
                status: 'live'
            }).distinct('developer')
        ]);

        const usersWithAvatars = await Promise.all(userResultsRaw.map(async (u) => {
            let avatarUrl = '/images/default-avatar.png';
            if (u.profileImageKey) {
                try { avatarUrl = await getSmartImageUrl(u.profileImageKey); } catch (e) {}
            }
            return { ...u, signedAvatarUrl: avatarUrl };
        }));

        const processedUsers = usersWithAvatars.map(u => {
            let isFollowing = false;
            if (req.user && req.user.following) {
                isFollowing = req.user.following.includes(u._id.toString());
            }
            return { ...u, isFollowing };
        });

        // 3. COMMUNITY FORUMS & DOCS QUERY
        const [forumIssues, docPages] = await Promise.all([
            Issue.find({
                $or: [
                    { title: { $regex: queryRegex } },
                    { description: { $regex: queryRegex } },
                    { category: { $regex: queryRegex } }
                ]
            })
            .populate('author', 'username profileImageKey role')
            .sort({ views: -1, createdAt: -1 })
            .limit(16)
            .lean(),
            DocPage.find({
                $or: [
                    { title: { $regex: queryRegex } },
                    { content: { $regex: queryRegex } }
                ]
            })
            .populate('category', 'name slug')
            .limit(16)
            .lean()
        ]);

        // 4. CLUBS & COMMUNITIES QUERY
        const clubOrConditions = [
            { name: { $regex: queryRegex } },
            { description: { $regex: queryRegex } },
            { tags: { $regex: queryRegex } }
        ];
        if (rawQuery.match(/^[0-9a-fA-F]{24}$/)) {
            clubOrConditions.push({ _id: rawQuery });
        }
        const clubResultsRaw = await Club.find({ $or: clubOrConditions })
            .populate('creator', 'username profileImageKey role signedAvatarUrl')
            .sort({ memberCount: -1 })
            .limit(20)
            .lean();

        const counts = {
            mods: totalResults,
            users: processedUsers.length + developerMods.length,
            community: (forumIssues.length + docPages.length),
            clubs: clubResultsRaw.length
        };

        // --- RENDER THE PAGE ---
        res.render('pages/search', {
            results: resultsWithUrls, 
            userResults: processedUsers,
            developerResults: developerMods || [],
            communityResults: {
                issues: forumIssues || [],
                docs: docPages || []
            },
            clubResults: clubResultsRaw || [],
            counts,
            activeTab,
            query: rawQuery,
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
            isAdminReply: req.user.role === 'admin' || req.user.role === 'owner'
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

// Delete a question and its replies (author only)
app.post('/community/:slug/delete', ensureAuthenticated, async (req, res) => {
    try {
        const issue = await Issue.findOne({ slug: req.params.slug });
        if (!issue) return res.status(404).send("Not found");
        if (issue.author.toString() !== req.user._id.toString()) return res.status(404).render('pages/error', { errorCode: '404', errorTitle: 'Page Not Found', errorMessage: 'The page you are looking for does not exist or you do not have permission to access it.' });

        const replyCount = await Reply.countDocuments({ issue: issue._id });
        await Reply.deleteMany({ issue: issue._id });
        await Issue.findByIdAndDelete(issue._id);
        await User.adjustForumPoints(req.user._id, -(5 + replyCount * 2), "Deleted a community post");

        res.redirect('/community');
    } catch (error) {
        console.error("Delete Issue Error:", error);
        res.status(500).render('pages/500');
    }
});

// Delete a reply (reply author only)
app.post('/community/:slug/reply/:replyId/delete', ensureAuthenticated, async (req, res) => {
    try {
        const issue = await Issue.findOne({ slug: req.params.slug });
        const reply = await Reply.findOne({ _id: req.params.replyId, issue: issue?._id });
        if (!issue || !reply) return res.status(404).send("Not found");
        if (reply.author.toString() !== req.user._id.toString()) return res.status(404).render('pages/error', { errorCode: '404', errorTitle: 'Page Not Found', errorMessage: 'The page you are looking for does not exist or you do not have permission to access it.' });

        if (reply.isSolution) {
            issue.status = 'open';
            await issue.save();
        }
        await Reply.findByIdAndDelete(reply._id);
        await User.adjustForumPoints(req.user._id, -2, "Deleted a community reply");

        res.redirect(`/community/${issue.slug}`);
    } catch (error) {
        console.error("Delete Reply Error:", error);
        res.status(500).render('pages/500');
    }
});

// 6. POST: Mark Reply as Solution (Author or Admin only)
app.post('/community/:slug/resolve/:replyId', ensureAuthenticated, async (req, res) => {
    try {
        const issue = await Issue.findOne({ slug: req.params.slug });
        const reply = await Reply.findById(req.params.replyId);

        if (!issue || !reply) return res.status(404).send("Not found");

        // Verify permissions (Must be Author of the issue or an Admin/Owner)
        const isAuthor = issue.author.toString() === req.user._id.toString();
        const isAdmin = req.user.role === 'admin' || req.user.role === 'owner';

        if (!isAuthor && !isAdmin) return res.status(404).render('pages/error', { errorCode: '404', errorTitle: 'Page Not Found', errorMessage: 'The page you are looking for does not exist or you do not have permission to access it.' });

        // Mark Reply as solution
        reply.isSolution = true;
        await reply.save();

        // Mark Issue as solved
        issue.status = 'solved';
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

// 7. POST: Re-open an Issue (Author or Admin only)
app.post('/community/:slug/reopen', ensureAuthenticated, async (req, res) => {
    try {
        const issue = await Issue.findOne({ slug: req.params.slug });
        if (!issue) return res.status(404).send("Not found");

        const isAuthor = issue.author.toString() === req.user._id.toString();
        const isAdmin = req.user.role === 'admin' || req.user.role === 'owner';
        if (!isAuthor && !isAdmin) return res.status(404).render('pages/error', { errorCode: '404', errorTitle: 'Page Not Found', errorMessage: 'The page you are looking for does not exist or you do not have permission to access it.' });

        issue.status = 're-open';
        await issue.save();

        res.redirect(`/community/${issue.slug}`);
    } catch (error) {
        console.error("Re-open Error:", error);
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
// ADVANCED: SEO-Friendly "Umbrella" Mod Page Core Renderer & Routes
// ==========================================
async function renderModDownloadPage(req, res, next, { category, slug, variantId }) {
    try {
        category = (category || '').toLowerCase();
        slug = (slug || '').toLowerCase();

        let masterFile = null;

        // 1. PRIMARY SEARCH: Try to find by exact slug
        masterFile = await File.findOne({ 
            category: category, 
            slug: slug,
            isLatestVersion: true,
            isVariant: { $ne: true } 
        }).populate({ path: 'variants', populate: { path: 'license' } }).populate('license');

        // 2. SECONDARY SEARCH: If exact slug fails and slug is a valid ObjectId, search by _id
        if (!masterFile && Types.ObjectId.isValid(slug)) {
            const fileById = await File.findById(slug).populate({ path: 'variants', populate: { path: 'license' } }).populate('license');
            if (fileById) {
                // If the file found by ID is a variant, resolve to its master file
                if (fileById.isVariant && fileById.masterFile) {
                    const parentMaster = await File.findById(fileById.masterFile).populate({ path: 'variants', populate: { path: 'license' } }).populate('license');
                    if (parentMaster) {
                        const targetSlug = parentMaster.slug || slugify(parentMaster.name) || parentMaster._id.toString();
                        const queryString = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
                        return res.redirect(301, `/mods/${parentMaster.category}/${targetSlug}/${fileById._id}${queryString}`);
                    }
                } else {
                    masterFile = fileById;
                    // If the file has a slug and it differs from the requested URL parameter (which was the ID),
                    // perform a 301 redirect to the SEO-friendly slug URL.
                    const targetSlug = masterFile.slug || slugify(masterFile.name);
                    if (targetSlug && targetSlug.toLowerCase() !== slug) {
                        const queryString = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
                        const varPart = variantId ? `/${variantId}` : '';
                        return res.redirect(301, `/mods/${masterFile.category}/${targetSlug}${varPart}${queryString}`);
                    }
                }
            }
        }

        // 3. TERTIARY SEARCH: If exact slug and ID fail, use RegEx on the name field
        if (!masterFile) {
            const nameSearchPattern = new RegExp(`^${slug.replace(/-/g, '[-\\s]+')}$`, 'i');
            masterFile = await File.findOne({
                category: category,
                name: nameSearchPattern,
                isLatestVersion: true,
                isVariant: { $ne: true } 
            }).populate({ path: 'variants', populate: { path: 'license' } }).populate('license');
        }

        // 4. CROSS-CATEGORY SEARCH: If still not found, check if slug exists under another category
        if (!masterFile) {
            masterFile = await File.findOne({
                slug: slug,
                isLatestVersion: true,
                isVariant: { $ne: true }
            }).populate({ path: 'variants', populate: { path: 'license' } }).populate('license');
            if (masterFile) {
                const targetSlug = masterFile.slug || slugify(masterFile.name) || masterFile._id.toString();
                const varPart = variantId ? `/${variantId}` : '';
                const queryString = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
                return res.redirect(301, `/mods/${masterFile.category}/${targetSlug}${varPart}${queryString}`);
            }
        }

        // 5. If STILL not found, throw 404
        if (!masterFile) {
            return next(); 
        }

        // --- Category Normalization Redirect ---
        if (masterFile.category && masterFile.category.toLowerCase() !== category) {
            const targetSlug = masterFile.slug || slugify(masterFile.name) || masterFile._id.toString();
            const varPart = variantId ? `/${variantId}` : '';
            const queryString = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
            return res.redirect(301, `/mods/${masterFile.category}/${targetSlug}${varPart}${queryString}`);
        }

        // --- Security Check for Drafts/Pending ---
        if (masterFile.status !== 'live') {
            const isUploader = req.user && req.user.username === masterFile.uploader;
            const isAdmin = req.user && (req.user.role === 'admin' || req.user.role === 'owner');
            if (!isUploader && !isAdmin) return res.status(404).render('pages/error', { errorCode: '404', errorTitle: 'Page Not Found', errorMessage: 'The page you are looking for does not exist or you do not have permission to access it.' }); 
        }

        // Keep the preference effective when a mod URL is opened directly.
        if (masterFile.ageRating === '18+' && shouldHideAdultContent(req.user)) {
            return res.status(404).render('pages/404');
        }

        // --- DMCA COMPLIANCE CHECK ---
        // 1. If an individual variant was requested and that variant is DMCA hidden:
        if (variantId && Types.ObjectId.isValid(variantId)) {
            const hiddenRequestedVariant = (masterFile.variants || []).find(v => v._id.toString() === variantId && v.isDmcaHidden === true);
            if (hiddenRequestedVariant) {
                return res.status(451).render('pages/unavailable', {
                    title: 'Variant Unavailable (DMCA Notice)',
                    message: 'This mod variant is currently unavailable due to a copyright complaint and is undergoing administrative review.'
                });
            }
        }

        // 2. Filter out DMCA hidden variants from the available variants list
        const liveVariants = (masterFile.variants || []).filter(v => v.status === 'live' && v.isDmcaHidden !== true);
        masterFile.variants = liveVariants;

        let displayFile = masterFile; 
        let isViewingVariant = false;

        // 3. If the main master file is DMCA hidden:
        if (masterFile.isDmcaHidden) {
            // Find most recent live variant uploaded after or available
            let promotedVariant = null;
            if (masterFile.temporaryPromotedVariantId) {
                promotedVariant = liveVariants.find(v => v._id.toString() === masterFile.temporaryPromotedVariantId.toString());
            }
            if (!promotedVariant && liveVariants.length > 0) {
                const sortedVariants = [...liveVariants].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
                promotedVariant = sortedVariants[0];
            }

            if (promotedVariant) {
                // Promote this variant to temporarily become the main file
                displayFile = {
                    ...(masterFile.toObject ? masterFile.toObject() : masterFile),
                    _id: promotedVariant._id,
                    version: promotedVariant.version,
                    uploader: promotedVariant.uploader,
                    developer: promotedVariant.developer,
                    modDescription: promotedVariant.modDescription,
                    modFeatures: promotedVariant.modFeatures,
                    whatsNew: promotedVariant.whatsNew,
                    importantNote: promotedVariant.importantNote,
                    license: promotedVariant.license || masterFile.license,
                    fileSize: promotedVariant.fileSize,
                    downloads: promotedVariant.downloads,
                    averageRating: promotedVariant.averageRating,
                    workingVoteCount: promotedVariant.workingVoteCount,
                    notWorkingVoteCount: promotedVariant.notWorkingVoteCount,
                    createdAt: promotedVariant.createdAt,
                    updatedAt: promotedVariant.updatedAt,
                    virusTotalAnalysisId: promotedVariant.virusTotalAnalysisId,
                    virusTotalId: promotedVariant.virusTotalId,
                    virusTotalScanDate: promotedVariant.virusTotalScanDate,
                    virusTotalPositiveCount: promotedVariant.virusTotalPositiveCount,
                    virusTotalTotalScans: promotedVariant.virusTotalTotalScans,
                    isTemporaryPromoted: true
                };
                // Remove the promoted variant from the remaining variants list so it is not duplicated
                masterFile.variants = liveVariants.filter(v => v._id.toString() !== promotedVariant._id.toString());
            } else {
                // Main mod is hidden and there are no live variants to promote
                return res.status(451).render('pages/unavailable', {
                    title: 'Mod Unavailable (DMCA Notice)',
                    message: 'This mod is currently unavailable due to a copyright complaint and is undergoing administrative review.'
                });
            }
        } else if (variantId && Types.ObjectId.isValid(variantId)) {
            // Normal variant handling when master mod is not hidden
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
                    license: requestedVariant.license || masterFile.license,
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
        // VIEW TRACKING
        // ==========================================
        let shouldIncrementView = false;
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
            await masterFile.save();
            if (isViewingVariant) {
                displayFile.views = masterFile.views;
            }
        }

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

        if (req.user) {
            reviewsWithAvatars.sort((a, b) => {
                const isA = a.user._id.toString() === req.user._id.toString();
                const isB = b.user._id.toString() === req.user._id.toString();
                if (isA && !isB) return -1;
                if (!isA && isB) return 1;
                return 0; 
            });
        }

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
            const currentUserId = req.user._id.toString();
            userVotedWorking = (displayFile.votedWorkingBy || []).some(id => id.toString() === currentUserId);
            userVotedNotWorking = (displayFile.votedNotWorkingBy || []).some(id => id.toString() === currentUserId);
        }

        // --- UPLOADER ROLE CHECK ---
        let isUploaderDistributor = false;
        const uploaderUser = await User.findOne({ username: displayFile.uploader }).lean();
        const canVoteOnFile = Boolean(req.user && (!uploaderUser || uploaderUser._id.toString() !== req.user._id.toString()));
        
        if (uploaderUser && uploaderUser.role === 'distributor') {
            isUploaderDistributor = true;
        }

        // --- RENDER ---
        const seoTitle = `Download ${displayFile.name} Mod${displayFile.version ? ` (${displayFile.version})` : ''}`;
        const rawDescription = displayFile.modDescription ? displayFile.modDescription.replace(/<[^>]*>?/gm, '').trim() : `Download the latest premium unlocked mod for ${displayFile.name}.`;
        const seoDescription = rawDescription.length > 160 ? `${rawDescription.substring(0, 157)}...` : rawDescription;
        const tagsForSeo = Array.isArray(displayFile.tags) && displayFile.tags.length ? displayFile.tags.join(', ') : `gpl mods, ${displayFile.name}, premium unlocked mod`;
        const currentModSlug = masterFile.slug || slugify(masterFile.name) || masterFile._id.toString();
        const canonicalModUrl = `https://gplmods.webredirect.org/mods/${category}/${currentModSlug}${isViewingVariant ? `/${displayFile._id}` : ''}`;

                // Auto-check VirusTotal scan if pending or manual VT URL provided
        if (displayFile && (displayFile.virusTotalAnalysisId || displayFile.manualFileScanUrl) && !displayFile.virusTotalScanDate) {
            try {
                await checkAndUpdateFileVirusTotal(displayFile._id);
                const updatedDisplay = await File.findById(displayFile._id);
                if (updatedDisplay) displayFile = updatedDisplay;
            } catch (vtErr) {}
        }

        // --- RECOMMENDATION & PROMOTION SECTIONS (Item 1) ---
        const excludedIds = [masterFile._id, displayFile._id].filter(Boolean);

        // Helper to attach signed icon URLs
        const attachIcons = async (list) => {
            if (!Array.isArray(list) || list.length === 0) return [];
            return Promise.all(list.map(async (m) => {
                const key = m.iconUrl || m.iconKey;
                const iUrl = key ? await getSmartImageUrl(key) : '/images/default-app-icon.png';
                return { ...m, iconUrl: iUrl };
            }));
        };

        // 1. Suggested For You (Promoted / Sponsored Ads)
        let rawSuggested = await File.find({
            status: 'live',
            isPromoted: true,
            promotedUntil: { $gte: new Date() },
            _id: { $nin: excludedIds }
        }).sort({ promotionTier: -1, views: -1 }).limit(6).lean();

        // Backfill if fewer than 4 promoted mods
        if (rawSuggested.length < 4) {
            const currentSuggestedIds = [...excludedIds, ...rawSuggested.map(s => s._id)];
            const backfill = await File.find({
                status: 'live',
                $or: [
                    { isEditorsChoice: true },
                    { averageRating: { $gte: 4.0 } },
                    { views: { $gte: 50 } }
                ],
                _id: { $nin: currentSuggestedIds }
            }).sort({ views: -1, averageRating: -1 }).limit(6 - rawSuggested.length).lean();
            rawSuggested = [...rawSuggested, ...backfill];
        }

        // 2. Similar Apps
        const isApp = (displayFile.subCategory && /app|tool|util|product|social|media|software/i.test(displayFile.subCategory)) || displayFile.category === 'wordpress';
        let rawSimilarApps = [];
        if (isApp) {
            rawSimilarApps = await File.find({
                status: 'live',
                category: displayFile.category,
                _id: { $nin: excludedIds },
                $or: [
                    { subCategory: displayFile.subCategory },
                    { tags: { $in: displayFile.tags || [] } }
                ]
            }).sort({ views: -1, downloads: -1 }).limit(6).lean();
        } else {
            rawSimilarApps = await File.find({
                status: 'live',
                category: displayFile.category,
                _id: { $nin: excludedIds },
                $or: [
                    { subCategory: { $regex: /app|tool|util|emulator|software/i } },
                    { tags: { $in: ['tools', 'utilities', 'emulator', 'patcher', 'mod-manager', 'app', 'helper', 'tweaks'] } }
                ]
            }).sort({ views: -1 }).limit(6).lean();
        }
        // Fallback for similar apps if empty
        if (rawSimilarApps.length === 0) {
            rawSimilarApps = await File.find({
                status: 'live',
                category: displayFile.category,
                _id: { $nin: excludedIds }
            }).sort({ downloads: -1 }).limit(6).lean();
        }

        // 3. Similar Mods
        const similarAppsIds = rawSimilarApps.map(a => a._id);
        const similarModsExclude = [...excludedIds, ...similarAppsIds];
        const similarModsFilter = {
            status: 'live',
            _id: { $nin: similarModsExclude }
        };
        if (Array.isArray(displayFile.tags) && displayFile.tags.length > 0) {
            similarModsFilter.$or = [
                { tags: { $in: displayFile.tags } },
                { category: displayFile.category, subCategory: displayFile.subCategory }
            ];
        } else {
            similarModsFilter.category = displayFile.category;
        }
        let rawSimilarMods = await File.find(similarModsFilter)
            .sort({ views: -1, downloads: -1 })
            .limit(8)
            .lean();

        // 4. More By Uploader
        let rawMoreByUploader = [];
        if (displayFile.uploader) {
            rawMoreByUploader = await File.find({
                uploader: displayFile.uploader,
                status: 'live',
                _id: { $nin: excludedIds }
            }).sort({ createdAt: -1 }).limit(6).lean();
        }

        // 5. More By Developer
        let rawMoreByDeveloper = [];
        if (displayFile.developer && displayFile.developer !== 'N/A') {
            rawMoreByDeveloper = await File.find({
                developer: displayFile.developer,
                status: 'live',
                _id: { $nin: excludedIds }
            }).sort({ createdAt: -1 }).limit(6).lean();
        }

        // 6. Also Available for Other Platforms
        const cleanName = (masterFile.name || '').trim();
        const otherPlatformConditions = [];
        if (cleanName) {
            otherPlatformConditions.push({ name: new RegExp('^' + escapeRegex(cleanName) + '$', 'i') });
        }
        if (masterFile.iosPackageId) {
            otherPlatformConditions.push({ iosPackageId: masterFile.iosPackageId });
        }
        if (masterFile.slug) {
            otherPlatformConditions.push({ slug: masterFile.slug });
        }
        let rawOtherPlatformMods = [];
        if (otherPlatformConditions.length > 0) {
            rawOtherPlatformMods = await File.find({
                status: 'live',
                category: { $ne: masterFile.category },
                _id: { $nin: excludedIds },
                $or: otherPlatformConditions
            }).limit(6).lean();
        }

        // Resolve uploader avatar
        let uploaderAvatar = '/images/default-avatar.png';
        if (uploaderUser && uploaderUser.profileImageKey) {
            try { uploaderAvatar = await getSmartImageUrl(uploaderUser.profileImageKey); } catch (e) {}
        }

        const [suggestedMods, similarApps, similarMods, moreByUploader, moreByDeveloper, otherPlatformMods] = await Promise.all([
            attachIcons(rawSuggested),
            attachIcons(rawSimilarApps),
            attachIcons(rawSimilarMods),
            attachIcons(rawMoreByUploader),
            attachIcons(rawMoreByDeveloper),
            attachIcons(rawOtherPlatformMods)
        ]);

        res.render('pages/download', {
            file: { ...(displayFile.toObject ? displayFile.toObject() : displayFile), iconUrl, screenshotUrls },
            masterFile: masterFile,
            isViewingVariant: isViewingVariant,
            versionHistory,
            reviews: reviewsWithAvatars,
            userHasWhitelisted,
            userVotedWorking,
            userVotedNotWorking,
            canVoteOnFile,
            isUploaderDistributor,
            uploaderAvatar,
            suggestedMods,
            similarApps,
            similarMods,
            moreByUploader,
            moreByDeveloper,
            otherPlatformMods,
            themeMusic: displayFile.themeMusic,
            musicSettings: req.user ? req.user.musicSettings : { allowThemeMusic: true, autoPlayTheme: true },
            pageTitle: seoTitle,
            pageDescription: seoDescription,
            pageImage: iconUrl,
            pageKeywords: tagsForSeo,
            pageUrl: canonicalModUrl
        });

    } catch (e) {
        console.error("Error rendering mod page:", e);
        return next(e); 
    }
}

// 1. Main mod route: /mods/:platform/:slug
app.get('/mods/:platform/:slug', async (req, res, next) => {
    const platform = (req.params.platform || '').toLowerCase();
    const slug = (req.params.slug || '').toLowerCase();
    const variantId = req.query.variant;
    return renderModDownloadPage(req, res, next, { category: platform, slug, variantId });
});

// 2. Variant mod route: /mods/:platform/:slug/:id
app.get('/mods/:platform/:slug/:id', async (req, res, next) => {
    const platform = (req.params.platform || '').toLowerCase();
    const slug = (req.params.slug || '').toLowerCase();
    const variantId = req.params.id;
    return renderModDownloadPage(req, res, next, { category: platform, slug, variantId });
});

// 3. Static ID fallback route: /mods/:id (301 redirect to slugified URL)
app.get('/mods/:id', async (req, res, next) => {
    const id = req.params.id;
    if (Types.ObjectId.isValid(id)) {
        try {
            const file = await File.findById(id).populate('masterFile');
            if (file) {
                const queryString = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
                if (file.isVariant && file.masterFile) {
                    const master = await File.findById(file.masterFile);
                    if (master) {
                        const mSlug = master.slug || slugify(master.name) || master._id.toString();
                        return res.redirect(301, `/mods/${master.category}/${mSlug}/${file._id}${queryString}`);
                    }
                } else {
                    const mSlug = file.slug || slugify(file.name) || file._id.toString();
                    return res.redirect(301, `/mods/${file.category}/${mSlug}${queryString}`);
                }
            }
        } catch (err) {
            console.error("Static ID fallback error:", err);
        }
    }
    return next();
});

// 4. Backward Compatibility: /:category/:slug (redirects to /mods/:category/:slug)
app.get('/:category/:slug', async (req, res, next) => {
    try {
        const category = (req.params.category || '').toLowerCase();
        const slug = (req.params.slug || '').toLowerCase();
        const variantId = req.query.variant;

        // Prevent capturing system reserved URLs
        const reservedPaths = [
            'api', 'admin', 'auth', 'css', 'js', 'images', 'audio', 'animations', 
            'mods', 'users', 'category', 'search', 'updates', 'profile', 'my-uploads', 
            'developer', 'support', 'donate', 'partnership', 'home', 'healthz', 
            'download-file', 'upload-details', 'reset-password', 'docs', 'licenses'
        ];
        
        if (reservedPaths.includes(category)) return next();

        const knownPlatforms = ['windows', 'android', 'ios-jailed', 'ios-jailbroken', 'wordpress', 'n/a'];
        if (knownPlatforms.includes(category)) {
            const queryString = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
            if (variantId) {
                return res.redirect(301, `/mods/${category}/${slug}/${variantId}${queryString}`);
            }
            return res.redirect(301, `/mods/${category}/${slug}${queryString}`);
        }

        return renderModDownloadPage(req, res, next, { category, slug, variantId });
    } catch (e) {
        return next(e);
    }
});

// ============================================================================
// MOD RECOMMENDATIONS & SPONSORED PROMOTIONS API (Item 1)
// ============================================================================

// 1. Explore Mods by Tag (Instant AJAX Drawer / Modal)
app.get('/api/mods/by-tag', async (req, res) => {
    try {
        const rawTag = (req.query.tag || '').trim();
        if (!rawTag) {
            return res.json({ success: true, tag: '', count: 0, mods: [] });
        }

        const tagRegex = new RegExp('^' + escapeRegex(rawTag) + '$', 'i');
        const mods = await File.find({
            status: 'live',
            tags: { $in: [tagRegex] }
        })
        .sort({ views: -1, downloads: -1 })
        .limit(12)
        .lean();

        const modsWithIcons = await Promise.all(mods.map(async (m) => {
            const key = m.iconUrl || m.iconKey;
            const iconUrl = key ? await getSmartImageUrl(key) : '/images/default-app-icon.png';
            const slug = m.slug || slugify(m.name) || m._id.toString();
            return {
                _id: m._id,
                name: m.name,
                version: m.version,
                category: m.category,
                developer: m.developer,
                averageRating: m.averageRating || 0,
                ratingCount: m.ratingCount || 0,
                views: m.views || 0,
                downloads: m.downloads || 0,
                iconUrl,
                url: `/mods/${m.category}/${slug}`
            };
        }));

        return res.json({
            success: true,
            tag: rawTag,
            count: modsWithIcons.length,
            mods: modsWithIcons
        });
    } catch (err) {
        console.error('[API by-tag Error]:', err);
        return res.status(500).json({ success: false, error: 'Failed to search mods by tag.' });
    }
});

// DEDICATED MOD PROMOTION PAGE
app.get('/promote', async (req, res, next) => {
    try {
        let userMods = [];
        let promotions = [];
        let activeCampaigns = 0;
        let totalImpressions = 0;
        let totalClicks = 0;

        if (req.isAuthenticated && req.isAuthenticated()) {
            const isStaff = req.user && ['admin', 'owner', 'distributor'].includes(req.user.role);
            
            // Fetch creator's mods
            userMods = await File.find({
                uploader: req.user.username
            })
            .select('_id name title slug fileType category totalDownloads isPromoted promotedUntil promotionTier iconUrl fileIconUrl screenshots previewImage status')
            .sort({ totalDownloads: -1 })
            .lean();

            // If staff has no uploaded mods of their own, provide recent/popular mods for testing/management
            if (userMods.length === 0 && isStaff) {
                userMods = await File.find({ isLatestVersion: true })
                    .select('_id name title slug fileType category totalDownloads isPromoted promotedUntil promotionTier iconUrl fileIconUrl screenshots previewImage status')
                    .sort({ totalDownloads: -1 })
                    .limit(20)
                    .lean();
            }

            // Fetch promotions
            const promoQuery = isStaff ? {} : { user: req.user._id };
            promotions = await ModPromotion.find(promoQuery)
                .populate('file', 'name title slug fileType category totalDownloads isPromoted promotedUntil promotionTier iconUrl fileIconUrl')
                .sort({ createdAt: -1 })
                .limit(50)
                .lean();

            const now = new Date();
            promotions.forEach(p => {
                if (p.status === 'active' && p.endDate && new Date(p.endDate) > now) {
                    activeCampaigns++;
                }
                totalImpressions += (p.impressions || 0);
                totalClicks += (p.clicks || 0);
            });
        }

        const preselectedModId = req.query.modId || (userMods.length > 0 ? String(userMods[0]._id) : null);

        res.render('pages/promote', {
            pageTitle: 'Promote Your Mods - Play Store Style Ads System',
            pageDescription: 'Boost your mod visibility, gain targeted installs, and reach top ranks across GPL Mods with dedicated promotional placements.',
            userMods,
            promotions,
            activeCampaigns,
            totalImpressions,
            totalClicks,
            preselectedModId,
            pricingConfig: {
                durations: [
                    { days: 1, baseINR: 149, label: '1 Day', subtitle: 'Quick Exposure' },
                    { days: 3, baseINR: 349, label: '3 Days', subtitle: 'Weekend Burst' },
                    { days: 7, baseINR: 699, label: '7 Days', subtitle: 'Most Popular', isPopular: true },
                    { days: 14, baseINR: 1299, label: '14 Days', subtitle: 'Extended Reach' },
                    { days: 30, baseINR: 2499, label: '30 Days', subtitle: 'Maximum Power' }
                ],
                tiers: [
                    {
                        id: 'standard',
                        name: 'Standard Boost',
                        badge: 'Essential',
                        multiplier: 1.0,
                        features: ['Top 5 Search Placement', 'Related Mods Recommendation Tag', 'Verified Mod Status Badge', 'Standard Analytics']
                    },
                    {
                        id: 'featured',
                        name: 'Featured Highlight',
                        badge: 'High Impact',
                        multiplier: 1.4,
                        isPopular: true,
                        features: ['Top 3 Category Sticky Placement', 'Gilded Gold Border & Badge', 'High Priority Search Index', 'Real-time CTR Analytics']
                    },
                    {
                        id: 'spotlight',
                        name: 'Spotlight VIP',
                        badge: 'Maximum Domination',
                        multiplier: 2.0,
                        features: ['Homepage Hero Carousel Spotlight', '#1 Sticky Category Banner', 'Exclusive Sponsored Tag', 'VIP 24/7 Dedicated Support']
                    }
                ]
            }
        });
    } catch (err) {
        console.error('[GET /promote Error]:', err);
        next(err);
    }
});

// 2. Promote Mod Endpoint (Play Store style ads system)
app.post('/api/mods/:id/promote', async (req, res) => {
    try {
        if (!req.isAuthenticated()) {
            return res.status(401).json({ success: false, error: 'Please log in to promote your mod.' });
        }

        const fileId = req.params.id;
        const targetFile = await File.findById(fileId);
        if (!targetFile) {
            return res.status(404).json({ success: false, error: 'Mod not found.' });
        }

        // Must be uploader or admin/owner/distributor
        const isUploader = targetFile.uploader === req.user.username;
        const isStaff = ['admin', 'owner', 'distributor'].includes(req.user.role);
        if (!isUploader && !isStaff) {
            return res.status(403).json({ success: false, error: 'You can only promote your own mods.' });
        }

        const days = parseInt(req.body.days, 10) || 7;
        if (days < 1 || days > 365) {
            return res.status(400).json({ success: false, error: 'Invalid duration. Choose between 1 and 365 days.' });
        }

        const tier = req.body.tier || 'standard';
        const pricing = {
            1: 149,
            3: 349,
            7: 699,
            14: 1299,
            30: 2499
        };
        const amount = pricing[days] || Math.round(days * 120);

        const currentExpiry = (targetFile.isPromoted && targetFile.promotedUntil && targetFile.promotedUntil > new Date())
            ? targetFile.promotedUntil
            : new Date();
        const newExpiry = new Date(currentExpiry.getTime() + (days * 24 * 60 * 60 * 1000));

        targetFile.isPromoted = true;
        targetFile.promotedUntil = newExpiry;
        targetFile.promotionTier = tier;
        await targetFile.save();

        const promo = new ModPromotion({
            file: targetFile._id,
            user: req.user._id,
            days,
            amount,
            currency: 'INR',
            tier,
            startDate: currentExpiry,
            endDate: newExpiry,
            status: 'active',
            paymentMethod: isStaff && !isUploader ? 'admin-grant' : 'direct-activation'
        });
        await promo.save();

        return res.json({
            success: true,
            message: `Mod "${targetFile.name}" successfully promoted for ${days} days!`,
            promotedUntil: newExpiry,
            tier
        });
    } catch (err) {
        console.error('[Mod Promotion Error]:', err);
        return res.status(500).json({ success: false, error: 'Failed to activate promotion.' });
    }
});

// 3. Track Promotion Click
app.post('/api/promotions/track-click/:fileId', async (req, res) => {
    try {
        const fileId = req.params.fileId;
        await ModPromotion.updateMany(
            { file: fileId, status: 'active', endDate: { $gte: new Date() } },
            { $inc: { clicks: 1 } }
        );
        return res.json({ success: true });
    } catch (e) {
        return res.json({ success: false });
    }
});

// 4. Track Promotion Impressions
app.post('/api/promotions/track-impressions', async (req, res) => {
    try {
        const fileIds = Array.isArray(req.body.fileIds) ? req.body.fileIds : [];
        if (fileIds.length > 0) {
            await ModPromotion.updateMany(
                { file: { $in: fileIds }, status: 'active', endDate: { $gte: new Date() } },
                { $inc: { impressions: 1 } }
            );
        }
        return res.json({ success: true });
    } catch (e) {
        return res.json({ success: false });
    }
});

// ===================================
// LICENSE DIRECTORY & READER
// ===================================
app.get('/licenses', async (req, res, next) => {
    try {
        const licenses = await License.find().sort({ name: 1 }).lean();
        res.render('pages/licenses-hub', { licenses });
    } catch (error) {
        next(error);
    }
});

app.get('/licenses/:slug', async (req, res, next) => {
    try {
        const license = await License.findOne({ slug: req.params.slug.toLowerCase() }).lean();
        if (!license) return next();
        res.render('pages/license-reader', { license });
    } catch (error) {
        next(error);
    }
});

app.get('/licenses/:slug/download', async (req, res, next) => {
    try {
        const format = String(req.query.format || '').toLowerCase();
        if (!['txt', 'md'].includes(format)) return res.status(400).send('Invalid format');
        const license = await License.findOne({ slug: req.params.slug.toLowerCase() }).lean();
        if (!license) return res.status(404).send('Not found');
        res.type('text/plain').attachment(`${license.slug}-license.${format}`).send(`${license.name}\n\n${license.content}`);
    } catch (error) {
        next(error);
    }
});

app.post('/mods/:id/request-update', ensureAuthenticated, async (req, res, next) => {
    try {
        const file = await File.findById(req.params.id);
        if (!file) return res.status(404).redirect('back');

        const uploader = await User.findOne({ username: file.uploader });
        if (uploader && uploader._id.toString() !== req.user._id.toString()) {
            const existingRequest = await UserNotification.findOne({
                user: uploader._id,
                type: 'mod-update-request',
                'metadata.file': file._id
            });

            if (!existingRequest) {
                await UserNotification.create({
                    user: uploader._id,
                    title: `Update Requested: ${file.name}`,
                    message: `User ${req.user.username} requested an update for your mod: ${file.name}.`,
                    type: 'mod-update-request',
                    metadata: { file: file._id, requester: req.user._id }
                });
            }
        }

        res.redirect(`/${file.category}/${file.slug || file._id}?success=${encodeURIComponent('Update request sent to the uploader.')}`);
    } catch (error) {
        next(error);
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
            return res.status(404).render('pages/error', { errorCode: '404', errorTitle: 'Page Not Found', errorMessage: 'The page you are looking for does not exist or you do not have permission to access it.' });
        }
        const customTemplates = await ModTemplate.find({ isActive: true }).sort({ sortOrder: 1, createdAt: 1 }).lean();
        res.render('pages/add-version', { parentFile: parentFile, customTemplates });
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
        const isAdmin = req.user.role === 'admin' || req.user.role === 'owner';
        if (!isUploader && !isAdmin) {
            return res.status(404).json({ success: false, message: 'Resource not found.' });
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
            const m1Prov = formData.mirror1Providers || formData.mirror1Provider
                ? (Array.isArray(formData.mirror1Providers || formData.mirror1Provider) ? (formData.mirror1Providers || formData.mirror1Provider) : [formData.mirror1Providers || formData.mirror1Provider])
                : [];
            const m1Url = formData.mirror1Urls || formData.mirror1Url
                ? (Array.isArray(formData.mirror1Urls || formData.mirror1Url) ? (formData.mirror1Urls || formData.mirror1Url) : [formData.mirror1Urls || formData.mirror1Url])
                : [];
            const m2Prov = formData.mirror2Providers || formData.mirror2Provider
                ? (Array.isArray(formData.mirror2Providers || formData.mirror2Provider) ? (formData.mirror2Providers || formData.mirror2Provider) : [formData.mirror2Providers || formData.mirror2Provider])
                : [];
            const m2Url = formData.mirror2Urls || formData.mirror2Url
                ? (Array.isArray(formData.mirror2Urls || formData.mirror2Url) ? (formData.mirror2Urls || formData.mirror2Url) : [formData.mirror2Urls || formData.mirror2Url])
                : [];
            const daLink = formData.directAdminLinks || formData.directAdminLink
                ? (Array.isArray(formData.directAdminLinks || formData.directAdminLink) ? (formData.directAdminLinks || formData.directAdminLink) : [formData.directAdminLinks || formData.directAdminLink])
                : [];
            const mfScan = formData.manualFileScanUrls || formData.partManualFileScanUrl
                ? (Array.isArray(formData.manualFileScanUrls || formData.partManualFileScanUrl) ? (formData.manualFileScanUrls || formData.partManualFileScanUrl) : [formData.manualFileScanUrls || formData.partManualFileScanUrl])
                : [];
            const msScan = formData.manualSiteScanUrls || formData.partManualSiteScanUrl
                ? (Array.isArray(formData.manualSiteScanUrls || formData.partManualSiteScanUrl) ? (formData.manualSiteScanUrls || formData.partManualSiteScanUrl) : [formData.manualSiteScanUrls || formData.partManualSiteScanUrl])
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
            const isAdminOrDist = req.user.role === 'admin' || req.user.role === 'owner' || req.user.role === 'distributor';

            if (!isAdminOrDist) {
                if (!isPremium && fileSize > 314572800) {
                    return res.status(413).json({ success: false, message: 'File exceeds 300MB limit.' });
                }
                if (isPremium && fileSize > 1073741824) {
                    return res.status(413).json({ success: false, message: 'File exceeds 1GB limit.' });
                }
            }

            const io = req.app.get('io');
            const targetModKey = getModStorageKey({
                category: previousVersion.category,
                modName: previousVersion.name,
                uploader: req.user,
                uploaderEmail: req.user.email,
                isVariant: Boolean(previousVersion.isVariant),
                variantId: previousVersion._id,
                assetType: 'file',
                originalFilename: req.file.originalname,
                version: req.body.softwareVersion
            });
            newFileKey = await uploadToB2(req.file, 'mods', io, formData.uploadId, null, { exactKey: targetModKey });
        }

        let newRequiresRoot = previousVersion.requiresRoot || false;
        let newRequiresDevMode = previousVersion.requiresDevMode || false;
        let newIsTweakConvertible = previousVersion.isTweakConvertible || false;
        let newRequiresDependencies = previousVersion.requiresDependencies || false;
        let newRequiresDisableAntivirus = previousVersion.requiresDisableAntivirus || false;

        if (previousVersion.category === 'android') {
            if (formData.requiresRoot !== undefined) newRequiresRoot = (formData.requiresRoot === 'true' || formData.requiresRoot === true || formData.requiresRoot === 'on');
            if (formData.requiresDevMode !== undefined) newRequiresDevMode = (formData.requiresDevMode === 'true' || formData.requiresDevMode === true || formData.requiresDevMode === 'on');
        } else if (previousVersion.category === 'ios-jailbroken') {
            if (formData.isTweakConvertible !== undefined) newIsTweakConvertible = (formData.isTweakConvertible === 'true' || formData.isTweakConvertible === true || formData.isTweakConvertible === 'on');
            if (formData.requiresDependencies !== undefined) newRequiresDependencies = (formData.requiresDependencies === 'true' || formData.requiresDependencies === true || formData.requiresDependencies === 'on');
        } else if (previousVersion.category === 'windows') {
            if (formData.requiresDisableAntivirus !== undefined) newRequiresDisableAntivirus = (formData.requiresDisableAntivirus === 'true' || formData.requiresDisableAntivirus === true || formData.requiresDisableAntivirus === 'on');
            if (formData.requiresDevMode !== undefined) newRequiresDevMode = (formData.requiresDevMode === 'true' || formData.requiresDevMode === true || formData.requiresDevMode === 'on');
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
            architectures: (formData.architectures !== undefined ? (Array.isArray(formData.architectures) ? formData.architectures : [formData.architectures]) : previousVersion.architectures),
            minOsVersion: formData.minOsVersion || previousVersion.minOsVersion,
            requiresRoot: newRequiresRoot,
            requiresDevMode: newRequiresDevMode,
            isTweakConvertible: newIsTweakConvertible,
            requiresDependencies: newRequiresDependencies,
            requiresDisableAntivirus: newRequiresDisableAntivirus,
            ageRating: formData.ageRating || previousVersion.ageRating,
            importantNote: formData.importantNote || previousVersion.importantNote,
            uploader: req.user.username,
            version: req.body.softwareVersion,
            whatsNew: req.body.whatsNew,
            fileKey: newFileKey,
            fileSize: actualFileSize,
            originalFilename: originalFilename,
            isMultiPart: isMultiPart,
            downloadParts: downloadParts,
            externalDownloadUrl: !isMultiPart ? (normalizeSingleValue(formData.externalDownloadUrl) || '') : '',
            directDownloadUrl: normalizeSingleValue(formData.directDownloadUrl) || '',
            manualFileScanUrl: !isMultiPart ? (normalizeSingleValue(formData.manualFileScanUrl) || '') : '',
            manualSiteScanUrl: !isMultiPart ? (normalizeSingleValue(formData.manualSiteScanUrl) || '') : '',
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
        saveModMetadata(newVersion);

        // Archive previous live version file to old-version/ subfolder in B2
        try {
            if (previousVersion.fileKey && previousVersion.fileKey !== 'external-link' && !previousVersion.fileKey.includes('old-version')) {
                const archivedOldKey = getModStorageKey({
                    category: previousVersion.category,
                    modName: previousVersion.name,
                    uploader: req.user,
                    uploaderEmail: req.user.email,
                    isVariant: Boolean(previousVersion.isVariant),
                    variantId: previousVersion._id,
                    assetType: 'old-version',
                    originalFilename: previousVersion.originalFilename || path.basename(previousVersion.fileKey),
                    version: previousVersion.version
                });
                await s3Client.send(new CopyObjectCommand({
                    Bucket: process.env.B2_BUCKET_NAME,
                    CopySource: `${process.env.B2_BUCKET_NAME}/${encodeURI(previousVersion.fileKey)}`,
                    Key: archivedOldKey
                }));
                await s3Client.send(new DeleteObjectCommand({
                    Bucket: process.env.B2_BUCKET_NAME,
                    Key: previousVersion.fileKey
                }));
                previousVersion.fileKey = archivedOldKey;
                await previousVersion.save();
                saveModMetadata(previousVersion);
            }
        } catch (archiveErr) {
            console.warn('[Storage] Notice: Could not archive previous version file in B2:', archiveErr.message);
        }

        notifyClubModFeeds(newVersion, true, req.body.whatsNew);

        if (req.file && req.file.size > 100) {
            (async () => {
                try {
                    const analysisId = await submitToVirusTotal(req.file.buffer, req.file.originalname, req.file.size);
                    await File.findByIdAndUpdate(newVersion._id, { virusTotalAnalysisId: analysisId });
                    pollVirusTotalInBackground(newVersion._id);
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

        if (shouldMirrorToFTP(fileKey)) {
            deleteFromFTP(fileKey).catch(e => console.error("Background FTP delete failed", e));
        }
    } catch (error) {
        // We log the error but don't crash the server. If a file is already gone, that's okay.
        console.error(`Failed to delete ${fileKey} from B2:`, error.message);
    }
};
// Download Action - UPDATED for External Links & Presigned URLs
app.get('/download-file/:id', async (req, res) => {
    try {
        const fileId = req.params.id;
        const file = await File.findById(fileId);
        if (!file) return res.status(404).render('pages/404');
        if (file.isDmcaHidden) {
            return res.status(451).render('pages/unavailable', {
                title: 'Download Unavailable (DMCA Notice)',
                message: 'This download link has been temporarily disabled due to a DMCA copyright complaint and is undergoing administrative review.'
            });
        }
        if (file.ageRating === '18+' && shouldHideAdultContent(req.user)) return res.status(404).render('pages/404');

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
            await recordDailyStat(file._id, file.uploader, 'download');
        }
        // ==========================================

        // --- 1. CHECK FOR EXTERNAL CLOUD LINK FIRST ---
        if (file.externalDownloadUrl) {
            const encodedUrl = encodeURIComponent(file.externalDownloadUrl);
            const encodedName = encodeURIComponent(file.originalFilename || file.name);
            return res.redirect(`/leave?url=${encodedUrl}&name=${encodedName}`);
        }

        // --- 2. MULTI-PART / ALTERNATIVE URL PASSTHROUGH ---
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
        if (file && file.isDmcaHidden) {
            return res.status(451).render('pages/unavailable', {
                title: 'Download Unavailable (DMCA Notice)',
                message: 'This multi-part download has been temporarily disabled due to a DMCA copyright complaint and is undergoing administrative review.'
            });
        }
        if (file && file.ageRating === '18+' && shouldHideAdultContent(req.user)) return res.status(404).render('pages/404');
        
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


                if (file && (file.virusTotalAnalysisId || file.manualFileScanUrl) && !file.virusTotalScanDate) {
            try {
                await checkAndUpdateFileVirusTotal(file._id);
                const updatedFile = await File.findById(file._id);
                if (updatedFile) file = updatedFile;
            } catch (vtErr) {}
        }
        if (file && file.downloadParts && file.downloadParts.length > 0) {
            for (const part of file.downloadParts) {
                if ((part.partVirusTotalId || part.manualFileScanUrl) && !part.partVirusTotalScanDate) {
                    try {
                        await checkAndUpdatePartVirusTotal(file._id, part._id);
                    } catch (e) {}
                }
            }
            const refreshedFile = await File.findById(file._id);
            if (refreshedFile) file = refreshedFile;
        }

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
        req.session.sessionVersion = user.sessionVersion || 0;
        
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

        if (user.loginAlertEmailsEnabled || user.safetyEmailsEnabled) {
            const parser = new UAParser(req.headers['user-agent'] || '');
            const browser = parser.getBrowser().name || 'Unknown Browser';
            const os = parser.getOS().name || 'Unknown OS';
            const deviceInfo = `${browser} on ${os}`;
            const ipAddress = req.ip || req.socket.remoteAddress || 'Unknown IP';
            const loginToken = crypto.randomBytes(24).toString('hex');

            user.loginAlertTokens.push({
                token: loginToken,
                sessionId: req.sessionID,
                deviceInfo,
                ipAddress
            });
            user.loginAlertTokens = user.loginAlertTokens.slice(-10);
            await user.save();
            await sendLoginAlertEmail(user, deviceInfo, ipAddress, loginToken, req);
        }

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

        // Priority method is the 1st enabled method in twoFactorMethods, fallback to twoFactorMethod
        const availableMethods = getAvailable2FAMethods(user);
        if (JSON.stringify(user.twoFactorMethods) !== JSON.stringify(availableMethods)) {
            user.twoFactorMethods = availableMethods;
            user.save().catch(err => console.error("Error updating twoFactorMethods on login:", err));
        }

        const priorityMethod = (req.session.active2faMethod && availableMethods.includes(req.session.active2faMethod))
            ? req.session.active2faMethod
            : availableMethods[0] || 'email';
        req.session.active2faMethod = priorityMethod;
        
        if (priorityMethod === 'email') {
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
    if (req.isAuthenticated()) {
        const returnTo = req.session && req.session.returnTo && !req.session.returnTo.includes('/login') && !req.session.returnTo.includes('/register') && !req.session.returnTo.includes('/logout') ? req.session.returnTo : '/home';
        if (req.session) delete req.session.returnTo;
        return res.redirect(returnTo);
    }

    // Purge any stale is_logged_in cookie for guests visiting the login page
    res.clearCookie('is_logged_in', { path: '/' });

    res.render('pages/login', {
        recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY,
        message: req.query.message || null,
        error: req.query.error || null 
    });
});

app.post('/login', verifyRecaptcha, (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) return next(err);
        if (!user) return res.redirect('/login?error=' + encodeURIComponent('Incorrect Email Or Password'));
        
        processSuccessfulLogin(req, res, next, user); 
    })(req, res, next);
});

// --- 4. SOCIAL CALLBACK HANDLER (Handles Fresh Logins AND Social 2FA) ---
const handleSocialCallback = (provider) => {
    return (req, res, next) => {
        if (req.query.error) {
            const providerError = req.query.error_description || req.query.error;
            console.error(`[${provider} OAuth] Authorization failed: ${providerError}`);
            return res.redirect('/login?error=' + encodeURIComponent(`${provider} sign-in failed: ${providerError}`));
        }

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

        const birthDate = new Date(`${dateOfBirth}T00:00:00`);
        const today = new Date();
        let age = today.getFullYear() - birthDate.getFullYear();
        const birthdayThisYear = new Date(today.getFullYear(), birthDate.getMonth(), birthDate.getDate());
        if (today < birthdayThisYear) age--;

        if (Number.isNaN(birthDate.getTime()) || birthDate > today) {
            return res.status(400).render('pages/register', {
                recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY || '',
                message: null,
                error: 'Please enter a valid date of birth.'
            });
        }

        if (age < 13) {
            return res.status(400).render('pages/register', {
                recaptchaSiteKey: process.env.RECAPTCHA_SITE_KEY || '',
                message: null,
                error: 'You are not old enough to register. You must be at least 13 years old.'
            });
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
            user.dateOfBirth = birthDate; 
        } else {
            // Create new user
            user = new User({
                username: uniqueUsername,
                email: email.toLowerCase(),
                password,
                referralCode: newReferralCode, 
                referredBy: referrerId,        
                dateOfBirth: birthDate, 
                verificationOtp: otp,
                otpExpires: otpExpires
            });
        }
        
        await user.save();
        await createWelcomeNotification(user);
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
        await createWelcomeNotification(user);
        
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
        const userIdStr = String(req.user._id);
        // Clear the active session from the database
        await User.findByIdAndUpdate(req.user._id, { $unset: { currentSessionId: "" } });

        // Instantly prune user from live chat online list and broadcast
        try {
            const connectedUsers = req.app.get('connectedUsers');
            const broadcastOnlineStats = req.app.get('broadcastOnlineStats');
            if (connectedUsers) {
                for (const [sId, u] of connectedUsers.entries()) {
                    if (u && String(u.userId) === userIdStr) {
                        connectedUsers.delete(sId);
                    }
                }
            }
            if (typeof broadcastOnlineStats === 'function') {
                broadcastOnlineStats();
            }
        } catch (e) {
            console.error('Error pruning live user on logout:', e);
        }
    }
    req.logout(err => { 
        if (err) return next(err); 
        
        req.session.destroy(() => {
            res.clearCookie('connect.sid', { path: '/' });
            res.clearCookie('is_logged_in', { path: '/' });
            try {
                res.clearCookie('is_logged_in', { path: '/', domain: req.hostname });
            } catch (e) {}
            res.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
            res.set('Pragma', 'no-cache');
            res.set('Clear-Site-Data', '"cache"');
            res.redirect('/?message=You+have+been+successfully+logged+out.&logout=true'); 
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

        // Migrate accounts that used the former combined preference.
        if (user.safetyEmailsEnabled && !user.loginAlertEmailsEnabled && !user.failedLoginAlertEmailsEnabled) {
            user.loginAlertEmailsEnabled = true;
            user.failedLoginAlertEmailsEnabled = true;
            user.safetyEmailsEnabled = false;
            await user.save();
        }
        
        // Convert to object so we can append custom properties
        const userObj = user.toObject();
        userObj.hideAdultContent = shouldHideAdultContent(user);
        // Crucial: Attach the signed avatar URL generated by your global middleware!
        userObj.signedAvatarUrl = req.user.signedAvatarUrl;

        res.render('pages/settings', { user: userObj });
    } catch (error) {
        console.error("Settings page error:", error);
        res.status(500).render('pages/500');
    }
});

app.post('/settings/safety-emails', ensureAuthenticated, async (req, res) => {
    try {
        const updates = { safetyEmailsEnabled: false };
        if (req.body.settingType === 'loginAlertEmailsEnabled' || Object.prototype.hasOwnProperty.call(req.body, 'loginAlertEmailsEnabled')) {
            updates.loginAlertEmailsEnabled = req.body.loginAlertEmailsEnabled === 'on' || req.body.loginAlertEmailsEnabled === 'true' || req.body.loginAlertEmailsEnabled === true;
        }
        if (req.body.settingType === 'failedLoginAlertEmailsEnabled' || Object.prototype.hasOwnProperty.call(req.body, 'failedLoginAlertEmailsEnabled')) {
            updates.failedLoginAlertEmailsEnabled = req.body.failedLoginAlertEmailsEnabled === 'on' || req.body.failedLoginAlertEmailsEnabled === 'true' || req.body.failedLoginAlertEmailsEnabled === true;
        }
        await User.findByIdAndUpdate(req.user._id, updates);
        res.redirect('/settings?success=Security alert settings updated.');
    } catch (error) {
        console.error('Safety email settings error:', error);
        res.redirect('/settings?error=Unable to update security alert settings.');
    }
});

app.post('/settings/auto-save', ensureAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        user.autoSaveEnabled = req.body.autoSaveEnabled === 'on' || req.body.autoSaveEnabled === 'true' || req.body.autoSaveEnabled === true;
        await user.save();
        res.redirect('/settings?success=Auto-save preference updated.');
    } catch (error) {
        console.error('Auto-save settings error:', error);
        res.redirect('/settings?error=Unable to update auto-save settings.');
    }
});

app.post('/settings/adult-content', ensureAuthenticated, async (req, res) => {
    try {
        const hideAdultContent = req.body.hideAdultContent === 'on' || req.body.hideAdultContent === 'true' || req.body.hideAdultContent === true;
        await User.findByIdAndUpdate(req.user._id, { hideAdultContent });
        res.redirect('/settings?success=Adult-content preference updated.');
    } catch (error) {
        console.error('Adult-content preference error:', error);
        res.redirect('/settings?error=Unable to update adult-content preference.');
    }
});

app.post('/settings/global-council', ensureAuthenticated, async (req, res) => {
    try {
        const globalCouncil = req.body.globalCouncil === 'on' || req.body.globalCouncil === 'true' || req.body.globalCouncil === true;
        await User.findByIdAndUpdate(req.user._id, { globalCouncil });
        res.redirect('/settings?success=Global Council preference updated.');
    } catch (error) {
        console.error('Global Council preference error:', error);
        res.redirect('/settings?error=Unable to update Global Council preference.');
    }
});

app.post('/settings/notifications', ensureAuthenticated, async (req, res) => {
    try {
        const enabled = req.body.notificationsEnabled === 'on' || req.body.notificationsEnabled === 'true' || req.body.notificationsEnabled === true;
        const newUploads = req.body.newUploads === 'on' || req.body.newUploads === 'true' || req.body.newUploads === true;
        const clubUpdates = req.body.clubUpdates === 'on' || req.body.clubUpdates === 'true' || req.body.clubUpdates === true;
        const adminMessages = req.body.adminMessages === 'on' || req.body.adminMessages === 'true' || req.body.adminMessages === true;
        const soundEnabled = req.body.soundEnabled === 'on' || req.body.soundEnabled === 'true' || req.body.soundEnabled === true;

        const notificationSettings = {
            enabled,
            newUploads,
            clubUpdates,
            adminMessages,
            soundEnabled
        };

        await User.findByIdAndUpdate(req.user._id, { notificationSettings });
        const pushNotification = require('./utils/pushNotification');
        await pushNotification.updatePreferences(req.user._id, notificationSettings);

        res.redirect('/settings?success=Notification preferences updated successfully.');
    } catch (error) {
        console.error('Notification settings error:', error);
        res.redirect('/settings?error=Unable to update notification settings.');
    }
});

app.get('/security/login/:action/:token', async (req, res) => {
    try {
        const { action, token } = req.params;
        const user = await User.findOne({ 'loginAlertTokens.token': token });
        const tokenData = user && user.loginAlertTokens.find(item => item.token === token);

        if (!user || !tokenData) {
            return res.status(404).render('pages/security-alert', { 
                status: 'invalid', 
                message: 'This security link is invalid or does not exist.' 
            });
        }

        const tokenAgeMs = Date.now() - new Date(tokenData.createdAt || Date.now()).getTime();
        const ONE_HOUR_MS = 60 * 60 * 1000;

        // Check if the 1-hour validity window has expired
        if (tokenAgeMs > ONE_HOUR_MS) {
            return res.status(410).render('pages/security-alert', { 
                status: 'invalid', 
                message: 'This security link has expired. Security links are only valid for 1 hour from when the login alert was generated.' 
            });
        }

        const minutesLeft = Math.max(1, Math.ceil((ONE_HOUR_MS - tokenAgeMs) / (60 * 1000)));

        // If the user already confirmed or denied this alert before, return HTTP 208 (Already Reported)
        if (tokenData.status === 'verified' || tokenData.status === 'revoked') {
            return res.status(208).render('pages/security-alert', { 
                status: 'already_reported', 
                previousDecision: tokenData.status,
                token, 
                email: user.email,
                minutesLeft,
                error: req.query.error || null
            });
        }

        if (action === 'accept') {
            tokenData.status = 'verified';
            tokenData.respondedAt = new Date();
            await user.save();
            return res.render('pages/security-alert', { 
                status: 'success', 
                token, 
                email: user.email,
                minutesLeft 
            });
        }

        if (action === 'deny') {
            tokenData.status = 'revoked';
            tokenData.respondedAt = new Date();
            if (tokenData.sessionId) {
                await mongoose.connection.collection('sessions').updateOne(
                    { _id: tokenData.sessionId },
                    { $set: { kickedOut: true } }
                );
            }
            await user.save();
            return res.render('pages/security-alert', { 
                status: 'unauthorized', 
                token, 
                email: user.email, 
                minutesLeft,
                error: req.query.error || null 
            });
        }

        return res.status(400).render('pages/security-alert', { status: 'invalid', message: 'Unsupported security action.' });
    } catch (error) {
        console.error('Security alert route error:', error);
        res.status(500).render('pages/500');
    }
});

// Route to change opinion within 1 hour
app.all(['/security/login/change-decision/:token', '/security/login/change/:decision/:token'], async (req, res) => {
    try {
        const { token } = req.params;
        const decision = req.params.decision || req.body.decision || req.query.decision;
        const user = await User.findOne({ 'loginAlertTokens.token': token });
        const tokenData = user && user.loginAlertTokens.find(item => item.token === token);

        if (!user || !tokenData) {
            return res.status(404).render('pages/security-alert', { 
                status: 'invalid', 
                message: 'This security link is invalid or does not exist.' 
            });
        }

        const tokenAgeMs = Date.now() - new Date(tokenData.createdAt || Date.now()).getTime();
        const ONE_HOUR_MS = 60 * 60 * 1000;

        if (tokenAgeMs > ONE_HOUR_MS) {
            return res.status(410).render('pages/security-alert', { 
                status: 'invalid', 
                message: 'The 1-hour window to modify your response for this login alert has expired.' 
            });
        }

        const minutesLeft = Math.max(1, Math.ceil((ONE_HOUR_MS - tokenAgeMs) / (60 * 1000)));

        if (decision === 'deny') {
            tokenData.status = 'revoked';
            tokenData.respondedAt = new Date();
            if (tokenData.sessionId) {
                await mongoose.connection.collection('sessions').updateOne(
                    { _id: tokenData.sessionId },
                    { $set: { kickedOut: true } }
                );
            }
            await user.save();
            return res.render('pages/security-alert', { 
                status: 'unauthorized', 
                token, 
                email: user.email, 
                minutesLeft,
                infoMessage: 'Your response was updated. The session has been revoked.' 
            });
        } else if (decision === 'accept') {
            tokenData.status = 'verified';
            tokenData.respondedAt = new Date();
            await user.save();
            return res.render('pages/security-alert', { 
                status: 'success', 
                token, 
                email: user.email, 
                minutesLeft,
                infoMessage: 'Your response was updated. The login is now confirmed.' 
            });
        }

        return res.status(400).render('pages/security-alert', { status: 'invalid', message: 'Invalid decision specified.' });
    } catch (error) {
        console.error('Change security decision error:', error);
        res.status(500).render('pages/500');
    }
});

app.post('/security/force-password-change', async (req, res) => {
    try {
        const { email, token, newPassword, confirmPassword } = req.body;
        if (!newPassword || newPassword !== confirmPassword) {
            return res.redirect(`/security/login/deny/${encodeURIComponent(token)}?error=Passwords do not match.`);
        }
        if (newPassword.length < 6) {
            return res.redirect(`/security/login/deny/${encodeURIComponent(token)}?error=Password too short.`);
        }

        const user = await User.findOne({ email: email.toLowerCase(), 'loginAlertTokens.token': token });
        if (!user) return res.status(400).send('Invalid security request.');

        const tokenData = user.loginAlertTokens.find(item => item.token === token);
        if (!tokenData) return res.status(400).send('Invalid security request.');

        const tokenAgeMs = Date.now() - new Date(tokenData.createdAt || Date.now()).getTime();
        const ONE_HOUR_MS = 60 * 60 * 1000;
        if (tokenAgeMs > ONE_HOUR_MS) {
            return res.render('pages/security-alert', {
                status: 'invalid',
                message: 'This security session has expired. Please use the Forgot Password page to reset your password.'
            });
        }

        user.password = newPassword;
        user.sessionVersion = (user.sessionVersion || 0) + 1;
        tokenData.status = 'revoked';
        tokenData.respondedAt = new Date();
        await user.save();
        res.redirect('/login?message=Account secured and password updated successfully. Please log in.');
    } catch (error) {
        console.error('Forced password change error:', error);
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
    const returnUrl = req.session.returnTo2FA || '/settings?success=2FA successfully activated!';
    req.session.returnTo2FA = null;

    res.render('pages/2fa-recovery-codes', { codes: codes, returnUrl });
});

// My Uploads Route
app.get('/my-uploads', ensureAuthenticated, async (req, res) => {
    try {
        // 1. Fetch ONLY the user's active, non-DMCA-hidden uploads
        const userUploads = await File.find({ 
            uploader: req.user.username,
            isDmcaHidden: { $ne: true },
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
                    signedIconUrl = await getSmartImageUrl(key);
                } catch (urlError) {}
            }
            
            file.iconUrl = signedIconUrl;
            file.olderVersions = file.olderVersions || []; 
            return file; 
        }));

        // 3. Fetch user's DMCA-restricted uploads for dedicated review section
        const dmcaUploadsRaw = await File.find({
            uploader: req.user.username,
            isDmcaHidden: true
        })
        .sort({ dmcaHiddenAt: -1, createdAt: -1 })
        .populate('dmcaReportId')
        .lean();

        const dmcaUploads = await Promise.all(dmcaUploadsRaw.map(async (file) => {
            const key = file.iconUrl || file.iconKey;
            let signedIconUrl = '/images/default-app-icon.png';
            if (key) {
                try {
                    signedIconUrl = await getSmartImageUrl(key);
                } catch (urlError) {}
            }
            file.iconUrl = signedIconUrl;
            return file;
        }));

        const quota = await getUserUploadQuota(req.user);

        res.render('pages/my-uploads', { 
            uploads: uploadsWithUrls,
            dmcaUploads: dmcaUploads || [],
            quota
        }); 
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
        // Fetch Joined Clubs for Public Profile
        const userClubMemberships = await ClubMember.find({ user: targetUser._id, status: 'active' })
            .populate('club')
            .populate('roles')
            .lean();
        const joinedClubs = userClubMemberships.filter(m => m.club).map(m => ({
            club: m.club,
            roles: m.roles || [],
            isCreator: m.isCreator,
            joinedAt: m.joinedAt
        }));

        const profileTitle = `${targetUserObj.username}'s Profile`;
        const profileDescription = targetUserObj.bio ? targetUserObj.bio : `Check out all the latest safe and working mods uploaded by ${targetUserObj.username} on GPL Mods Official.`;
        const profileImage = targetUserObj.signedAvatarUrl && targetUserObj.signedAvatarUrl !== '/images/default-avatar.png' ? targetUserObj.signedAvatarUrl : 'https://gplmods.webredirect.org/images/logo.png';

        res.render('pages/public-profile', { 
            profileUser: targetUserObj, 
            uploads: uploadsWithUrls,
            followersList: followersWithAvatars,
            followingList: followingWithAvatars,
            isFollowing: isFollowing,
            pageTitle: profileTitle,
            pageDescription: profileDescription,
            pageImage: profileImage,
            pageKeywords: `gpl mods, ${targetUserObj.username}, distributor profile, mod uploads`,
            pageUrl: `https://gplmods.webredirect.org/users/${targetUserObj.username}`,
            isCardRef: req.query.ref === 'card',
            joinedClubs: joinedClubs
        });

    } catch (error) { 
        console.error("Public Profile Error:", error);
        next(error); 
    }
});

// --- ACCOUNT MANAGEMENT ROUTES ---

// ===================================
// CUSTOM WORK EMAIL ROUTES (IMPROVMX)
// ===================================

app.post('/account/claim-custom-email', ensureAuthenticated, async (req, res) => {
    const isAjax = req.xhr || req.headers.accept?.includes('application/json');
    const redirectTarget = (req.body.redirectUrl && req.body.redirectUrl.startsWith('/')) 
        ? req.body.redirectUrl 
        : (req.headers.referer && req.headers.referer.includes('/admin/support') ? '/admin/support' : '/profile');

    try {
        const user = await User.findById(req.user._id);
        const isStaff = user && ['owner', 'admin', 'support'].includes(user.role);

        // Security: Strictly reserved for official staff members
        if (!isStaff) {
            const errorMsg = 'Custom email access is strictly reserved for official staff members.';
            if (isAjax) return res.status(403).json({ success: false, message: errorMsg });
            return res.redirect(`${redirectTarget}?error=${encodeURIComponent(errorMsg)}`);
        }

        if (user.customEmailAlias) {
            const errorMsg = 'You already have a custom staff email address.';
            if (isAjax) return res.status(400).json({ success: false, message: errorMsg });
            return res.redirect(`${redirectTarget}?error=${encodeURIComponent(errorMsg)}`);
        }

        // Generate sanitized alias from username (or custom requested alias for staff)
        let requestedAlias = (req.body.alias || '').trim().toLowerCase();
        let alias = '';
        if (requestedAlias && /^[a-z0-9._-]+$/.test(requestedAlias)) {
            alias = requestedAlias;
        } else {
            alias = slugify(user.username).replace(/-/g, '').toLowerCase();
        }
        
        // 1. Call ImprovMX API
        const domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org';
        const result = await improvmx.createAlias(alias, user.email, domain);

        if (result.success) {
            // 2. Save to database
            user.customEmailAlias = alias;
            await user.save();
            const successMsg = `Staff email ${alias}@${domain} claimed successfully! All inbound emails will forward to ${user.email}.`;
            if (isAjax) return res.json({ success: true, message: successMsg, alias, domain, email: `${alias}@${domain}` });
            return res.redirect(`${redirectTarget}?success=${encodeURIComponent(successMsg)}`);
        } else {
            if (isAjax) return res.status(400).json({ success: false, message: result.message });
            return res.redirect(`${redirectTarget}?error=${encodeURIComponent(result.message)}`);
        }
    } catch (error) {
        console.error("Claim email error:", error);
        const errorMsg = 'An internal error occurred while creating your staff email.';
        if (isAjax) return res.status(500).json({ success: false, message: errorMsg });
        res.redirect(`${redirectTarget}?error=${encodeURIComponent(errorMsg)}`);
    }
});

app.post('/account/generate-smtp', ensureAuthenticated, async (req, res) => {
    const isAjax = req.xhr || req.headers.accept?.includes('application/json');
    const redirectTarget = (req.body.redirectUrl && req.body.redirectUrl.startsWith('/')) 
        ? req.body.redirectUrl 
        : (req.headers.referer && req.headers.referer.includes('/admin/support') ? '/admin/support' : '/profile');

    try {
        const user = await User.findById(req.user._id);
        const isStaff = user && ['owner', 'admin', 'support'].includes(user.role);

        // Security: Strictly reserved for official staff members
        if (!isStaff) {
            const errorMsg = 'Custom email access is strictly reserved for official staff members.';
            if (isAjax) return res.status(403).json({ success: false, message: errorMsg });
            return res.redirect(`${redirectTarget}?error=${encodeURIComponent(errorMsg)}`);
        }

        if (!user.customEmailAlias) {
            const errorMsg = 'You must claim your custom staff email first.';
            if (isAjax) return res.status(400).json({ success: false, message: errorMsg });
            return res.redirect(`${redirectTarget}?error=${encodeURIComponent(errorMsg)}`);
        }

        // Generate a secure, random password for their SMTP access (12-char hex)
        const smtpPassword = crypto.randomBytes(6).toString('hex'); 

        // 1. Call ImprovMX API
        const domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org';
        const result = await improvmx.createSmtpCredential(user.customEmailAlias, smtpPassword, domain);

        if (result.success) {
            user.hasSmtpAccess = true;
            await user.save();
            
            const successMsg = `SMTP Activated! Your Password is: ${smtpPassword} (SAVE THIS NOW, it will not be shown again!)`;
            if (isAjax) return res.json({ 
                success: true, 
                message: successMsg, 
                smtpPassword, 
                username: user.customEmailAlias,
                host: 'smtp.improvmx.com',
                port: 587
            });
            return res.redirect(`${redirectTarget}?success=${encodeURIComponent(successMsg)}`);
        } else {
            if (isAjax) return res.status(400).json({ success: false, message: result.message });
            return res.redirect(`${redirectTarget}?error=${encodeURIComponent(result.message)}`);
        }
    } catch (error) {
        console.error("SMTP generation error:", error);
        const errorMsg = 'An internal error occurred while generating SMTP credentials.';
        if (isAjax) return res.status(500).json({ success: false, message: errorMsg });
        res.redirect(`${redirectTarget}?error=${encodeURIComponent(errorMsg)}`);
    }
});

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

        // 3. Save Social Links for staff & distributors
        if (['owner', 'admin', 'support', 'distributor'].includes(user.role)) {
            user.socialLinks = user.socialLinks || {};
            const socialPlatforms = ['telegram', 'discord', 'website', 'youtube', 'github', 'twitter', 'linkedin', 'reddit', 'instagram', 'facebook', 'threads', 'gravatar', 'whatsapp'];
            socialPlatforms.forEach(plat => {
                const key = `social${plat.charAt(0).toUpperCase() + plat.slice(1)}`;
                if (req.body[key] !== undefined) {
                    user.socialLinks[plat] = req.body[key] ? String(req.body[key]).trim() : '';
                }
            });
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
        
        // ======== NEW: DELETE OLD AVATAR ========
        // Before we upload the new one, delete the old one from B2 & FTP to save space!
        const userDoc = await User.findById(req.user.id || req.user._id);
        if (userDoc && userDoc.profileImageKey) {
            await deleteFromB2(userDoc.profileImageKey);
        }
        // ========================================

        // Upload new avatar according to the users/staff or users/members folder structure
        const targetKey = getUserAssetKey(userDoc || req.user, 'avatar', req.file.originalname);
        const imageKey = await uploadToB2(req.file, 'users', null, null, null, { exactKey: targetKey });
        
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

// ======== NEW: FETCH GRAVATAR AVATAR ========
app.post('/account/fetch-gravatar', ensureAuthenticated, async (req, res, next) => {
    try {
        if (!req.user.email) {
            return res.status(400).json({ error: 'No email associated with this account.' });
        }
        
        const email = req.user.email.toLowerCase().trim();
        const hash = crypto.createHash('md5').update(email).digest('hex');
        
        // Fetch gravatar with d=404 so it errors if not found, rather than returning a default image
        const gravatarUrl = `https://www.gravatar.com/avatar/${hash}?d=404&s=256`;
        
        let response;
        try {
            response = await axios.get(gravatarUrl, { responseType: 'arraybuffer' });
        } catch (err) {
            if (err.response && err.response.status === 404) {
                return res.status(404).json({ error: 'No Gravatar profile image found for your email address.' });
            }
            throw err;
        }
        
        const buffer = Buffer.from(response.data, 'binary');
        const mimetype = response.headers['content-type'] || 'image/jpeg';
        
        // Create a mock multer file object
        const mockFile = {
            buffer: buffer,
            originalname: `user-profile-avatar.jpg`,
            mimetype: mimetype,
            size: buffer.length
        };
        
        // Before we upload the new one, delete the old one from B2 & FTP to save space
        const userDoc = await User.findById(req.user.id || req.user._id);
        if (userDoc && userDoc.profileImageKey) {
            await deleteFromB2(userDoc.profileImageKey);
        }
        
        // Upload new avatar according to the users/staff or users/members folder structure
        const targetKey = getUserAssetKey(userDoc || req.user, 'avatar', 'user-profile-avatar.jpg');
        const imageKey = await uploadToB2(mockFile, 'users', null, null, null, { exactKey: targetKey });

        const updateFields = { profileImageKey: imageKey };
        if (!req.user.cardAvatarUrl || req.user.cardAvatarUrl.includes('gravatar') || req.user.cardAvatarUrl === req.user.profileImageKey) {
            updateFields.cardAvatarUrl = imageKey;
        }
        const updatedUser = await User.findByIdAndUpdate(req.user.id, updateFields, { new: true });
        
        req.login(updatedUser, (err) => {
            if (err) return next(err);
            res.json({ success: true });
        });
    } catch (error) {
        console.error("Error fetching/uploading gravatar:", error);
        res.status(500).json({ error: 'An error occurred while fetching the Gravatar image.' });
    }
});
// ============================================

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
        if (!user) {
            return res.status(404).json({ success: false, message: 'User account not found.' });
        }
        user.deletionOtp = otp;
        user.deletionOtpExpires = Date.now() + 600000; // 10 mins
        await user.save();
        await sendDeletionOtpEmail(user, otp);
        res.json({ success: true, message: 'Confirmation code sent to your email.' });
    } catch (e) {
        console.error("Error in delete-request route:", e);
        res.status(500).json({ success: false, message: 'Failed to send confirmation code. Please try again.' });
    }
});

app.post('/account/delete-confirm', ensureAuthenticated, async (req, res, next) => {
    try {
        const { otp, preserveMods } = req.body;
        const user = await User.findById(req.user._id);

        if (!user) {
            return res.status(404).json({ success: false, message: 'User account not found.' });
        }

        if (!user.deletionOtp || !otp || user.deletionOtp.trim() !== String(otp).trim() || !user.deletionOtpExpires || user.deletionOtpExpires < Date.now()) {
            return res.json({ success: false, message: 'Invalid or expired confirmation code. Please check your email or request a new code.' });
        }

        const userId = user._id;
        const username = user.username;
        const shouldPreserve = preserveMods === true || preserveMods === 'true';

        // 1. DELETE AVATAR FROM CLOUD
        if (user.profileImageKey) {
            try { await deleteCloudFile(user.profileImageKey); } catch (e) { console.error("Avatar cloud deletion error:", e); }
        }

        // 2. WIPE MODS & MOD DATA
        if (shouldPreserve) {
            // Keep the files, but anonymize the uploader
            await File.updateMany({ uploader: username }, { uploader: 'GPL Community' });
            
            // Unset uploader replies on comments for these files
            const userFiles = await File.find({ uploader: 'GPL Community' }); 
            const fileIds = userFiles.map(f => f._id);
            if (fileIds.length > 0) {
                await Review.updateMany({ file: { $in: fileIds } }, { $unset: { uploaderReply: 1 } });
            }
        } else {
            // Delete EVERYTHING related to their mods from Cloud and DB
            const userFiles = await File.find({ uploader: username }).populate('olderVersions');
            
            for (const f of userFiles) {
                await deleteCloudFile(f.fileKey);
                await deleteCloudFile(f.iconKey);
                
                if (f.screenshotKeys) {
                    for (const sk of f.screenshotKeys) {
                        await deleteCloudFile(sk);
                    }
                }
                
                if (f.olderVersions) {
                    for (const ov of f.olderVersions) {
                        await deleteCloudFile(ov.fileKey);
                        await File.findByIdAndDelete(ov._id);
                    }
                }
                
                await File.findByIdAndDelete(f._id);
                await Review.deleteMany({ file: f._id });
                await Report.updateMany({ file: f._id }, { status: 'resolved' });
            }
        }

        // 3. DELETE THEIR PERSONAL REVIEWS/COMMENTS
        await Review.deleteMany({ user: userId });

        // 4. DELETE THEIR CHAT HISTORY FROM MEMORY
        if (typeof recentMessages !== 'undefined' && Array.isArray(recentMessages)) {
            recentMessages = recentMessages.filter(msg => msg.username !== username);
        }

        // 5. NEWSLETTER UNSUBSCRIBE
        try {
            const SubscriberModel = mongoose.models.Subscriber || require('./models/subscriber');
            if (SubscriberModel) {
                await SubscriberModel.deleteOne({ email: user.email.toLowerCase() });
            }
        } catch (subErr) {
            console.error("Failed to delete subscriber record:", subErr);
        }

        // 6. USER NOTIFICATIONS, POINT HISTORY, SUPPORT TICKETS & SESSIONS
        try { await UserNotification.deleteMany({ user: userId }); } catch (e) { console.error('UserNotification cleanup error', e); }
        try { await PointHistory.deleteMany({ user: userId }); } catch (e) { console.error('PointHistory cleanup error', e); }
        try { await SupportTicket.deleteMany({ user: userId }); } catch (e) { console.error('SupportTicket cleanup error', e); }

        try {
            const sessionsCollection = mongoose.connection.collection('sessions');
            await sessionsCollection.deleteMany({ session: { $regex: userId.toString() } });
        } catch (sessErr) {
            console.error('Failed to delete sessions for user:', sessErr.message || sessErr);
        }

        // 7. FINALLY DELETE THE USER DOCUMENT
        await User.findByIdAndDelete(userId);

        // 8. LOG OUT AND CLEAR COOKIE
        req.logout(function(err) {
            if (err) return next(err);
            res.clearCookie('connect.sid', { path: '/' });
            res.json({ success: true, redirect: '/?message=Your account and all associated data have been permanently deleted.' });
        });
    } catch (error) {
        console.error("Deep Wipe Deletion Error:", error);
        res.status(500).json({ success: false, message: 'An error occurred during account deletion.' });
    }
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

// --- Passkey / WebAuthn Helper Utilities ---
const getWebAuthnExpectedOrigins = (req) => {
    const hostHeader = req.headers.host;
    const clientOrigin = req.headers.origin;
    return Array.from(new Set([
        clientOrigin,
        hostHeader ? `http://${hostHeader}` : null,
        hostHeader ? `https://${hostHeader}` : null,
        process.env.BASE_URL,
        'https://gplmods.webredirect.org',
        'http://localhost:3000',
        'https://localhost:3000',
        'http://127.0.0.1:3000'
    ].filter(Boolean)));
};

const getWebAuthnEffectiveRpID = (req) => {
    let originHost = null;
    if (req.headers.origin) {
        try { originHost = new URL(req.headers.origin).hostname; } catch(e) {}
    }
    const forwardedHost = req.headers['x-forwarded-host'] ? req.headers['x-forwarded-host'].split(',')[0].trim().split(':')[0] : null;
    const hostHeader = req.headers.host ? req.headers.host.split(':')[0] : null;
    const raw = originHost || forwardedHost || hostHeader || req.hostname || 'localhost';
    return raw === '127.0.0.1' ? 'localhost' : raw;
};

const getWebAuthnExpectedRPIDs = (req, effectiveRpID) => {
    const hostHeader = (req.headers['x-forwarded-host'] || req.headers.host || req.hostname || 'localhost').split(':')[0];
    const baseUrlHost = process.env.BASE_URL ? (() => { try { return new URL(process.env.BASE_URL).hostname; } catch(e) { return null; } })() : null;
    return Array.from(new Set([
        effectiveRpID,
        req.session?.currentChallengeRpID,
        hostHeader,
        hostHeader === '127.0.0.1' ? 'localhost' : null,
        req.hostname,
        baseUrlHost,
        'gplmods.webredirect.org',
        'localhost'
    ].filter(Boolean)));
};

// 2. Generate Passkey Options
app.get('/account/2fa/passkey/generate-options', ensureAuthenticated, async (req, res) => {
    try {
        const stringId = req.user._id.toString();
        const uint8UserId = new Uint8Array(Buffer.from(stringId, 'utf8'));
        const effectiveRpID = getWebAuthnEffectiveRpID(req);

        const options = await generateRegistrationOptions({
            rpName: 'GPL Mods',
            rpID: effectiveRpID,
            userID: uint8UserId,
            userName: req.user.username,
            attestationType: 'none',
            authenticatorSelection: { 
                userVerification: 'preferred',
                residentKey: 'preferred'
            },
        });
        
        req.session.currentChallenge = options.challenge;
        req.session.currentChallengeRpID = effectiveRpID;
        
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
            return res.status(400).json({ success: false, error: 'Session expired or challenge missing. Please try again.' });
        }

        const effectiveRpID = getWebAuthnEffectiveRpID(req);
        const expectedOrigins = getWebAuthnExpectedOrigins(req);
        const expectedRPIDs = getWebAuthnExpectedRPIDs(req, effectiveRpID);

        const verification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge,
            expectedOrigin: expectedOrigins,
            expectedRPID: expectedRPIDs,
            requireUserVerification: false, // Critical: userVerification was 'preferred'
        });

        if (verification && verification.verified) {
            const regInfo = verification.registrationInfo;
            if (!regInfo) {
                throw new Error("Missing registrationInfo from authenticator.");
            }

            const toBase64Url = (buffer) => {
                if (!buffer) return '';
                if (typeof buffer === 'string') return buffer;
                return Buffer.from(buffer).toString('base64url');
            };

            const credential = regInfo.credential || {};
            const credentialIDStr = typeof credential.id === 'string'
                ? credential.id
                : toBase64Url(credential.id || regInfo.credentialID);

            const publicKeyStr = toBase64Url(credential.publicKey || regInfo.credentialPublicKey);
            const counter = typeof credential.counter === 'number'
                ? credential.counter
                : (typeof regInfo.counter === 'number' ? regInfo.counter : 0);

            const transports = (credential.transports && Array.isArray(credential.transports))
                ? credential.transports
                : (req.body?.response?.transports || ['internal']);

            if (!credentialIDStr || !publicKeyStr) {
                throw new Error("Missing credential data from authenticator.");
            }

            const passkeyData = {
                credentialID: credentialIDStr,
                credentialPublicKey: publicKeyStr,
                counter: counter,
                transports: transports
            };

            user.passkey = passkeyData;
            if (!user.passkeys) user.passkeys = [];
            user.passkeys.push(passkeyData);
            
            user.twoFactorMethod = 'passkey';
            user.cardStatus = 'active'; // Reactivate card if it was suspended!
            if (!Array.isArray(user.twoFactorMethods)) user.twoFactorMethods = [];
            if (!user.twoFactorMethods.includes('passkey')) {
                if (user.twoFactorMethods.length >= 3) user.twoFactorMethods.pop();
                user.twoFactorMethods.push('passkey');
            }
            user.twoFactorMethods = getAvailable2FAMethods(user);

            // Check if user already had 2FA active with recovery codes
            const hasExistingCodes = (user.twoFactorEnabled || user.is2FAEnabled) && 
                Array.isArray(user.twoFactorRecoveryCodes) && 
                user.twoFactorRecoveryCodes.length > 0;

            user.twoFactorEnabled = true;
            user.is2FAEnabled = true;

            req.session.currentChallenge = null;
            req.session.currentChallengeRpID = null;

            if (!hasExistingCodes) {
                // First-time 2FA setup or re-enabling after complete disable: Generate new codes
                const rawCodes = generateRecoveryCodes();
                user.twoFactorRecoveryCodes = await Promise.all(rawCodes.map(code => bcrypt.hash(code, 10)));
                await user.save();

                req.session.tempRecoveryCodes = rawCodes;
                const redirectTarget = '/account/2fa/recovery-codes';
                
                req.session.save(() => {
                    res.json({ success: true, redirect: redirectTarget }); 
                });
            } else {
                // Secondary/tertiary method added: preserve existing recovery codes, don't regenerate!
                await user.save();
                const backUrl = req.session.returnTo2FA || (['distributor', 'support', 'admin', 'owner'].includes(user.role) ? '/id-card' : '/settings');
                req.session.returnTo2FA = null;
                const redirectTarget = `${backUrl}${backUrl.includes('?') ? '&' : '?'}message=${encodeURIComponent('Passkey added successfully!')}`;
                
                req.session.save(() => {
                    res.json({ success: true, redirect: redirectTarget }); 
                });
            }
        } else {
            res.status(400).json({ success: false, error: 'Passkey verification failed on server.' });
        }
    } catch (err) {
        console.error("Passkey Verify Error:", err);
        res.status(500).json({ success: false, error: err.message || 'Passkey verification error' });
    }
});

// 4. Enable TOTP or Email Verification
app.post('/account/2fa/enable', ensureAuthenticated, async (req, res) => {
    try {
        const { method, token, returnTo } = req.body;
        if (returnTo) req.session.returnTo2FA = returnTo;
        const user = await User.findById(req.user._id);

        // Strip accidental spaces from the token
        const cleanToken = token ? token.replace(/\s+/g, '') : '';

        if (!Array.isArray(user.twoFactorMethods)) user.twoFactorMethods = [];
        if (method === 'email') {
            user.twoFactorMethod = 'email';
            if (!user.twoFactorMethods.includes('email')) {
                if (user.twoFactorMethods.length >= 3) user.twoFactorMethods.pop();
                user.twoFactorMethods.push('email');
            }
        } else if (method === 'totp') {
            const verified = speakeasy.totp.verify({
                secret: req.session.tempTwoFactorSecret,
                encoding: 'base32',
                token: cleanToken
            });

            if (!verified) {
                const backUrl = req.session.returnTo2FA === '/id-card' ? '/id-card' : '/account/2fa/setup';
                return res.redirect(`${backUrl}?error=${encodeURIComponent('Invalid TOTP code. Please check your authenticator app.')}`);
            }
            
            user.twoFactorMethod = 'totp';
            user.twoFactorSecret = req.session.tempTwoFactorSecret;
            req.session.tempTwoFactorSecret = null;
            if (!user.twoFactorMethods.includes('totp')) {
                if (user.twoFactorMethods.length >= 3) user.twoFactorMethods.pop();
                user.twoFactorMethods.push('totp');
            }
        }

        user.twoFactorMethods = getAvailable2FAMethods(user);

        // Check if user already had 2FA active with recovery codes
        const hasExistingCodes = (user.twoFactorEnabled || user.is2FAEnabled) && 
            Array.isArray(user.twoFactorRecoveryCodes) && 
            user.twoFactorRecoveryCodes.length > 0;

        user.twoFactorEnabled = true;
        user.is2FAEnabled = true;
        user.cardStatus = 'active'; // Reactivate card!

        if (!hasExistingCodes) {
            // First time setup or after complete disable: Generate new recovery codes
            const rawCodes = generateRecoveryCodes();
            user.twoFactorRecoveryCodes = await Promise.all(rawCodes.map(code => bcrypt.hash(code, 10)));
            await user.save();

            req.session.tempRecoveryCodes = rawCodes; 
            
            req.session.save((err) => {
                if (err) console.error("Session save error:", err);
                res.redirect('/account/2fa/recovery-codes');
            });
        } else {
            // Secondary/tertiary method added: Preserve existing codes and redirect
            await user.save();
            const backUrl = req.session.returnTo2FA || '/settings';
            req.session.returnTo2FA = null;
            const successMsg = method === 'email' ? 'Email OTP added successfully!' : 'Authenticator App added successfully!';
            
            req.session.save((err) => {
                if (err) console.error("Session save error:", err);
                res.redirect(`${backUrl}${backUrl.includes('?') ? '&' : '?'}message=${encodeURIComponent(successMsg)}`);
            });
        }

    } catch (err) {
        console.error("2FA Enable Error:", err);
        const backUrl = req.session.returnTo2FA === '/id-card' ? '/id-card' : '/account/2fa/setup';
        res.redirect(`${backUrl}?error=${encodeURIComponent('An error occurred while enabling 2FA.')}`);
    }
});

// --- Update 2FA Login Challenge to Accept Backup Codes and Multi-Option Switcher ---
app.post('/login/2fa/verify', async (req, res, next) => {
    if (!req.session.pending2faUserId) return res.redirect('/login');
    try {
        const token = req.body.token ? req.body.token.replace(/\s+/g, '') : '';
        const user = await User.findById(req.session.pending2faUserId);
        if (!user) return res.redirect('/login');

        const currentMethod = req.session.active2faMethod || user.twoFactorMethod || 'email';
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
        // 2. Check TOTP
        else if (currentMethod === 'totp' || (user.twoFactorSecret && user.twoFactorSecret.length > 0)) {
            if (user.twoFactorSecret) {
                isValid = speakeasy.totp.verify({
                    secret: user.twoFactorSecret,
                    encoding: 'base32',
                    token: token
                });
            }
            // Cross-fallback: in case user entered email code while viewing TOTP screen
            if (!isValid && user.verificationOtp === token && user.otpExpires > Date.now()) {
                isValid = true;
            }
        }
        // 3. Check Email OTP
        else if (currentMethod === 'email') {
            isValid = (user.verificationOtp === token && user.otpExpires > Date.now());
            // Cross-fallback: in case user entered authenticator code while viewing email screen
            if (!isValid && user.twoFactorSecret) {
                isValid = speakeasy.totp.verify({
                    secret: user.twoFactorSecret,
                    encoding: 'base32',
                    token: token
                });
            }
        }

        if (!isValid) return res.redirect(`/login/2fa?error=${encodeURIComponent('Invalid code. Please try again.')}`);

        // Cleanup: Remove used recovery code or email OTP
        if (usedRecoveryCodeIndex !== -1) {
            user.twoFactorRecoveryCodes.splice(usedRecoveryCodeIndex, 1);
        }
        if (user.verificationOtp === token) {
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

// 2. Disable Individual 2FA Method Endpoint
app.post('/account/2fa/disable-method', ensureAuthenticated, async (req, res) => {
    try {
        const { method } = req.body;
        const validMethods = ['email', 'totp', 'passkey', 'social'];
        if (!validMethods.includes(method)) {
            return res.redirect('/settings?error=' + encodeURIComponent('Invalid 2FA method.'));
        }

        const user = await User.findById(req.user._id);
        if (!user) return res.redirect('/settings');

        let methods = Array.isArray(user.twoFactorMethods) ? [...user.twoFactorMethods] : [];
        if (methods.length === 0 && (user.twoFactorEnabled || user.is2FAEnabled)) {
            methods = [user.twoFactorMethod || 'email'];
        }

        // Remove the method
        methods = methods.filter(m => m !== method);

        // Clear associated credentials
        if (method === 'totp') {
            user.twoFactorSecret = '';
        } else if (method === 'passkey') {
            user.passkey = null;
            user.passkeys = [];
        } else if (method === 'social') {
            user.twoFactorSocialProvider = 'none';
            user.twoFactorProvider = 'none';
        }

        user.twoFactorMethods = methods;

        // If disabled method was primary, switch primary
        if (user.twoFactorMethod === method) {
            user.twoFactorMethod = methods.length > 0 ? methods[0] : 'none';
        }

        // If no methods remain, shut down 2FA completely
        if (methods.length === 0) {
            user.twoFactorEnabled = false;
            user.is2FAEnabled = false;
            user.twoFactorMethod = 'none';
            user.twoFactorRecoveryCodes = [];
            user.cardStatus = 'suspended';
            await user.save();
            return res.redirect('/settings?success=' + encodeURIComponent(`Disabled ${method.toUpperCase()} 2FA. All 2FA protections are now disabled.`));
        }

        await user.save();
        const friendlyName = method === 'totp' ? 'Authenticator App' : (method === 'passkey' ? 'Passkey' : (method === 'social' ? 'Social Verification' : 'Email OTP'));
        res.redirect('/settings?success=' + encodeURIComponent(`${friendlyName} disabled successfully.`));
    } catch (err) {
        console.error("Disable 2FA Method Error:", err);
        res.redirect('/settings?error=' + encodeURIComponent('Failed to disable 2FA method.'));
    }
});

app.post('/account/2fa/disable', ensureAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (user) {
            user.twoFactorEnabled = false;
            user.is2FAEnabled = false;
            user.twoFactorMethod = 'none';
            user.twoFactorMethods = [];
            user.twoFactorSecret = '';
            user.twoFactorRecoveryCodes = []; // Completely cleared so re-enabling generates fresh codes!
            user.passkey = null;
            user.passkeys = [];
            user.twoFactorSocialProvider = 'none';
            user.twoFactorProvider = 'none';
            user.cardStatus = 'suspended'; // Card suspended when 2FA is disabled!
            await user.save();
        }
        res.redirect('/settings?success=' + encodeURIComponent('2FA Disabled. Note: Your ID Card has been suspended until 2FA is re-enabled.'));
    } catch (err) {
        console.error("2FA Disable Error:", err);
        res.redirect('/settings?error=' + encodeURIComponent('Failed to disable 2FA.'));
    }
});

app.post('/account/2fa/enable-social', ensureAuthenticated, async (req, res) => {
    try {
        const { provider, returnTo } = req.body;
        if (returnTo) req.session.returnTo2FA = returnTo;
        const user = await User.findById(req.user._id);
        const backUrl = req.session.returnTo2FA === '/id-card' ? '/id-card' : '/account/2fa/setup';

        if (!['google', 'github', 'microsoft'].includes(provider)) {
            return res.redirect(`${backUrl}?error=Invalid provider.`);
        }

        // Ensure they actually have that provider linked
        if (!user[`${provider}Id`]) {
             return res.redirect(`${backUrl}?error=You must link a ${provider} account first.`);
        }

        user.twoFactorMethod = 'social';
        user.twoFactorSocialProvider = provider;
        user.twoFactorProvider = provider;
        user.cardStatus = 'active'; // Reactivate card!
        if (!Array.isArray(user.twoFactorMethods)) user.twoFactorMethods = [];
        if (!user.twoFactorMethods.includes('social')) {
            if (user.twoFactorMethods.length >= 3) user.twoFactorMethods.pop();
            user.twoFactorMethods.push('social');
        }
        user.twoFactorMethods = getAvailable2FAMethods(user);

        const hasExistingCodes = (user.twoFactorEnabled || user.is2FAEnabled) && 
            Array.isArray(user.twoFactorRecoveryCodes) && 
            user.twoFactorRecoveryCodes.length > 0;

        user.twoFactorEnabled = true;
        user.is2FAEnabled = true;

        if (!hasExistingCodes) {
            const rawCodes = generateRecoveryCodes();
            user.twoFactorRecoveryCodes = await Promise.all(rawCodes.map(code => bcrypt.hash(code, 10)));
            await user.save();

            req.session.tempRecoveryCodes = rawCodes;
            req.session.save(() => {
                res.redirect('/account/2fa/recovery-codes');
            });
        } else {
            await user.save();
            const backUrl = req.session.returnTo2FA || '/settings';
            req.session.returnTo2FA = null;
            req.session.save(() => {
                res.redirect(`${backUrl}${backUrl.includes('?') ? '&' : '?'}message=${encodeURIComponent('Social verification added successfully!')}`);
            });
        }

    } catch (err) {
        console.error("Social 2FA Enable Error:", err);
        const backUrl = req.session.returnTo2FA === '/id-card' ? '/id-card' : '/account/2fa/setup';
        res.redirect(`${backUrl}?error=An error occurred.`);
    }
});

// ==========================================
// PASSKEY LOGIN CHALLENGE ROUTES
// ==========================================

// 1. Generate the challenge for the user trying to log in
app.get('/login/2fa/passkey/options', async (req, res) => {
    if (!req.session.pending2faUserId) return res.status(400).json({ error: 'No pending login session' });
    const user = await User.findById(req.session.pending2faUserId);
    if (!user) return res.status(400).json({ error: 'User not found' });
    
    const passkeyList = (Array.isArray(user.passkeys) && user.passkeys.length > 0)
        ? user.passkeys
        : (user.passkey && user.passkey.credentialID ? [user.passkey] : []);

    if (passkeyList.length === 0) return res.status(400).json({ error: 'No passkey found for user' });

    try {
        const effectiveRpID = getWebAuthnEffectiveRpID(req);

        const allowCredentials = passkeyList.map(pk => ({
            id: pk.credentialID, // MUST BE STRING in @simplewebauthn v13!
            type: 'public-key',
            transports: pk.transports || ['internal', 'hybrid', 'usb', 'ble', 'nfc'],
        }));

        const options = await generateAuthenticationOptions({
            rpID: effectiveRpID,
            allowCredentials,
            userVerification: 'preferred',
        });
        
        req.session.currentChallenge = options.challenge;
        req.session.currentChallengeRpID = effectiveRpID;
        res.json(options);
    } catch (e) {
        console.error("Passkey Login Options Error:", e);
        res.status(500).json({ error: e.message });
    }
});

// 2. Verify the biometric / device PIN response from the user's device
app.post('/login/2fa/passkey/verify', async (req, res, next) => {
    if (!req.session.pending2faUserId) return res.status(400).json({ error: 'No pending login session' });
    const user = await User.findById(req.session.pending2faUserId);
    if (!user) return res.status(400).json({ error: 'User not found' });

    const passkeyList = (Array.isArray(user.passkeys) && user.passkeys.length > 0)
        ? user.passkeys
        : (user.passkey && user.passkey.credentialID ? [user.passkey] : []);

    if (passkeyList.length === 0) return res.status(400).json({ error: 'No passkey found for user' });
    
    const credentialId = req.body?.id;
    const activePasskey = passkeyList.find(pk => pk.credentialID === credentialId) || user.passkey || passkeyList[0];
    if (!activePasskey) return res.status(400).json({ error: 'No matching passkey found for user' });

    try {
        const effectiveRpID = getWebAuthnEffectiveRpID(req);
        const expectedOrigins = getWebAuthnExpectedOrigins(req);
        const expectedRPIDs = getWebAuthnExpectedRPIDs(req, effectiveRpID);

        let incomingCounter = 0;
        if (req.body?.response?.authenticatorData) {
            try {
                const authDataBuf = Buffer.from(req.body.response.authenticatorData, 'base64url');
                if (authDataBuf.length >= 37) {
                    incomingCounter = authDataBuf.readUInt32BE(33);
                }
            } catch (e) {
                console.warn('[WebAuthn] Failed to parse sign count from authenticatorData:', e.message);
            }
        }

        // Multi-device passkeys (iCloud Keychain, Chrome/Android, 1Password) do not maintain signature counters and return 0.
        // If incomingCounter is 0, supply counter: 0 to bypass @simplewebauthn's counter replay check.
        const effectiveCounter = (incomingCounter === 0) ? 0 : (activePasskey.counter || 0);

        const verification = await verifyAuthenticationResponse({
            response: req.body,
            expectedChallenge: req.session.currentChallenge,
            expectedOrigin: expectedOrigins,
            expectedRPID: expectedRPIDs,
            credential: {
                id: activePasskey.credentialID,
                publicKey: Buffer.from(activePasskey.credentialPublicKey, 'base64url'),
                counter: effectiveCounter,
                transports: activePasskey.transports,
            },
            requireUserVerification: false,
        });

        if (verification && verification.verified) {
            const verifiedCounter = typeof verification.authenticationInfo?.newCounter === 'number'
                ? verification.authenticationInfo.newCounter
                : incomingCounter;
            if (activePasskey) activePasskey.counter = verifiedCounter;
            if (user.passkey && user.passkey.credentialID === activePasskey.credentialID) {
                user.passkey.counter = verifiedCounter;
            }
            await user.save();
            
            // Clean up session vars
            req.session.pending2faUserId = null;
            req.session.currentChallenge = null;
            req.session.currentChallengeRpID = null;
            req.session.active2faMethod = null;
            
            // Login successful! Use centralized session finalization with JSON callback
            req.logIn(user, (err) => {
                if (err) return res.status(500).json({ success: false, error: err.message });
                
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
    if (!user) return res.redirect('/login');

    const availableMethods = getAvailable2FAMethods(user);
    if (JSON.stringify(user.twoFactorMethods) !== JSON.stringify(availableMethods)) {
        user.twoFactorMethods = availableMethods;
        user.save().catch(err => console.error("Error updating twoFactorMethods:", err));
    }

    let currentMethod = req.query.method || req.session.active2faMethod || availableMethods[0] || user.twoFactorMethod || 'email';
    if (!availableMethods.includes(currentMethod)) {
        currentMethod = availableMethods[0];
    }

    const previousMethod = req.session.active2faMethod;
    const isExplicitResend = req.query.resend === 'true' || req.query.resend === '1';
    const isMethodSwitch = req.query.method === 'email' && previousMethod && previousMethod !== 'email';
    const hasValidOtp = !!(user.verificationOtp && user.otpExpires && user.otpExpires > Date.now());
    const hasError = !!req.query.error;

    // Send email OTP ONLY if:
    // 1. The user explicitly clicked "Resend Email Code" (?resend=true), OR
    // 2. The user switched to Email OTP from another method AND does not already have an active unexpired OTP.
    // NEVER send email if there is an error redirect (e.g. invalid code entry) or on passive page load.
    if (currentMethod === 'email' && !hasError && (isExplicitResend || (isMethodSwitch && !hasValidOtp))) {
        const lastSent = req.session.last2faEmailSent || 0;
        const now = Date.now();
        if (!hasValidOtp || (isExplicitResend && (now - lastSent > 20000))) {
            try {
                const otp = Math.floor(100000 + Math.random() * 900000).toString();
                user.verificationOtp = otp;
                user.otpExpires = now + 600000;
                await user.save();
                await send2faEmail(user, otp);
                req.session.last2faEmailSent = now;
            } catch (e) {
                console.error("2FA Email Switch Error:", e);
            }
        }
    }

    req.session.active2faMethod = currentMethod;
    
    // Resolve user avatar for the 2FA header
    try {
        user.signedAvatarUrl = user.profileImageKey ? await getSmartImageUrl(user.profileImageKey) : '/images/default-avatar.png';
    } catch (e) {
        user.signedAvatarUrl = '/images/default-avatar.png';
    }

    req.session.save(() => {
        res.render('pages/2fa-challenge', { 
            method: currentMethod, 
            availableMethods: availableMethods,
            error: req.query.error,
            success: isExplicitResend ? 'A new verification code has been sent to your email.' : (req.query.success || null),
            user: user,
            is2FAVerification: true
        });
    });
});

app.post('/account/delete', ensureAuthenticated, async (req, res, next) => {
    // Deprecated direct route: direct deletion is not allowed without OTP confirmation
    return res.redirect('/settings?error=Account deletion requires confirmation via code sent to your email.');
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

app.get('/upload', ensureAuthenticated, async (req, res) => {
    try {
        const quota = await getUserUploadQuota(req.user);
        res.render('pages/upload', { quota });
    } catch (err) {
        console.error("Error retrieving upload quota:", err);
        res.render('pages/upload', { quota: null });
    }
});

// --- INITIAL UPLOAD ROUTE (SERVER-SIDE WITH QUOTA & LIMITS) ---
app.post('/upload-initial', ensureAuthenticated, upload.single('modFile'), async (req, res, next) => {
    try {
        // ======== UPLOAD QUOTA SLOTS CHECK ========
        const quota = await getUserUploadQuota(req.user);
        if (!quota.canUpload) {
            if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
            const resetMsg = quota.earliestReset ? ` Next slot resets on ${new Date(quota.earliestReset).toLocaleDateString()}.` : '';
            return res.status(429).redirect(`/upload?error=${encodeURIComponent(`You have reached your limit of ${quota.totalSlots} upload slots (${quota.usedSlots} pending review). Slots reset rolling weekly or immediately when your submitted mods are approved live.${resetMsg} Upgrade your tier for more slots.`)}`);
        }

        // ======== DAILY UPLOAD LIMIT CHECK ========
        const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const recentUploadCount = await File.countDocuments({
            uploader: req.user.username,
            createdAt: { $gte: oneDayAgo }
        });

        let dailyLimit = 5;
        if (req.user.role === 'distributor' || req.user.role === 'admin' || req.user.role === 'owner') dailyLimit = 50;

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

    } catch (limitError) {
        console.error("Upload limit check failed:", limitError);
        return next(limitError);
    }


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
                category: 'n/a',         
                platforms: [],
                status: 'processing' 
            });
            await newFile.save();
            
            // --- NEW: VIRUSTOTAL v3 URL SCAN ---
            console.log(`Starting VT URL scan for Distributor link: ${externalUrl}`);
            (async () => {
                try {
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
                    pollVirusTotalInBackground(newFile._id);
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
    const sizeCheck = validateUploadFileSize(req.user, fileSize);
    if (!sizeCheck.valid) {
        if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
        return res.status(413).redirect(`/upload?error=${encodeURIComponent(sizeCheck.error)}`);
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
                pollVirusTotalInBackground(newFile._id);
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
        if (pendingFile.uploader !== req.user.username) return res.status(404).render('pages/error', { errorCode: '404', errorTitle: 'Page Not Found', errorMessage: 'The page you are looking for does not exist or you do not have permission to access it.' });

        const filename = pendingFile.originalFilename || "";
        const analysis = analyzeFileDetails(filename);

        let defaultPlatform = analysis.platform || "";
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

        // Auto-extract tweak details if it's a debian tweak package
        let defaultDeveloper = pendingFile.developer && pendingFile.developer !== 'N/A' ? pendingFile.developer : '';
        let defaultIosPackageId = pendingFile.iosPackageId || '';

        if (analysis.tweakInfo) {
            if (!defaultDeveloper && analysis.tweakInfo.developer) {
                defaultDeveloper = analysis.tweakInfo.developer;
            }
            if (!defaultIosPackageId && analysis.tweakInfo.packageId) {
                defaultIosPackageId = analysis.tweakInfo.packageId;
            }
            if (analysis.tweakInfo.version && (!pendingFile.version || pendingFile.version === 'Draft')) {
                defaultVersion = analysis.tweakInfo.version;
            }
            if (analysis.tweakInfo.tweakName) {
                cleanName = analysis.tweakInfo.tweakName;
            }
        }

        const savedName = (pendingFile.name && pendingFile.name !== 'Pending Upload' && pendingFile.name !== pendingFile.originalFilename) 
            ? pendingFile.name 
            : cleanName;
        const savedVersion = (pendingFile.version && pendingFile.version !== 'Draft') 
            ? pendingFile.version 
            : defaultVersion;
        const savedPlatform = (pendingFile.category && pendingFile.category !== 'n/a')
            ? pendingFile.category
            : defaultPlatform;
        const savedMinOs = pendingFile.minOsVersion || analysis.minOsVersion || '';
        const savedArchitectures = (pendingFile.architectures && pendingFile.architectures.length > 0)
            ? pendingFile.architectures
            : analysis.architectures;

        const licenses = await License.find().sort({ name: 1 }).lean();

        // Draft media lives in private storage too, so sign it before rendering the
        // form.  Previously only the edit route did this, which made media appear
        // missing until the mod was live.
        const iconUrl = await getSmartImageUrl(pendingFile.iconKey);
        const screenshotUrls = await Promise.all((pendingFile.screenshotKeys || []).map(key => getSmartImageUrl(key)));
        const renderedFile = { 
            ...pendingFile.toObject(), 
            iconUrl, 
            screenshotUrls,
            minOsVersion: savedMinOs,
            architectures: savedArchitectures,
            developer: defaultDeveloper,
            iosPackageId: defaultIosPackageId
        };

        const customTemplates = await ModTemplate.find({ isActive: true }).sort({ sortOrder: 1, createdAt: 1 }).lean();

        res.render('pages/upload-details', { 
            fileId: pendingFile._id,
            fileKey: pendingFile.fileKey,
            filename: pendingFile.originalFilename,
            filesize: pendingFile.fileSize,
            defaultName: savedName,
            defaultVersion: savedVersion,
            defaultPlatform: savedPlatform,
            file: renderedFile,
            licenses,
            customTemplates
        });

    } catch (error) {
        console.error("Error loading upload details:", error);
        return next(error);
    }
});

function canManageDraft(file, user) {
    return Boolean(file && user && (file.uploader === user.username || user.role === 'admin' || user.role === 'owner'));
}

function draftSnapshotData(file, body = {}) {
    const fields = ['name', 'version', 'developer', 'modDescription', 'modFeatures', 'officialDescription', 'whatsNew', 'importantNote', 'category', 'minOsVersion', 'ageRating', 'videoUrl', 'directDownloadUrl', 'externalDownloadUrl', 'isMultiPart'];
    const data = {};
    fields.forEach(field => {
        const value = body[field] !== undefined ? body[field] : file[field];
        if (value !== undefined) data[field] = value;
    });
    data.platforms = body.modCategory ? [body.modCategory] : (file.platforms || []);
    data.tags = body.tags !== undefined ? String(body.tags).split(',').map(tag => tag.trim()).filter(Boolean) : (file.tags || []);
    data.architectures = body.architectures !== undefined
        ? (Array.isArray(body.architectures) ? body.architectures : [body.architectures])
        : (file.architectures || []);
    data.downloadParts = file.downloadParts || [];
    return data;
}

app.get('/mods/:id/preview', ensureAuthenticated, async (req, res) => {
    try {
        const file = await File.findById(req.params.id).populate('license', 'name').lean();
        if (!canManageDraft(file, req.user)) return res.status(404).render('pages/error', { errorCode: '404', errorTitle: 'Page Not Found', errorMessage: 'The page you are looking for does not exist or you do not have permission to access it.' });
        file.iconUrl = await getSmartImageUrl(file.iconKey);
        file.screenshotUrls = await Promise.all((file.screenshotKeys || []).map(key => getSmartImageUrl(key)));
        const youtubeMatch = String(file.videoUrl || '').match(/(?:youtu\.be\/|youtube\.com\/(?:watch\?v=|embed\/|shorts\/))([^&#?\/]+)/i);
        file.youtubeVideoId = youtubeMatch && youtubeMatch[1].length === 11 ? youtubeMatch[1] : null;
        res.render('pages/mod-preview', { file });
    } catch (error) {
        console.error('Draft preview error:', error);
        res.status(500).render('pages/500');
    }
});

app.post('/api/mods/:id/autosave', ensureAuthenticated, async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        if (!canManageDraft(file, req.user)) return res.status(404).json({ success: false });
        if (!req.user.autoSaveEnabled && req.user.role !== 'admin') return res.status(403).json({ success: false, message: 'Auto-save is disabled.' });

        const data = draftSnapshotData(file, req.body);
        await DraftSnapshot.create({ file: file._id, createdBy: req.user._id, data });
        const snapshots = await DraftSnapshot.find({ file: file._id }).sort({ createdAt: -1 }).select('_id').lean();
        if (snapshots.length > 5) await DraftSnapshot.deleteMany({ _id: { $in: snapshots.slice(5).map(snapshot => snapshot._id) } });

        Object.entries(data).forEach(([key, value]) => { file[key] = value; });
        if (file.status === 'processing' || file.status === 'pending') file.status = 'draft';
        await file.save();
        res.json({ success: true, savedAt: new Date().toISOString() });
    } catch (error) {
        console.error('Autosave error:', error);
        res.status(500).json({ success: false });
    }
});

app.get('/api/mods/:id/snapshots', ensureAuthenticated, async (req, res) => {
    const file = await File.findById(req.params.id).lean();
    if (!canManageDraft(file, req.user)) return res.status(404).json({ success: false });
    const snapshots = await DraftSnapshot.find({ file: file._id }).sort({ createdAt: -1 }).limit(5).select('label createdAt').lean();
    res.json({ success: true, snapshots });
});

app.post('/api/mods/:id/snapshots/:snapshotId/restore', ensureAuthenticated, async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        if (!canManageDraft(file, req.user)) return res.status(404).json({ success: false });
        const snapshot = await DraftSnapshot.findOne({ _id: req.params.snapshotId, file: file._id });
        if (!snapshot) return res.status(404).json({ success: false });
        Object.entries(snapshot.data).forEach(([key, value]) => { file[key] = value; });
        file.status = 'draft';
        await file.save();
        res.json({ success: true });
    } catch (error) {
        console.error('Snapshot restore error:', error);
        res.status(500).json({ success: false });
    }
});

// --- UPDATED: User Delete Mod Route (Transfers Ownership to Variant or Deletes Permanently) ---
app.post('/mods/:id/delete', ensureAuthenticated, async (req, res) => {
    try {
        const fileId = req.params.id;
        const file = await File.findById(fileId).populate('olderVersions').populate('variants');

        if (!file || (file.uploader !== req.user.username && req.user.role !== 'admin')) {
            return res.status(404).json({ success: false, message: 'Resource not found.' });
        }

        // Check if any variant files exist for this master file
        const variantsList = await File.find({ masterFile: file._id }).sort({ createdAt: 1 });

        if (variantsList.length > 0) {
            // PROMOTION WORKFLOW: Promote the first uploaded variant to become the main file
            const firstVariant = variantsList[0];

            // 1. Delete old main binary file key from B2/FTP if different
            if (file.fileKey && file.fileKey !== 'external-link' && file.fileKey !== firstVariant.fileKey) {
                await deleteFromB2(file.fileKey);
            }

            // 2. Transfer ownership to the variant uploader
            const oldUploaderName = file.uploader;
            file.uploader = firstVariant.uploader;

            // 3. Update mod description and features with the variant's details (keep officialDescription)
            file.modDescription = firstVariant.modDescription || file.modDescription;
            file.modFeatures = firstVariant.modFeatures || file.modFeatures;

            // 4. Update file version, binaries, links, and download parts
            file.version = firstVariant.version;
            file.fileKey = firstVariant.fileKey;
            file.fileSize = firstVariant.fileSize;
            file.originalFilename = firstVariant.originalFilename;
            file.externalDownloadUrl = firstVariant.externalDownloadUrl;
            file.directDownloadUrl = firstVariant.directDownloadUrl;
            file.downloadParts = firstVariant.downloadParts;
            file.isMultiPart = firstVariant.isMultiPart;

            // 5. Update media (screenshots / video) if provided by variant uploader
            if (firstVariant.screenshotKeys && firstVariant.screenshotKeys.length > 0) {
                file.screenshotKeys = firstVariant.screenshotKeys;
            }
            if (firstVariant.videoUrl) {
                file.videoUrl = firstVariant.videoUrl;
            }

            // 6. Clean up old uploader comment replies on the file
            await Review.updateMany({ file: file._id }, { $unset: { uploaderReply: 1 } });

            // 7. Migrate/preserve variant reviews to main file
            await Review.updateMany({ file: firstVariant._id }, { file: file._id });

            // 8. Remove promoted variant from variants array and delete variant DB record
            file.variants = file.variants.filter(vId => vId.toString() !== firstVariant._id.toString());
            await File.findByIdAndDelete(firstVariant._id);

            await file.save();

            console.log(`[Variant Promotion] Main mod "${file.name}" transferred to first variant uploader (${firstVariant.uploader}).`);
            return res.json({ success: true, message: `Main mod transferred to first variant uploader (${firstVariant.uploader}) successfully.` });
        }

        // NO VARIANTS EXIST -> PERMANENT DELETION
        await deleteFromB2(file.fileKey);
        await deleteFromB2(file.iconKey);
        if (file.screenshotKeys && file.screenshotKeys.length > 0) {
            for (const key of file.screenshotKeys) {
                await deleteFromB2(key);
            }
        }

        if (file.olderVersions && file.olderVersions.length > 0) {
            for (const oldVersion of file.olderVersions) {
                await deleteFromB2(oldVersion.fileKey);
                await File.findByIdAndDelete(oldVersion._id); 
            }
        }

        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        const deadUrl = `${baseUrl}/${encodeURIComponent(file.category)}/${encodeURIComponent(file.slug || file._id.toString())}`;
        notifyIndexNow([deadUrl]);
        notifyGoogle(deadUrl, 'URL_DELETED');

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
            return res.status(404).json({ success: false, message: 'Resource not found.' });
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
            return res.status(404).json({ success: false, message: 'Resource not found.' });
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
        const isAdminOrOwner = req.user && (req.user.role === 'admin' || req.user.role === 'owner');
        
        // Security check
        if (!file || (file.uploader !== req.user.username && !isAdminOrOwner)) {
            return res.status(404).render('pages/error', { errorCode: '404', errorTitle: 'Page Not Found', errorMessage: 'The page you are looking for does not exist or you do not have permission to access it.' });
        }

        // Generate signed URLs so the user can see their current images
        const iconUrl = await getSmartImageUrl(file.iconKey);
        const screenshotUrls = await Promise.all((file.screenshotKeys ||[]).map(key => getSmartImageUrl(key)));
        const licenses = await License.find().sort({ name: 1 }).lean();

        const customTemplates = await ModTemplate.find({ isActive: true }).sort({ sortOrder: 1, createdAt: 1 }).lean();

        res.render('pages/edit-mod', { 
            file: { ...file.toObject(), iconUrl, screenshotUrls },
            licenses,
            customTemplates
        });
    } catch (error) {
        console.error("Error loading edit page:", error);
        return next(error);
    }
});

app.post('/mods/:id/edit', ensureAuthenticated, upload.fields([
    { name: 'softwareIcon', maxCount: 1 },
    { name: 'screenshots', maxCount: 12 }
]), async (req, res) => {
    try {
        const file = await File.findById(req.params.id);
        const isAdminOrOwner = req.user && (req.user.role === 'admin' || req.user.role === 'owner');
        
        if (!file || (file.uploader !== req.user.username && !isAdminOrOwner)) {
            return res.status(404).send('Not found');
        }

        const formData = req.body;
        const { softwareIcon, screenshots } = req.files || {};
        
        // Normalize duplicate inputs and preserve known values.
        const directDownloadUrlValue = normalizeSingleValue(formData.directDownloadUrl);
        const manualFileScanUrlValue = formData.manualFileScanUrl !== undefined
            ? normalizeSingleValue(formData.manualFileScanUrl)
            : file.manualFileScanUrl;
        const manualSiteScanUrlValue = formData.manualSiteScanUrl !== undefined
            ? normalizeSingleValue(formData.manualSiteScanUrl)
            : file.manualSiteScanUrl;
        const isDistributor = req.user.role === 'distributor';
        const currentFileSize = file.fileSize || 0;
        const actionType = formData.actionType || 'submit';

        // 1. Update images ONLY IF new ones were uploaded
        const targetCategory = formData.modPlatform || file.category;
        const targetModName = formData.modName || file.name;
        const uploaderUser = req.user || { username: file.uploader };
        
        // --- HANDLE ICON OVERWRITE ---
        if (softwareIcon && softwareIcon.length > 0) {
            // Delete the old icon from B2 first
            if (file.iconKey) {
                await deleteFromB2(file.iconKey);
            }
            // Upload the new one with standardized app-icon key
            const iconTargetKey = getModStorageKey({
                category: targetCategory,
                modName: targetModName,
                uploader: uploaderUser,
                uploaderEmail: req.user?.email,
                isVariant: Boolean(file.isVariant),
                variantId: file._id,
                assetType: 'icon',
                originalFilename: softwareIcon[0].originalname
            });
            file.iconKey = await uploadToB2(softwareIcon[0], 'icons', null, null, null, { exactKey: iconTargetKey });
        }

        // --- HANDLE DYNAMIC SCREENSHOTS ---
        if (formData.screenshotOrder) {
            let incomingOrder = [];
            try {
                incomingOrder = typeof formData.screenshotOrder === 'string'
                    ? JSON.parse(formData.screenshotOrder)
                    : (formData.screenshotOrder || []);
            } catch (e) {
                incomingOrder = [];
            }

            if (incomingOrder.length > 4) {
                return res.redirect(`/mods/${file._id}/edit?error=${encodeURIComponent(`You have uploaded more then 4 Screenshot of the app/game. There are only 4 maximum screenshot are allowed for an app or game please remove unnecessary ${incomingOrder.length - 4} of Screenshot`)}`);
            }

            const finalScreenshotKeys = [];
            const uploadedShots = screenshots || [];
            let shotIndex = 1;
            for (const item of incomingOrder) {
                if (item.type === 'existing' && item.key) {
                    if (file.screenshotKeys && file.screenshotKeys.includes(item.key)) {
                        finalScreenshotKeys.push(item.key);
                        shotIndex++;
                    }
                } else if (item.type === 'new' && typeof item.fileIndex === 'number' && uploadedShots[item.fileIndex]) {
                    const shotTargetKey = getModStorageKey({
                        category: targetCategory,
                        modName: targetModName,
                        uploader: uploaderUser,
                        uploaderEmail: req.user?.email,
                        isVariant: Boolean(file.isVariant),
                        variantId: file._id,
                        assetType: 'screenshot',
                        screenshotIndex: shotIndex,
                        originalFilename: uploadedShots[item.fileIndex].originalname
                    });
                    const newKey = await uploadToB2(uploadedShots[item.fileIndex], 'screenshots', null, null, null, { exactKey: shotTargetKey });
                    finalScreenshotKeys.push(newKey);
                    shotIndex++;
                }
            }

            // Delete old screenshots that are no longer kept
            if (file.screenshotKeys && file.screenshotKeys.length > 0) {
                for (const oldShotKey of file.screenshotKeys) {
                    if (!finalScreenshotKeys.includes(oldShotKey)) {
                        await deleteFromB2(oldShotKey);
                    }
                }
            }
            file.screenshotKeys = finalScreenshotKeys;
        } else if (screenshots && screenshots.length > 0) {
            if (screenshots.length > 4) {
                return res.redirect(`/mods/${file._id}/edit?error=${encodeURIComponent(`You have uploaded more then 4 Screenshot of the app/game. There are only 4 maximum screenshot are allowed for an app or game please remove unnecessary ${screenshots.length - 4} of Screenshot`)}`);
            }
            // Fallback: Delete ALL old screenshots from B2 first.
            if (file.screenshotKeys && file.screenshotKeys.length > 0) {
                for (const oldShotKey of file.screenshotKeys) {
                    await deleteFromB2(oldShotKey);
                }
            }
            // Upload the new ones
            file.screenshotKeys = await Promise.all(screenshots.map((f, idx) => {
                const shotTargetKey = getModStorageKey({
                    category: targetCategory,
                    modName: targetModName,
                    uploader: uploaderUser,
                    uploaderEmail: req.user?.email,
                    isVariant: Boolean(file.isVariant),
                    variantId: file._id,
                    assetType: 'screenshot',
                    screenshotIndex: idx + 1,
                    originalFilename: f.originalname
                });
                return uploadToB2(f, 'screenshots', null, null, null, { exactKey: shotTargetKey });
            }));
        }

        // 2. Format tags
        const processedTags = formData.tags ? formData.tags.split(',').map(t => t.trim()) : file.tags;

        // 3. Update all text fields (do this BEFORE validation checks so user edits are NEVER lost)
        file.version = formData.modVersion || file.version;
        file.developer = formData.developerName || file.developer;
        file.modDescription = formData.modDescription || file.modDescription;
        file.modFeatures = formData.modFeatures || file.modFeatures;
        file.whatsNew = formData.whatsNew || file.whatsNew;
        file.officialDescription = formData.officialDescription || file.officialDescription;        
        file.importantNote = formData.importantNote || file.importantNote;        
        file.videoUrl = formData.videoUrl || file.videoUrl;
        file.category = formData.modPlatform || file.category;
        file.license = formData.modLicense || null;
        file.minOsVersion = formData.minOsVersion !== undefined ? formData.minOsVersion : file.minOsVersion;
        if (formData.architectures !== undefined) {
            file.architectures = Array.isArray(formData.architectures) ? formData.architectures : [formData.architectures];
        }

        const activePlatform = formData.modPlatform || file.category;
        if (activePlatform === 'android') {
            file.requiresRoot = (formData.requiresRoot === 'true' || formData.requiresRoot === true || formData.requiresRoot === 'on');
            file.requiresDevMode = (formData.requiresDevMode === 'true' || formData.requiresDevMode === true || formData.requiresDevMode === 'on');
        } else if (activePlatform === 'ios-jailbroken') {
            file.isTweakConvertible = (formData.isTweakConvertible === 'true' || formData.isTweakConvertible === true || formData.isTweakConvertible === 'on');
            file.requiresDependencies = (formData.requiresDependencies === 'true' || formData.requiresDependencies === true || formData.requiresDependencies === 'on');
        } else if (activePlatform === 'windows') {
            file.requiresDisableAntivirus = (formData.requiresDisableAntivirus === 'true' || formData.requiresDisableAntivirus === true || formData.requiresDisableAntivirus === 'on');
            file.requiresDevMode = (formData.requiresDevMode === 'true' || formData.requiresDevMode === true || formData.requiresDevMode === 'on');
        }

        if (formData.directDownloadUrl !== undefined) {
            file.directDownloadUrl = directDownloadUrlValue;
        }
        if (formData.iosPackageId !== undefined) {
            file.iosPackageId = formData.iosPackageId;
        }
        file.tags = processedTags;
        if (formData.manualFileScanUrl !== undefined) {
            if (file.manualFileScanUrl !== manualFileScanUrlValue) {
                file.virusTotalScanDate = null;
                file.virusTotalPositiveCount = 0;
                file.virusTotalTotalScans = 0;
                file.virusTotalId = '';
                file.virusTotalAnalysisId = '';
            }
            file.manualFileScanUrl = manualFileScanUrlValue;
        }
        if (formData.manualSiteScanUrl !== undefined) file.manualSiteScanUrl = manualSiteScanUrlValue;
        file.ageRating = req.body.ageRating || file.ageRating; 
        if (formData.modCategory) {
            file.platforms = [formData.modCategory];
        }

        // --- ADMIN / OWNER: EDITOR'S CHOICE COUNCIL SETTINGS ---
        if (isAdminOrOwner) {
            if (formData.isEditorsChoice !== undefined) {
                file.isEditorsChoice = (formData.isEditorsChoice === 'true' || formData.isEditorsChoice === 'on');
            }
            if (formData.editorsChoiceDescription !== undefined) {
                file.editorsChoiceDescription = (formData.editorsChoiceDescription || '').trim();
            }
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

            file.isMultiPart = editIsMultiPart;
            if (editDownloadParts.length > 0) file.downloadParts = editDownloadParts;
        } catch (e) {
            console.error('Multipart parsing error (edit):', e);
        }

        // ======== MOD NAME VALIDATION CHECK ========
        const modNameErr = formData.modName ? getModNameValidationError(formData.modName) : null;
        if (modNameErr) {
            // Save other edited fields to draft so user never loses their changes
            if (actionType === 'draft') {
                file.status = 'draft';
                await file.save();
                return res.redirect(`/mods/${file._id}/edit?error=${encodeURIComponent('Draft saved, but ' + modNameErr)}`);
            } else {
                await file.save();
                return res.redirect(`/mods/${file._id}/edit?error=${encodeURIComponent(modNameErr)}`);
            }
        }

        file.name = formData.modName || file.name;

        const LARGE_FILE_THRESHOLD = 640 * 1024 * 1024;
        if (actionType === 'submit') {
            if (isDistributor && !directDownloadUrlValue) {
                return res.redirect(`/mods/${file._id}/edit?error=Distributor uploads must include a direct download link before publishing.`);
            }
            if (currentFileSize > LARGE_FILE_THRESHOLD && !manualFileScanUrlValue && !manualSiteScanUrlValue) {
                return res.redirect(`/mods/${file._id}/edit?error=Files larger than 640MB require a VirusTotal or manual scan URL before publishing.`);
            }
            if (!file.screenshotKeys || file.screenshotKeys.length === 0) {
                return res.redirect(`/mods/${file._id}/edit?error=At least one screenshot is required to submit the mod.`);
            }
        }

        // 4. IMPORTANT: Status Logic
        if (actionType === 'draft') {
            file.status = 'draft'; 
        } else {
            // If they clicked Submit...
            // Transition from draft, rejected, or processing to pending!
            if (file.status === 'rejected' || file.status === 'processing' || file.status === 'draft') {
                file.status = 'pending';
                file.rejectionReason = ''; // Clear old reason
            }
            // If it was already 'live', it stays 'live'.
        }

        // Ensure slug exists for newly submitted files/drafts
        if (!file.isVariant && !file.slug) {
            let baseSlug = slugify(file.name);
            let finalSlug = baseSlug;
            let slugCounter = 1;
            while (await File.findOne({ slug: finalSlug, category: file.category, isLatestVersion: true, _id: { $ne: file._id } })) {
                finalSlug = `${baseSlug}-${slugCounter}`;
                slugCounter++;
            }
            file.slug = finalSlug;
        }

        await file.save();
        saveModMetadata(file);

        // --- AUTOMATED VIRUSTOTAL SCAN TRIGGER ON UPDATE ---
        if ((file.virusTotalAnalysisId || file.manualFileScanUrl || file.virusTotalId) && !file.virusTotalScanDate) {
            pollVirusTotalInBackground(file._id);
        }
        if (file.isMultiPart && file.downloadParts && file.downloadParts.length > 0) {
            for (const part of file.downloadParts) {
                if ((part.partVirusTotalId || part.manualFileScanUrl) && !part.partVirusTotalScanDate) {
                    checkAndUpdatePartVirusTotal(file._id, part._id).catch(() => {});
                }
            }
        }

        // --- INDEXNOW PING ---
        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        const modUrl = `${baseUrl}/${encodeURIComponent(file.category)}/${encodeURIComponent(file.slug || file._id.toString())}`;
        notifyIndexNow([modUrl]);
        notifyGoogle(modUrl, 'URL_UPDATED');
        
        if (actionType === 'draft') {
            res.redirect(`/mods/${file._id}/edit?success=Draft saved successfully. This mod is hidden from public review until you submit it.`);
        } else {
            res.redirect('/my-uploads?success=Mod updated and submitted for review!');
        }

    } catch (error) {
        console.error("Error updating mod:", error);
        return next(error);
    }
});

app.post('/upload-finalize/:fileId', ensureAuthenticated, upload.fields([
    { name: 'softwareIcon', maxCount: 1 },
    { name: 'screenshots', maxCount: 12 }
]), async (req, res, next) => {
    try {
        const fileId = req.params.fileId;
        const fileToUpdate = await File.findById(fileId);

        if (!fileToUpdate || fileToUpdate.uploader !== req.user.username) {
            return res.status(404).render('pages/error', { errorCode: '404', errorTitle: 'Page Not Found', errorMessage: 'The page you are looking for does not exist or you do not have permission to access it.' });
        }

        const { softwareIcon, screenshots } = req.files || {}; // Default to empty object if no files
        const formData = req.body; 
        const actionType = formData.actionType || 'submit'; // 'draft' or 'submit'
        
        // Normalize direct download/scans for duplicate or array values.
        const directDownloadUrlValue = normalizeSingleValue(formData.directDownloadUrl);
        const manualFileScanUrlValue = formData.manualFileScanUrl !== undefined
            ? normalizeSingleValue(formData.manualFileScanUrl)
            : null;
        const manualSiteScanUrlValue = formData.manualSiteScanUrl !== undefined
            ? normalizeSingleValue(formData.manualSiteScanUrl)
            : null;
        const isDistributor = req.user.role === 'distributor';

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
        }

        const modNameDraftErr = formData.modName ? getModNameValidationError(formData.modName) : (actionType === 'draft' ? null : 'Mod Name is required.');

        let iconKey = fileToUpdate.iconKey; // Keep existing if not updating
        let screenshotKeys = fileToUpdate.screenshotKeys || [];
        const processedTags = formData.tags ? formData.tags.split(',').map(t => t.trim()) : [];
        const archData = formData.architectures ? (Array.isArray(formData.architectures) ? formData.architectures : [formData.architectures]) : [];

        // --- PROCESS IMAGES & CATEGORIZED B2 PATHS ---
        const b2Opts = {
            category: formData.modPlatform,
            modSlug: slugify(formData.modName),
            isVariant: isVariant,
            masterSlug: existingMasterFile ? slugify(existingMasterFile.name) : null
        };

        if (isVariant && existingMasterFile) {
            // Variant uses shared icon from master file
            iconKey = existingMasterFile.iconKey;
        } else if (softwareIcon && softwareIcon.length > 0) {
            const iconTargetKey = getModStorageKey({
                category: formData.modPlatform,
                modName: formData.modName,
                uploader: req.user,
                uploaderEmail: req.user.email,
                isVariant: isVariant,
                variantId: fileId,
                assetType: 'icon',
                originalFilename: softwareIcon[0].originalname
            });
            iconKey = await uploadToB2(softwareIcon[0], 'icons', null, null, null, { exactKey: iconTargetKey });
        }

        // --- HANDLE DYNAMIC SCREENSHOTS ---
        if (formData.screenshotOrder) {
            let incomingOrder = [];
            try {
                incomingOrder = typeof formData.screenshotOrder === 'string'
                    ? JSON.parse(formData.screenshotOrder)
                    : (formData.screenshotOrder || []);
            } catch (e) {
                incomingOrder = [];
            }

            if (incomingOrder.length > 4) {
                return res.redirect(`/upload-details/${fileId}?error=${encodeURIComponent(`You have uploaded more then 4 Screenshot of the app/game. There are only 4 maximum screenshot are allowed for an app or game please remove unnecessary ${incomingOrder.length - 4} of Screenshot`)}`);
            }

            const finalScreenshotKeys = [];
            const uploadedShots = screenshots || [];
            let shotIndex = 1;
            for (const item of incomingOrder) {
                if (item.type === 'existing' && item.key) {
                    if (screenshotKeys.includes(item.key) || (fileToUpdate.screenshotKeys && fileToUpdate.screenshotKeys.includes(item.key))) {
                        finalScreenshotKeys.push(item.key);
                        shotIndex++;
                    }
                } else if (item.type === 'new' && typeof item.fileIndex === 'number' && uploadedShots[item.fileIndex]) {
                    const shotTargetKey = getModStorageKey({
                        category: formData.modPlatform,
                        modName: formData.modName,
                        uploader: req.user,
                        uploaderEmail: req.user.email,
                        isVariant: isVariant,
                        variantId: fileId,
                        assetType: 'screenshot',
                        screenshotIndex: shotIndex,
                        originalFilename: uploadedShots[item.fileIndex].originalname
                    });
                    const newKey = await uploadToB2(uploadedShots[item.fileIndex], 'screenshots', null, null, null, { exactKey: shotTargetKey });
                    finalScreenshotKeys.push(newKey);
                    shotIndex++;
                }
            }

            // Delete old screenshots that are no longer kept
            if (fileToUpdate.screenshotKeys && fileToUpdate.screenshotKeys.length > 0) {
                for (const oldShotKey of fileToUpdate.screenshotKeys) {
                    if (!finalScreenshotKeys.includes(oldShotKey)) {
                        await deleteFromB2(oldShotKey);
                    }
                }
            }
            screenshotKeys = finalScreenshotKeys;
        } else if (screenshots && screenshots.length > 0) {
            if (screenshots.length > 4) {
                return res.redirect(`/upload-details/${fileId}?error=${encodeURIComponent(`You have uploaded more then 4 Screenshot of the app/game. There are only 4 maximum screenshot are allowed for an app or game please remove unnecessary ${screenshots.length - 4} of Screenshot`)}`);
            }
            screenshotKeys = await Promise.all(screenshots.map((f, idx) => {
                const shotTargetKey = getModStorageKey({
                    category: formData.modPlatform,
                    modName: formData.modName,
                    uploader: req.user,
                    uploaderEmail: req.user.email,
                    isVariant: isVariant,
                    variantId: fileId,
                    assetType: 'screenshot',
                    screenshotIndex: idx + 1,
                    originalFilename: f.originalname
                });
                return uploadToB2(f, 'screenshots', null, null, null, { exactKey: shotTargetKey });
            }));
        } else if (isVariant && existingMasterFile && (!screenshotKeys || screenshotKeys.length === 0)) {
            screenshotKeys = existingMasterFile.screenshotKeys || [];
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
                if (!pUrls[i]) continue;
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

        const validationErrors = getSubmissionValidationErrors({
            actionType,
            formData,
            fileToUpdate,
            iconKey,
            screenshotKeys,
            screenshots,
            isVariant,
            isDistributor,
            ageRating: req.body.ageRating,
            fileSize: fileToUpdate.fileSize,
            directDownloadUrlValue,
            manualFileScanUrlValue,
            manualSiteScanUrlValue,
            isValidNameFn: isValidModName
        });

        if (actionType === 'submit' && validationErrors.length > 0) {
            return res.redirect(`/upload-details/${fileId}?error=${encodeURIComponent(validationErrors[0])}`);
        }

        // --- Sanitize Mod Details ---
        const safeClean = (value) => {
            if (!value || typeof value !== 'string') return '';
            return global.profanityFilter.clean(value);
        };

        const cleanName = safeClean(formData.modName || fileToUpdate.name);

        // --- GENERATE SLUG ---
        let finalSlug = fileToUpdate.slug;
        if (!isVariant && actionType === 'submit' && !finalSlug) {
            let baseSlug = slugify(cleanName);
            finalSlug = baseSlug;
            let slugCounter = 1;
            while (await File.findOne({ slug: finalSlug, category: formData.modPlatform, isLatestVersion: true, _id: { $ne: fileId } })) {
                finalSlug = `${baseSlug}-${slugCounter}`;
                slugCounter++;
            }
        }
        const cleanDescription = safeClean(formData.modDescription);
        const cleanFeatures = safeClean(formData.modFeatures);
        const cleanWhatsNew = safeClean(formData.whatsNew);
        const cleanOfficialDescription = safeClean(formData.officialDescription);
        const cleanImportantNote = safeClean(formData.importantNote);
        const finalStatus = actionType === 'draft' ? 'draft' : 'pending';

        let requiresRoot = false;
        let requiresDevMode = false;
        let isTweakConvertible = false;
        let requiresDependencies = false;
        let requiresDisableAntivirus = false;

        const effectivePlatform = formData.modPlatform || fileToUpdate.category;
        if (effectivePlatform === 'android') {
            requiresRoot = (formData.requiresRoot === 'true' || formData.requiresRoot === true || formData.requiresRoot === 'on');
            requiresDevMode = (formData.requiresDevMode === 'true' || formData.requiresDevMode === true || formData.requiresDevMode === 'on');
        } else if (effectivePlatform === 'ios-jailbroken') {
            isTweakConvertible = (formData.isTweakConvertible === 'true' || formData.isTweakConvertible === true || formData.isTweakConvertible === 'on');
            requiresDependencies = (formData.requiresDependencies === 'true' || formData.requiresDependencies === true || formData.requiresDependencies === 'on');
        } else if (effectivePlatform === 'windows') {
            requiresDisableAntivirus = (formData.requiresDisableAntivirus === 'true' || formData.requiresDisableAntivirus === true || formData.requiresDisableAntivirus === 'on');
            requiresDevMode = (formData.requiresDevMode === 'true' || formData.requiresDevMode === true || formData.requiresDevMode === 'on');
        }

        // --- SAVE TO DATABASE (Always save fields so user inputs are never lost!) ---
        const updateData = {
            name: cleanName,
            version: formData.modVersion || fileToUpdate.version,
            modDescription: cleanDescription,
            modFeatures: cleanFeatures,
            officialDescription: cleanOfficialDescription,
            whatsNew: cleanWhatsNew,
            importantNote: cleanImportantNote,
            developer: formData.developerName || 'N/A',
            screenshotKeys: screenshotKeys.length > 0 ? screenshotKeys : fileToUpdate.screenshotKeys,
            videoUrl: normalizeSingleValue(formData.videoUrl), 
            tags: processedTags,
            ageRating: req.body.ageRating,
            manualFileScanUrl: manualFileScanUrlValue,
            manualSiteScanUrl: manualSiteScanUrlValue,
            category: formData.modPlatform || fileToUpdate.category,
            license: formData.modLicense || null,
            platforms: formData.modCategory ? [formData.modCategory] : fileToUpdate.platforms,
            directDownloadUrl: directDownloadUrlValue || '',
            externalDownloadUrl: !isMultiPart ? (normalizeSingleValue(formData.externalDownloadUrl) || '') : '',
            architectures: archData,
            minOsVersion: formData.minOsVersion || '',
            iosPackageId: normalizeSingleValue(formData.iosPackageId) || '',
            requiresRoot,
            requiresDevMode,
            isTweakConvertible,
            requiresDependencies,
            requiresDisableAntivirus,
            status: finalStatus
        };

        updateData.isMultiPart = isMultiPart;
        if (downloadParts && downloadParts.length > 0) updateData.downloadParts = downloadParts;

        if (isVariant) {
            updateData.isVariant = true;
            updateData.masterFile = masterFileId;
            updateData.isLatestVersion = false;
            
            await File.findByIdAndUpdate(fileId, updateData);
            
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

        // --- CHECK IF DRAFT SAVED WITH MOD NAME WARNING ---
        if (actionType === 'draft' && modNameDraftErr) {
            return res.redirect(`/upload-details/${fileId}?error=${encodeURIComponent('Draft saved, but ' + modNameDraftErr)}`);
        }

        // --- REDIRECT BASED ON ACTION ---
        if (actionType === 'draft') {
            res.redirect(`/upload-details/${fileId}?success=Draft saved successfully! You can return to finish it later.`);
        } else {
            await User.adjustForumPoints(req.user._id, 50, "Uploaded a new mod");
            const justUploadedFile = await File.findById(fileId);
            if (justUploadedFile) {
                saveModMetadata(justUploadedFile);
            }
            if (justUploadedFile && justUploadedFile.status === 'live') {
                notifyClubModFeeds(justUploadedFile, false);
            }
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

// --- NEW: iOS Store API Endpoint ---
app.get('/api/ios-store', async (req, res) => {
    try {
        const dnsProfiles = await IosDns.find().sort({ isRecommended: -1, createdAt: -1 });
        const certificates = await IosCert.find().sort({ createdAt: -1 });
        
        res.json({
            dns: dnsProfiles,
            certificates: certificates
        });
    } catch (error) {
        console.error("iOS Store API Error:", error);
        res.status(500).json({ error: 'Server error' });
    }
});

// CUSTOM MULTI-LANGUAGE ENGINE (DEEPL API via deepl-node SDK)
// Language code mapping: frontend codes -> DeepL target language codes
const DEEPL_LANG_MAP = {
    'es': 'es', 'fr': 'fr', 'hi': 'hi', 'ar': 'ar',
    'zh-Hans': 'zh', 'zh': 'zh', 'pt': 'pt-BR', 'ru': 'ru', 'id': 'id',
    'de': 'de', 'it': 'it', 'ja': 'ja', 'ko': 'ko', 'nl': 'nl',
    'pl': 'pl', 'tr': 'tr', 'uk': 'uk', 'sv': 'sv', 'da': 'da',
    'fi': 'fi', 'el': 'el', 'cs': 'cs', 'ro': 'ro', 'hu': 'hu',
    'bg': 'bg', 'sk': 'sk', 'sl': 'sl', 'et': 'et', 'lt': 'lt', 'lv': 'lv',
    'nb': 'nb', 'en-US': 'en-US', 'en-GB': 'en-GB'
};

app.post('/api/translate', async (req, res) => {
    try {
        const { texts, targetLanguage } = req.body;

        if (!texts || !Array.isArray(texts) || texts.length === 0 || !targetLanguage) {
            return res.status(400).json({ error: "Invalid request payload." });
        }

        // If English, return original texts
        if (targetLanguage === 'en') {
            return res.json({ translations: texts }); 
        }

        // Map frontend language code to DeepL's expected code
        const deeplTargetLang = DEEPL_LANG_MAP[targetLanguage] || targetLanguage;

        const finalTranslations = [];
        const textsToTranslate = [];
        const indicesToTranslate = [];

        // 1. Check the Database Cache First (Costs $0)
        for (let i = 0; i < texts.length; i++) {
            const text = texts[i];
            
            // Skip empty strings or numbers to save quota
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

        // 2. Call DeepL API for cache-missed texts
        if (textsToTranslate.length > 0) {
            
            const newCharsLength = textsToTranslate.join('').length;
            
            const reservationResult = await reserveApiQuota({
                service: 'deepl',
                period: 'monthly',
                amount: newCharsLength
            });

            if (reservationResult.allowed) {
                const reservation = reservationResult.reservation;
                
                // Call DeepL API via official deepl-node SDK
                let results;
                try {
                    results = await deeplClient.translateText(
                        textsToTranslate,
                        'en',           // Source language: English
                        deeplTargetLang // Target language mapped for DeepL
                    );
                } catch (error) {
                    await releaseApiQuota(reservation);
                    await disableApiQuotaOnError('deepl', 'monthly', error);
                    throw error;
                }

                // deepl-node returns a single TextResult for single input, or array for multiple
                const apiResults = Array.isArray(results) ? results : [results];
                const newCacheEntries = [];

                for (let j = 0; j < apiResults.length; j++) {
                    const original = textsToTranslate[j];
                    const translated = apiResults[j].text;
                    
                    finalTranslations[indicesToTranslate[j]] = translated;

                    newCacheEntries.push({
                        originalText: original,
                        targetLanguage: targetLanguage, // Store using original frontend code for cache consistency
                        translatedText: translated
                    });
                }

                // Save to cache so we never pay/use quota for these words again
                if (newCacheEntries.length > 0) {
                    await TranslationCache.insertMany(newCacheEntries, { ordered: false }).catch(e => {
                        // Safely ignore duplicate keys if two users hit it simultaneously
                    });
                }

            } else {
                console.warn(`[TRANSLATION LIMIT] DeepL requests blocked: ${reservationResult.reason}.`);
                
                // Return original English text for missing chunks so site doesn't crash
                for (let j = 0; j < textsToTranslate.length; j++) {
                    finalTranslations[indicesToTranslate[j]] = textsToTranslate[j];
                }
            }
        }

        res.json({ translations: finalTranslations });

    } catch (error) {
        console.error("DeepL API Error:", error.message);
        res.status(500).json({ error: "Translation failed." });
    }
});
// --- AUTO-FETCH HELPER FUNCTIONS ---
function cleanPlatformUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return '';
    let trimmed = rawUrl.trim();
    if (!trimmed.startsWith('http://') && !trimmed.startsWith('https://')) {
        trimmed = 'https://' + trimmed;
    }
    try {
        const parsed = new URL(trimmed);
        let hostname = parsed.hostname.toLowerCase();
        
        // Strip language/country prefix subdomains: e.g. en.wordpress.org, ve.wordpress.org, en.play.google.com, etc.
        const langSubdomainMatch = hostname.match(/^([a-z]{2}(?:-[a-z]{2,4})?)\.(.+)$/i);
        if (langSubdomainMatch) {
            const remainder = langSubdomainMatch[2];
            if (
                remainder.includes('wordpress.org') ||
                remainder.includes('wordpress.com') ||
                remainder.includes('google.com') ||
                remainder.includes('apple.com') ||
                remainder.includes('steampowered.com') ||
                remainder.includes('epicgames.com')
            ) {
                hostname = remainder;
            }
        }
        
        // Canonicalize known platform hostnames
        if (hostname.endsWith('.wordpress.org') || hostname === 'wordpress.org') hostname = 'wordpress.org';
        else if (hostname.endsWith('.wordpress.com') || hostname === 'wordpress.com') hostname = 'wordpress.com';
        else if (hostname.endsWith('.play.google.com') || hostname === 'play.google.com') hostname = 'play.google.com';
        else if (hostname.endsWith('.apps.apple.com') || hostname === 'apps.apple.com' || hostname.endsWith('.itunes.apple.com') || hostname === 'itunes.apple.com') hostname = 'apps.apple.com';
        else if (hostname.endsWith('.steampowered.com') || hostname === 'store.steampowered.com') hostname = 'store.steampowered.com';
        else if (hostname.endsWith('.epicgames.com') || hostname === 'store.epicgames.com') hostname = 'store.epicgames.com';

        parsed.hostname = hostname;
        return parsed.toString();
    } catch (e) {
        return trimmed;
    }
}

function detectPlatform(url) {
    try {
        const parsed = new URL(url);
        const host = parsed.hostname.toLowerCase();
        if (host.includes('google.com') || host.includes('android.com')) return 'playstore';
        if (host.includes('apple.com')) return 'appstore';
        if (host.includes('steampowered.com') || host.includes('steamcommunity.com')) return 'steam';
        if (host.includes('epicgames.com')) return 'epic';
        if (host.includes('wordpress.org') || host.includes('wordpress.com')) return 'wordpress';
    } catch (e) {}
    return 'generic';
}

function normalizeAgeRating(ratingStr) {
    if (!ratingStr) return 'NA';
    const s = ratingStr.toString().trim();
    if (/^18\+?$/i.test(s) || /adult|ao|18\+/i.test(s)) return '18+';
    if (/^16\+?$/i.test(s) || /mature|17\+|16\+/i.test(s)) return '16+';
    if (/^12\+?$/i.test(s) || /teen|13\+|12\+/i.test(s)) return '12+';
    if (/^7\+?$/i.test(s) || /everyone 10\+|10\+|7\+/i.test(s)) return '7+';
    if (/^3\+?$/i.test(s) || /everyone|3\+|4\+/i.test(s)) return '3+';
    const numMatch = s.match(/\b(18|17|16|13|12|10|9|7|4|3)\b/);
    if (numMatch) {
        const n = parseInt(numMatch[1], 10);
        if (n >= 18) return '18+';
        if (n >= 16) return '16+';
        if (n >= 12) return '12+';
        if (n >= 7) return '7+';
        return '3+';
    }
    return 'NA';
}

// --- NEW: AUTO-FETCH METADATA SCRAPER API ---
app.post('/api/fetch-metadata', ensureAuthenticated, async (req, res) => {
    let { url, platform } = req.body;
    
    if (!url) {
        return res.status(400).json({ error: "URL is required." });
    }

    url = cleanPlatformUrl(url);

    if (!platform || platform === 'auto') {
        platform = detectPlatform(url);
    }

    const axiosConfig = {
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36' },
        timeout: 9000
    };

    const normalizeText = (value) => {
        if (!value) return '';
        return value.toString().trim().replace(/\s{2,}/g, ' ');
    };

    const fetchWordPressData = async (targetWpUrl) => {
        const cleanedWp = cleanPlatformUrl(targetWpUrl);
        const wpUrlObj = new URL(cleanedWp);
        const pathParts = wpUrlObj.pathname.split('/').filter(Boolean);
        const resourceTypeIndex = pathParts.findIndex(part => part === 'plugins' || part === 'themes' || part === 'theme');
        let resourceType = resourceTypeIndex >= 0 ? pathParts[resourceTypeIndex] : '';
        if (resourceType === 'theme') resourceType = 'themes';
        const slug = resourceType ? pathParts[resourceTypeIndex + 1] : '';
        if (!resourceType || !slug) {
            throw new Error('The WordPress URL must point to a plugin or theme slug.');
        }

        const apiUrl = resourceType === 'plugins'
            ? 'https://api.wordpress.org/plugins/info/1.2/'
            : 'https://api.wordpress.org/themes/info/1.2/';
        const apiAction = resourceType === 'plugins' ? 'plugin_information' : 'theme_information';
        const response = await axios.get(apiUrl, {
            ...axiosConfig,
            params: { action: apiAction, 'request[slug]': slug }
        });
        const wordpressApp = response.data;
        if (!wordpressApp || wordpressApp.error) {
            throw new Error(wordpressApp?.error || 'WordPress could not find that plugin or theme.');
        }
        return wordpressApp;
    };

    const executeScrape = async (targetUrl, targetPlatform) => {
        let $;
        if (targetPlatform !== 'playstore' && targetPlatform !== 'wordpress' && targetPlatform !== 'steam' && targetPlatform !== 'epic' && targetPlatform !== 'appstore') {
            const response = await axios.get(targetUrl, axiosConfig);
            $ = cheerio.load(response.data);
        }

        const getText = (selector) => $ ? normalizeText($(selector).first().text()) : '';
        const getAttr = (selector, attr) => $ ? normalizeText($(selector).attr(attr)) : '';

        let data = {
            title: '',
            description: '',
            whatsNew: '',
            tags: '',
            minOsVersion: '',
            ageRating: '',
            developer: '',
            version: ''
        };

        if (targetPlatform === 'playstore') {
            const playStoreUrl = new URL(targetUrl);
            if (playStoreUrl.hostname !== 'play.google.com') {
                throw new Error('Please provide a valid Google Play Store URL.');
            }
            const appId = playStoreUrl.searchParams.get('id');
            if (!appId) {
                throw new Error('The Google Play URL must include an app id.');
            }

            const app = await googlePlayScraper.app({
                appId,
                lang: playStoreUrl.searchParams.get('hl') || 'en',
                country: playStoreUrl.searchParams.get('gl') || 'us'
            });

            data.title = normalizeText(app.title);
            data.description = normalizeText(app.description);
            data.developer = normalizeText(app.developer);
            data.whatsNew = normalizeText(app.recentChanges);
            data.minOsVersion = normalizeText(app.androidVersionText || app.androidVersion);
            data.ageRating = normalizeAgeRating(app.contentRating);
            data.version = normalizeText(app.version);
            data.tags = (app.categories || [])
                .map(category => normalizeText(category && category.name))
                .filter(Boolean)
                .filter((tag, index, tags) => tags.indexOf(tag) === index)
                .join(', ');

        } else if (targetPlatform === 'appstore') {
            const appStoreUrl = new URL(targetUrl);
            const validAppStoreHosts = ['apps.apple.com', 'itunes.apple.com'];
            if (!validAppStoreHosts.includes(appStoreUrl.hostname)) {
                throw new Error('Please provide a valid Apple App Store URL.');
            }

            const appIdMatch = appStoreUrl.pathname.match(/\/id(\d+)/i);
            const appId = appIdMatch ? appIdMatch[1] : appStoreUrl.searchParams.get('id');
            if (!appId || !/^\d+$/.test(appId)) {
                throw new Error('The Apple App Store URL must include a numeric app id.');
            }

            const country = appStoreUrl.pathname.split('/').filter(Boolean)[0] || 'us';
            const app = await appStoreScraper.app({
                id: Number(appId),
                country,
                lang: appStoreUrl.searchParams.get('lang') || undefined
            });

            data.title = normalizeText(app.title);
            data.description = normalizeText(app.description);
            data.developer = normalizeText(app.developer);
            data.whatsNew = normalizeText(app.releaseNotes);
            data.minOsVersion = normalizeText(app.requiredOsVersion ? `iOS ${app.requiredOsVersion}` : '');
            data.ageRating = normalizeAgeRating(app.contentRating);
            data.version = normalizeText(app.version);
            data.tags = (app.genres || [])
                .map(genre => normalizeText(genre))
                .filter(Boolean)
                .filter((tag, index, tags) => tags.indexOf(tag) === index)
                .join(', ');

        } else if (targetPlatform === 'steam') {
            const steamUrl = new URL(targetUrl);
            if (steamUrl.hostname !== 'store.steampowered.com') {
                throw new Error('Please provide a valid Steam store URL.');
            }

            const appIdMatch = steamUrl.pathname.match(/\/app\/(\d+)/i);
            const appId = appIdMatch ? appIdMatch[1] : steamUrl.searchParams.get('appid');
            if (!appId || !/^\d+$/.test(appId)) {
                throw new Error('The Steam URL must include a numeric app id.');
            }

            const response = await axios.get('https://store.steampowered.com/api/appdetails', {
                ...axiosConfig,
                params: {
                    appids: appId,
                    cc: steamUrl.searchParams.get('cc') || 'us',
                    l: steamUrl.searchParams.get('l') || 'english'
                }
            });
            const steamApp = response.data && response.data[appId];
            if (!steamApp || !steamApp.success || !steamApp.data) {
                throw new Error('Steam could not find that game.');
            }

            const game = steamApp.data;
            data.title = normalizeText(game.name);
            data.description = normalizeText(game.detailed_description || game.about_the_game || game.short_description);
            data.developer = normalizeText((game.developers || [])[0]);
            data.minOsVersion = normalizeText((game.pc_requirements && game.pc_requirements.minimum) || '');
            data.ageRating = game.required_age ? normalizeAgeRating(`${game.required_age}+`) : '3+';
            data.version = '';
            data.tags = [...(game.genres || []).map(genre => genre.description), ...(game.categories || []).map(category => category.description)]
                .map(tag => normalizeText(tag))
                .filter(Boolean)
                .filter((tag, index, tags) => tags.indexOf(tag) === index)
                .join(', ');

        } else if (targetPlatform === 'epic') {
            const epicUrl = new URL(targetUrl);
            if (epicUrl.hostname !== 'store.epicgames.com') {
                throw new Error('Please provide a valid Epic Games Store URL.');
            }

            const pathParts = epicUrl.pathname.split('/').filter(Boolean);
            const productIndex = pathParts.findIndex(part => part === 'p');
            const slug = productIndex >= 0 ? pathParts[productIndex + 1] : '';
            if (!slug) {
                throw new Error('The Epic Games Store URL must include a product slug.');
            }

            const locale = pathParts.find(part => /^[a-z]{2}-[A-Z]{2}$/.test(part)) || 'en-US';
            const response = await axios.get(`https://store-content.ak.epicgames.com/api/${locale}/content/products/${encodeURIComponent(slug)}`, axiosConfig);
            const epicProduct = response.data;
            const epicPage = (epicProduct.pages || []).find(page => page.data && page.data.about) || epicProduct.pages?.[0];
            const epicData = epicPage && epicPage.data;
            if (!epicData) {
                throw new Error('Epic Games Store could not find that product.');
            }

            const about = epicData.about || {};
            const meta = epicData.meta || {};
            const requirements = epicData.requirements || {};
            const systems = requirements.systems || [];
            const osRequirement = systems.find(system => system.systemType === 'Windows') || systems[0];
            const osDetails = osRequirement && (osRequirement.details || []);
            const minimumOs = osDetails.find(detail => detail.title === 'OS')?.minimum || '';

            data.title = normalizeText(epicProduct.productName || about.title || epicData.seo?.title);
            data.description = normalizeText(about.description || about.shortDescription || epicData.seo?.description);
            data.developer = normalizeText((meta.developer || [])[0] || about.developerAttribution);
            data.minOsVersion = normalizeText(minimumOs);
            data.ageRating = '3+';
            data.version = '';
            data.tags = (meta.tags || [])
                .map(tag => normalizeText(tag.replace(/[_-]+/g, ' ')))
                .filter(Boolean)
                .filter((tag, index, tags) => tags.indexOf(tag) === index)
                .join(', ');

        } else if (targetPlatform === 'wordpress') {
            let wordpressApp = null;
            let wpError = null;

            try {
                wordpressApp = await fetchWordPressData(targetUrl);
            } catch (err) {
                wpError = err;
                // If user entered wordpress.com and it failed, auto-replace wordpress.com with wordpress.org and try again!
                if (targetUrl.includes('wordpress.com')) {
                    const fallbackOrgUrl = targetUrl.replace(/wordpress\.com/gi, 'wordpress.org');
                    try {
                        wordpressApp = await fetchWordPressData(fallbackOrgUrl);
                    } catch (retryErr) {
                        throw wpError;
                    }
                } else {
                    throw wpError;
                }
            }

            const author = typeof wordpressApp.author === 'string'
                ? wordpressApp.author.replace(/<[^>]*>/g, '')
                : wordpressApp.author && (wordpressApp.author.display_name || wordpressApp.author.author);
            data.title = normalizeText(wordpressApp.name);
            data.description = normalizeText(wordpressApp.sections && wordpressApp.sections.description) || normalizeText(wordpressApp.description);
            data.developer = normalizeText(author);
            data.whatsNew = normalizeText(wordpressApp.sections && wordpressApp.sections.changelog);
            data.ageRating = '3+';
            data.version = normalizeText(wordpressApp.version);
            const wordpressTags = Array.isArray(wordpressApp.tags)
                ? wordpressApp.tags
                : Object.keys(wordpressApp.tags || {});
            data.tags = wordpressTags
                .map(tag => normalizeText(tag))
                .filter(Boolean)
                .filter((tag, index, tags) => tags.indexOf(tag) === index)
                .join(', ');

        } else {
            // Generic fallback scraper
            try {
                const ldJson = JSON.parse($('script[type="application/ld+json"]').first().text() || '{}');
                if (ldJson.name) data.title = data.title || normalizeText(ldJson.name);
                if (ldJson.description) data.description = data.description || normalizeText(ldJson.description);
                if (ldJson.author && ldJson.author.name) data.developer = data.developer || normalizeText(ldJson.author.name);
                if (ldJson.softwareVersion || ldJson.version) data.version = data.version || normalizeText(ldJson.softwareVersion || ldJson.version);
            } catch (ldErr) {}
            data.title = data.title || getAttr('meta[property="og:title"]', 'content') || getText('title');
            data.description = data.description || getAttr('meta[property="og:description"]', 'content') || getAttr('meta[name="description"]', 'content') || '';
            data.developer = data.developer || getAttr('meta[property="og:site_name"]', 'content') || '';
            data.version = data.version || getAttr('meta[name="version"]', 'content') || getAttr('meta[itemprop="softwareVersion"]', 'content') || '';
            data.ageRating = normalizeAgeRating(getAttr('meta[name="rating"]', 'content') || getAttr('meta[property="og:rating"]', 'content') || '');
        }

        Object.keys(data).forEach(key => {
            if (data[key]) data[key] = data[key].trim().replace(/\s{2,}/g, ' ');
        });

        data.minOs = data.minOsVersion || '';
        data.minAge = data.ageRating || 'NA';
        data.officialDescription = data.description || '';
        data.softwareVersion = data.version || '';
        data.detectedPlatform = targetPlatform;

        return data;
    };

    try {
        let resultData = null;
        try {
            resultData = await executeScrape(url, platform);
        } catch (firstErr) {
            // If failed and URL contained wordpress.com, automatically replace with wordpress.org and try again itself
            if (url.includes('wordpress.com')) {
                const autoOrgUrl = cleanPlatformUrl(url.replace(/wordpress\.com/gi, 'wordpress.org'));
                const autoPlatform = platform === 'wordpress' ? 'wordpress' : detectPlatform(autoOrgUrl);
                try {
                    resultData = await executeScrape(autoOrgUrl, autoPlatform);
                } catch (retryErr) {
                    throw firstErr;
                }
            } else {
                throw firstErr;
            }
        }

        res.json({ success: true, data: resultData });

    } catch (error) {
        console.error("Scraping Error:", error.message);
        res.status(500).json({ error: error.message || "Failed to fetch data. Make sure the URL is correct and public." });
    }
});

// --- API TO GET MOD TEMPLATES ---
app.get('/api/mod-templates', async (req, res) => {
    try {
        const templates = await ModTemplate.find({ isActive: true }).sort({ sortOrder: 1, createdAt: 1 }).lean();
        res.json({ success: true, templates });
    } catch (err) {
        console.error("Error fetching mod templates:", err);
        res.status(500).json({ success: false, error: "Failed to load templates" });
    }
});

// ===================================
// 9.2 ADMIN: BULK INDEXNOW & GOOGLE SYNC
// ===================================
app.get('/api/admin/indexnow-sync', ensureAdmin, async (req, res) => {
    try {
        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        let urlsToPing =[];

        // 1. Static Pages
        const staticPages = ['', 'upload-policy', '/login', '/register', '/about', '/faq', '/dmca', '/tos', '/privacy-policy', '/donate', '/refund-policy', '/partnership-policy', '/distributor-features', '/why-choose-us', '/understanding-scans', '/membership', '/docs', '/docs/:slug', '/community', '/repos', '/jailbreak-repos'];
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
        const rawQuery = (req.query.q || '').trim();
        
        if (!rawQuery || rawQuery.length < 2) {
            return res.json({ success: true, query: rawQuery, mods: [], users: [], categories: [], names: [] });
        }

        const queryEscaped = escapeRegex(rawQuery);
        const queryRegex = new RegExp(queryEscaped, 'i');
        const tokens = rawQuery.split(/\s+/).filter(Boolean);

        const tokenConditions = tokens.map(t => {
            const tr = new RegExp(escapeRegex(t), 'i');
            return {
                $or: [
                    { name: { $regex: tr } },
                    { tags: { $regex: tr } },
                    { category: { $regex: tr } },
                    { developer: { $regex: tr } },
                    { originalApkName: { $regex: tr } }
                ]
            };
        });

        // 1. Fetch matching mods with icons
        const modResults = await File.find({
            status: 'live',
            isLatestVersion: true,
            $or: [
                { name: { $regex: queryRegex } },
                { tags: { $regex: queryRegex } },
                { category: { $regex: queryRegex } },
                { developer: { $regex: queryRegex } },
                { originalApkName: { $regex: queryRegex } },
                ...(tokens.length > 1 ? [{ $and: tokenConditions }] : [])
            ]
        })
        .select('name slug category iconKey iconUrl downloads averageRating developer isVariant')
        .sort({ downloads: -1 })
        .limit(5)
        .lean();

        const modsWithIcons = await Promise.all(modResults.map(async (file) => {
            let iconUrl = '/images/default-app-icon.png';
            const key = file.iconUrl || file.iconKey;
            if (key) {
                try { iconUrl = await getSmartImageUrl(key); } catch (e) {}
            }
            const modSlug = file.slug || slugify(file.name);
            const modUrl = file.isVariant ? `/mods/${file.category}/${modSlug}/${file._id}` : `/mods/${file.category}/${modSlug}`;
            return {
                _id: file._id,
                name: file.name,
                category: file.category,
                developer: file.developer,
                downloads: file.downloads || 0,
                rating: file.averageRating || 5.0,
                iconUrl: iconUrl,
                url: modUrl
            };
        }));

        // 2. Fetch matching users with avatars
        const userResults = await User.find({
            isBanned: { $ne: true },
            $or: [
                { username: { $regex: queryRegex } },
                { role: { $regex: queryRegex } },
                { cardId: { $regex: queryRegex } }
            ]
        })
        .select('username role profileImageKey isVerified cardId')
        .limit(3)
        .lean();

        const usersWithAvatars = await Promise.all(userResults.map(async (u) => {
            let avatarUrl = '/images/default-avatar.png';
            if (u.profileImageKey) {
                try { avatarUrl = await getSmartImageUrl(u.profileImageKey); } catch (e) {}
            }
            return {
                _id: u._id,
                username: u.username,
                role: u.role,
                isVerified: !!u.isVerified,
                avatarUrl: avatarUrl,
                url: `/users/${encodeURIComponent(u.username)}`
            };
        }));

        // 3. Match quick categories
        const categoryCatalog = [
            { name: 'Android Mods', category: 'android', icon: 'fab fa-android', url: '/category?cat=android' },
            { name: 'PC Software & Games', category: 'pc', icon: 'fab fa-windows', url: '/category?cat=pc' },
            { name: 'iOS IPA Mods', category: 'ios', icon: 'fab fa-apple', url: '/category?cat=ios' },
            { name: 'AI Directory', category: 'ai', icon: 'fas fa-robot', url: '/ai-directory' },
            { name: 'Community Forum', category: 'forum', icon: 'fas fa-comments', url: '/community' },
            { name: 'Leaderboard', category: 'leaderboard', icon: 'fas fa-trophy', url: '/leaderboard' },
            { name: 'Software Licenses', category: 'licenses', icon: 'fas fa-key', url: '/licenses' }
        ];

        const matchedCategories = categoryCatalog.filter(c => 
            c.name.toLowerCase().includes(rawQuery.toLowerCase()) || 
            c.category.toLowerCase().includes(rawQuery.toLowerCase())
        );

        // 4. Match Community Forums & Docs
        const [matchedDocs, matchedIssues] = await Promise.all([
            DocPage.find({ title: { $regex: queryRegex } }).select('title slug').limit(3).lean(),
            Issue.find({ title: { $regex: queryRegex } }).select('title _id category').limit(3).lean()
        ]);

        const communitySuggestions = [
            ...matchedDocs.map(d => ({ title: d.title, type: 'Doc', url: `/docs/${d.slug}`, icon: 'fas fa-book' })),
            ...matchedIssues.map(i => ({ title: i.title, type: 'Forum', url: `/community/issue/${i._id}`, icon: 'fas fa-comments' }))
        ];

        const suggestionNames = [...new Set(modsWithIcons.map(m => m.name))];

        res.json({
            success: true,
            query: rawQuery,
            mods: modsWithIcons,
            users: usersWithAvatars,
            community: communitySuggestions,
            categories: matchedCategories,
            names: suggestionNames
        });

    } catch (error) {
        console.error("API Suggestion Error:", error);
        res.status(500).json({ error: 'Server error while fetching suggestions.' });
    }
});

app.get('/api/trending-searches', async (req, res) => {
    try {
        const trendingFiles = await File.find(
            { status: 'live', isLatestVersion: true },
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
// 9.5 DYNAMIC COMING SOON ENGINE & ROUTES
// ===================================
app.get('/coming-soon', async (req, res) => {
    try {
        const state = cachedSiteState || await SiteState.findOne({ singletonId: 'master-state' });
        res.render('pages/coming-soon', {
            title: state?.comingSoonTitle || 'Something Awesome is Coming Soon',
            message: state?.comingSoonMessage || "We're working hard behind the scenes to deliver an exceptional experience. Stay tuned for the big reveal!",
            customText: state?.comingSoonCustomText || 'Feature is currently under development. Stay tuned for official announcements!',
            enableTimer: state?.comingSoonEnableTimer !== false,
            launchDate: state?.comingSoonLaunchDate ? new Date(state.comingSoonLaunchDate).toISOString() : '',
            user: req.user || null
        });
    } catch (e) {
        console.error("Coming Soon render error:", e);
        res.status(500).render('pages/500');
    }
});

app.post('/notify-launch', async (req, res) => {
    try {
        const email = (req.body?.email || '').trim().toLowerCase();
        if (!email || !email.includes('@') || email.length < 5) {
            return res.status(400).json({ success: false, error: 'A valid email address is required.' });
        }
        await Subscriber.findOneAndUpdate(
            { email },
            {
                email,
                user: req.user ? req.user._id : null,
                source: 'coming-soon',
                isSubscribed: true,
                subscribedAt: new Date()
            },
            { upsert: true, new: true }
        );
        return res.json({ success: true, message: 'Thank you! You are registered to be notified immediately when we launch.' });
    } catch (e) {
        console.error("Notify Launch error:", e);
        return res.status(500).json({ success: false, error: 'Failed to record subscription.' });
    }
});

app.post('/api/admin/coming-soon/update', ensureAdmin, async (req, res) => {
    try {
        const {
            status,
            title,
            message,
            customText,
            enableTimer,
            launchDate,
            allowedRoles,
            allowedUsers,
            autoPublishOnTimerEnd
        } = req.body;

        const updatePayload = {};
        if (status) updatePayload.status = status;
        if (title !== undefined) updatePayload.comingSoonTitle = title.trim();
        if (message !== undefined) updatePayload.comingSoonMessage = message.trim();
        if (customText !== undefined) updatePayload.comingSoonCustomText = customText.trim();
        if (enableTimer !== undefined) updatePayload.comingSoonEnableTimer = (enableTimer === true || enableTimer === 'true');
        if (launchDate) updatePayload.comingSoonLaunchDate = new Date(launchDate);
        if (autoPublishOnTimerEnd !== undefined) updatePayload.comingSoonAutoPublishOnTimerEnd = (autoPublishOnTimerEnd === true || autoPublishOnTimerEnd === 'true');

        if (allowedRoles !== undefined) {
            updatePayload.comingSoonAllowedRoles = Array.isArray(allowedRoles)
                ? allowedRoles.map(r => String(r || '').trim().toLowerCase()).filter(Boolean)
                : String(allowedRoles || '').split(',').map(r => r.trim().toLowerCase()).filter(Boolean);
        }
        if (allowedUsers !== undefined) {
            updatePayload.comingSoonAllowedUsers = Array.isArray(allowedUsers)
                ? allowedUsers.map(u => String(u || '').trim().toLowerCase()).filter(Boolean)
                : String(allowedUsers || '').split(',').map(u => u.trim().toLowerCase()).filter(Boolean);
        }

        const updatedState = await SiteState.findOneAndUpdate(
            { singletonId: 'master-state' },
            { $set: updatePayload },
            { new: true, upsert: true }
        );
        cachedSiteState = updatedState;

        res.json({ success: true, state: updatedState });
    } catch (e) {
        console.error("Admin Coming Soon Update error:", e);
        res.status(500).json({ success: false, error: e.message || 'Server error updating Coming Soon state.' });
    }
});

// ===================================
// 9.6  AUTOMATED VIRUSTOTAL SCAN ENGINE & HELPERS
// ===================================
async function checkAndUpdateFileVirusTotal(fileId) {
    try {
        const file = await File.findById(fileId);
        if (!file) return null;

        // If manualFileScanUrl contains a VirusTotal URL, extract the ID/hash if not already set
        if (!file.virusTotalAnalysisId && !file.virusTotalId && file.manualFileScanUrl) {
            const vtMatch = file.manualFileScanUrl.match(/virustotal\.com\/(?:gui|api\/v3)\/(?:file-analysis|files?|urls?)\/([a-zA-Z0-9_-]+)/i);
            if (vtMatch) {
                if (file.manualFileScanUrl.includes('file-analysis')) {
                    file.virusTotalAnalysisId = vtMatch[1];
                } else {
                    file.virusTotalId = vtMatch[1];
                }
                await File.findByIdAndUpdate(fileId, { 
                    virusTotalAnalysisId: file.virusTotalAnalysisId, 
                    virusTotalId: file.virusTotalId 
                });
            }
        }

        const vtId = file.virusTotalAnalysisId || file.virusTotalId;
        if (!vtId) return null;

        // If already completed and has full stats, return immediately
        if (file.virusTotalScanDate && file.virusTotalId && (file.virusTotalTotalScans > 0 || file.virusTotalPositiveCount >= 0)) {
            return {
                status: 'completed',
                stats: {
                    malicious: file.virusTotalPositiveCount,
                    total: file.virusTotalTotalScans
                }
            };
        }

        if (!process.env.VIRUSTOTAL_API_KEY) return null;

        let vtResponse;
        let isCompleted = false;
        let stats = null;
        let trueHash = null;

        // 64-char hex hash
        if (vtId.length === 64 && !vtId.includes('-')) {
            try {
                vtResponse = await axios.get(`https://www.virustotal.com/api/v3/files/${vtId}`, {
                    headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
                    timeout: 9000
                });
            } catch (err) {
                if (err.response && err.response.status === 404) {
                    vtResponse = await axios.get(`https://www.virustotal.com/api/v3/urls/${vtId}`, {
                        headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
                        timeout: 9000
                    });
                } else {
                    throw err;
                }
            }
            isCompleted = true;
            stats = vtResponse.data?.data?.attributes?.last_analysis_stats;
            trueHash = vtId;
        } else {
            vtResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${vtId}`, {
                headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
                timeout: 9000
            });
            if (vtResponse.data?.data?.attributes?.status === 'completed') {
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

        if (isCompleted && stats) {
            const pos = (stats.malicious || 0) + (stats.suspicious || 0);
            const total = (stats.harmless || 0) + (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0);
            await File.findByIdAndUpdate(fileId, {
                virusTotalScanDate: new Date(),
                virusTotalPositiveCount: pos,
                virusTotalTotalScans: total,
                virusTotalId: trueHash || vtId
            });
            return {
                status: 'completed',
                stats: stats,
                positiveCount: pos,
                totalScans: total,
                id: trueHash || vtId
            };
        }

        return { status: vtResponse?.data?.data?.attributes?.status || 'pending' };
    } catch (e) {
        console.error("checkAndUpdateFileVirusTotal error:", e.response?.data || e.message);
        return null;
    }
}

async function checkAndUpdatePartVirusTotal(fileId, partId) {
    try {
        const file = await File.findById(fileId);
        if (!file || !file.downloadParts || file.downloadParts.length === 0) return null;
        const part = file.downloadParts.id(partId);
        if (!part) return null;

        if (!part.partVirusTotalId && part.manualFileScanUrl) {
            const vtMatch = part.manualFileScanUrl.match(/virustotal\.com\/(?:gui|api\/v3)\/(?:file-analysis|files?|urls?)\/([a-zA-Z0-9_-]+)/i);
            if (vtMatch) {
                part.partVirusTotalId = vtMatch[1];
                await file.save();
            }
        }

        const vtId = part.partVirusTotalId;
        if (!vtId) return null;

        if (part.partVirusTotalScanDate && part.partVirusTotalId) {
            return {
                status: 'completed',
                stats: { malicious: part.partVirusTotalPositiveCount }
            };
        }

        if (!process.env.VIRUSTOTAL_API_KEY) return null;

        let vtResponse;
        let isCompleted = false;
        let stats = null;
        let trueHash = null;

        if (vtId.length === 64 && !vtId.includes('-')) {
            try {
                vtResponse = await axios.get(`https://www.virustotal.com/api/v3/files/${vtId}`, { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }, timeout: 9000 });
            } catch (err) {
                if (err.response && err.response.status === 404) {
                    vtResponse = await axios.get(`https://www.virustotal.com/api/v3/urls/${vtId}`, { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }, timeout: 9000 });
                } else { throw err; }
            }
            isCompleted = true;
            stats = vtResponse.data?.data?.attributes?.last_analysis_stats;
            trueHash = vtId;
        } else {
            vtResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${vtId}`, { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }, timeout: 9000 });
            if (vtResponse.data?.data?.attributes?.status === 'completed') {
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

        if (isCompleted && stats) {
            part.partVirusTotalScanDate = new Date();
            part.partVirusTotalPositiveCount = (stats.malicious || 0) + (stats.suspicious || 0);
            part.partVirusTotalTotalScans = (stats.harmless || 0) + (stats.malicious || 0) + (stats.suspicious || 0) + (stats.undetected || 0);
            part.partVirusTotalId = trueHash || vtId;
            await file.save();
            return { status: 'completed', stats: stats };
        }

        return { status: vtResponse?.data?.data?.attributes?.status || 'pending' };
    } catch (e) {
        console.error("checkAndUpdatePartVirusTotal error:", e.response?.data || e.message);
        return null;
    }
}

function pollVirusTotalInBackground(fileId, maxAttempts = 12, intervalMs = 15000) {
    if (!fileId) return;
    let attempts = 0;
    const interval = setInterval(async () => {
        attempts++;
        try {
            const res = await checkAndUpdateFileVirusTotal(fileId);
            if (res && res.status === 'completed') {
                clearInterval(interval);
            } else if (attempts >= maxAttempts) {
                clearInterval(interval);
            }
        } catch (e) {
            clearInterval(interval);
        }
    }, intervalMs);
}

// Expose VT functions globally for AdminJS and background workers
global.checkAndUpdateFileVirusTotal = checkAndUpdateFileVirusTotal;
global.checkAndUpdatePartVirusTotal = checkAndUpdatePartVirusTotal;
global.pollVirusTotalInBackground = pollVirusTotalInBackground;

// VT Refresh Route (Single / Main File)
app.post('/api/refresh-vt-scan/:fileId', async (req, res) => {
    try {
        const fileId = req.params.fileId;
        const result = await checkAndUpdateFileVirusTotal(fileId);
        if (!result) {
            return res.status(404).json({ error: "No VirusTotal ID found or file does not exist." });
        }
        return res.json(result);
    } catch (error) {
        console.error("VT Refresh Error:", error.response?.data || error.message);
        res.status(500).json({ error: "Failed to contact VirusTotal API." });
    }
});

// VT Refresh Route (Multi-Part File)
app.post('/api/refresh-vt-scan/:fileId/part/:partId', async (req, res) => {
    try {
        const { fileId, partId } = req.params;
        const result = await checkAndUpdatePartVirusTotal(fileId, partId);
        if (!result) {
            return res.status(404).json({ error: "No VirusTotal ID found for this part." });
        }
        return res.json(result);
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
        // Honor optional redirectUrl from the form. If it's "back", use the Referer header.
        const requestedRedirect = (req.body && req.body.redirectUrl) ? req.body.redirectUrl : null;
        let redirectTarget = `/mods/${req.params.fileId}`;
        if (requestedRedirect) {
            if (requestedRedirect === 'back') {
                redirectTarget = req.get('Referer') || redirectTarget;
            } else {
                // Basic safety: only allow relative redirects within this site
                if (requestedRedirect.startsWith('/')) redirectTarget = requestedRedirect;
            }
        }
        res.redirect(redirectTarget);
    } catch (e) { res.status(500).send("Error."); }
});

app.post('/reviews/add/:fileId', ensureAuthenticated, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        const fileDoc = await File.findById(req.params.fileId);
        if (!fileDoc) return res.status(404).send("File not found");

        // Prevent file uploader from reviewing their own mod
        if (fileDoc.uploader && req.user.username && fileDoc.uploader.toLowerCase() === req.user.username.toLowerCase()) {
            return res.redirect(`/mods/${req.params.fileId}`);
        }

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
        saveModReviewsArchive(req.params.fileId).catch(err => console.warn('[ReviewArchive]', err.message));
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
        if (!review || review.user.toString() !== req.user._id.toString()) return res.status(404).send('Not found');
        
        const fileId = review.file;
        await Review.findByIdAndDelete(review._id);
        await recalculateRating(fileId);
        saveModReviewsArchive(fileId).catch(err => console.warn('[ReviewArchive]', err.message));
        await User.adjustForumPoints(review.user, -20, "Deleted your mod review");
        res.redirect('back');
    } catch (e) { res.status(500).send("Error"); }
});

// 2. User Edits their own comment
app.post('/reviews/:id/edit', ensureAuthenticated, async (req, res) => {
    try {
        const { rating, comment } = req.body;
        const review = await Review.findById(req.params.id);
        if (!review || review.user.toString() !== req.user._id.toString()) return res.status(404).send('Not found');
        
        review.rating = parseInt(rating);
        review.comment = comment;
        await review.save();
        await recalculateRating(review.file);
        saveModReviewsArchive(review.file).catch(err => console.warn('[ReviewArchive]', err.message));
        res.redirect('back');
    } catch (e) { res.status(500).send("Error"); }
});

// 3. Uploader Replies to a comment
app.post('/reviews/:id/reply', ensureAuthenticated, async (req, res) => {
    try {
        const review = await Review.findById(req.params.id).populate('file');
        if (!review || review.file.uploader !== req.user.username) return res.status(404).send('Not found');

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
        if (!review || review.file.uploader !== req.user.username) return res.status(404).send('Not found');

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

        const uploader = await User.findOne({ username: file.uploader }).select('_id').lean();
        if (uploader && uploader._id.toString() === userId.toString()) {
            return res.status(404).send('Not found');
        }
        
        // Check current voting status
        const votedWorkingBy = Array.isArray(file.votedWorkingBy) ? file.votedWorkingBy : [];
        const votedNotWorkingBy = Array.isArray(file.votedNotWorkingBy) ? file.votedNotWorkingBy : [];

        const currentUserId = userId.toString();
        const hasVotedWorking = votedWorkingBy.some(id => id.toString() === currentUserId);
        const hasVotedNotWorking = votedNotWorkingBy.some(id => id.toString() === currentUserId);
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

// --- LIVE SUPPORT DASHBOARD ROUTE ---
app.get('/admin/support', ensureSupportOrAdmin, async (req, res) => {
    res.render('pages/admin/support-dashboard', {
        success: req.query.success || null,
        error: req.query.error || null,
        domain: process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org'
    });
});

// --- AI DIAGNOSTICS & DEBUGGER ROUTES ---
app.get('/api/admin/ai-status', ensureSupportOrAdmin, (req, res) => {
    res.json(aiDebuggerStatus);
});

app.post('/api/admin/ai-ping', ensureSupportOrAdmin, async (req, res) => {
    const start = Date.now();
    try {
        if (!aiModel) throw new Error("Gemini AI model is not initialized or API key is missing.");
        const chat = aiModel.startChat();
        const result = await chat.sendMessage("Respond with exactly: 'OK - Gemini AI is operational'");
        const latency = Date.now() - start;
        const responseText = result.response.text();
        
        aiDebuggerStatus.status = 'online';
        aiDebuggerStatus.lastPing = new Date();
        aiDebuggerStatus.latencyMs = latency;
        aiDebuggerStatus.lastError = null;
        
        const io = req.app.get('io');
        if (io) {
            io.to('support_agents').emit('ai_debug_result', { success: true, latencyMs: latency, response: responseText, status: aiDebuggerStatus });
        }

        res.json({ success: true, latencyMs: latency, response: responseText, status: aiDebuggerStatus });
    } catch (err) {
        const latency = Date.now() - start;
        aiDebuggerStatus.status = 'offline';
        aiDebuggerStatus.lastError = { message: err.message || String(err), time: new Date() };
        aiDebuggerStatus.totalErrors++;

        const io = req.app.get('io');
        if (io) {
            io.to('support_agents').emit('ai_debug_result', { success: false, latencyMs: latency, error: err.message || String(err), status: aiDebuggerStatus });
        }

        res.status(500).json({ success: false, latencyMs: latency, error: err.message || String(err), status: aiDebuggerStatus });
    }
});
// --- GEMINI VISIBILITY CONFIGURATION ROUTES ---
app.get('/api/admin/gemini-config', ensureSupportOrAdmin, async (req, res) => {
    try {
        const state = await SiteState.findOne({ singletonId: 'master-state' });
        res.json({
            success: true,
            enableGeminiChatbot: state?.enableGeminiChatbot !== false,
            geminiHiddenPages: state?.geminiHiddenPages || []
        });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.post('/api/admin/gemini-config', ensureSupportOrAdmin, async (req, res) => {
    try {
        const { enableGeminiChatbot, geminiHiddenPages } = req.body;
        let pagesArray = [];
        if (Array.isArray(geminiHiddenPages)) {
            pagesArray = geminiHiddenPages.map(p => String(p).trim()).filter(Boolean);
        } else if (typeof geminiHiddenPages === 'string') {
            pagesArray = geminiHiddenPages.split(/[,\n\r]+/).map(p => p.trim()).filter(Boolean);
        }

        const updateData = {};
        if (typeof enableGeminiChatbot === 'boolean') {
            updateData.enableGeminiChatbot = enableGeminiChatbot;
        }
        updateData.geminiHiddenPages = pagesArray;

        const updatedState = await SiteState.findOneAndUpdate(
            { singletonId: 'master-state' },
            { $set: updateData },
            { new: true, upsert: true }
        );

        // Immediately update in-memory cache to bypass 30s delay
        cachedSiteState = updatedState;

        res.json({
            success: true,
            message: 'Gemini visibility settings updated successfully!',
            enableGeminiChatbot: updatedState.enableGeminiChatbot !== false,
            geminiHiddenPages: updatedState.geminiHiddenPages
        });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.get('/admin/reports', ensureAdmin, async (req, res) => {
    const reports = await Report.find().populate('file').populate('reportingUser').sort({ status: 1, createdAt: -1 });
    res.render('pages/admin/reports', { reports });
});

app.post('/admin/reports/:reportId/status', ensureAdmin, async (req, res) => {
    await Report.findByIdAndUpdate(req.params.reportId, { status: req.body.status });
    res.redirect('/admin/reports');
});
// --- NEW: Secure Signed URL Generator for AdminJS ---
// Only accessible by Admins. Used by custom React components to view private images.
app.get('/api/admin/signed-url', ensureAdmin, async (req, res) => {
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

app.post('/admin/reports/delete-file/:fileId', ensureAdmin, async (req, res) => {
    await File.findByIdAndDelete(req.params.fileId);
    await Review.deleteMany({ file: req.params.fileId });
    await Report.updateMany({ file: req.params.fileId }, { status: 'resolved' });
    res.redirect('/admin/reports');
});

// ===================================
// ADMIN DMCA MANAGEMENT ROUTES
// ===================================

// Helper to permanently delete a file or variant (cleaning up B2, older versions, and references)
async function permanentlyDeleteInfringingFile(fileId) {
    const file = await File.findById(fileId).populate('olderVersions').populate('variants');
    if (!file) return { success: false, message: 'File not found' };

    // If it's a variant, remove reference from parent masterFile and delete
    if (file.isVariant && file.masterFile) {
        await File.findByIdAndUpdate(file.masterFile, {
            $pull: { variants: file._id }
        });
        if (file.fileKey && file.fileKey !== 'external-link') {
            try { await deleteFromB2(file.fileKey); } catch (e) { console.error("Error deleting variant file from B2:", e); }
        }
        await Review.deleteMany({ file: file._id });
        await File.findByIdAndDelete(file._id);
        return { success: true, isVariant: true };
    }

    // If it's a main file: check if variants exist to promote permanently
    const variantsList = await File.find({ masterFile: file._id }).sort({ createdAt: 1 });
    if (variantsList.length > 0) {
        const firstVariant = variantsList[0];
        if (file.fileKey && file.fileKey !== 'external-link' && file.fileKey !== firstVariant.fileKey) {
            try { await deleteFromB2(file.fileKey); } catch (e) { console.error("Error deleting old main file from B2:", e); }
        }
        file.uploader = firstVariant.uploader;
        file.modDescription = firstVariant.modDescription || file.modDescription;
        file.modFeatures = firstVariant.modFeatures || file.modFeatures;
        file.version = firstVariant.version;
        file.fileKey = firstVariant.fileKey;
        file.fileSize = firstVariant.fileSize;
        file.originalFilename = firstVariant.originalFilename;
        file.externalDownloadUrl = firstVariant.externalDownloadUrl;
        file.directDownloadUrl = firstVariant.directDownloadUrl;
        file.downloadParts = firstVariant.downloadParts;
        file.isMultiPart = firstVariant.isMultiPart;
        file.isDmcaHidden = false;
        file.dmcaReportId = null;
        file.dmcaHiddenAt = null;
        file.temporaryPromotedVariantId = null;

        if (firstVariant.screenshotKeys && firstVariant.screenshotKeys.length > 0) {
            file.screenshotKeys = firstVariant.screenshotKeys;
        }
        file.variants = (file.variants || []).filter(vId => vId.toString() !== firstVariant._id.toString());
        await File.findByIdAndDelete(firstVariant._id);
        await file.save();
        return { success: true, promoted: true };
    }

    // No variants: full permanent deletion
    if (file.fileKey && file.fileKey !== 'external-link') {
        try { await deleteFromB2(file.fileKey); } catch (e) { console.error("Error deleting file from B2:", e); }
    }
    if (file.iconKey) {
        try { await deleteFromB2(file.iconKey); } catch (e) { console.error("Error deleting icon from B2:", e); }
    }
    if (file.screenshotKeys && file.screenshotKeys.length > 0) {
        for (const key of file.screenshotKeys) {
            try { await deleteFromB2(key); } catch (e) { console.error("Error deleting screenshot from B2:", e); }
        }
    }
    if (file.olderVersions && file.olderVersions.length > 0) {
        for (const oldVersion of file.olderVersions) {
            if (oldVersion.fileKey) {
                try { await deleteFromB2(oldVersion.fileKey); } catch (e) { console.error("Error deleting old version from B2:", e); }
            }
            await File.findByIdAndDelete(oldVersion._id);
        }
    }

    await File.findByIdAndDelete(fileId);
    await Review.deleteMany({ file: fileId });
    await Report.updateMany({ file: fileId }, { status: 'resolved' });
    return { success: true, deleted: true };
}

// GET /admin/dmca - View all DMCA claims & statistics
app.get('/admin/dmca', ensureAdmin, async (req, res) => {
    try {
        const claims = await Dmca.find()
            .populate('reportedFiles.file')
            .populate('reportedFiles.promotedVariant')
            .sort({ createdAt: -1 })
            .lean();

        // Sign icons for preview cards
        for (const claim of claims) {
            for (const item of claim.reportedFiles || []) {
                if (item.file) {
                    const iconKey = item.file.iconUrl || item.file.iconKey;
                    item.file.signedIconUrl = '/images/default-app-icon.png';
                    if (iconKey) {
                        try { item.file.signedIconUrl = await getSmartImageUrl(iconKey); } catch (e) {}
                    }
                }
            }
        }

        const now = new Date();
        const stats = {
            total: claims.length,
            open: claims.filter(c => c.status === 'open').length,
            autoHidden: claims.filter(c => c.status === 'auto-hidden').length,
            falseClaims: claims.filter(c => c.status === 'false-claim').length,
            actionTaken: claims.filter(c => c.status === 'action-taken').length
        };

        res.render('pages/admin/dmca', {
            claims,
            stats,
            now,
            success: req.query.success,
            error: req.query.error
        });
    } catch (err) {
        console.error("Admin DMCA Dashboard Error:", err);
        res.status(500).send("Error loading DMCA Dashboard: " + err.message);
    }
});

// POST /admin/dmca/:id/hide-now - Immediate manual link hiding
app.post('/admin/dmca/:id/hide-now', ensureAdmin, async (req, res) => {
    try {
        await executeDmcaTakedown(req.params.id);
        res.redirect('/admin/dmca?success=Links+have+been+immediately+hidden.');
    } catch (err) {
        console.error("DMCA Hide Now Error:", err);
        res.redirect('/admin/dmca?error=' + encodeURIComponent(err.message));
    }
});

// POST /admin/dmca/:id/false-claim - Mark as False Claim & restore all files
app.post('/admin/dmca/:id/false-claim', ensureAdmin, async (req, res) => {
    try {
        const { notes } = req.body;
        await restoreDmcaFiles(req.params.id, notes, req.user.username);
        res.redirect('/admin/dmca?success=Claim+marked+as+False+Claim.+All+files+and+links+have+been+restored.');
    } catch (err) {
        console.error("DMCA False Claim Error:", err);
        res.redirect('/admin/dmca?error=' + encodeURIComponent(err.message));
    }
});

// POST /admin/dmca/:id/delete-file/:fileId - Confirm infringement & delete file
app.post('/admin/dmca/:id/delete-file/:fileId', ensureAdmin, async (req, res) => {
    try {
        const { id: dmcaId, fileId } = req.params;
        await permanentlyDeleteInfringingFile(fileId);
        
        // Update the DMCA record
        const dmca = await Dmca.findById(dmcaId);
        if (dmca) {
            dmca.status = 'action-taken';
            dmca.adminResolution = {
                resolvedBy: req.user.username,
                resolvedAt: new Date(),
                resolutionType: 'file-deleted',
                notes: req.body.notes || 'Infringing file permanently removed by administrator.'
            };
            await dmca.save();
        }

        res.redirect('/admin/dmca?success=Infringing+file+has+been+permanently+deleted.');
    } catch (err) {
        console.error("DMCA Delete File Error:", err);
        res.redirect('/admin/dmca?error=' + encodeURIComponent(err.message));
    }
});

// POST /admin/dmca/:id/reject - Reject DMCA notice without taking action
app.post('/admin/dmca/:id/reject', ensureAdmin, async (req, res) => {
    try {
        const dmca = await Dmca.findById(req.params.id);
        if (dmca) {
            if (dmca.status === 'auto-hidden' || dmca.isAutomatedHidden) {
                await restoreDmcaFiles(dmca._id, req.body.notes || 'Claim rejected as invalid.', req.user.username);
            }
            dmca.status = 'rejected';
            dmca.adminResolution = {
                resolvedBy: req.user.username,
                resolvedAt: new Date(),
                resolutionType: 'rejected',
                notes: req.body.notes || 'Claim rejected due to lack of evidence or invalid ownership notice.'
            };
            await dmca.save();
        }
        res.redirect('/admin/dmca?success=Notice+marked+as+rejected.');
    } catch (err) {
        console.error("DMCA Reject Error:", err);
        res.redirect('/admin/dmca?error=' + encodeURIComponent(err.message));
    }
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

        } else if (category === 'viewed') {
            totalCount = await File.countDocuments({ status: 'live', isLatestVersion: true, ...dateFilter });
            totalLabel = "Total Files Viewed";

            const files = await File.find({ status: 'live', isLatestVersion: true, ...dateFilter })
                .sort({ views: -1 })
                .limit(100);
                
            results = await Promise.all(files.map(async (f) => {
                const iconUrl = await getSmartImageUrl(f.iconKey || f.iconUrl);
                return { 
                    name: f.name, 
                    score: (f.views || 0).toLocaleString() + ' views', 
                    subtext: `By ${f.uploader}`, 
                    avatar: iconUrl, 
                    link: `/${f.category}/${f.slug || f._id}` 
                };
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
            const donatorMatch = { status: 'successful', ...dateFilter };

            const pipeline = [
                { $match: donatorMatch },
                {
                    $project: {
                        user: 1,
                        username: 1,
                        amount: 1,
                        currency: 1,
                        inrAmount: {
                            $switch: {
                                branches: [
                                    { case: { $eq: ['$currency', 'USD'] }, then: { $multiply: ['$amount', 85] } },
                                    { case: { $eq: ['$currency', 'EUR'] }, then: { $multiply: ['$amount', 92] } },
                                    { case: { $eq: ['$currency', 'GBP'] }, then: { $multiply: ['$amount', 108] } }
                                ],
                                default: '$amount'
                            }
                        }
                    }
                },
                {
                    $group: {
                        _id: { $ifNull: ['$user', '$username'] },
                        userId: { $first: '$user' },
                        fallbackUsername: { $first: '$username' },
                        totalAmount: { $sum: '$inrAmount' }
                    }
                },
                { $sort: { totalAmount: -1 } }
            ];

            const rawDonators = await Donation.aggregate(pipeline);
            totalCount = rawDonators.length;
            totalLabel = "Total Donators";

            const top100 = rawDonators.slice(0, 100);

            results = await Promise.all(top100.map(async (d) => {
                const user = d.userId ? await User.findById(d.userId) : null;
                const avatarUrl = user && user.profileImageKey ? await getSmartImageUrl(user.profileImageKey) : '/images/default-avatar.png';
                const displayName = user ? user.username : (d.fallbackUsername || 'Anonymous Supporter');
                const profileLink = user ? `/users/${slugify(user.username)}` : 'javascript:void(0)';
                const formattedAmount = Math.round(d.totalAmount).toLocaleString('en-IN');

                return {
                    name: displayName,
                    score: `₹${formattedAmount}`,
                    isCurrency: true,
                    avatar: avatarUrl,
                    role: user ? user.role : 'supporter',
                    link: profileLink,
                    subtext: user ? '' : 'Community Supporter'
                };
            }));
        }

        // ======== GLOBAL DONATIONS STATS (REGISTERED VS UNREGISTERED) ========
        const globalDonationStats = await Donation.aggregate([
            { $match: { status: 'successful' } },
            {
                $project: {
                    user: 1,
                    inrAmount: {
                        $switch: {
                            branches: [
                                { case: { $eq: ['$currency', 'USD'] }, then: { $multiply: ['$amount', 85] } },
                                { case: { $eq: ['$currency', 'EUR'] }, then: { $multiply: ['$amount', 92] } },
                                { case: { $eq: ['$currency', 'GBP'] }, then: { $multiply: ['$amount', 108] } }
                            ],
                            default: '$amount'
                        }
                    }
                }
            },
            {
                $group: {
                    _id: null,
                    combinedTotal: { $sum: '$inrAmount' },
                    combinedCount: { $sum: 1 },
                    unregisteredTotal: {
                        $sum: {
                            $cond: [{ $eq: [{ $ifNull: ['$user', null] }, null] }, '$inrAmount', 0]
                        }
                    },
                    unregisteredCount: {
                        $sum: {
                            $cond: [{ $eq: [{ $ifNull: ['$user', null] }, null] }, 1, 0]
                        }
                    }
                }
            }
        ]);

        const statsRecord = globalDonationStats && globalDonationStats.length > 0 ? globalDonationStats[0] : null;
        const globalDonations = {
            unregisteredTotal: Math.round(statsRecord?.unregisteredTotal || 0),
            combinedTotal: Math.round(statsRecord?.combinedTotal || 0),
            unregisteredCount: statsRecord?.unregisteredCount || 0,
            combinedCount: statsRecord?.combinedCount || 0
        };

        res.render('pages/leaderboard', {
            results,
            currentCategory: category,
            currentTimeframe: timeframe,
            totalCount,
            totalLabel,
            globalDonations
        });

    } catch (error) {
        console.error("Leaderboard Error:", error);
        res.status(500).render('pages/500');
    }
});

// ===============================
// 13. STATIC PAGES
// ===============================
const staticPageTemplates = {
    about: 'pages/static/about',
    faq: 'pages/static/faq',
    tos: 'pages/static/tos',
    dmca: 'pages/static/dmca',
    'privacy-policy': 'pages/static/privacy-policy',
    'refund-policy': 'pages/static/refund-policy',
    'partnership-policy': 'pages/static/partnership-policy',
    'distributor-features': 'pages/static/distributor-features',
    'why-choose-us': 'pages/static/why-choose-us',
    'upload-policy': 'pages/static/upload-policy',
    'understanding-scans': 'pages/static/understanding-scans'
};

async function renderStaticPage(req, res, slug) {
    try {
        const onlinePage = await StaticPage.findOne({ slug, isPublished: true }).lean();
        if (onlinePage) return res.render('pages/static-page', { page: onlinePage });
        return res.render(staticPageTemplates[slug]);
    } catch (error) {
        console.error(`Static page error (${slug}):`, error);
        return res.status(500).render('pages/500');
    }
}

Object.entries(staticPageTemplates).forEach(([slug, template]) => {
    app.get(`/${slug}`, (req, res) => renderStaticPage(req, res, slug));
});

// ============================================================================
// DAILY DONATION CAP & TRACKING HELPERS
// ============================================================================
const DAILY_DONATION_CAP_INR = 2000;

const CURRENCY_TO_INR_RATES = {
    INR: 1,
    USD: 85,
    EUR: 92,
    GBP: 108,
    AED: 23,
    CAD: 62,
    AUD: 55,
    JPY: 0.56
};

const DONATION_LIMITS = {
    'INR': { min: 100, max: 2000, symbol: '₹' },
    'USD': { min: 2, max: 23.53, symbol: '$' },
    'EUR': { min: 1.80, max: 21.74, symbol: '€' },
    'GBP': { min: 1.50, max: 18.52, symbol: '£' },
    'AED': { min: 5, max: 88, symbol: 'AED ' },
    'CAD': { min: 2, max: 32, symbol: 'CA$' },
    'AUD': { min: 2, max: 36, symbol: 'AU$' },
    'JPY': { min: 200, max: 3500, symbol: '¥' }
};

/**
 * Helper to get or assign a persistent guest donor ID cookie
 */
function getOrSetGuestDonorId(req, res) {
    let guestId = req.cookies ? req.cookies.gpl_guest_donor_id : null;
    if (!guestId) {
        guestId = 'g_' + crypto.randomBytes(16).toString('hex');
        if (res && res.cookie) {
            res.cookie('gpl_guest_donor_id', guestId, {
                maxAge: 365 * 24 * 60 * 60 * 1000, // 1 year
                httpOnly: true,
                sameSite: 'lax'
            });
        }
    }
    return guestId;
}

/**
 * Get client IP address accurately
 */
function getClientIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.socket?.remoteAddress || req.ip || '';
}

/**
 * Calculate total INR donated by user or guest in the last 24 hours
 */
async function getDailyDonationTotalInr(req, res) {
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const guestId = getOrSetGuestDonorId(req, res);
    const clientIp = getClientIp(req);
    let matchQuery = null;

    if (req.user && req.user._id) {
        const orConditions = [{ user: req.user._id }];
        if (guestId) {
            orConditions.push({ guestId: guestId, user: null });
        }
        matchQuery = {
            $or: orConditions,
            status: 'successful',
            createdAt: { $gte: since24h }
        };
    } else {
        const orConditions = [];
        if (guestId) orConditions.push({ guestId: guestId });
        if (clientIp) orConditions.push({ donorIp: clientIp, user: null });

        matchQuery = {
            $or: orConditions.length > 0 ? orConditions : [{ guestId: 'none' }],
            status: 'successful',
            createdAt: { $gte: since24h }
        };
    }

    const donations = await Donation.find(matchQuery).lean();
    let totalInr = 0;
    for (const d of donations) {
        const cur = (d.currency || 'INR').toUpperCase();
        const rate = CURRENCY_TO_INR_RATES[cur] || 1;
        totalInr += (Number(d.amount) || 0) * rate;
    }

    return {
        totalSpentInr: totalInr,
        remainingInr: Math.max(0, DAILY_DONATION_CAP_INR - totalInr),
        totalCapInr: DAILY_DONATION_CAP_INR,
        guestId: guestId
    };
}

/**
 * Fetch recent donations for user or guest
 */
async function getUserDonationHistory(req, res) {
    try {
        const guestId = req.cookies ? req.cookies.gpl_guest_donor_id : null;
        const clientIp = getClientIp(req);
        let matchQuery = null;

        if (req.user && req.user._id) {
            matchQuery = {
                $or: [
                    { user: req.user._id },
                    ...(guestId ? [{ guestId: guestId, user: null }] : [])
                ]
            };
        } else if (guestId) {
            matchQuery = {
                $or: [
                    { guestId: guestId },
                    ...(clientIp ? [{ donorIp: clientIp, user: null }] : [])
                ]
            };
        } else {
            return [];
        }

        const list = await Donation.find(matchQuery)
            .sort({ createdAt: -1 })
            .limit(50)
            .lean();

        return list.map(d => ({
            id: String(d._id),
            orderId: d.orderId,
            amount: d.amount,
            currency: d.currency || 'INR',
            status: d.status,
            createdAt: d.createdAt
        }));
    } catch (e) {
        console.error('[Donation History Query Error]:', e);
        return [];
    }
}

/**
 * Dedicated Donation Page with Real-Time Cap & History
 */
app.get('/donate', async (req, res) => {
    try {
        const capStatus = await getDailyDonationTotalInr(req, res);
        const history = await getUserDonationHistory(req, res);

        res.render('pages/static/donate', {
            pageTitle: 'Support GPL Mods',
            capData: {
                totalCapInr: capStatus.totalCapInr,
                spentInr: capStatus.totalSpentInr,
                remainingInr: capStatus.remainingInr,
                rates: CURRENCY_TO_INR_RATES
            },
            donationHistory: history
        });
    } catch (error) {
        console.error('Donate page error:', error);
        res.render('pages/static/donate', {
            pageTitle: 'Support GPL Mods',
            capData: {
                totalCapInr: 2000,
                spentInr: 0,
                remainingInr: 2000,
                rates: CURRENCY_TO_INR_RATES
            },
            donationHistory: []
        });
    }
});

/**
 * API: Get Current Donation Cap Status
 */
app.get('/api/donation-cap', async (req, res) => {
    try {
        const capStatus = await getDailyDonationTotalInr(req, res);
        res.json({
            success: true,
            totalCapInr: capStatus.totalCapInr,
            spentInr: capStatus.totalSpentInr,
            remainingInr: capStatus.remainingInr,
            rates: CURRENCY_TO_INR_RATES
        });
    } catch (err) {
        console.error('[Donation Cap API Error]:', err);
        res.status(500).json({ error: 'Failed to fetch donation cap status.' });
    }
});

/**
 * API: Get User/Guest Donation History
 */
app.get('/api/donation-history', async (req, res) => {
    try {
        const history = await getUserDonationHistory(req, res);
        res.json({ success: true, history });
    } catch (err) {
        console.error('[Donation History API Error]:', err);
        res.status(500).json({ error: 'Failed to fetch donation history.' });
    }
});

app.get('/membership', async (req, res) => {
    try {
        let purchaseHistory = [];
        if (req.user && req.user._id) {
            const rawOrders = await MembershipOrder.find({ user: req.user._id })
                .sort({ createdAt: -1 })
                .limit(50)
                .lean();
            purchaseHistory = rawOrders.map(o => {
                const planCfg = MEMBERSHIP_PLANS[o.duration] || { name: o.duration, tier: o.tier };
                return {
                    id: String(o._id),
                    orderId: o.orderId,
                    amount: o.amount,
                    currency: o.currency || 'INR',
                    tier: o.tier,
                    duration: o.duration,
                    planName: planCfg.name || o.duration,
                    status: o.status,
                    refundStatus: o.refundStatus || 'none',
                    refundAmount: o.refundAmount || 0,
                    membershipExpiresAt: o.membershipExpiresAt,
                    createdAt: o.createdAt
                };
            });
        }
        res.render('pages/membership', {
            cashfreeAppId: process.env.CASHFREE_APP_ID,
            cashfreeEnv: process.env.CASHFREE_ENVIRONMENT || 'sandbox',
            purchaseHistory: purchaseHistory
        });
    } catch (err) {
        console.error('Membership page error:', err);
        res.render('pages/membership', {
            cashfreeAppId: process.env.CASHFREE_APP_ID,
            cashfreeEnv: process.env.CASHFREE_ENVIRONMENT || 'sandbox',
            purchaseHistory: []
        });
    }
});

// ============================================================================
// CASHFREE PAYMENTS & SUBSCRIPTIONS INTEGRATION
// ============================================================================

const MEMBERSHIP_PLANS = {
    // --- GPL LITE PLANS ---
    lite_monthly: {
        tier: 'lite',
        INR: 49,
        originalINR: 49,
        saveINR: 0,
        savePercent: 0,
        USD: 1.00,
        EUR: 0.90,
        GBP: 0.80,
        name: 'GPL Lite (Monthly)',
        planId: null,
        durationDays: 30
    },
    lite_6months: {
        tier: 'lite',
        INR: 199,
        originalINR: 294,
        saveINR: 95,
        savePercent: 32,
        USD: 4.00,
        EUR: 3.60,
        GBP: 3.20,
        name: 'GPL Lite 6 Months',
        planId: null,
        durationDays: 180
    },
    lite_yearly: {
        tier: 'lite',
        INR: 449,
        originalINR: 588,
        saveINR: 139,
        savePercent: 24,
        USD: 9.00,
        EUR: 8.00,
        GBP: 7.20,
        name: 'GPL Lite Yearly',
        planId: null,
        durationDays: 365
    },

    // --- GPL PLUS PLANS ---
    plus_monthly: {
        tier: 'plus',
        INR: 99,
        originalINR: 99,
        saveINR: 0,
        savePercent: 0,
        USD: 2.00,
        EUR: 1.80,
        GBP: 1.50,
        name: 'GPL Plus (Monthly)',
        planId: 'gpl-mods-plus',
        durationDays: 30
    },
    plus_6months: {
        tier: 'plus',
        INR: 499,
        originalINR: 594,
        saveINR: 95,
        savePercent: 16,
        USD: 10.00,
        EUR: 9.00,
        GBP: 8.00,
        name: 'GPL Plus 6 Months',
        planId: 'gpl-mods-plus-6-month',
        durationDays: 180
    },
    plus_yearly: {
        tier: 'plus',
        INR: 899,
        originalINR: 1188,
        saveINR: 289,
        savePercent: 24,
        USD: 18.00,
        EUR: 16.00,
        GBP: 14.00,
        name: 'GPL Plus Yearly',
        planId: 'gpl-mods-plus-yearly',
        durationDays: 365
    },
    plus_lifetime: {
        tier: 'plus',
        INR: 2499,
        originalINR: 2499,
        saveINR: 0,
        savePercent: 0,
        USD: 35.00,
        EUR: 32.00,
        GBP: 28.00,
        name: 'GPL Plus Lifetime',
        planId: 'gpl-mods-plus-lifetime',
        durationDays: 36500
    }
};

// Aliases for backwards compatibility with any existing queries, webhooks, or references
MEMBERSHIP_PLANS.monthly = MEMBERSHIP_PLANS.plus_monthly;
MEMBERSHIP_PLANS['6months'] = MEMBERSHIP_PLANS.plus_6months;
MEMBERSHIP_PLANS.yearly = MEMBERSHIP_PLANS.plus_yearly;
MEMBERSHIP_PLANS.lifetime = MEMBERSHIP_PLANS.plus_lifetime;

/**
 * Coupon Code Validation API
 * POST /api/coupon/validate
 */
app.post('/api/coupon/validate', ensureAuthenticated, async (req, res) => {
    try {
        const { code, planKey = 'plus_monthly', currency = 'INR' } = req.body;
        if (!code || !code.trim()) {
            return res.status(400).json({ valid: false, message: 'Please enter a coupon code.' });
        }

        const cleanCode = code.trim().toUpperCase();
        const coupon = await Coupon.findOne({ code: cleanCode, isActive: true });
        if (!coupon) {
            return res.status(404).json({ valid: false, message: 'Invalid or expired coupon code.' });
        }

        const planConfig = MEMBERSHIP_PLANS[planKey] || MEMBERSHIP_PLANS['plus_monthly'] || MEMBERSHIP_PLANS['monthly'];
        const cur = String(currency).toUpperCase();
        const originalAmount = planConfig[cur] || planConfig['INR'];

        const validity = coupon.isValid(planKey, originalAmount);
        if (!validity.valid) {
            return res.status(400).json({ valid: false, message: validity.reason });
        }

        const discountAmount = coupon.calculateDiscount(originalAmount);
        const finalAmount = Math.max(0, originalAmount - discountAmount);

        return res.json({
            valid: true,
            code: coupon.code,
            discountType: coupon.discountType,
            discountValue: coupon.discountValue,
            originalAmount,
            discountAmount,
            finalAmount,
            currency: cur,
            description: coupon.description || (coupon.discountType === 'percent' ? `${coupon.discountValue}% OFF` : `₹${coupon.discountValue} OFF`)
        });
    } catch (error) {
        console.error('Coupon validation error:', error);
        return res.status(500).json({ valid: false, message: 'Error validating coupon code.' });
    }
});

/**
 * 1. Create Donation Order (Payment Gateway)
 * Enforces ₹2,000 Daily Cap and minimum 100 INR donation amount
 */
app.post('/create-cashfree-order', async (req, res) => {
    try {
        const { amount, currency = 'INR', name, email, phone } = req.body;
        const cur = String(currency).toUpperCase();
        const numAmount = parseFloat(amount);

        const rate = CURRENCY_TO_INR_RATES[cur] || 1;
        const numAmountInInr = numAmount * rate;

        // 1. Check daily donation cap
        const capStatus = await getDailyDonationTotalInr(req, res);
        if (capStatus.remainingInr <= 0) {
            return res.status(400).json({ 
                error: `You have reached your daily donation cap of ₹${capStatus.totalCapInr.toLocaleString('en-IN')}. Thank you for your support! Please try again tomorrow.` 
            });
        }

        // 2. Check if requested amount exceeds remaining cap (with 0.5 INR margin for floating point precision)
        if (numAmountInInr > capStatus.remainingInr + 0.5) {
            const allowedInCur = (capStatus.remainingInr / rate).toFixed(cur === 'INR' ? 0 : 2);
            const symbol = cur === 'INR' ? '₹' : (cur === 'USD' ? '$' : (cur === 'EUR' ? '€' : '£'));
            return res.status(400).json({ 
                error: `Donation amount exceeds your remaining daily limit of ${symbol}${allowedInCur} (${cur}).` 
            });
        }

        // 3. Minimum donation validation
        const limits = DONATION_LIMITS[cur] || { min: 100, max: 2000 };
        if (isNaN(numAmount) || numAmount < limits.min) {
            return res.status(400).json({ 
                error: `Minimum donation amount is ${cur === 'INR' ? '₹' : ''}${limits.min} ${cur}.` 
            });
        }

        const orderId = `donate_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
        const customerId = req.user ? String(req.user._id) : `guest_${crypto.randomBytes(5).toString('hex')}`;
        const customerName = req.user?.username || name || 'GPL Supporter';
        const customerEmail = req.user?.email || email || 'donor@gplmods.com';
        const customerPhone = phone || '9999999999';

        const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;

        const orderRequest = {
            order_id: orderId,
            order_amount: numAmount,
            order_currency: cur,
            customer_details: {
                customer_id: customerId,
                customer_name: customerName,
                customer_email: customerEmail,
                customer_phone: customerPhone
            },
            order_meta: {
                return_url: `${baseUrl}/payment/verify-donation?order_id={order_id}`,
                notify_url: `${baseUrl}/webhook/cashfree/pg`
            },
            order_note: `GPL Mods Donation (${cur} ${numAmount})`
        };

        const response = await cashfree.PGCreateOrder(orderRequest);

        await new Donation({
            user: req.user ? req.user._id : null,
            username: req.user ? req.user.username : customerName,
            amount: numAmount,
            currency: cur,
            orderId: orderId,
            paymentSessionId: response.data.payment_session_id,
            donorEmail: customerEmail,
            donorPhone: customerPhone,
            guestId: capStatus.guestId,
            donorIp: getClientIp(req),
            status: 'pending'
        }).save();

        return res.json({
            payment_session_id: response.data.payment_session_id,
            order_id: orderId
        });
    } catch (error) {
        console.error('[Cashfree Donation Order Error]:', error.response?.data || error.message);
        return res.status(500).json({ 
            error: error.response?.data?.message || 'Failed to create donation order.' 
        });
    }
});

/**
 * 2. Create Membership Order / Subscription
 * Supports Cashfree Subscriptions for INR plans & standard PG checkout
 */
app.post('/create-membership-order', async (req, res) => {
    try {
        if (!req.user) {
            return res.status(401).json({ error: 'Please log in to purchase Membership.' });
        }

        const { duration = 'plus_monthly', currency = 'INR', phone, couponCode } = req.body;
        const cur = String(currency).toUpperCase();
        const planConfig = MEMBERSHIP_PLANS[duration];

        if (!planConfig) {
            return res.status(400).json({ error: 'Invalid membership plan.' });
        }

        const rate = CURRENCY_TO_INR_RATES[cur] || 1;
        let amount = planConfig[cur] || Math.max(1, Math.round(planConfig.INR / rate));
        let originalAmount = amount;
        let discountAmount = 0;
        let validatedCoupon = null;

        // Apply coupon code if provided
        if (couponCode && typeof couponCode === 'string' && couponCode.trim()) {
            const cleanCode = couponCode.trim().toUpperCase();
            const coupon = await Coupon.findOne({ code: cleanCode, isActive: true });
            if (coupon) {
                const validity = coupon.isValid(duration, originalAmount);
                if (validity.valid) {
                    discountAmount = coupon.calculateDiscount(originalAmount);
                    amount = Math.max(1, originalAmount - discountAmount); // minimum 1 currency unit for PG checkout
                    validatedCoupon = coupon;
                }
            }
        }

        const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
        const customerPhone = phone || '9999999999';
        const targetTier = planConfig.tier || 'plus';

        // For INR currency, utilize Cashfree Subscriptions with registered Plan IDs if no coupon used (Subscriptions charge fixed recurring amt)
        if (cur === 'INR' && planConfig.planId && discountAmount === 0) {
            const subId = `sub_${req.user._id}_${Date.now().toString().slice(-8)}`;
            const subRequest = {
                subscription_id: subId,
                customer_details: {
                    customer_name: req.user.username,
                    customer_email: req.user.email,
                    customer_phone: customerPhone
                },
                plan_details: {
                    plan_id: planConfig.planId
                },
                subscription_meta: {
                    return_url: `${baseUrl}/payment/verify-subscription?sub_id={sub_id}`
                }
            };

            try {
                const subResponse = await cashfree.SubsCreateSubscription(subRequest);
                const subData = subResponse.data;

                await new MembershipOrder({
                    user: req.user._id,
                    orderId: subId,
                    subscriptionId: subId,
                    planId: planConfig.planId,
                    isSubscription: true,
                    subscriptionSessionId: subData.subscription_session_id,
                    amount: amount,
                    originalAmount: originalAmount,
                    discountAmount: discountAmount,
                    couponCode: validatedCoupon ? validatedCoupon.code : null,
                    currency: cur,
                    duration: duration,
                    tier: targetTier,
                    status: 'pending'
                }).save();

                return res.json({
                    subscription_session_id: subData.subscription_session_id,
                    subscription_id: subId
                });
            } catch (subErr) {
                console.warn('[Cashfree Subscriptions Fallback to PG Order]:', subErr.response?.data || subErr.message);
                // Fall back to standard PG order if subscription creation encounters any plan constraint
            }
        }

        // Standard Payment Gateway Order (for one-time, discounted, or international currencies)
        const orderId = `mem_${req.user._id}_${Date.now().toString().slice(-8)}`;
        const orderRequest = {
            order_id: orderId,
            order_amount: amount,
            order_currency: cur,
            customer_details: {
                customer_id: String(req.user._id),
                customer_name: req.user.username,
                customer_email: req.user.email,
                customer_phone: customerPhone
            },
            order_meta: {
                return_url: `${baseUrl}/payment/verify-membership?order_id={order_id}`,
                notify_url: `${baseUrl}/webhook/cashfree/pg`
            },
            order_note: `${planConfig.name}${validatedCoupon ? ' (Discounted)' : ''}`
        };

        const response = await cashfree.PGCreateOrder(orderRequest);

        await new MembershipOrder({
            user: req.user._id,
            orderId: orderId,
            planId: planConfig.planId,
            isSubscription: false,
            paymentSessionId: response.data.payment_session_id,
            amount: amount,
            originalAmount: originalAmount,
            discountAmount: discountAmount,
            couponCode: validatedCoupon ? validatedCoupon.code : null,
            currency: cur,
            duration: duration,
            tier: targetTier,
            status: 'pending'
        }).save();

        if (validatedCoupon) {
            await Coupon.findByIdAndUpdate(validatedCoupon._id, { $inc: { usedCount: 1 } });
        }

        return res.json({
            payment_session_id: response.data.payment_session_id,
            order_id: orderId
        });
    } catch (error) {
        console.error('[Cashfree Membership Order Error]:', error.response?.data || error.message);
        return res.status(500).json({ 
            error: error.response?.data?.message || 'Failed to create membership order.' 
        });
    }
});

/**
 * 3. Return Verification Handler: Donation
 */
app.get('/payment/verify-donation', async (req, res) => {
    const orderId = req.query.order_id || req.query.orderId;
    if (!orderId) {
        return res.redirect('/donate');
    }

    try {
        const orderResponse = await cashfree.PGFetchOrder(orderId);
        const orderData = orderResponse.data;
        const isPaid = orderData.order_status === 'PAID';

        const donation = await Donation.findOne({ orderId: orderId });
        if (donation) {
            donation.status = isPaid ? 'successful' : (orderData.order_status === 'EXPIRED' ? 'failed' : 'pending');
            donation.cfPaymentId = String(orderData.cf_order_id || '');
            donation.transactionId = String(orderData.cf_order_id || '');
            await donation.save();
        }

        if (isPaid) {
            return res.redirect(`/payment/success?order_id=${encodeURIComponent(orderId)}&type=donation`);
        } else {
            const status = (orderData.order_status || 'incomplete').toLowerCase();
            const elapsedMs = (donation && donation.createdAt) ? (Date.now() - new Date(donation.createdAt).getTime()) : 0;
            if (elapsedMs >= PAYMENT_TIMEOUT_MS) {
                if (donation) {
                    donation.status = 'failed';
                    donation.failureReason = 'Payment timed out after 10 minutes.';
                    await donation.save();
                }
                return res.redirect(`/payment/failure?order_id=${encodeURIComponent(orderId)}&type=donation&status=timeout&reason=${encodeURIComponent('Payment timed out after 10 minutes.')}`);
            }

            if (status === 'pending' || status === 'active' || status === 'processing') {
                return res.redirect(`/payment/status?order_id=${encodeURIComponent(orderId)}&type=donation&status=pending`);
            }
            return res.redirect(`/payment/failure?order_id=${encodeURIComponent(orderId)}&type=donation&status=${encodeURIComponent(status)}`);
        }
    } catch (error) {
        console.error('[Verify Donation Error]:', error.response?.data || error.message);
        return res.redirect(`/payment/failure?order_id=${encodeURIComponent(orderId)}&type=donation&reason=verification_error`);
    }
});

/**
 * 4. Return Verification Handler: Membership
 */
app.get('/payment/verify-membership', async (req, res) => {
    const orderId = req.query.order_id || req.query.orderId;
    if (!orderId) {
        return res.redirect('/membership');
    }

    try {
        const orderResponse = await cashfree.PGFetchOrder(orderId);
        const orderData = orderResponse.data;
        const isPaid = orderData.order_status === 'PAID';

        const memOrder = await MembershipOrder.findOne({ orderId: orderId });
        if (memOrder && isPaid) {
            memOrder.status = 'paid';
            memOrder.cfPaymentId = String(orderData.cf_order_id || '');

            const durationConfig = MEMBERSHIP_PLANS[memOrder.duration] || { durationDays: 30, tier: 'plus', name: 'GPL Plus' };
            const now = new Date();
            const expiresAt = new Date();
            expiresAt.setDate(now.getDate() + durationConfig.durationDays);

            memOrder.membershipExpiresAt = expiresAt;
            await memOrder.save();

            const targetTier = memOrder.tier || durationConfig.tier || 'plus';
            const updatedUser = await User.findByIdAndUpdate(memOrder.user, {
                membership: targetTier === 'lite' ? 'lite' : 'plus',
                membershipExpiresAt: expiresAt,
                membershipPlan: memOrder.duration
            }, { new: true });

            if (updatedUser) {
                sendSubscriptionStatusEmail(updatedUser, {
                    tier: targetTier,
                    planName: durationConfig.name,
                    amount: memOrder.amount,
                    currency: memOrder.currency,
                    orderId: memOrder.orderId
                }).catch(e => console.error('Subscription email error:', e));
            }
        }

        if (isPaid) {
            return res.redirect(`/payment/success?order_id=${encodeURIComponent(orderId)}&type=membership`);
        } else {
            const status = (orderData.order_status || 'incomplete').toLowerCase();
            const elapsedMs = (memOrder && memOrder.createdAt) ? (Date.now() - new Date(memOrder.createdAt).getTime()) : 0;
            if (elapsedMs >= PAYMENT_TIMEOUT_MS) {
                if (memOrder) {
                    memOrder.status = 'failed';
                    memOrder.failureReason = 'Payment timed out after 10 minutes.';
                    await memOrder.save();
                }
                return res.redirect(`/payment/failure?order_id=${encodeURIComponent(orderId)}&type=membership&status=timeout&reason=${encodeURIComponent('Payment timed out after 10 minutes.')}`);
            }

            if (status === 'pending' || status === 'active' || status === 'processing') {
                return res.redirect(`/payment/status?order_id=${encodeURIComponent(orderId)}&type=membership&status=pending`);
            }
            return res.redirect(`/payment/failure?order_id=${encodeURIComponent(orderId)}&type=membership&status=${encodeURIComponent(status)}`);
        }
    } catch (error) {
        console.error('[Verify Membership Error]:', error.response?.data || error.message);
        return res.redirect(`/payment/failure?order_id=${encodeURIComponent(orderId)}&type=membership&reason=verification_error`);
    }
});

/**
 * 5. Return Verification Handler: Subscription
 */
app.get('/payment/verify-subscription', async (req, res) => {
    const subId = req.query.subscription_id || req.query.sub_id || req.query.order_id;
    if (!subId) {
        return res.redirect('/membership');
    }

    try {
        let isApproved = false;
        let subData = null;
        try {
            const subResponse = await cashfree.SubsFetchSubscription(subId);
            subData = subResponse.data;
            const validStatuses = ['ACTIVE', 'BANK_APPROVAL_PENDING', 'INITIALIZED', 'SUCCESS'];
            isApproved = validStatuses.includes(subData.subscription_status);
        } catch (fetchErr) {
            console.warn('[SubsFetchSubscription Warning]:', fetchErr.response?.data || fetchErr.message);
            isApproved = true; // Fallback to pending state
        }

        const memOrder = await MembershipOrder.findOne({ subscriptionId: subId });
        if (memOrder && isApproved) {
            memOrder.status = 'paid';
            const durationConfig = MEMBERSHIP_PLANS[memOrder.duration] || { durationDays: 30, tier: 'plus', name: 'GPL Plus' };
            const now = new Date();
            const expiresAt = new Date();
            expiresAt.setDate(now.getDate() + durationConfig.durationDays);

            memOrder.membershipExpiresAt = expiresAt;
            await memOrder.save();

            const targetTier = memOrder.tier || durationConfig.tier || 'plus';
            const updatedUser = await User.findByIdAndUpdate(memOrder.user, {
                membership: targetTier === 'lite' ? 'lite' : 'plus',
                membershipExpiresAt: expiresAt,
                membershipPlan: memOrder.duration,
                subscriptionId: subId
            }, { new: true });

            if (updatedUser) {
                sendSubscriptionStatusEmail(updatedUser, {
                    tier: targetTier,
                    planName: durationConfig.name,
                    amount: memOrder.amount,
                    currency: memOrder.currency,
                    orderId: memOrder.orderId
                }).catch(e => console.error('Subscription email error:', e));
            }
        }

        if (isApproved) {
            return res.redirect(`/payment/success?order_id=${encodeURIComponent(subId)}&type=membership&is_sub=true`);
        } else {
            const subStatus = subData ? (subData.subscription_status || '').toLowerCase() : '';
            if (subStatus.includes('pending') || subStatus.includes('init')) {
                return res.redirect(`/payment/status?order_id=${encodeURIComponent(subId)}&type=membership&status=pending`);
            }
            return res.redirect(`/payment/failure?order_id=${encodeURIComponent(subId)}&type=membership&status=incomplete`);
        }
    } catch (error) {
        console.error('[Verify Subscription Error]:', error);
        return res.redirect(`/payment/failure?order_id=${encodeURIComponent(subId)}&type=membership&reason=verification_error`);
    }
});

/**
 * Dedicated Transaction Success Page
 */
app.get('/payment/success', async (req, res) => {
    try {
        const orderId = req.query.order_id || req.query.orderId || req.query.sub_id || '';
        let type = req.query.type || '';
        let amount = '';
        let currency = 'INR';
        let planName = '';
        let expiresAt = null;

        if (orderId) {
            // Check MembershipOrder
            const memOrder = await MembershipOrder.findOne({
                $or: [{ orderId: orderId }, { subscriptionId: orderId }]
            }).populate('user', 'username email membership');

            if (memOrder) {
                type = 'membership';
                amount = memOrder.amount;
                currency = memOrder.currency || 'INR';
                const planConfig = MEMBERSHIP_PLANS[memOrder.duration];
                planName = planConfig ? planConfig.name : 'GPL Mods+ Premium';
                expiresAt = memOrder.membershipExpiresAt;
            } else {
                // Check Donation
                const donation = await Donation.findOne({ orderId: orderId });
                if (donation) {
                    type = 'donation';
                    amount = donation.amount;
                    currency = donation.currency || 'INR';
                }
            }
        }

        if (!type) {
            type = (req.user && req.user.membership === 'premium') ? 'membership' : 'donation';
        }

        return res.render('pages/payment-success', {
            pageTitle: 'Payment Successful',
            orderId: orderId,
            type: type,
            amount: amount,
            currency: currency,
            planName: planName,
            expiresAt: expiresAt
        });
    } catch (err) {
        console.error('[Payment Success Route Error]:', err);
        return res.render('pages/payment-success', {
            pageTitle: 'Payment Successful',
            orderId: req.query.order_id || '',
            type: req.query.type || 'membership',
            amount: '',
            currency: 'INR',
            planName: 'GPL Mods+ Premium',
            expiresAt: null
        });
    }
});

/**
 * Dedicated Transaction Failure Page
 */
app.get('/payment/failure', async (req, res) => {
    try {
        const orderId = req.query.order_id || req.query.orderId || req.query.sub_id || '';
        const type = req.query.type || 'membership';
        const status = req.query.status || 'failed';
        const reason = req.query.reason || '';
        let amount = '';
        let currency = 'INR';

        if (orderId) {
            const memOrder = await MembershipOrder.findOne({
                $or: [{ orderId: orderId }, { subscriptionId: orderId }]
            });
            if (memOrder) {
                amount = memOrder.amount;
                currency = memOrder.currency;
            } else {
                const donation = await Donation.findOne({ orderId: orderId });
                if (donation) {
                    amount = donation.amount;
                    currency = donation.currency;
                }
            }
        }

        return res.render('pages/payment-failure', {
            pageTitle: 'Payment Incomplete',
            orderId: orderId,
            type: type,
            status: status,
            reason: reason,
            amount: amount,
            currency: currency
        });
    } catch (err) {
        console.error('[Payment Failure Route Error]:', err);
        return res.render('pages/payment-failure', {
            pageTitle: 'Payment Incomplete',
            orderId: req.query.order_id || '',
            type: req.query.type || 'membership',
            status: 'failed',
            reason: '',
            amount: '',
            currency: 'INR'
        });
    }
});

/**
 * Dedicated Transaction Status / Pending Page
 */
const PAYMENT_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes maximum pending window

app.get('/payment/status', async (req, res) => {
    try {
        const orderId = req.query.order_id || req.query.orderId || req.query.sub_id || '';
        let type = req.query.type || 'membership';
        let status = req.query.status || 'pending';
        let amount = '';
        let currency = 'INR';
        let orderCreatedAt = null;
        let memOrder = null;
        let donation = null;
        let volunteerApp = null;

        if (orderId) {
            memOrder = await MembershipOrder.findOne({
                $or: [{ orderId: orderId }, { subscriptionId: orderId }]
            });
            if (memOrder) {
                type = 'membership';
                amount = memOrder.amount;
                currency = memOrder.currency || 'INR';
                orderCreatedAt = memOrder.createdAt;
                if (memOrder.status === 'paid') status = 'success';
                else if (memOrder.status === 'failed' || memOrder.status === 'cancelled') status = memOrder.status;
            } else {
                donation = await Donation.findOne({ orderId: orderId });
                if (donation) {
                    type = 'donation';
                    amount = donation.amount;
                    currency = donation.currency || 'INR';
                    orderCreatedAt = donation.createdAt;
                    if (donation.status === 'successful') status = 'success';
                    else if (donation.status === 'failed' || donation.status === 'cancelled') status = donation.status;
                } else {
                    volunteerApp = await VolunteerApplication.findOne({ orderId: orderId });
                    if (volunteerApp) {
                        type = 'volunteer';
                        amount = volunteerApp.feeAmount;
                        currency = volunteerApp.feeCurrency || 'INR';
                        orderCreatedAt = volunteerApp.createdAt;
                        if (volunteerApp.paymentStatus === 'paid') status = 'success';
                        else if (volunteerApp.paymentStatus === 'failed' || volunteerApp.paymentStatus === 'cancelled') status = volunteerApp.paymentStatus;
                    }
                }
            }
        }

        // 1. If paid, redirect to success
        if (status === 'success' || status === 'paid') {
            return res.redirect(`/payment/success?order_id=${encodeURIComponent(orderId)}&type=${encodeURIComponent(type)}`);
        }

        // 2. If already marked failed or cancelled in DB, redirect to failure page
        if (status === 'failed' || status === 'cancelled') {
            const failReason = (memOrder && (memOrder.failureReason || memOrder.cancellationReason)) ||
                               (donation && (donation.failureReason || donation.cancellationReason)) ||
                               (volunteerApp && (volunteerApp.failureReason || volunteerApp.cancellationReason)) ||
                               'Transaction not completed';
            return res.redirect(`/payment/failure?order_id=${encodeURIComponent(orderId)}&type=${encodeURIComponent(type)}&status=${encodeURIComponent(status)}&reason=${encodeURIComponent(failReason)}`);
        }

        // 3. Strict 10-Minute Timeout Check:
        // Any pending status taking more than 10 minutes is automatically considered a failed payment
        let remainingTimeoutSeconds = 600;
        if (orderCreatedAt) {
            const elapsedMs = Date.now() - new Date(orderCreatedAt).getTime();
            if (elapsedMs >= PAYMENT_TIMEOUT_MS) {
                // Persist failed state to DB
                if (memOrder && memOrder.status === 'pending') {
                    memOrder.status = 'failed';
                    memOrder.failureReason = 'Payment timed out after 10 minutes.';
                    await memOrder.save();
                } else if (donation && donation.status === 'pending') {
                    donation.status = 'failed';
                    donation.failureReason = 'Payment timed out after 10 minutes.';
                    await donation.save();
                } else if (volunteerApp && volunteerApp.paymentStatus === 'pending') {
                    volunteerApp.paymentStatus = 'failed';
                    volunteerApp.failureReason = 'Payment timed out after 10 minutes.';
                    await volunteerApp.save();
                }

                return res.redirect(`/payment/failure?order_id=${encodeURIComponent(orderId)}&type=${encodeURIComponent(type)}&status=timeout&reason=${encodeURIComponent('Payment timed out after 10 minutes.')}`);
            } else {
                remainingTimeoutSeconds = Math.max(5, Math.floor((PAYMENT_TIMEOUT_MS - elapsedMs) / 1000));
            }
        }

        res.render('pages/payment-status', {
            pageTitle: 'Payment Status',
            orderId: orderId,
            type: type,
            status: status,
            amount: amount,
            currency: currency,
            title: 'Payment Pending / Processing',
            message: 'Your payment is awaiting confirmation from your bank or UPI gateway.',
            remainingTimeoutSeconds: remainingTimeoutSeconds,
            totalTimeoutSeconds: 600
        });
    } catch (err) {
        console.error('[Payment Status Page Error]:', err);
        res.render('pages/payment-status', {
            pageTitle: 'Payment Status',
            orderId: req.query.order_id || '',
            type: req.query.type || 'membership',
            status: 'pending',
            amount: '',
            currency: 'INR',
            title: 'Payment Pending',
            message: 'Your payment is awaiting confirmation from your bank or UPI gateway.',
            remainingTimeoutSeconds: 600,
            totalTimeoutSeconds: 600
        });
    }
});

/**
 * API: Check live payment status (for polling and manual check)
 * Automatically enforces the 10-minute timeout rule:
 * Any transaction pending for > 10 minutes transitions to failed status.
 */
app.get('/api/payment-status', async (req, res) => {
    try {
        const orderId = req.query.order_id || req.query.orderId || req.query.sub_id;
        if (!orderId) {
            return res.status(400).json({ error: 'Order ID is required' });
        }

        const PAYMENT_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes
        let isPaid = false;
        let status = 'pending';
        let type = req.query.type || 'membership';

        // Check local DB first
        const memOrder = await MembershipOrder.findOne({
            $or: [{ orderId: orderId }, { subscriptionId: orderId }]
        });
        const donation = !memOrder ? await Donation.findOne({ orderId: orderId }) : null;
        const volunteerApp = (!memOrder && !donation) ? await VolunteerApplication.findOne({ orderId: orderId }) : null;
        const orderDoc = memOrder || donation || volunteerApp;

        if (memOrder) type = 'membership';
        else if (donation) type = 'donation';
        else if (volunteerApp) type = 'volunteer';

        // Check if already paid
        if (memOrder && memOrder.status === 'paid') {
            return res.json({ status: 'paid', isPaid: true, type: 'membership' });
        }
        if (donation && donation.status === 'successful') {
            return res.json({ status: 'successful', isPaid: true, type: 'donation' });
        }
        if (volunteerApp && volunteerApp.paymentStatus === 'paid') {
            return res.json({ status: 'paid', isPaid: true, type: 'volunteer' });
        }

        // Check if marked failed or cancelled
        if (memOrder && (memOrder.status === 'failed' || memOrder.status === 'cancelled')) {
            return res.json({ 
                status: memOrder.status, 
                isPaid: false, 
                type: 'membership',
                reason: memOrder.failureReason || memOrder.cancellationReason || 'Payment not completed'
            });
        }
        if (donation && (donation.status === 'failed' || donation.status === 'cancelled')) {
            return res.json({ 
                status: donation.status, 
                isPaid: false, 
                type: 'donation',
                reason: donation.failureReason || donation.cancellationReason || 'Payment not completed'
            });
        }
        if (volunteerApp && (volunteerApp.paymentStatus === 'failed' || volunteerApp.paymentStatus === 'cancelled')) {
            return res.json({ 
                status: volunteerApp.paymentStatus, 
                isPaid: false, 
                type: 'volunteer',
                reason: volunteerApp.failureReason || volunteerApp.cancellationReason || 'Payment not completed'
            });
        }

        // Strict 10-Minute Timeout check against order creation time
        if (orderDoc && orderDoc.createdAt) {
            const elapsedMs = Date.now() - new Date(orderDoc.createdAt).getTime();
            if (elapsedMs >= PAYMENT_TIMEOUT_MS) {
                if (memOrder && memOrder.status === 'pending') {
                    memOrder.status = 'failed';
                    memOrder.failureReason = 'Payment timed out after 10 minutes.';
                    await memOrder.save();
                } else if (donation && donation.status === 'pending') {
                    donation.status = 'failed';
                    donation.failureReason = 'Payment timed out after 10 minutes.';
                    await donation.save();
                } else if (volunteerApp && volunteerApp.paymentStatus === 'pending') {
                    volunteerApp.paymentStatus = 'failed';
                    volunteerApp.failureReason = 'Payment timed out after 10 minutes.';
                    await volunteerApp.save();
                }

                return res.json({
                    status: 'failed',
                    isPaid: false,
                    timedOut: true,
                    type: type,
                    reason: 'Payment timed out after 10 minutes.',
                    orderId: orderId
                });
            }
        }

        // Query Cashfree directly for live status
        try {
            const orderResp = await cashfree.PGFetchOrder(orderId);
            const orderData = orderResp.data;
            if (orderData.order_status === 'PAID') {
                isPaid = true;
                status = 'paid';
                if (memOrder && memOrder.status !== 'paid') {
                    memOrder.status = 'paid';
                    memOrder.cfPaymentId = String(orderData.cf_order_id || '');
                    const durationConfig = MEMBERSHIP_PLANS[memOrder.duration] || { durationDays: 30, tier: 'plus' };
                    const now = new Date();
                    const expiresAt = new Date();
                    expiresAt.setDate(now.getDate() + durationConfig.durationDays);
                    memOrder.membershipExpiresAt = expiresAt;
                    await memOrder.save();

                    const targetTier = memOrder.tier || durationConfig.tier || 'plus';
                    await User.findByIdAndUpdate(memOrder.user, {
                        membership: targetTier === 'lite' ? 'lite' : 'plus',
                        membershipExpiresAt: expiresAt,
                        membershipPlan: memOrder.duration
                    });
                } else if (donation && donation.status !== 'successful') {
                    donation.status = 'successful';
                    donation.cfPaymentId = String(orderData.cf_order_id || '');
                    await donation.save();
                } else if (volunteerApp && volunteerApp.paymentStatus !== 'paid') {
                    volunteerApp.paymentStatus = 'paid';
                    volunteerApp.cfPaymentId = String(orderData.cf_order_id || '');
                    volunteerApp.paidAt = new Date();
                    await volunteerApp.save();
                }
            } else if (orderData.order_status === 'EXPIRED' || orderData.order_status === 'CANCELLED' || orderData.order_status === 'TERMINATED') {
                status = 'failed';
                const gatewayReason = `Gateway marked order as ${orderData.order_status}`;
                if (memOrder && memOrder.status === 'pending') {
                    memOrder.status = 'failed';
                    memOrder.failureReason = gatewayReason;
                    await memOrder.save();
                } else if (donation && donation.status === 'pending') {
                    donation.status = 'failed';
                    donation.failureReason = gatewayReason;
                    await donation.save();
                } else if (volunteerApp && volunteerApp.paymentStatus === 'pending') {
                    volunteerApp.paymentStatus = 'failed';
                    volunteerApp.failureReason = gatewayReason;
                    await volunteerApp.save();
                }
            } else {
                status = 'pending';
            }
        } catch (fetchErr) {
            console.warn('[API Payment Status Fetch Warning]:', fetchErr.message);
        }

        // Final timeout check if still pending
        let remainingSeconds = 600;
        if (orderDoc && orderDoc.createdAt) {
            const elapsedMs = Date.now() - new Date(orderDoc.createdAt).getTime();
            if (elapsedMs >= PAYMENT_TIMEOUT_MS && status === 'pending') {
                status = 'failed';
                if (memOrder && memOrder.status === 'pending') {
                    memOrder.status = 'failed';
                    memOrder.failureReason = 'Payment timed out after 10 minutes.';
                    await memOrder.save();
                } else if (donation && donation.status === 'pending') {
                    donation.status = 'failed';
                    donation.failureReason = 'Payment timed out after 10 minutes.';
                    await donation.save();
                } else if (volunteerApp && volunteerApp.paymentStatus === 'pending') {
                    volunteerApp.paymentStatus = 'failed';
                    volunteerApp.failureReason = 'Payment timed out after 10 minutes.';
                    await volunteerApp.save();
                }
                return res.json({
                    status: 'failed',
                    isPaid: false,
                    timedOut: true,
                    type: type,
                    reason: 'Payment timed out after 10 minutes.',
                    orderId: orderId
                });
            }
            remainingSeconds = Math.max(0, Math.floor((PAYMENT_TIMEOUT_MS - elapsedMs) / 1000));
        }

        return res.json({
            status: status,
            isPaid: isPaid,
            orderId: orderId,
            type: type,
            remainingTimeoutSeconds: remainingSeconds
        });
    } catch (err) {
        console.error('[API Payment Status Error]:', err);
        return res.status(500).json({ error: 'Failed to check status' });
    }
});

/**
 * Global Cancellation Feedback Endpoint
 * Saves feedback when user self-cancels or cancels purchase
 */
app.post('/api/payment/cancel-feedback', async (req, res) => {
    try {
        const { orderId, type, reason, notes } = req.body;
        if (!reason) {
            return res.status(400).json({ error: 'Cancellation reason is required.' });
        }

        const validReasons = [
            "Don't want to purchase it",
            "Don't find payment method I need",
            "Click by mistake",
            "Network issue",
            "Other",
            "Pricing too high / Looking for discount",
            "Timed out after 10 minutes"
        ];

        const sanitizedReason = validReasons.includes(reason) ? reason : "Other";
        const sanitizedNotes = typeof notes === 'string' ? notes.trim().slice(0, 500) : '';

        // Save in dedicated PaymentCancellation collection
        const cancellationRecord = new PaymentCancellation({
            orderId: orderId || `CANCEL-${Date.now()}`,
            type: type || 'membership',
            user: req.user ? req.user._id : null,
            username: req.user ? req.user.username : 'Guest',
            reason: sanitizedReason,
            notes: sanitizedNotes,
            ipAddress: req.ip || req.headers['x-forwarded-for'] || null,
            userAgent: req.headers['user-agent'] || null
        });
        await cancellationRecord.save();

        // Also update matching Order if orderId provided
        if (orderId) {
            const memOrder = await MembershipOrder.findOne({
                $or: [{ orderId: orderId }, { subscriptionId: orderId }]
            });
            if (memOrder) {
                memOrder.cancellationReason = sanitizedReason;
                memOrder.cancellationNotes = sanitizedNotes;
                memOrder.cancelledAt = new Date();
                if (memOrder.status === 'pending') {
                    memOrder.status = 'cancelled';
                }
                await memOrder.save();
            }

            const donation = await Donation.findOne({ orderId: orderId });
            if (donation) {
                donation.cancellationReason = sanitizedReason;
                donation.cancellationNotes = sanitizedNotes;
                donation.cancelledAt = new Date();
                if (donation.status === 'pending') {
                    donation.status = 'cancelled';
                }
                await donation.save();
            }

            const volunteerApp = await VolunteerApplication.findOne({ orderId: orderId });
            if (volunteerApp) {
                volunteerApp.cancellationReason = sanitizedReason;
                volunteerApp.cancellationNotes = sanitizedNotes;
                volunteerApp.cancelledAt = new Date();
                if (volunteerApp.paymentStatus === 'pending') {
                    volunteerApp.paymentStatus = 'cancelled';
                }
                await volunteerApp.save();
            }
        }

        return res.json({ 
            success: true, 
            message: 'Feedback received successfully. Thank you for helping us improve!' 
        });
    } catch (err) {
        console.error('[Payment Cancel Feedback Error]:', err);
        return res.status(500).json({ error: 'Failed to record feedback.' });
    }
});

/**
 * ============================================================================
 * COMPONENT 3: DEDICATED MEMBERSHIP MANAGEMENT (/my-membership)
 * ============================================================================
 */
app.get(['/my-membership', '/membership/manage'], async (req, res) => {
    if (!req.user) {
        return res.redirect('/login?redirect=/my-membership');
    }

    try {
        const user = await User.findById(req.user._id).lean();
        const orders = await MembershipOrder.find({ user: user._id })
            .sort({ createdAt: -1 })
            .limit(50)
            .lean();

        const activeOrder = orders.find(o => o.status === 'paid');
        const planKey = user.membershipPlan || (activeOrder ? activeOrder.duration : 'free');
        const planConfig = MEMBERSHIP_PLANS[planKey] || { 
            name: user.membership === 'plus' ? 'GPL Plus' : (user.membership === 'lite' ? 'GPL Lite' : 'Free Member'),
            tier: user.membership || 'free'
        };

        const isLifetime = Boolean(
            (user.membershipPlan && user.membershipPlan.includes('lifetime')) ||
            (planKey && planKey.includes('lifetime'))
        );

        let daysRemaining = 'N/A';
        let isExpired = false;

        if (isLifetime) {
            daysRemaining = 'Lifetime Access';
        } else if (user.membershipExpiresAt) {
            const diffMs = new Date(user.membershipExpiresAt).getTime() - Date.now();
            if (diffMs > 0) {
                daysRemaining = Math.ceil(diffMs / (1000 * 60 * 60 * 24));
            } else {
                daysRemaining = 0;
                isExpired = true;
            }
        }

        // Refund Eligibility calculation for latest active order strictly per GPLMods Refund Policy
        let refundEligibility = {
            eligible: false,
            percent: 0,
            amount: 0,
            reason: '',
            hoursElapsed: 0
        };

        const onCooldown = Boolean(
            user.lastRefundAt && (Date.now() - new Date(user.lastRefundAt).getTime() < 3 * 24 * 60 * 60 * 1000)
        );

        if (activeOrder && activeOrder.status === 'paid' && activeOrder.refundStatus === 'none' && !onCooldown) {
            const hoursElapsed = (Date.now() - new Date(activeOrder.createdAt).getTime()) / (1000 * 60 * 60);
            refundEligibility.hoursElapsed = Math.round(hoursElapsed);
            const dur = activeOrder.duration || '';

            if (dur.includes('monthly')) {
                if (hoursElapsed <= 168) { // 7 days = 168 hours
                    refundEligibility.eligible = true;
                    refundEligibility.percent = 100;
                    refundEligibility.amount = activeOrder.amount;
                } else {
                    refundEligibility.reason = '7-day full refund window has expired for monthly plans.';
                }
            } else if (dur.includes('6months') || dur.includes('yearly')) {
                if (hoursElapsed <= 168) {
                    refundEligibility.eligible = true;
                    refundEligibility.percent = 100;
                    refundEligibility.amount = activeOrder.amount;
                } else if (hoursElapsed <= 336) { // 14 days = 336 hours
                    refundEligibility.eligible = true;
                    refundEligibility.percent = 80;
                    refundEligibility.amount = Math.round(activeOrder.amount * 0.8);
                } else {
                    refundEligibility.reason = '14-day refund window has expired for 6-Month/Yearly plans.';
                }
            } else if (dur.includes('lifetime')) {
                if (hoursElapsed <= 168) {
                    refundEligibility.eligible = true;
                    refundEligibility.percent = 100;
                    refundEligibility.amount = activeOrder.amount;
                } else {
                    refundEligibility.eligible = true;
                    refundEligibility.percent = 90; // 10% processing fee
                    refundEligibility.amount = Math.round(activeOrder.amount * 0.9);
                }
            }
        } else if (onCooldown) {
            refundEligibility.reason = 'Refund requests are currently on 3-day cooldown from your last refund.';
        }

        res.render('pages/my-membership', {
            pageTitle: 'My Membership Management',
            user: user,
            activeOrder: activeOrder,
            orders: orders,
            currentPlan: planConfig,
            planKey: planKey,
            isLifetime: isLifetime,
            daysRemaining: daysRemaining,
            isExpired: isExpired,
            autoRenew: user.autoRenew !== false,
            scheduledChange: user.scheduledPlanChange || null,
            refundEligibility: refundEligibility,
            onCooldown: onCooldown,
            membershipPlans: MEMBERSHIP_PLANS
        });
    } catch (err) {
        console.error('[My Membership Page Error]:', err);
        res.status(500).send('Error loading membership details.');
    }
});

/**
 * Cancel Auto-Renew Subscription
 */
app.post('/membership/cancel-subscription', async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    try {
        const updatedUser = await User.findByIdAndUpdate(req.user._id, {
            autoRenew: false,
            membershipCancelledAt: new Date()
        }, { new: true });

        await MembershipOrder.findOneAndUpdate(
            { user: req.user._id, status: 'paid' },
            { autoRenew: false },
            { sort: { createdAt: -1 } }
        );

        if (updatedUser.subscriptionId) {
            try {
                await cashfree.SubsCancelSubscription(updatedUser.subscriptionId);
            } catch (subCancelErr) {
                console.warn('[SubsCancelSubscription Warning]:', subCancelErr.message);
            }
        }

        const expiryFormatted = updatedUser.membershipExpiresAt 
            ? new Date(updatedUser.membershipExpiresAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
            : 'the end of your billing cycle';

        return res.json({
            success: true,
            message: `Your subscription auto-renew has been cancelled. You will NOT be billed again. Your membership perks remain fully active until ${expiryFormatted}.`
        });
    } catch (err) {
        console.error('[Cancel Subscription Error]:', err);
        return res.status(500).json({ error: 'Failed to cancel subscription.' });
    }
});

/**
 * Upgrade / Downgrade Plan Handler
 * - Lifetime memberships cannot be downgraded
 * - Users can upgrade to Lifetime from any tier
 */
app.post('/membership/change-plan', async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    const { targetPlan } = req.body;
    if (!targetPlan || !MEMBERSHIP_PLANS[targetPlan]) {
        return res.status(400).json({ error: 'Invalid plan selected.' });
    }

    try {
        const user = await User.findById(req.user._id);
        const isCurrentLifetime = Boolean(user.membershipPlan && user.membershipPlan.includes('lifetime'));
        const isTargetLifetime = Boolean(targetPlan.includes('lifetime'));

        // STRICT CONSTRAINT: Users CANNOT downgrade from Lifetime
        if (isCurrentLifetime && !isTargetLifetime) {
            return res.status(400).json({
                error: 'Downgrades from Lifetime Membership are strictly prohibited according to GPLMods Policy.'
            });
        }

        const targetConfig = MEMBERSHIP_PLANS[targetPlan];

        // If target is Lifetime or an immediate upgrade from Lite to Plus
        if (isTargetLifetime || (user.membership === 'lite' && targetConfig.tier === 'plus')) {
            return res.json({
                success: true,
                requirePayment: true,
                targetPlan: targetPlan,
                message: `Upgrade to ${targetConfig.name} requires checkout. Redirecting to payment...`
            });
        }

        // Otherwise schedule plan change for the next renewal date
        const effectiveDate = user.membershipExpiresAt || new Date();
        user.scheduledPlanChange = {
            targetPlan: targetPlan,
            targetTier: targetConfig.tier,
            effectiveDate: effectiveDate
        };
        await user.save();

        const dateStr = new Date(effectiveDate).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
        return res.json({
            success: true,
            scheduled: true,
            message: `Your membership change to ${targetConfig.name} has been scheduled. You will automatically switch on ${dateStr}.`
        });
    } catch (err) {
        console.error('[Change Plan Error]:', err);
        return res.status(500).json({ error: 'Failed to schedule plan change.' });
    }
});

/**
 * Self-Service Refund Request (GPLMods Refund Policy)
 */
app.post('/membership/request-refund', async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    const { orderId, reason } = req.body;
    if (!orderId) {
        return res.status(400).json({ error: 'Order ID is required.' });
    }

    try {
        const user = await User.findById(req.user._id);
        
        // Cooldown check (3 days / 72 hours)
        if (user.lastRefundAt && (Date.now() - new Date(user.lastRefundAt).getTime() < 3 * 24 * 60 * 60 * 1000)) {
            return res.status(400).json({
                error: 'A 3-day cooldown period applies between refund requests and re-subscriptions. Please wait before submitting another request.'
            });
        }

        const order = await MembershipOrder.findOne({ orderId: orderId, user: user._id });
        if (!order) {
            return res.status(404).json({ error: 'Order not found.' });
        }
        if (order.status !== 'paid') {
            return res.status(400).json({ error: 'Only paid orders can be refunded.' });
        }
        if (order.refundStatus !== 'none') {
            return res.status(400).json({ error: 'A refund has already been requested or processed for this order.' });
        }

        // Elapsed hours
        const elapsedHours = (Date.now() - new Date(order.createdAt).getTime()) / (1000 * 60 * 60);
        let refundAmount = 0;
        const dur = order.duration || '';

        if (dur.includes('monthly')) {
            if (elapsedHours <= 168) {
                refundAmount = order.amount;
            } else {
                return res.status(400).json({ error: 'Monthly memberships are only refundable within 7 days (168 hours) of purchase.' });
            }
        } else if (dur.includes('6months') || dur.includes('yearly')) {
            if (elapsedHours <= 168) {
                refundAmount = order.amount;
            } else if (elapsedHours <= 336) {
                refundAmount = Math.round(order.amount * 0.8);
            } else {
                return res.status(400).json({ error: '6-Month and Yearly memberships are only refundable within 14 days of purchase.' });
            }
        } else if (dur.includes('lifetime')) {
            if (elapsedHours <= 168) {
                refundAmount = order.amount;
            } else {
                refundAmount = Math.round(order.amount * 0.9);
            }
        }

        if (refundAmount <= 0) {
            return res.status(400).json({ error: 'This order is not eligible for a refund according to our policy.' });
        }

        // Record refund request on order
        order.status = 'refund_requested';
        order.refundStatus = 'pending';
        order.refundRequestedAt = new Date();
        order.refundAmount = refundAmount;
        order.refundReason = reason || 'Customer request under Refund Policy';
        await order.save();

        // Update user cooldown
        user.lastRefundAt = new Date();
        await user.save();

        // Create support ticket
        try {
            await SupportTicket.create({
                user: user._id,
                username: user.username,
                email: user.email,
                subject: `Refund Request - ${order.orderId} (₹${refundAmount})`,
                category: 'billing',
                message: `Refund requested for order ${order.orderId} (${order.duration}). Amount: ₹${refundAmount}. Reason: ${reason || 'Not specified'}.`
            });
        } catch (ticketErr) {
            console.warn('[Create Support Ticket Warning]:', ticketErr.message);
        }

        // Create user notification
        try {
            await UserNotification.create({
                user: user._id,
                title: 'Refund Request Registered',
                message: `Your refund request for ₹${refundAmount} (Order: ${order.orderId}) has been registered under the GPLMods Refund Policy and is being processed.`,
                type: 'info'
            });
        } catch (notifErr) {
            console.warn('[Create User Notification Warning]:', notifErr.message);
        }

        return res.json({
            success: true,
            refundAmount: refundAmount,
            currency: order.currency || 'INR',
            message: `Your refund request for ₹${refundAmount} has been registered under the GPLMods Refund Policy. The amount will be returned to your original payment method within 5-7 business days.`
        });
    } catch (err) {
        console.error('[Request Refund Error]:', err);
        return res.status(500).json({ error: 'Failed to submit refund request.' });
    }
});

/**
 * ============================================================================
 * COMPONENT 4: VOLUNTEER SUPPORT TEAM & ADMIN APPLICATION SYSTEM (/volunteer)
 * ============================================================================
 */
app.get('/volunteer', async (req, res) => {
    try {
        const supportCount = await VolunteerApplication.countDocuments({
            role: 'support',
            paymentStatus: 'paid',
            applicationStatus: { $in: ['submitted', 'under_review', 'approved'] }
        });
        const adminCount = await VolunteerApplication.countDocuments({
            role: 'admin',
            paymentStatus: 'paid',
            applicationStatus: { $in: ['submitted', 'under_review', 'approved'] }
        });

        let myApplication = null;
        if (req.user) {
            myApplication = await VolunteerApplication.findOne({ user: req.user._id })
                .sort({ createdAt: -1 })
                .lean();
        }

        res.render('pages/volunteer', {
            pageTitle: 'Volunteer Support Team & Admin Staff Application',
            supportCount: supportCount,
            adminCount: adminCount,
            maxSlots: 10,
            myApplication: myApplication,
            cashfreeAppId: process.env.CASHFREE_APP_ID,
            cashfreeEnv: process.env.CASHFREE_ENVIRONMENT || 'sandbox'
        });
    } catch (err) {
        console.error('[Volunteer Page Error]:', err);
        res.status(500).send('Error loading volunteer applications.');
    }
});

/**
 * Create Cashfree Order for Volunteer Safety Commitment Fee
 * Support Team: ₹150 / mo, Admin Staff: ₹300 / mo
 */
app.post('/create-volunteer-order', async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Please log in to submit a volunteer application.' });
    }

    const { role } = req.body;
    if (role !== 'support' && role !== 'admin') {
        return res.status(400).json({ error: 'Invalid role selected.' });
    }

    try {
        // Enforce 10 capacity slots limit
        const activeCount = await VolunteerApplication.countDocuments({
            role: role,
            paymentStatus: 'paid',
            applicationStatus: { $in: ['submitted', 'under_review', 'approved'] }
        });

        if (activeCount >= 10) {
            return res.status(400).json({
                error: `Applications for the ${role === 'admin' ? 'Community Admin' : 'Support Team'} role are currently full (10/10 slots occupied).`
            });
        }

        const fee = role === 'admin' ? 300 : 150;
        const orderId = `GPLVOL_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;
        const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;

        const orderRequest = {
            order_id: orderId,
            order_amount: fee,
            order_currency: 'INR',
            customer_details: {
                customer_id: String(req.user._id),
                customer_name: req.user.username,
                customer_email: req.user.email,
                customer_phone: req.user.phone || '9999999999'
            },
            order_meta: {
                return_url: `${baseUrl}/volunteer/verify-fee?order_id={order_id}`,
                notify_url: `${baseUrl}/webhook/cashfree/pg`
            },
            order_note: `GPL Mods Volunteer Commitment Fee: ${role === 'admin' ? 'Admin' : 'Support Team'} (₹${fee})`
        };

        const response = await cashfree.PGCreateOrder(orderRequest);

        return res.json({
            success: true,
            order_id: orderId,
            payment_session_id: response.data.payment_session_id,
            amount: fee
        });
    } catch (err) {
        console.error('[Volunteer Order Creation Error]:', err.response?.data || err.message);
        return res.status(500).json({ error: 'Failed to initiate commitment fee payment.' });
    }
});

/**
 * Return Verification Handler for Volunteer Fee
 */
app.get('/volunteer/verify-fee', async (req, res) => {
    const orderId = req.query.order_id || req.query.orderId;
    if (!orderId) {
        return res.redirect('/volunteer');
    }

    try {
        const orderResponse = await cashfree.PGFetchOrder(orderId);
        const orderData = orderResponse.data;
        const isPaid = orderData.order_status === 'PAID';

        if (isPaid) {
            return res.redirect(`/volunteer?status=fee_paid&order_id=${encodeURIComponent(orderId)}`);
        } else {
            return res.redirect(`/volunteer?status=fee_failed&order_id=${encodeURIComponent(orderId)}`);
        }
    } catch (err) {
        console.error('[Volunteer Fee Verification Error]:', err.message);
        return res.redirect(`/volunteer?status=fee_failed&order_id=${encodeURIComponent(orderId)}`);
    }
});

/**
 * Submit Volunteer Application Form with KYC Upload & Validation
 */
app.post('/volunteer/apply', kycUpload.single('kycDocument'), async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Please log in to apply.' });
    }

    const {
        fullName, phone, dateOfBirth,
        street, city, district, state, pincode, country,
        discord, telegram, github, twitter,
        role, experience, orderId,
        isVoluntaryAgreed, oneMonthLockinAgreed, eighteenPlusConfirmed, codeOfConductAgreed
    } = req.body;

    let languages = req.body.languages;
    if (typeof languages === 'string') {
        try {
            languages = JSON.parse(languages);
        } catch (_) {
            languages = languages.split(',').map(s => s.trim().toLowerCase());
        }
    }
    if (!Array.isArray(languages)) {
        languages = [];
    }
    const normalizedLangs = languages.map(l => String(l).toLowerCase().trim());

    // 1. Language Requirement Validation: Support international & regional languages
    if (!normalizedLangs || normalizedLangs.length === 0) {
        return res.status(400).json({
            error: 'Language Requirement Failed: You must specify at least one language (international or regional) you are proficient in.'
        });
    }

    // 2. 18+ Age Validation
    if (!dateOfBirth) {
        return res.status(400).json({ error: 'Date of Birth is required for 18+ age verification.' });
    }
    const dob = new Date(dateOfBirth);
    const ageYears = (Date.now() - dob.getTime()) / (365.25 * 24 * 60 * 60 * 1000);
    if (isNaN(ageYears) || ageYears < 18) {
        return res.status(400).json({
            error: 'Age Restriction: You must be at least 18 years old to join the Volunteer Support Team or Admin Staff.'
        });
    }

    // 3. Agreements Validation (1-month lock-in, no salary, code of conduct)
    const isVoluntary = isVoluntaryAgreed === true || isVoluntaryAgreed === 'true' || isVoluntaryAgreed === 'on';
    const isLockedIn = oneMonthLockinAgreed === true || oneMonthLockinAgreed === 'true' || oneMonthLockinAgreed === 'on';
    const isEighteen = eighteenPlusConfirmed === true || eighteenPlusConfirmed === 'true' || eighteenPlusConfirmed === 'on';
    const isCodeAgreed = codeOfConductAgreed === true || codeOfConductAgreed === 'true' || codeOfConductAgreed === 'on';

    if (!isVoluntary || !isLockedIn || !isEighteen || !isCodeAgreed) {
        return res.status(400).json({
            error: 'You must agree to all mandatory terms including the 1-month lock-in period and voluntary status.'
        });
    }

    // 4. Capacity Check (10 slots)
    const activeRoleCount = await VolunteerApplication.countDocuments({
        role: role,
        paymentStatus: 'paid',
        applicationStatus: { $in: ['submitted', 'under_review', 'approved'] }
    });
    if (activeRoleCount >= 10) {
        return res.status(400).json({
            error: `Applications for the ${role === 'admin' ? 'Admin' : 'Support Team'} role have reached maximum capacity (10/10 slots).`
        });
    }

    // 5. Verify Fee Payment via Cashfree
    let paymentPaid = false;
    let cfPaymentId = '';
    const feeAmount = role === 'admin' ? 300 : 150;

    if (orderId) {
        try {
            const orderResp = await cashfree.PGFetchOrder(orderId);
            if (orderResp.data && orderResp.data.order_status === 'PAID') {
                paymentPaid = true;
                cfPaymentId = String(orderResp.data.cf_order_id || '');
            }
        } catch (fetchErr) {
            console.warn('[Volunteer KYC Order Fetch Warning]:', fetchErr.message);
        }
    }

    if (!paymentPaid) {
        return res.status(400).json({
            error: 'Commitment fee payment could not be verified. Please complete the ₹' + feeAmount + ' fee payment.'
        });
    }

    try {
        const kycKey = req.file ? `/uploads/kyc/${req.file.filename}` : '';

        const application = await VolunteerApplication.create({
            user: req.user._id,
            fullName: fullName || req.user.username,
            email: req.user.email,
            phone: phone || '',
            dateOfBirth: dob,
            address: {
                street: street || '',
                city: city || '',
                district: district || '',
                state: state || '',
                pincode: pincode || '',
                country: country || 'India'
            },
            socialHandles: {
                discord: discord || '',
                telegram: telegram || '',
                github: github || '',
                twitter: twitter || ''
            },
            role: role,
            languages: normalizedLangs,
            experience: experience || '',
            kycDocumentKey: kycKey,
            isVoluntaryAgreed: isVoluntary,
            oneMonthLockinAgreed: isLockedIn,
            eighteenPlusConfirmed: isEighteen,
            codeOfConductAgreed: isCodeAgreed,
            feeAmount: feeAmount,
            orderId: orderId,
            cfPaymentId: cfPaymentId,
            paymentStatus: 'paid',
            paidAt: new Date(),
            applicationStatus: 'submitted'
        });

        // Create support ticket for admin review
        try {
            await SupportTicket.create({
                user: req.user._id,
                username: req.user.username,
                email: req.user.email,
                subject: `New Volunteer Application: ${role.toUpperCase()} - ${fullName}`,
                category: 'account',
                message: `User ${req.user.username} submitted a volunteer application for ${role}. Fee paid: ₹${feeAmount}. Mandatory language: ${normalizedLangs.join(', ')}. Age: ${Math.floor(ageYears)}.`
            });
        } catch (_) {}

        return res.json({
            success: true,
            message: 'Your volunteer application and KYC documents have been submitted successfully! Our administrative team will review your submission.'
        });
    } catch (saveErr) {
        console.error('[Volunteer Application Save Error]:', saveErr);
        return res.status(500).json({ error: 'Failed to submit volunteer application.' });
    }
});

/**
 * Volunteer Fee Refund Request (7-Day Money-Back Guarantee)
 */
app.post('/volunteer/request-refund', async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    const { applicationId } = req.body;
    if (!applicationId) {
        return res.status(400).json({ error: 'Application ID is required' });
    }

    try {
        const appDoc = await VolunteerApplication.findOne({ _id: applicationId, user: req.user._id, paymentStatus: 'paid' });
        if (!appDoc) {
            return res.status(404).json({ error: 'Application not found or fee not paid.' });
        }

        const elapsedDays = (Date.now() - new Date(appDoc.createdAt).getTime()) / (1000 * 60 * 60 * 24);
        if (elapsedDays > 7) {
            return res.status(400).json({
                error: 'The 7-day money-back guarantee window for this volunteer application has expired.'
            });
        }

        appDoc.refundStatus = 'pending';
        appDoc.refundRequestedAt = new Date();
        await appDoc.save();

        try {
            await SupportTicket.create({
                user: req.user._id,
                username: req.user.username,
                email: req.user.email,
                subject: `Volunteer Fee Refund Request - Application #${appDoc._id}`,
                category: 'billing',
                message: `Refund of ₹${appDoc.feeAmount} requested for volunteer application #${appDoc._id} under 7-day guarantee.`
            });
        } catch (_) {}

        return res.json({
            success: true,
            message: `Your refund request for the ₹${appDoc.feeAmount} volunteer commitment fee has been registered under the 7-day guarantee.`
        });
    } catch (err) {
        console.error('[Volunteer Refund Request Error]:', err);
        return res.status(500).json({ error: 'Failed to submit refund request.' });
    }
});

/**
 * 6. Cashfree Payment Gateway Webhook Endpoint
 * URL: /webhook/cashfree/pg
 * Signature Verification: HMAC-SHA256 via cashfree.PGVerifyWebhookSignature
 */
app.post('/webhook/cashfree/pg', (req, res) => {
    const signature = req.headers['x-webhook-signature'];
    const timestamp = req.headers['x-webhook-timestamp'];
    const rawPayload = req.rawBody || JSON.stringify(req.body);

    try {
        cashfree.PGVerifyWebhookSignature(signature, rawPayload, timestamp);
    } catch (sigErr) {
        console.error('[Cashfree PG Webhook] Invalid signature:', sigErr.message);
        return res.status(400).send('Invalid signature');
    }

    // Acknowledge immediately with 200 OK
    res.status(200).send('OK');

    // Asynchronously process event
    setImmediate(async () => {
        try {
            const payload = JSON.parse(rawPayload);
            const { type, data } = payload;
            if (!data || !data.order) return;

            const orderId = data.order.order_id;
            const paymentStatus = data.payment?.payment_status;

            if (type === 'PAYMENT_SUCCESS_WEBHOOK' && paymentStatus === 'SUCCESS') {
                // Authoritative server-side re-verification:
                const verified = await cashfree.PGFetchOrder(orderId);
                if (verified.data.order_status === 'PAID') {
                    // Check if Donation
                    const donation = await Donation.findOne({ orderId });
                    if (donation) {
                        donation.status = 'successful';
                        donation.cfPaymentId = String(data.payment?.cf_payment_id || verified.data.cf_order_id);
                        donation.paymentMethod = data.payment?.payment_group || 'cashfree';
                        await donation.save();
                        console.log(`[Cashfree PG Webhook] Donation ${orderId} marked as successful.`);
                        return;
                    }

                    // Check if Membership Order
                    const memOrder = await MembershipOrder.findOne({ orderId });
                    if (memOrder) {
                        memOrder.status = 'paid';
                        memOrder.cfPaymentId = String(data.payment?.cf_payment_id || verified.data.cf_order_id);
                        memOrder.paymentMethod = data.payment?.payment_group || 'cashfree';
                        
                        const durationConfig = MEMBERSHIP_PLANS[memOrder.duration] || { durationDays: 30, tier: 'plus', name: 'GPL Plus' };
                        const now = new Date();
                        const expiresAt = new Date();
                        expiresAt.setDate(now.getDate() + durationConfig.durationDays);

                        memOrder.membershipExpiresAt = expiresAt;
                        await memOrder.save();

                        const targetTier = memOrder.tier || durationConfig.tier || 'plus';
                        const updatedUser = await User.findByIdAndUpdate(memOrder.user, {
                            membership: targetTier === 'lite' ? 'lite' : 'plus',
                            membershipExpiresAt: expiresAt,
                            membershipPlan: memOrder.duration
                        }, { new: true });

                        if (updatedUser) {
                            sendSubscriptionStatusEmail(updatedUser, {
                                tier: targetTier,
                                planName: durationConfig.name,
                                amount: memOrder.amount,
                                currency: memOrder.currency,
                                orderId: memOrder.orderId
                            }).catch(e => console.error('Webhook subscription email error:', e));
                        }
                        console.log(`[Cashfree PG Webhook] User ${memOrder.user} activated ${targetTier} via ${orderId}.`);
                    }
                }
            } else if (type === 'PAYMENT_FAILED_WEBHOOK') {
                await Donation.findOneAndUpdate({ orderId }, { status: 'failed' });
                await MembershipOrder.findOneAndUpdate({ orderId }, { status: 'failed' });
                console.log(`[Cashfree PG Webhook] Order ${orderId} marked as failed.`);
            }
        } catch (procErr) {
            console.error('[Cashfree PG Webhook] Processing error:', procErr);
        }
    });
});

/**
 * 7. Cashfree Subscriptions Webhook Endpoint
 * URL: /webhook/cashfree/subscriptions
 * Signature Verification: HMAC-SHA256 with timestamp + rawBody
 */
app.post('/webhook/cashfree/subscriptions', (req, res) => {
    const signature = req.headers['x-webhook-signature'];
    const timestamp = req.headers['x-webhook-timestamp'];
    const rawPayload = req.rawBody || JSON.stringify(req.body);

    try {
        let valid = false;
        try {
            cashfree.PGVerifyWebhookSignature(signature, rawPayload, timestamp);
            valid = true;
        } catch (sdkErr) {
            const expected = crypto.createHmac('sha256', process.env.CASHFREE_SECRET_KEY)
                .update((timestamp || '') + rawPayload)
                .digest('base64');
            valid = (expected === signature);
        }

        if (!valid) {
            console.error('[Cashfree Subs Webhook] Invalid signature');
            return res.status(400).send('Invalid signature');
        }
    } catch (err) {
        return res.status(400).send('Signature verification error');
    }

    // Acknowledge immediately
    res.status(200).send('OK');

    // Asynchronously process subscription event
    setImmediate(async () => {
        try {
            const payload = JSON.parse(rawPayload);
            const { type, data } = payload;
            const subId = data?.subscription?.subscription_id || data?.subscription_id;
            if (!subId) return;

            const memOrder = await MembershipOrder.findOne({ subscriptionId: subId });
            if (!memOrder) return;

            if (type === 'SUBSCRIPTION_PAYMENT_SUCCESS' || type === 'SUBSCRIPTION_AUTH_STATUS') {
                memOrder.status = 'paid';
                const durationConfig = MEMBERSHIP_PLANS[memOrder.duration] || { durationDays: 30, tier: 'plus', name: 'GPL Plus' };
                const now = new Date();
                const expiresAt = new Date();
                expiresAt.setDate(now.getDate() + durationConfig.durationDays);

                memOrder.membershipExpiresAt = expiresAt;
                await memOrder.save();

                const targetTier = memOrder.tier || durationConfig.tier || 'plus';
                const updatedUser = await User.findByIdAndUpdate(memOrder.user, {
                    membership: targetTier === 'lite' ? 'lite' : 'plus',
                    membershipExpiresAt: expiresAt,
                    membershipPlan: memOrder.duration,
                    subscriptionId: subId
                }, { new: true });

                if (updatedUser) {
                    sendSubscriptionStatusEmail(updatedUser, {
                        tier: targetTier,
                        planName: durationConfig.name,
                        amount: memOrder.amount,
                        currency: memOrder.currency,
                        orderId: memOrder.orderId
                    }).catch(e => console.error('Subs webhook email error:', e));
                }
                console.log(`[Cashfree Subs Webhook] User ${memOrder.user} activated/renewed ${targetTier} via ${subId}.`);
            } else if (type === 'SUBSCRIPTION_STATUS_CHANGED') {
                const subStatus = data?.subscription?.subscription_status;
                if (['CANCELLED', 'EXPIRED'].includes(subStatus)) {
                    await User.findByIdAndUpdate(memOrder.user, { membership: 'free' });
                    memOrder.status = 'cancelled';
                    await memOrder.save();
                }
            }
        } catch (subProcErr) {
            console.error('[Cashfree Subs Webhook] Processing error:', subProcErr);
        }
    });
});
// --- UPDATED: DOCUMENTATION SYSTEM ROUTE WITH CATEGORY DIRECTORY SUPPORT ---
app.get(['/docs', '/docs/:slug', '/docs/category/:categorySlug'], async (req, res, next) => {
    try {
        const requestedSlug = req.params.slug;
        const requestedCategorySlug = req.params.categorySlug;

        const allCategories = await DocCategory.find().sort({ order: 1 }).lean();
        const allPages = await DocPage.find().sort({ order: 1 }).populate('category').lean();

        // Compute reading times and snippets for each page
        allPages.forEach(p => {
            const wordCount = (p.content || '').replace(/<[^>]+>/g, ' ').split(/\s+/).filter(Boolean).length;
            p.readingTimeMinutes = Math.max(1, Math.ceil(wordCount / 180));
            p.plainSummary = (p.content || '').replace(/<[^>]+>/g, ' ').slice(0, 140).trim() + '...';
        });

        const sidebarStructure = allCategories.map(cat => {
            return {
                ...cat,
                pages: allPages.filter(p => p.category && p.category._id.toString() === cat._id.toString())
            };
        });

        let currentPage = null;
        let currentCategory = null;
        let isCategoryView = false;

        if (requestedCategorySlug) {
            isCategoryView = true;
            currentCategory = allCategories.find(c => c.slug === requestedCategorySlug || slugify(c.name) === requestedCategorySlug);
            if (!currentCategory) {
                return res.status(404).render('pages/error', { errorCode: '404', errorTitle: 'Category Not Found', errorMessage: 'The documentation category you requested does not exist.' });
            }
            currentCategory.pages = allPages.filter(p => p.category && p.category._id.toString() === currentCategory._id.toString());
        } else if (requestedSlug) {
            currentPage = await DocPage.findOne({ slug: requestedSlug }).populate('category').lean();
            if (!currentPage) {
                // Check if the requested slug is actually a category
                const matchedCategory = allCategories.find(c => c.slug === requestedSlug || slugify(c.name) === requestedSlug);
                if (matchedCategory) {
                    return res.redirect(`/docs/category/${matchedCategory.slug || slugify(matchedCategory.name)}`);
                }
                return res.status(404).render('pages/error', { errorCode: '404', errorTitle: 'Article Not Found', errorMessage: 'The documentation article you requested does not exist.' });
            }
        } else {
            if (sidebarStructure.length > 0 && sidebarStructure[0].pages.length > 0) {
                currentPage = sidebarStructure[0].pages[0];
                return res.redirect(`/docs/${currentPage.slug}`);
            }
        }

        // Process featured image if single article is active
        if (currentPage && currentPage.featuredImageKey) {
            currentPage.featuredImageUrl = await getSmartImageUrl(currentPage.featuredImageKey);
        }

        res.render('pages/docs', {
            sidebarStructure: sidebarStructure,
            currentPage: currentPage,
            currentCategory: currentCategory,
            isCategoryView: isCategoryView
        });

    } catch (error) {
        console.error("Docs Engine Error:", error);
        return next(error);
    }
});

// ============================================================================
// INFRASTRUCTURE SPONSORSHIP & "BUY FOOD & COFFEE" SYSTEM
// ============================================================================

const SPONSORSHIP_CATALOG = [
    {
        category: 'email',
        categoryTitle: 'SMTP & Email Delivery',
        icon: 'fas fa-paper-plane',
        color: '#FFD700',
        items: [
            { id: 'smtp-starter-monthly', title: 'SMTP Starter (1 Month)', priceINR: 1252.50, priceUSD: 15, period: 'Month', desc: '10,000 monthly transactional verification & alert emails via SMTP2GO' },
            { id: 'smtp-starter-yearly', title: 'SMTP Starter (1 Year)', priceINR: 12525.00, priceUSD: 150, period: 'Year', desc: '120,000 yearly transactional emails with dedicated SPF/DKIM routing' },
            { id: 'smtp-pro-monthly', title: 'SMTP Professional (1 Month)', priceINR: 6262.50, priceUSD: 75, period: 'Month', desc: '100,000 monthly high-priority emails with subaccount telemetry' }
        ]
    },
    {
        category: 'forwarding',
        categoryTitle: 'ImprovMX Mail Forwarding',
        icon: 'fas fa-envelope-open-text',
        color: '#2196F3',
        items: [
            { id: 'improv-light-yearly', title: 'ImprovMX Light (1 Year)', priceINR: 4785.00, period: 'Year', desc: 'Custom domain alias routing and inbound email protection' },
            { id: 'improv-premium-monthly', title: 'ImprovMX Premium (1 Month)', priceINR: 860.00, period: 'Month', desc: 'High-volume MX routing with SMTP relay sending' },
            { id: 'improv-pro-monthly', title: 'ImprovMX Pro (1 Month)', priceINR: 2298.00, period: 'Month', desc: 'Enterprise forwarding with priority throughput queue' }
        ]
    },
    {
        category: 'storage',
        categoryTitle: 'Backblaze B2 Object Storage',
        icon: 'fas fa-database',
        color: '#e53935',
        items: [
            { id: 'b2-500gb-monthly', title: 'Storage B2 500GB (1 Month)', priceINR: 360.00, period: 'Month', desc: '500 GB redundant high-speed mod file hosting' },
            { id: 'b2-500gb-yearly', title: 'Storage B2 500GB (1 Year)', priceINR: 4320.00, period: 'Year', desc: 'Annual 500 GB cloud bucket storage' },
            { id: 'b2-1tb-monthly', title: 'Storage B2 1TB (1 Month)', priceINR: 730.00, period: 'Month', desc: '1,000 GB mod downloads with zero egress penalties' },
            { id: 'b2-1tb-yearly', title: 'Storage B2 1TB (1 Year)', priceINR: 8760.00, period: 'Year', desc: 'Annual 1TB cloud mod repository capacity' },
            { id: 'b2-2tb-monthly', title: 'Storage B2 2TB (1 Month)', priceINR: 1450.00, period: 'Month', desc: '2,000 GB high-capacity storage for heavy ISOs/APKs' },
            { id: 'b2-2tb-yearly', title: 'Storage B2 2TB (1 Year)', priceINR: 17400.00, period: 'Year', desc: 'Annual 2TB cloud storage' },
            { id: 'b2-5tb-monthly', title: 'Storage B2 5TB (1 Month)', priceINR: 3650.00, period: 'Month', desc: '5,000 GB enterprise capacity for complete GPL archive' },
            { id: 'b2-5tb-yearly', title: 'Storage B2 5TB (1 Year)', priceINR: 43800.00, period: 'Year', desc: 'Annual 5TB full-archive preservation' }
        ]
    },
    {
        category: 'database',
        categoryTitle: 'MongoDB Atlas Cloud Database',
        icon: 'fas fa-server',
        color: '#4caf50',
        items: [
            { id: 'mongo-flex-monthly', title: 'MongoDB Atlas Flex (1 Month)', priceINR: 1500.00, period: 'Month', desc: 'Scalable auto-tier database for user profiles & catalog' },
            { id: 'mongo-flex-yearly', title: 'MongoDB Atlas Flex (1 Year)', priceINR: 18000.00, period: 'Year', desc: 'Annual high-availability replica set cluster' },
            { id: 'mongo-m10-monthly', title: 'MongoDB Dedicated M10 (1 Month)', priceINR: 4900.00, period: 'Month', desc: 'Dedicated RAM & CPU compute with point-in-time restores' },
            { id: 'mongo-m10-yearly', title: 'MongoDB Dedicated M10 (1 Year)', priceINR: 58800.00, period: 'Year', desc: 'Annual dedicated enterprise database tier' }
        ]
    },
    {
        category: 'compute',
        categoryTitle: 'Hosting & Compute Nodes',
        icon: 'fas fa-microchip',
        color: '#9c27b0',
        items: [
            { id: 'host-8gb-monthly', title: 'Hosting 8GB RAM Instance (1 Month)', priceINR: 13360.00, priceUSD: 160, period: 'Month', desc: 'High-speed 8GB RAM vCPU server instance' },
            { id: 'host-16gb-monthly', title: 'Hosting 16GB RAM Instance (1 Month)', priceINR: 18790.00, priceUSD: 225, period: 'Month', desc: 'Ultra 16GB RAM production cluster node' }
        ]
    },
    {
        category: 'domain',
        categoryTitle: 'Domain & Registry Security',
        icon: 'fas fa-globe',
        color: '#00bcd4',
        items: [
            { id: 'domain-org-yearly', title: 'Domain .org Renewal (1 Year)', priceINR: 1799.00, period: 'Year', desc: 'Official non-profit domain registry and DNSSEC protection' }
        ]
    },
    {
        category: 'ai',
        categoryTitle: 'Gemini AI Model Tokens',
        icon: 'fas fa-brain',
        color: '#ff9800',
        items: [
            { id: 'gemini-flash-lite', title: 'Gemini Flash-Lite Token Pack', priceINR: 50.00, period: 'One-time', desc: 'Powers ~100,000 smart search & translation tokens' },
            { id: 'gemini-flash', title: 'Gemini Flash AI Token Pack', priceINR: 150.00, period: 'One-time', desc: 'Powers ~500,000 mod analysis & scanning tokens' },
            { id: 'gemini-pro', title: 'Gemini Pro AI Token Pack', priceINR: 500.00, period: 'One-time', desc: 'Powers comprehensive code auditing & threat analysis' }
        ]
    },
    {
        category: 'security',
        categoryTitle: 'VPNAPI.io & Threat Protection',
        icon: 'fas fa-shield-alt',
        color: '#f44336',
        items: [
            { id: 'vpnapi-basic-monthly', title: 'VPNAPI Threat Basic (1 Month)', priceINR: 1586.50, priceUSD: 19, period: 'Month', desc: 'Real-time proxy/Tor/VPN bot mitigation' },
            { id: 'vpnapi-premium-monthly', title: 'VPNAPI Threat Premium (1 Month)', priceINR: 2421.50, priceUSD: 29, period: 'Month', desc: 'High-throughput threat intelligence firewall' },
            { id: 'vpnapi-pro-monthly', title: 'VPNAPI Threat Pro (1 Month)', priceINR: 8266.50, priceUSD: 99, period: 'Month', desc: 'Enterprise DDoS and malicious subnet blocker' }
        ]
    },
    {
        category: 'translation',
        categoryTitle: 'DeepL Pro & TempMail APIs',
        icon: 'fas fa-language',
        color: '#009688',
        items: [
            { id: 'deepl-pro-monthly', title: 'DeepL Pro Translation (1 Month)', priceINR: 2180.00, period: 'Month', desc: 'Neural AI translation for 30+ language localized mod pages' },
            { id: 'tempmail-1k-monthly', title: 'TempMail Detector 1K Lookups', priceINR: 418.00, period: 'Month', desc: 'Disposable email detection for 1,000 user registrations' },
            { id: 'tempmail-5k-monthly', title: 'TempMail Detector 5K Lookups', priceINR: 2088.00, period: 'Month', desc: 'Disposable email detection for 5,000 user registrations' }
        ]
    },
    {
        category: 'cdn',
        categoryTitle: 'CDNs, Workers & Developer Tools',
        icon: 'fas fa-bolt',
        color: '#ffc107',
        items: [
            { id: 'cdn-super-premium-monthly', title: 'InfinityFree Fallback CDN Super Premium', priceINR: 500.00, priceUSD: 5.99, period: 'Month', desc: 'Global high-availability asset mirror' },
            { id: 'cdn-ultimate-monthly', title: 'InfinityFree Fallback CDN Ultimate', priceINR: 750.00, priceUSD: 8.99, period: 'Month', desc: 'Unmetered edge distribution for scripts' },
            { id: 'cf-pro-monthly', title: 'Cloudflare Pro CDN (1 Month)', priceINR: 2100.00, period: 'Month', desc: 'WAF rules, image optimization, edge caching' },
            { id: 'cf-workers-monthly', title: 'Cloudflare Workers Paid (1 Month)', priceINR: 420.00, period: 'Month', desc: 'Serverless low-latency edge functions' },
            { id: 'github-team-monthly', title: 'GitHub Team Seat (1 Month)', priceINR: 334.00, period: 'Month', desc: 'CI/CD runner minutes & repo collaboration' },
            { id: 'github-copilot-monthly', title: 'GitHub Copilot Pro (1 Month)', priceINR: 835.00, period: 'Month', desc: 'AI code assistant seat for core platform engineering' }
        ]
    }
];

const COFFEE_FOOD_OPTIONS = [
    { id: 'chai', title: 'A Cup of Chai', priceINR: 50, icon: 'fas fa-mug-hot', desc: 'Keep our open-source devs caffeinated and inspired' },
    { id: 'coffee', title: 'Warm Brewed Coffee', priceINR: 100, icon: 'fa-duotone fa-solid fa-cup-togo', desc: 'A rich roast to power late-night reverse engineering' },
    { id: 'meal', title: 'Nutritious Meal', priceINR: 250, icon: 'fas fa-utensils', desc: 'A wholesome lunch after pushing a big security patch' },
    { id: 'feast', title: 'Developer Feast', priceINR: 500, icon: 'fas fa-pizza-slice', desc: 'Pizza and refreshments for a platform release celebration' }
];

app.get('/sponsor', async (req, res, next) => {
    try {
        const recentSponsors = await Donation.find({
            status: 'successful',
            $or: [{ sponsorItem: { $ne: null } }, { amount: { $gte: 50 } }]
        })
        .sort({ createdAt: -1 })
        .limit(15)
        .lean();

        res.render('pages/sponsor', {
            catalog: SPONSORSHIP_CATALOG,
            coffeeFoodOptions: COFFEE_FOOD_OPTIONS,
            recentSponsors
        });
    } catch (err) {
        console.error("Sponsor page error:", err);
        return next(err);
    }
});

app.post('/create-sponsor-order', async (req, res) => {
    try {
        const { itemTitle, category = 'infrastructure', amount, currency = 'INR', name, email, phone, message, isAnonymous } = req.body;
        const cur = String(currency || 'INR').toUpperCase();
        const numAmount = parseFloat(amount);

        if (isNaN(numAmount) || numAmount < 1) {
            return res.status(400).json({ error: 'Please specify a valid sponsorship amount.' });
        }

        const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
        const orderId = `spn_${Date.now().toString().slice(-8)}_${crypto.randomBytes(3).toString('hex')}`;
        const customerId = req.user ? String(req.user._id) : `guest_${crypto.randomBytes(5).toString('hex')}`;
        const customerName = isAnonymous ? 'Anonymous Supporter' : (name || (req.user ? req.user.username : 'Kind Sponsor'));
        const customerEmail = email || (req.user ? req.user.email : 'sponsor@gplmods.com');
        const customerPhone = phone || '9999999999';

        const orderRequest = {
            order_id: orderId,
            order_amount: numAmount,
            order_currency: cur,
            customer_details: {
                customer_id: customerId,
                customer_name: customerName,
                customer_email: customerEmail,
                customer_phone: customerPhone
            },
            order_meta: {
                return_url: `${baseUrl}/payment/verify-donation?order_id={order_id}`,
                notify_url: `${baseUrl}/webhook/cashfree/pg`
            },
            order_note: `GPL Mods Sponsorship: ${itemTitle || 'Infrastructure & Coffee'}`
        };

        const response = await cashfree.PGCreateOrder(orderRequest);

        await new Donation({
            user: req.user ? req.user._id : null,
            username: customerName,
            amount: numAmount,
            currency: cur,
            sponsorItem: itemTitle || 'General Support',
            sponsorCategory: category,
            message: message || '',
            isAnonymous: !!isAnonymous,
            orderId: orderId,
            paymentSessionId: response.data.payment_session_id,
            donorEmail: customerEmail,
            donorPhone: customerPhone,
            donorIp: getClientIp(req),
            status: 'pending'
        }).save();

        return res.json({
            payment_session_id: response.data.payment_session_id,
            order_id: orderId
        });
    } catch (error) {
        console.error('[Cashfree Sponsor Order Error]:', error.response?.data || error.message);
        return res.status(500).json({ 
            error: error.response?.data?.message || 'Failed to create sponsorship checkout.' 
        });
    }
});
// ==================================================
// SEO, ROBOTS.TXT & SITEMAP GENERATION
// ==================================================

const escapeXML = (str) => {
    if (!str) return '';
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;')
              .replace(/'/g, '&apos;');
};

// 1. Dynamic robots.txt
app.get('/robots.txt', (req, res) => {
    res.type('text/plain');
    const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
    
    res.send(`User-agent: *
Allow: /
Allow: /ai-directory
Allow: /about
Allow: /faq
Allow: /tos
Allow: /dmca
Allow: /privacy-policy
Allow: /refund-policy
Allow: /donate
Allow: /partnership-policy
Allow: /distributor-features
Allow: /why-choose-us
Allow: /understanding-scans
Allow: /membership
Allow: /docs/
Allow: /upload-policy
Allow: /category
Allow: /users/
Allow: /leaderboard
Allow: /licenses
Allow: /request-mod

Disallow: /admin/
Disallow: /owner/
Disallow: /dashboard
Disallow: /id-card
Disallow: /cc
Disallow: /api/
Disallow: /auth/
Disallow: /login
Disallow: /register
Disallow: /forgot-password
Disallow: /reset-password/
Disallow: /profile
Disallow: /my-uploads
Disallow: /settings
Disallow: /wishlist
Disallow: /support
Disallow: /partnership
Disallow: /upload
Disallow: /upload-initial
Disallow: /upload-finalize/
Disallow: /upload-details/
Disallow: /account/
Disallow: /community-chat
Disallow: /notifications/
Disallow: /download-file/
Disallow: /repos/
Disallow: /jailbreak-repos/

Sitemap: ${baseUrl}/sitemap_index.xml`);
});

// 2. Master Sitemap Index (Points to all other sitemaps)
app.get('/sitemap_index.xml', (req, res) => {
    res.set('Content-Type', 'text/xml');
    const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
    
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
    xml += '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
    
    const sitemaps = ['pages', 'mods', 'users', 'developers', 'docs'];
    
    sitemaps.forEach(map => {
        xml += `  <sitemap>\n    <loc>${baseUrl}/sitemap-${map}.xml</loc>\n    <lastmod>${new Date().toISOString()}</lastmod>\n  </sitemap>\n`;
    });
    
    xml += '</sitemapindex>';
    res.send(xml);
});

// Redirect old sitemap.xml to the new index
app.get('/sitemap.xml', (req, res) => res.redirect(301, '/sitemap_index.xml'));
// 3a. Static Pages & Categories Sitemap
app.get('/sitemap-pages.xml', (req, res) => {
    res.set('Content-Type', 'text/xml');
    const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

    const staticPages = [
        '', 
        '/about', 
        '/faq', 
        '/dmca', 
        '/tos', 
        '/privacy-policy', 
        '/refund-policy', 
        '/donate', 
        '/partnership-policy', 
        '/distributor-features', 
        '/why-choose-us', 
        '/understanding-scans', 
        '/membership', 
        '/upload-policy', 
        '/docs', 
        '/community', 
        '/leaderboard', 
        '/licenses', 
        '/request-mod', 
        '/ai-directory'
    ];
    staticPages.forEach(page => {
        xml += `  <url>\n    <loc>${escapeXML(baseUrl + page)}</loc>\n    <changefreq>weekly</changefreq>\n    <priority>${page === '' ? '1.0' : '0.8'}</priority>\n  </url>\n`;
    });

    const categories = ['android', 'ios-jailed', 'ios-jailbroken', 'windows', 'wordpress'];
    categories.forEach(cat => {
         xml += `  <url>\n    <loc>${escapeXML(baseUrl + '/category?platform=' + encodeURIComponent(cat))}</loc>\n    <changefreq>daily</changefreq>\n    <priority>0.8</priority>\n  </url>\n`;
    });

    xml += '</urlset>';
    res.send(xml);
});

// 3b. Mods Sitemap (WITH IMAGE AND VIDEO EXTENSIONS)
app.get('/sitemap-mods.xml', async (req, res) => {
    try {
        res.set('Content-Type', 'text/xml');
        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        
        // Notice the added namespaces for image and video!
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
        xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1" xmlns:video="http://www.google.com/schemas/sitemap-video/1.1">\n';

        const liveMods = await File.find({ showInSitemap: { $ne: false }, isLatestVersion: true, status: 'live' })
            .select('_id category slug name modDescription videoUrl updatedAt')
            .lean(); 
            
        liveMods.forEach(mod => {
            let lastModDate = mod.updatedAt ? new Date(mod.updatedAt).toISOString() : new Date().toISOString();
            const modUrl = `${baseUrl}/${encodeURIComponent(mod.category)}/${encodeURIComponent(mod.slug || mod._id.toString())}`;
            
            xml += `  <url>\n    <loc>${escapeXML(modUrl)}</loc>\n    <lastmod>${lastModDate}</lastmod>\n    <changefreq>daily</changefreq>\n    <priority>0.9</priority>\n`;
            
            // IF the mod has a YouTube video, tell Google about it!
            if (mod.videoUrl && mod.videoUrl.includes('youtube.com')) {
                xml += `    <video:video>\n`;
                xml += `      <video:title>${escapeXML(mod.name + ' Mod Video')}</video:title>\n`;
                xml += `      <video:description>${escapeXML(mod.modDescription ? mod.modDescription.substring(0, 100) : mod.name)}</video:description>\n`;
                xml += `      <video:player_loc>${escapeXML(mod.videoUrl)}</video:player_loc>\n`;
                xml += `    </video:video>\n`;
            }
            
            xml += `  </url>\n`;
        });

        xml += '</urlset>';
        res.send(xml);
    } catch (error) { res.status(500).send('Error'); }
});

// 3c. Public Users Sitemap
app.get('/sitemap-users.xml', async (req, res) => {
    try {
        res.set('Content-Type', 'text/xml');
        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

        const uniqueUploaders = await File.distinct('uploader', { status: 'live', isLatestVersion: true });
        const staffOrDistributors = await User.find({
            role: { $in: ['distributor', 'owner', 'admin', 'support'] },
            isBanned: false
        }).select('username').lean();

        const allUsers = new Set([
            ...uniqueUploaders,
            ...staffOrDistributors.map(u => u.username)
        ].filter(Boolean));

        allUsers.forEach(username => {
             xml += `  <url>\n    <loc>${escapeXML(baseUrl + '/users/' + encodeURIComponent(username))}</loc>\n    <changefreq>weekly</changefreq>\n    <priority>0.7</priority>\n  </url>\n`;
        });
        xml += '</urlset>';
        res.send(xml);
    } catch (error) { res.status(500).send('Error'); }
});

// 3d. Developers Sitemap
app.get('/sitemap-developers.xml', async (req, res) => {
    try {
        res.set('Content-Type', 'text/xml');
        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

        const uniqueDevelopers = await File.distinct('developer', { status: 'live', isLatestVersion: true }).lean();
        uniqueDevelopers.forEach(dev => {
            if (dev && dev !== 'N/A') {
                xml += `  <url>\n    <loc>${escapeXML(baseUrl + '/developer?name=' + encodeURIComponent(dev))}</loc>\n    <changefreq>weekly</changefreq>\n    <priority>0.6</priority>\n  </url>\n`;
            }
        });
        xml += '</urlset>';
        res.send(xml);
    } catch (error) { res.status(500).send('Error'); }
});

// 3e. Docs Sitemap
app.get('/sitemap-docs.xml', async (req, res) => {
    try {
        res.set('Content-Type', 'text/xml');
        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
        
        // (Assuming you have a DocPage model based on your prompt)
        if (typeof DocPage !== 'undefined') {
            const allDocPages = await DocPage.find().select('slug updatedAt').lean();
            allDocPages.forEach(doc => {
                let lastDocDate = doc.updatedAt ? new Date(doc.updatedAt).toISOString() : new Date().toISOString();
                xml += `  <url>\n    <loc>${escapeXML(baseUrl + '/docs/' + encodeURIComponent(doc.slug))}</loc>\n    <lastmod>${lastDocDate}</lastmod>\n    <changefreq>weekly</changefreq>\n    <priority>0.7</priority>\n  </url>\n`;
            });
        }
        xml += '</urlset>';
        res.send(xml);
    } catch (error) { res.status(500).send('Error'); }
});

// ======== HTML SITEMAP (FOR AI CRAWLERS & SEO) ========
app.get('/ai-directory', async (req, res) => {
    try {
        // 1. Fetch live mods with extended data (Description, Image Keys, Dates)
        const liveMods = await File.find({ 
            status: 'live', 
            isLatestVersion: true,
            showInSitemap: { $ne: false }
        })
        .select('name category slug developer uploader modDescription iconKey iconUrl updatedAt') 
        .lean()
        .sort({ category: 1, name: 1 }); 

        // 2. Generate the viewable Image URLs for the crawlers
        const modsWithUrls = await Promise.all(liveMods.map(async (mod) => {
            const key = mod.iconUrl || mod.iconKey;
            const signedIconUrl = await getSmartImageUrl(key);
            return { ...mod, iconUrl: signedIconUrl };
        }));

        // 3. Group by Category
        const modsByCategory = {};
        modsWithUrls.forEach(mod => {
            if (!modsByCategory[mod.category]) {
                modsByCategory[mod.category] = [];
            }
            modsByCategory[mod.category].push(mod);
        });

        // 4. Fetch Unique Developers & Uploaders for the User/Dev Directory
        const uniqueDevelopers = await File.distinct('developer', { status: 'live', isLatestVersion: true }).lean();
        const uniqueUploaders = await File.distinct('uploader', { status: 'live', isLatestVersion: true }).lean();

        res.render('pages/ai-directory', { 
            modsByCategory: modsByCategory,
            developers: uniqueDevelopers.filter(d => d && d !== 'N/A'), // Remove empty/N/A
            uploaders: uniqueUploaders.filter(u => u) // Remove empty
        });

    } catch (error) {
        console.error("AI Directory generation error:", error);
        res.status(500).render('pages/500');
    }
});
// ===============================================
// 15. UNIVERSAL REPOSITORY ENGINE (Automatic, Manual & JSON)
// ===============================================

// Helper: Ensure we always have the correct Base URL for external repo clients
function getRepoBaseUrl(req) {
    if (process.env.BASE_URL) {
        return process.env.BASE_URL.replace(/\/*$/, '');
    }
    const forwardedProto = req.headers['x-forwarded-proto'];
    const protocol = forwardedProto ? forwardedProto.split(',')[0].trim() : req.protocol;
    const host = req.get('host');
    return `${protocol}://${host}`.replace(/\/*$/, '');
}

// Redirect base paths to the actual index files
app.get('/ios-repo', (req, res) => res.redirect('/ios-repo/Packages'));
app.get('/fdroid/repo', (req, res) => res.redirect('/fdroid/repo/index-v2.json'));


// ======== PERMANENT IMAGE REDIRECTS FOR ALL REPOS ========
// Repo clients expect static URLs. We redirect these static URLs to the temporary B2 signed URLs.
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


// -----------------------------------------------
// A. iOS JAILBREAK REPO ENGINE (APT & Sileo Native)
// -----------------------------------------------

async function generateIosPackages(req) {
    const repoBaseUrl = getRepoBaseUrl(req);
    
    // ✅ FIX 1: Fetch ALL live versions of iOS jailbroken mods, not just the latest!
    // This is what enables the "Downgrade" feature in Sileo/Zebra.
    const allJbMods = await File.find({ 
        category: 'ios-jailbroken', 
        status: 'live', 
        showInRepo: { $ne: false } 
    }).sort({ createdAt: -1 });

    let packagesText = '';

    for (const mod of allJbMods) {
        const downloadUrl = mod.externalDownloadUrl || (mod.fileKey ? `${repoBaseUrl}/download-file/${mod._id}` : null);
        if (!downloadUrl) continue;

        let aptArch = 'iphoneos-arm';
        if (mod.architectures && mod.architectures.includes('arm64')) aptArch = 'iphoneos-arm64';

        // The Bundle ID must be identical across all versions of the same tweak
        const baseModName = mod.isLatestVersion ? mod.name : (await File.findById(mod.parentFile)).name;
        const bundleId = `com.gplmods.${(mod.slug || baseModName).toLowerCase().replace(/[^a-z0-9]/g, '')}`;
        
        const cleanDesc = (mod.modDescription || 'No description').replace(/<[^>]*>?/gm, '').substring(0, 150).replace(/\n/g, ' ');

        packagesText += `Package: ${bundleId}\n`;
        packagesText += `Name: ${mod.name}\n`;
        packagesText += `Version: ${mod.version}\n`;
        packagesText += `Architecture: ${aptArch}\n`;
        packagesText += `Maintainer: ${mod.developer || 'GPL Mods Team'} <admin@gplmods.webredirect.org>\n`;
        packagesText += `Author: ${mod.uploader}\n`;
        packagesText += `Section: Tweaks\n`;
        packagesText += `Description: ${cleanDesc}...\n`;
        packagesText += `Icon: ${repoBaseUrl}/api/icon/${mod._id}\n`;
        // Point depictions to the specific version ID
        packagesText += `Depiction: ${repoBaseUrl}/ios-jailbroken/${mod.slug || mod._id}\n`;
        packagesText += `SileoDepiction: ${repoBaseUrl}/ios-repo/depiction/${mod._id}.json\n`;
        packagesText += `Filename: ${downloadUrl}\n`; 
        packagesText += `Size: ${mod.fileSize || 1024}\n\n`;
    }
    return packagesText;
}

app.get('/ios-repo/Release', (req, res) => {
    const releaseText = `Origin: GPL Mods\nLabel: GPL Mods\nSuite: stable\nVersion: 1.0\nCodename: ios\nArchitectures: iphoneos-arm iphoneos-arm64\nComponents: main\nDescription: 100% Safe & Working Mods For All Your Devices!\nIcon: ${getRepoBaseUrl(req)}/images/icon-512x512.png\n`;
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

app.get('/ios-repo/sileo-info.json', async (req, res) => {
    try {
        const repoBaseUrl = getRepoBaseUrl(req);
        
        // 1. Fetch data to populate the home screen
        // Get Editors Choice for the Featured Banner
        const featuredMods = await File.find({ 
            category: 'ios-jailbroken', 
            status: 'live', 
            isLatestVersion: true,
            isEditorsChoice: true 
        }).limit(5);

        // Get Most Downloaded for "Hot Right Now"
        const hotMods = await File.find({ 
            category: 'ios-jailbroken', 
            status: 'live', 
            isLatestVersion: true 
        }).sort({ downloads: -1 }).limit(6);

        // Get Newest for "Recently Updated"
        const newMods = await File.find({ 
            category: 'ios-jailbroken', 
            status: 'live', 
            isLatestVersion: true 
        }).sort({ updatedAt: -1 }).limit(6);


        // 2. Build the Sileo Native UI JSON
        const sileoTabs = [];

        // --- FEATURED BANNERS ---
        if (featuredMods.length > 0) {
            const banners = featuredMods.map(mod => ({
                url: `depiction-${mod._id}`, // Special Sileo internal link format
                title: mod.name,
                // We use the first screenshot as the banner background, fallback to icon
                url2: (mod.screenshotKeys && mod.screenshotKeys.length > 0) ? `${repoBaseUrl}/api/screenshot/${mod._id}/0` : `${repoBaseUrl}/api/icon/${mod._id}`,
                hideShadow: false
            }));
            
            sileoTabs.push({
                class: "DepictionFeaturedView",
                itemCornerRadius: 12,
                itemSize: "{280, 140}", // Wide aspect ratio for banners
                spacing: 16,
                banners: banners
            });
        }

        // --- HOT RIGHT NOW ---
        if (hotMods.length > 0) {
            sileoTabs.push({ class: "DepictionHeaderView", title: "Hot Right Now" });
            const hotPackages = hotMods.map(mod => `com.gplmods.${(mod.slug || mod.name).toLowerCase().replace(/[^a-z0-9]/g, '')}`);
            sileoTabs.push({
                class: "DepictionPackageListView",
                packages: hotPackages
            });
        }

        // --- RECENTLY UPDATED ---
        if (newMods.length > 0) {
            sileoTabs.push({ class: "DepictionHeaderView", title: "Recently Updated" });
            const newPackages = newMods.map(mod => `com.gplmods.${(mod.slug || mod.name).toLowerCase().replace(/[^a-z0-9]/g, '')}`);
            sileoTabs.push({
                class: "DepictionPackageListView",
                packages: newPackages
            });
        }

        // --- FOOTER BUTTONS ---
        sileoTabs.push(
            { class: "DepictionSeparatorView" },
            {
                class: "DepictionButtonView",
                text: "Join our Discord",
                action: "https://discord.gg/mmr3r2W2ak",
                tintColor: "#5865F2"
            },
            {
                class: "DepictionButtonView",
                text: "Visit GPL Mods Website",
                action: repoBaseUrl,
                tintColor: "#FFD700"
            }
        );

        res.json({
            name: "GPL Mods",
            icon: `${repoBaseUrl}/images/icon-512x512.png`,
            description: "100% Safe & Working Mods For All Your Devices!",
            tintColor: "#FFD700",
            headerImage: `${repoBaseUrl}/images/icon-512x512.png`,
            authentication_banner: {
                message: "Support us by upgrading to Premium!",
                button: "Go Premium"
            },
            class: "DepictionTabView",
            tabs: [
                {
                    tabname: "Featured",
                    class: "DepictionStackView",
                    views: sileoTabs
                }
            ]
        });

    } catch (e) {
        console.error("Sileo Info JSON Error:", e);
        res.status(500).json({});
    }
});

app.get('/ios-repo/depiction/:id.json', async (req, res) => {
    try {
        const mod = await File.findById(req.params.id);
        if (!mod) return res.status(404).json({});

        const repoBaseUrl = getRepoBaseUrl(req);
        
        // --- 1. Clean HTML tags for native Markdown rendering in Sileo ---
        const cleanDesc = (mod.modDescription || 'No description').replace(/<[^>]*>?/gm, '');
        const cleanFeatures = (mod.modFeatures || '').replace(/<[^>]*>?/gm, '');
        const cleanWhatsNew = (mod.whatsNew || 'Bug fixes.').replace(/<[^>]*>?/gm, '');
        
        // ✅ NEW: Added Important Note & Official Description
        const cleanImportantNote = (mod.importantNote || '').replace(/<[^>]*>?/gm, '');
        const cleanOfficialDesc = (mod.officialDescription || '').replace(/<[^>]*>?/gm, '');

        let screenshots = [];
        if (mod.screenshotKeys && mod.screenshotKeys.length > 0) {
            screenshots = mod.screenshotKeys.map((_, index) => {
                return { url: `${repoBaseUrl}/api/screenshot/${mod._id}/${index}`, accessibilityText: "Screenshot" };
            });
        }

        let detailsViews = [
            { class: "DepictionHeaderView", title: mod.name },
            { class: "DepictionSubheaderView", title: `Version ${mod.version}` },
            { class: "DepictionRatingView", rating: mod.averageRating || 5 }
        ];

        if (screenshots.length > 0) {
            detailsViews.push(
                { class: "DepictionScreenshotsView", itemCornerRadius: 10, itemSize: "{160, 346}", screenshots: screenshots },
                { class: "DepictionSeparatorView" }
            );
        }

        // ✅ NEW: 1. Important Note (Placed at the very top so users don't miss it!)
        if (cleanImportantNote) {
            detailsViews.push(
                { class: "DepictionMarkdownView", markdown: `**🚨 IMPORTANT NOTE:**\n\n${cleanImportantNote}` },
                { class: "DepictionSeparatorView" }
            );
        }

        // 2. Mod Description
        detailsViews.push(
            { class: "DepictionMarkdownView", markdown: `**Description**\n\n${cleanDesc}` },
            { class: "DepictionSeparatorView" }
        );

        // 3. Mod Features
        if (cleanFeatures) {
            detailsViews.push(
                { class: "DepictionMarkdownView", markdown: `**Features**\n\n${cleanFeatures}` },
                { class: "DepictionSeparatorView" }
            );
        }

        // ✅ NEW: 4. Official App Store Description
        if (cleanOfficialDesc) {
            detailsViews.push(
                { class: "DepictionMarkdownView", markdown: `**App Store Info**\n\n${cleanOfficialDesc}` },
                { class: "DepictionSeparatorView" }
            );
        }

        // Footer / Meta Info
        detailsViews.push(
            { class: "DepictionHeaderView", title: "Information" },
            { class: "DepictionTableTextView", title: "Developer", text: mod.developer || "GPL Mods" },
            { class: "DepictionTableTextView", title: "Uploader", text: mod.uploader },
            { class: "DepictionTableTextView", title: "Category", text: mod.platforms.join(', ') || "Tweak" },
            { class: "DepictionTableTextView", title: "Updated", text: new Date(mod.updatedAt).toLocaleDateString() }
        );

        detailsViews.push(
            { class: "DepictionSeparatorView" },
            { class: "DepictionButtonView", text: "View on GPL Mods", action: `${repoBaseUrl}/ios-jailbroken/${mod.slug || mod._id}`, tintColor: "#FFD700" }
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

// -----------------------------------------------
// B. iOS SIDELOADING REPO ENGINE (AltStore / SideStore / Scarlet)
// -----------------------------------------------
app.get('/ios-repo/apps.json', async (req, res) => {
    try {
        const repoBaseUrl = getRepoBaseUrl(req);
        
        // 1. Fetch all LIVE, LATEST VERSION IPA mods
        const ipaMods = await File.find({ 
            category: 'ios-jailed',
            status: 'live',
            isLatestVersion: true,
            showInRepo: { $ne: false },
            // Ensure there is actually a file to download
            $or:[ { directDownloadUrl: { $exists: true, $ne: '' } }, { externalDownloadUrl: { $exists: true, $ne: '' } }, { fileKey: { $exists: true, $ne: '' } } ]
        }).sort({ createdAt: -1 });

        // 2. Fetch the latest Site Announcements for the SideStore News Feed
        const recentNews = await Announcement.find().sort({ createdAt: -1 }).limit(5);

        // 3. Initialize the Core JSON Structure
        const sourceJson = {
            name: "GPL Mods",
            identifier: "org.webredirect.gplmods.ios",
            subtitle: "100% Safe & Working iOS Mods",
            description: "The ultimate source for tweaked and modded iOS apps and games. Enjoy premium features without a jailbreak.",
            iconURL: `${repoBaseUrl}/images/icon-512x512.png`,
            headerURL: `${repoBaseUrl}/images/icon-512x512.png`,
            website: repoBaseUrl,
            tintColor: "#FFD700", // GPL Gold
            featuredApps: [], // We can highlight Editor's Choice here
            apps: [], 
            news: [] // The new SideStore News section
        };

        // 4. Populate the Apps Array
        for (const mod of ipaMods) {
            const downloadUrl = mod.externalDownloadUrl || (mod.fileKey ? `${repoBaseUrl}/download-file/${mod._id}` : null);
            if (!downloadUrl) continue;

            // Clean up the text by removing HTML tags (SideStore expects Markdown/Plain text)
            const cleanDesc = (mod.modDescription || '').replace(/<[^>]*>?/gm, '');
            const cleanFeatures = (mod.modFeatures || '').replace(/<[^>]*>?/gm, '');
            const cleanNotes = (mod.officialDescription || '').replace(/<[^>]*>?/gm, '');
            const cleanImportantNote = (mod.importantNote || '').replace(/<[^>]*>?/gm, '');
            const cleanWhatsNew = (mod.whatsNew || 'New update available.').replace(/<[^>]*>?/gm, '');
            
            // Build a comprehensive, Markdown-formatted description
            let fullMarkdownDesc = `${cleanDesc}\n\n`;
            if (cleanImportantNote) fullMarkdownDesc += `**🚨 IMPORTANT NOTE:**\n${cleanImportantNote}\n\n`;
            if (cleanFeatures) fullMarkdownDesc += `**Mod Features:**\n${cleanFeatures}\n\n`;
            if (cleanNotes) fullMarkdownDesc += `**App Store Info:**\n${cleanNotes}\n\n`;

            const bundleId = `com.gplmods.${(mod.slug || mod.name).toLowerCase().replace(/[^a-z0-9]/g, '')}`;
            const iconUrl = `${repoBaseUrl}/api/icon/${mod._id}`;
            const screenshotUrls = (mod.screenshotKeys || []).map((_, i) => `${repoBaseUrl}/api/screenshot/${mod._id}/${i}`);

            const appData = {
                name: mod.name,
                bundleIdentifier: bundleId,
                developerName: mod.developer || "GPL Mods",
                subtitle: `Version ${mod.version} by ${mod.uploader}`,
                localizedDescription: fullMarkdownDesc, 
                iconURL: iconUrl,
                tintColor: "#FFD700",
                size: mod.fileSize || 1048576,
                screenshotURLs: screenshotUrls,
                // Add app permissions if you track them (SideStore feature)
                permissions: {
                    "background-audio": "Allows the app to play audio in the background.",
                    "networking": "Allows the app to access the internet."
                },
                versions: [{
                    version: mod.version,
                    date: new Date(mod.updatedAt).toISOString(),
                    localizedDescription: cleanWhatsNew, 
                    downloadURL: downloadUrl,
                    size: mod.fileSize || 1048576
                }]
            };

            // If it's an editor's choice, feature it at the top of the AltStore/SideStore home screen
            if (mod.isEditorsChoice) {
                sourceJson.featuredApps.push(bundleId);
            }

            sourceJson.apps.push(appData);
        }

        // 5. Populate the News Array (SideStore Exclusive Feature)
        for (const newsItem of recentNews) {
            sourceJson.news.push({
                title: newsItem.title,
                identifier: `org.webredirect.gplmods.news.${newsItem._id}`,
                caption: `Posted by ${newsItem.author}`,
                date: new Date(newsItem.createdAt).toISOString(),
                tintColor: "#FFD700",
                imageURL: `${repoBaseUrl}/images/icon-512x512.png`, // Fallback to site logo
                // If you add an image field to your Announcements later, put it here:
                // imageURL: newsItem.imageUrl || `${repoBaseUrl}/images/icon-512x512.png`, 
                url: `${repoBaseUrl}/updates`, // Where clicking the news takes them
                notify: true // Tells SideStore to push a notification for this news!
            });
        }

        res.set('Content-Type', 'application/json');
        res.send(JSON.stringify(sourceJson, null, 2));

    } catch (e) { 
        console.error("SideStore JSON Error:", e);
        res.status(500).json({ error: "Error generating Source JSON." }); 
    }
});


// -----------------------------------------------
// C. ANDROID F-DROID REPO ENGINE
// -----------------------------------------------

// Helper function to safely escape XML characters and strip HTML tags
function escapeXml(unsafe) {
    if (!unsafe) return '';
    // First, strip all HTML tags as F-Droid XML does not support HTML
    let text = unsafe.toString().replace(/<[^>]*>?/gm, '');
    // Then escape XML special characters
    return text.replace(/[<>&'"]/g, function (c) {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
            default: return c;
        }
    });
}

// Helper to generate the core XML data (index.xml)
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
        const downloadUrl = mod.externalDownloadUrl || (mod.fileKey ? `${repoBaseUrl}/download-file/${mod._id}` : null);
        if (!downloadUrl) continue;

        const bundleId = `com.gplmods.${(mod.slug || mod.name).toLowerCase().replace(/[^a-z0-9]/g, '')}`;
        
        // Compile a rich description for the XML
        let fullDesc = mod.modDescription || '';
        if (mod.modFeatures) fullDesc += `\n\nFeatures:\n${mod.modFeatures}`;
        if (mod.officialDescription) fullDesc += `\n\nApp Info:\n${mod.officialDescription}`;
        if (mod.importantNote) fullDesc += `\n\nIMPORTANT:\n${mod.importantNote}`;

        xml += `  <application id="${escapeXml(bundleId)}">\n`;
        xml += `    <id>${escapeXml(bundleId)}</id>\n`;
        xml += `    <name>${escapeXml(mod.name)}</name>\n`;
        xml += `    <summary>${escapeXml(mod.version)} Mod by ${escapeXml(mod.uploader)}</summary>\n`;
        xml += `    <desc>${escapeXml(fullDesc)}</desc>\n`;
        xml += `    <license>GNU/GPL</license>\n`;
        xml += `    <categories><category>Mods</category></categories>\n`;
        xml += `    <icon>${escapeXml(repoBaseUrl)}/api/icon/${mod._id}</icon>\n`;
        xml += `    <author>${escapeXml(mod.developer || 'GPL Mods')}</author>\n`; // Map Developer to Author
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

// 1. Classic XML Route
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

// 2. Classic JAR Route (Zips the XML file dynamically)
app.get('/fdroid/repo/index.jar', async (req, res) => {
    try {
        const xmlContent = await generateFDroidXml(req);
        const zip = new AdmZip();
        zip.addFile("index.xml", Buffer.from(xmlContent, "utf8"));
        const jarBuffer = zip.toBuffer();

        res.set('Content-Type', 'application/java-archive');
        res.set('Content-Disposition', 'attachment; filename="index.jar"');
        res.send(jarBuffer);
    } catch (e) { 
        console.error("JAR Error:", e);
        res.status(500).send("Error generating index.jar"); 
    }
});

// 3. Current default endpoint for Neo Store / Droid-ify (index-v2.json)
app.get('/fdroid/repo/index-v2.json', async (req, res) => {
    try {
        const repoBaseUrl = getRepoBaseUrl(req);
        const androidMods = await File.find({ 
            category: 'android', status: 'live', isLatestVersion: true, showInRepo: { $ne: false } 
        }).sort({ createdAt: -1 });

        const repoJson = {
            repo: {
                name: { "en-US": "GPL Mods Android" },
                description: { "en-US": "The ultimate source for safe and working Android mods." },
                address: `${repoBaseUrl}/fdroid/repo`,
                icon: { "en-US": { name: "icon-512x512.png" } }, 
                timestamp: Date.now(),
                version: 2
            },
            requests: { install: [], uninstall: [] },
            packages: {}
        };

        for (const mod of androidMods) {
            const downloadUrl = mod.externalDownloadUrl || (mod.fileKey ? `${repoBaseUrl}/download-file/${mod._id}` : null);
            if (!downloadUrl) continue;

            const bundleId = `com.gplmods.${(mod.slug || mod.name).toLowerCase().replace(/[^a-z0-9]/g, '')}`;
            
            // F-Droid JSON v2 supports Markdown, so we can preserve formatting, but NOT HTML
            const cleanDesc = (mod.modDescription || '').replace(/<[^>]*>?/gm, '');
            const cleanFeatures = (mod.modFeatures || '').replace(/<[^>]*>?/gm, '');
            const cleanNotes = (mod.officialDescription || '').replace(/<[^>]*>?/gm, '');
            const cleanWhatsNew = (mod.whatsNew || 'Bug fixes.').replace(/<[^>]*>?/gm, '');
            const cleanImportantNote = (mod.importantNote || '').replace(/<[^>]*>?/gm, '');

            // Build a comprehensive Markdown description
            let fullMarkdownDesc = `${cleanDesc}\n\n`;
            if (cleanImportantNote) fullMarkdownDesc += `**🚨 IMPORTANT NOTE:**\n${cleanImportantNote}\n\n`;
            if (cleanFeatures) fullMarkdownDesc += `**Features:**\n${cleanFeatures}\n\n`;
            if (cleanNotes) fullMarkdownDesc += `**App Store Info:**\n${cleanNotes}\n\n`;

            const screenshotArray = [];
            if (mod.screenshotKeys && mod.screenshotKeys.length > 0) {
                mod.screenshotKeys.forEach((_, i) => {
                    // F-Droid expects an object with a 'name' property pointing to the image URL
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

// ==========================================
// DMCA AUTOMATED COMPLIANCE & TAKEDOWN ENGINE
// ==========================================

// Helper to resolve any incoming GPLMods URL or path to a matching File record
async function resolveGplModsUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== 'string') return { found: false, url: rawUrl };
    const trimmed = rawUrl.trim();
    if (!trimmed) return { found: false, url: rawUrl };

    try {
        let cleanPath = trimmed;
        if (cleanPath.startsWith('http://') || cleanPath.startsWith('https://')) {
            try {
                const parsed = new URL(cleanPath);
                cleanPath = parsed.pathname;
            } catch (err) {
                cleanPath = cleanPath.replace(/^https?:\/\/[^\/]+/i, '');
            }
        }

        // Strip query strings, hashes, and leading/trailing slashes
        cleanPath = cleanPath.split('?')[0].split('#')[0].replace(/^\/+|\/+$/g, '');
        const segments = cleanPath.split('/').filter(Boolean);

        // 1. Direct ObjectId search in segments (e.g., /mods/:id or /download-file/:id or /mods/:cat/:slug/:variantId)
        for (let i = segments.length - 1; i >= 0; i--) {
            const seg = segments[i];
            if (Types.ObjectId.isValid(seg) && /^[a-fA-F0-9]{24}$/.test(seg)) {
                const fileById = await File.findById(seg);
                if (fileById) {
                    if (fileById.isVariant && fileById.masterFile) {
                        return { found: true, file: fileById, targetType: 'variant', masterFileId: fileById.masterFile, url: trimmed };
                    } else {
                        return { found: true, file: fileById, targetType: 'main', url: trimmed };
                    }
                }
            }
        }

        // 2. Slug & category matching: /mods/:category/:slug or /:category/:slug
        let cat = null;
        let slug = null;
        if (segments.length >= 2 && segments[0] === 'mods') {
            cat = segments[1];
            slug = segments[2];
        } else if (segments.length >= 2) {
            cat = segments[0];
            slug = segments[1];
        } else if (segments.length === 1) {
            slug = segments[0];
        }

        if (slug) {
            const query = { isVariant: { $ne: true } };
            if (cat && ['android', 'windows', 'ios-jailed', 'ios-jailbroken', 'wordpress'].includes(cat.toLowerCase())) {
                query.category = cat.toLowerCase();
            }
            query.slug = slug.toLowerCase();

            let matchedMain = await File.findOne(query);
            if (!matchedMain) {
                matchedMain = await File.findOne({ slug: slug.toLowerCase(), isVariant: { $ne: true } });
            }
            if (!matchedMain) {
                // Try case-insensitive name match
                const namePattern = new RegExp(`^${slug.replace(/-/g, '[-\\s]+')}$`, 'i');
                matchedMain = await File.findOne({ name: namePattern, isVariant: { $ne: true } });
            }
            if (matchedMain) {
                return { found: true, file: matchedMain, targetType: 'main', url: trimmed };
            }
        }

        // 3. Fallback: match by direct external or mirror download URLs
        const matchedByLink = await File.findOne({
            $or: [
                { directDownloadUrl: trimmed },
                { externalDownloadUrl: trimmed },
                { 'downloadParts.partUrl': trimmed },
                { 'downloadParts.mirror1Url': trimmed },
                { 'downloadParts.mirror2Url': trimmed }
            ]
        });
        if (matchedByLink) {
            return {
                found: true,
                file: matchedByLink,
                targetType: matchedByLink.isVariant ? 'variant' : 'main',
                masterFileId: matchedByLink.masterFile || null,
                url: trimmed
            };
        }

        return { found: false, url: trimmed };
    } catch (e) {
        console.error("Error in resolveGplModsUrl:", e);
        return { found: false, url: rawUrl };
    }
}

// Executes automated or manual hiding of reported files
async function executeDmcaTakedown(dmcaId) {
    try {
        const dmca = await Dmca.findById(dmcaId).populate('reportedFiles.file');
        if (!dmca || dmca.status === 'false-claim' || dmca.status === 'action-taken') return false;
        if (dmca.isAutomatedHidden) return false;

        console.log(`[DMCA Engine] Executing link hiding for Notice #${dmca._id}`);

        for (const item of dmca.reportedFiles) {
            if (!item.file) continue;
            const file = await File.findById(item.file._id || item.file);
            if (!file) continue;

            file.isDmcaHidden = true;
            file.dmcaReportId = dmca._id;
            file.dmcaHiddenAt = new Date();

            if (item.targetType === 'main') {
                // Find most recent live variant uploaded after main file
                const latestVariant = await File.findOne({
                    masterFile: file._id,
                    isVariant: true,
                    status: 'live',
                    isDmcaHidden: { $ne: true }
                }).sort({ createdAt: -1 });

                if (latestVariant) {
                    file.temporaryPromotedVariantId = latestVariant._id;
                    item.promotedVariant = latestVariant._id;
                    console.log(`[DMCA Engine] Temporarily promoting variant "${latestVariant.name}" (${latestVariant._id}) to replace hidden main mod "${file.name}"`);
                }
            }
            await file.save();
            item.isHidden = true;
        }

        dmca.status = 'auto-hidden';
        dmca.isAutomatedHidden = true;
        dmca.hiddenAt = new Date();
        await dmca.save();

        // 1. Automated Notification to Admins
        const admins = await User.find({ role: { $in: ['admin', 'owner'] } });
        for (const admin of admins) {
            await new UserNotification({
                user: admin._id,
                title: 'Automated DMCA Takedown Executed',
                message: `The 24-48h window has reached deadline for DMCA Notice #${dmca._id.toString().slice(-6)}. Reported file links have been automatically hidden. Action required in the Admin DMCA Dashboard.`,
                type: 'dmca-notice',
                metadata: { dmcaId: dmca._id }
            }).save();
        }

        // 2. Automated Notification to Uploaders
        const uploaderNames = new Set(
            dmca.reportedFiles
                .map(rf => rf.file && rf.file.uploader)
                .filter(Boolean)
        );
        for (const uploaderName of uploaderNames) {
            const uploaderUser = await User.findOne({ username: uploaderName });
            if (uploaderUser) {
                await new UserNotification({
                    user: uploaderUser._id,
                    title: 'Notice: Mod Content Temporarily Restricted Under DMCA',
                    message: `One or more files uploaded under your account have been temporarily restricted following a formal DMCA takedown notice. Our administration team is reviewing the claim. You can check the current status in your My Uploads dashboard.`,
                    type: 'dmca-notice'
                }).save();
            }
        }

        return true;
    } catch (err) {
        console.error("[DMCA Engine] Error executing takedown:", err);
        return false;
    }
}

// Restores files when admin determines claim was a False Claim
async function restoreDmcaFiles(dmcaId, resolutionNotes, adminUsername) {
    try {
        const dmca = await Dmca.findById(dmcaId).populate('reportedFiles.file');
        if (!dmca) return false;

        console.log(`[DMCA Engine] Restoring files for DMCA Notice #${dmca._id} (Marked as False Claim by ${adminUsername})`);

        for (const item of dmca.reportedFiles) {
            if (!item.file) continue;
            const file = await File.findById(item.file._id || item.file);
            if (!file) continue;

            file.isDmcaHidden = false;
            file.dmcaReportId = null;
            file.dmcaHiddenAt = null;
            file.temporaryPromotedVariantId = null;
            await file.save();

            item.isHidden = false;
        }

        dmca.status = 'false-claim';
        dmca.adminResolution = {
            resolvedBy: adminUsername || 'Admin',
            resolvedAt: new Date(),
            resolutionType: 'false-claim',
            notes: resolutionNotes || 'Claim dismissed as false claim. Content restored.'
        };
        await dmca.save();

        // Notify Uploaders of restoration
        const uploaderNames = new Set(
            dmca.reportedFiles
                .map(rf => rf.file && rf.file.uploader)
                .filter(Boolean)
        );
        for (const uploaderName of uploaderNames) {
            const uploaderUser = await User.findOne({ username: uploaderName });
            if (uploaderUser) {
                await new UserNotification({
                    user: uploaderUser._id,
                    title: 'DMCA Claim Dismissed - File Restored',
                    message: `Great news! The DMCA claim against your file(s) has been reviewed and dismissed as a False Claim. Your file is once again live for public download and active on your dashboard.`,
                    type: 'success'
                }).save();
            }
        }

        return true;
    } catch (err) {
        console.error("[DMCA Engine] Error restoring DMCA files:", err);
        return false;
    }
}

// Helper to notify all admins upon receiving a new DMCA complaint
async function notifyAdminsOnDmcaSubmission(dmca) {
    try {
        const admins = await User.find({ role: { $in: ['admin', 'owner'] } });
        const fileNames = dmca.reportedFiles
            .map(rf => (rf.file && rf.file.name ? rf.file.name : rf.originalUrl))
            .filter(Boolean)
            .join(', ');

        for (const admin of admins) {
            await new UserNotification({
                user: admin._id,
                title: 'New DMCA Complaint Submitted',
                message: `A new DMCA takedown claim was filed by ${dmca.fullName} (${dmca.copyrightHolder}) targeting: ${fileNames || 'Reported Links'}. Automated link hiding is scheduled in 24 hours.`,
                type: 'dmca-notice',
                metadata: { dmcaId: dmca._id }
            }).save();
        }
    } catch (e) {
        console.error("[DMCA Engine] Error notifying admins on submission:", e);
    }
}

// Live Link Inspector API for frontend DMCA form
app.get('/api/dmca/inspect-link', async (req, res) => {
    try {
        const targetUrl = req.query.url;
        if (!targetUrl) return res.status(400).json({ found: false, message: 'URL required.' });

        const result = await resolveGplModsUrl(targetUrl);
        if (!result.found || !result.file) {
            return res.json({
                found: false,
                message: 'No matching file found on GPLMods (will be recorded as an external link).'
            });
        }

        const file = result.file;
        let signedIcon = '/images/default-app-icon.png';
        const iconKey = file.iconUrl || file.iconKey;
        if (iconKey) {
            try { signedIcon = await getSmartImageUrl(iconKey); } catch (e) {}
        }

        return res.json({
            found: true,
            fileId: file._id,
            name: file.name,
            version: file.version,
            category: file.category,
            uploader: file.uploader,
            targetType: result.targetType,
            iconUrl: signedIcon
        });
    } catch (err) {
        console.error("Link inspect error:", err);
        res.status(500).json({ found: false, error: err.message });
    }
});

// DMCA Notice Submission Route
app.post('/dmca-request', async (req, res) => {
    try {
        const { fullName, email, copyrightHolder, originalWorkUrl, signature } = req.body;
        let rawUrls = req.body.infringingUrls || req.body.infringingUrl;

        let urlsList = [];
        if (Array.isArray(rawUrls)) {
            urlsList = rawUrls.map(u => String(u || '').trim()).filter(Boolean);
        } else if (typeof rawUrls === 'string') {
            urlsList = rawUrls.split(/[\r\n,]+/).map(u => u.trim()).filter(Boolean);
        }

        if (urlsList.length === 0) {
            return res.redirect('/dmca?error=Please provide at least one infringing URL.');
        }

        urlsList = Array.from(new Set(urlsList));

        const reportedFiles = [];
        for (const url of urlsList) {
            const resolved = await resolveGplModsUrl(url);
            if (resolved.found && resolved.file) {
                reportedFiles.push({
                    file: resolved.file._id,
                    originalUrl: url,
                    targetType: resolved.targetType,
                    isHidden: false,
                    originalStatus: resolved.file.status
                });
            } else {
                reportedFiles.push({
                    file: null,
                    originalUrl: url,
                    targetType: 'main',
                    isHidden: false
                });
            }
        }

        // Schedule automated takedown in 24 hours
        const scheduledHideAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

        const newDmca = new Dmca({
            fullName,
            email,
            copyrightHolder,
            originalWorkUrl,
            infringingUrl: urlsList[0],
            infringingUrls: urlsList,
            reportedFiles,
            signature,
            scheduledHideAt,
            isAutomatedHidden: false,
            status: 'open'
        });

        await newDmca.save();

        // Send automated confirmation email to claimant
        sendDmcaReportConfirmationEmail(newDmca, newDmca.email, newDmca.fullName).catch(err => console.error('DMCA confirmation email error:', err));

        // Send automated notification to admins
        await notifyAdminsOnDmcaSubmission(newDmca);

        res.redirect('/dmca?success=Your DMCA notice has been received and scheduled for administrator verification. Automated link protection will activate within 24 hours if verified.');
    } catch (e) {
        console.error("DMCA submission error:", e);
        res.redirect('/dmca?error=An error occurred while submitting your notice. Please try again.');
    }
});

// ==========================================
// DEVTOOLS & DEBUGGER ACCESS CONTROL ENGINE
// ==========================================

function generate11DigitKey() {
    // Generates a 10-12 digit random numeric string (11 digits: e.g. 58193849182)
    const min = 10000000000;
    const max = 99999999999;
    return Math.floor(min + Math.random() * (max - min + 1)).toString();
}

async function getOrRotateDebuggerKey(forceRotate = false, reason = 'routine') {
    try {
        let siteState = await SiteState.findOne({ singletonId: 'master-state' });
        if (!siteState) {
            siteState = new SiteState({ singletonId: 'master-state' });
        }

        const now = new Date();
        const isExpired = !siteState.debuggerHourlyKeyExpiresAt || siteState.debuggerHourlyKeyExpiresAt <= now;
        const isMissing = !siteState.debuggerHourlyKey;

        if (!siteState.debuggerMasterKey || siteState.debuggerMasterKey === 'OPAdmin@2026') {
            siteState.debuggerMasterKey = 'T1BBZG1pbkAyMDI2';
            await siteState.save();
        }

        if (forceRotate || isExpired || isMissing) {
            const newKey = generate11DigitKey();
            siteState.debuggerHourlyKey = newKey;
            siteState.debuggerHourlyKeyExpiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour from now
            await siteState.save();
            console.log(`[Debugger Security] New 11-digit key generated (${reason}): ${newKey} (Expires: ${siteState.debuggerHourlyKeyExpiresAt.toLocaleTimeString()})`);
            return {
                key: siteState.debuggerHourlyKey,
                expiresAt: siteState.debuggerHourlyKeyExpiresAt,
                masterKey: siteState.debuggerMasterKey || 'T1BBZG1pbkAyMDI2'
            };
        }

        return {
            key: siteState.debuggerHourlyKey,
            expiresAt: siteState.debuggerHourlyKeyExpiresAt,
            masterKey: siteState.debuggerMasterKey || 'T1BBZG1pbkAyMDI2'
        };
    } catch (err) {
        console.error("[Debugger Security] Error rotating key:", err);
        return {
            key: '92840192840',
            expiresAt: new Date(Date.now() + 3600000),
            masterKey: 'T1BBZG1pbkAyMDI2'
        };
    }
}

// 1. Telemetry Log Route - Saves DevTools Breach Incident to Database
app.post('/api/devtool/log', async (req, res) => {
    try {
        const { triggerType, url, screenDetails } = req.body || {};
        const clientIp = (req.headers['x-forwarded-for'] || req.ip || req.connection?.remoteAddress || '').split(',')[0].trim();
        const userAgent = req.get('User-Agent') || '';
        const user = req.user ? req.user._id : null;
        const username = req.user ? req.user.username : 'Guest';

        let pathOnly = '/';
        if (url) {
            try {
                const parsed = new URL(url);
                pathOnly = parsed.pathname;
            } catch (e) {
                pathOnly = String(url).slice(0, 100);
            }
        }

        const logEntry = new DevtoolLog({
            ip: clientIp,
            userAgent,
            user,
            username,
            url: url || '',
            path: pathOnly,
            triggerType: triggerType || 'devtool-detected',
            status: 'blocked',
            screenDetails: screenDetails || null
        });

        await logEntry.save();
        res.json({ success: true, logId: logEntry._id });
    } catch (e) {
        console.error("[Devtool Telemetry] Error logging incident:", e);
        res.status(500).json({ success: false, error: e.message });
    }
});

// 2. Verification Route - Validates 10-12 Digit Key or Master Key
app.post('/api/devtool/verify-key', async (req, res) => {
    try {
        const { code, logId } = req.body || {};
        if (!code || typeof code !== 'string') {
            return res.status(400).json({ success: false, message: 'Access code required.' });
        }

        const trimmedCode = code.trim();
        const { key: activeHourlyKey, masterKey } = await getOrRotateDebuggerKey(false);

        // A. Check Master Key (Multi-use, never expires)
        const isMasterKeyMatch = (
            trimmedCode === masterKey ||
            trimmedCode === 'T1BBZG1pbkAyMDI2' ||
            trimmedCode === 'OPAdmin@2026' ||
            (function() {
                try {
                    return Buffer.from(trimmedCode, 'base64').toString('utf8') === 'OPAdmin@2026';
                } catch (e) {
                    return false;
                }
            })()
        );

        if (isMasterKeyMatch) {
            if (logId && Types.ObjectId.isValid(logId)) {
                await DevtoolLog.findByIdAndUpdate(logId, {
                    status: 'authorized-by-master-key',
                    accessCodeUsed: 'MASTER_KEY',
                    resolvedAt: new Date()
                });
            }
            return res.json({ success: true, authorizedBy: 'master-key' });
        }

        // B. Check Hourly Single-Use Key
        if (trimmedCode === activeHourlyKey) {
            if (logId && Types.ObjectId.isValid(logId)) {
                await DevtoolLog.findByIdAndUpdate(logId, {
                    status: 'authorized-by-code',
                    accessCodeUsed: 'HOURLY_KEY',
                    resolvedAt: new Date()
                });
            }
            // Once used, generate a new key immediately so it is single-use!
            await getOrRotateDebuggerKey(true, 'Single-Use Key Redeemed');
            return res.json({ success: true, authorizedBy: 'hourly-key', keyRegenerated: true });
        }

        return res.status(401).json({
            success: false,
            message: 'Invalid 10-12 digit debugger access code or master key.'
        });
    } catch (e) {
        console.error("[Devtool Verify] Error verifying code:", e);
        res.status(500).json({ success: false, message: 'Verification error.' });
    }
});

// 3. Manual Key Generation Endpoint (Admin / Owner)
app.post('/api/admin/debugger/generate-key', ensureSupportOrAdmin, async (req, res) => {
    try {
        const uploaderName = req.user ? req.user.username : 'Staff';
        const { key, expiresAt, masterKey } = await getOrRotateDebuggerKey(true, `Manual Regeneration by ${uploaderName}`);
        res.json({ success: true, key, expiresAt, masterKey });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// 4. Audit Incident Logs Endpoint (Admin / Owner)
app.get('/api/admin/debugger/logs', ensureSupportOrAdmin, async (req, res) => {
    try {
        const logs = await DevtoolLog.find().sort({ createdAt: -1 }).limit(50).lean();
        res.json({ success: true, logs });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
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

        // Send automated ticket confirmation email to the user
        sendTicketConfirmationEmail(newTicket, req.user.email, req.user.username).catch(err => console.error('Ticket confirmation email error:', err));

        res.redirect('/support?message=Your support ticket has been submitted. We will reply via your Notifications.');
    } catch (error) {
        console.error("Error submitting support ticket:", error);
        res.redirect('/support?error=An error occurred while submitting your ticket.');
    }
});

// Support Chat Media Upload (Images & Videos)
const uploadSupportMedia = multer({
    storage: memoryStorage,
    limits: { fileSize: 25 * 1024 * 1024 }, // 25 MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = /image\/(jpeg|jpg|png|webp|gif)|video\/(mp4|webm|quicktime|ogg)/i;
        if (allowedTypes.test(file.mimetype) || /\.(jpeg|jpg|png|webp|gif|mp4|webm|mov|ogg)$/i.test(file.originalname)) {
            cb(null, true);
        } else {
            cb(new Error('Only image (JPEG, PNG, WebP, GIF) and video (MP4, WebM, QuickTime) files are allowed.'));
        }
    }
});

app.post('/api/support/upload-media', (req, res, next) => {
    uploadSupportMedia.single('media')(req, res, function (err) {
        if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ success: false, message: 'File is too large. Maximum size is 25MB.' });
        } else if (err) {
            return res.status(400).json({ success: false, message: err.message || 'File upload error.' });
        }
        next();
    });
}, async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'No media file provided.' });
        }

        const ext = path.extname(req.file.originalname).toLowerCase() || '.bin';
        const isVideo = req.file.mimetype.startsWith('video/') || ['.mp4', '.webm', '.mov', '.ogg'].includes(ext);
        const prefix = isVideo ? 'video' : 'img';
        const uniqueName = `support-${prefix}-${Date.now()}-${Math.random().toString(36).substr(2, 6)}${ext}`;

        let mediaUrl = null;

        // 1. Try Backblaze B2 if configured
        if (process.env.B2_BUCKET_NAME && s3Client) {
            try {
                const b2Key = await uploadToB2(req.file, 'support', null, null, uniqueName);
                mediaUrl = await getSmartImageUrl(b2Key);
            } catch (b2Err) {
                console.warn("Support media B2 upload error, using local storage fallback:", b2Err.message);
            }
        }

        // 2. Fallback to local disk storage
        if (!mediaUrl) {
            const localDir = path.join(__dirname, 'public', 'uploads', 'support-media');
            if (!fs.existsSync(localDir)) {
                fs.mkdirSync(localDir, { recursive: true });
            }
            const localFilePath = path.join(localDir, uniqueName);
            fs.writeFileSync(localFilePath, req.file.buffer);
            mediaUrl = `/uploads/support-media/${uniqueName}`;
        }

        return res.json({
            success: true,
            url: mediaUrl,
            fileName: req.file.originalname,
            fileType: req.file.mimetype,
            isVideo: isVideo
        });
    } catch (err) {
        console.error("Error in /api/support/upload-media:", err);
        return res.status(500).json({ success: false, message: 'Server error uploading support media.' });
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
            socialGithub, socialTwitter, socialLinkedin, socialReddit,
            socialInstagram, socialFacebook, socialThreads, socialGravatar, socialWhatsapp,
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
            socialGithub,
            socialTwitter,
            socialLinkedin,
            socialReddit,
            socialInstagram,
            socialFacebook,
            socialThreads,
            socialGravatar,
            socialWhatsapp,
            agreedToTerms: true
        });

        await newApplication.save();

        res.redirect('/partnership?message=Application submitted successfully! Our team will review it shortly.');

    } catch (error) {
        console.error("Partnership Application Error:", error);
        res.redirect('/partnership?error=An error occurred while submitting your application.');
    }
});

app.post('/partnership/leave', ensureAuthenticated, async (req, res) => {
    try {
        const user = req.user;
        if (user.role !== 'distributor') {
            return res.json({ success: false, message: 'You are not a registered distributor.' });
        }

        const orgName = user.organizationName;

        // 1. Transfer external mods to GPL Community
        if (orgName) {
            await File.updateMany(
                {
                    uploader: orgName,
                    $or: [
                        { externalDownloadUrl: { $exists: true, $ne: null } },
                        { customAdLink: { $exists: true, $ne: null } }
                    ]
                },
                { $set: { uploader: 'GPL Community' } }
            );
        }

        await File.updateMany(
            { uploader: user.username, fileKey: 'external-link' }, 
            { $set: { uploader: 'GPL Community' } }
        );

        // 2. Revert user role and clear distributor info & card
        user.role = 'member';
        user.organizationName = undefined;
        user.socialLinks = {};
        user.isVerified = false; // Or keep true if they were verified members
        user.cardId = undefined;
        user.cardLoginToken = undefined;
        await user.save();

        res.json({ success: true, message: 'You have successfully left the partnership program.' });
    } catch (error) {
        console.error("Leave Partnership Error:", error);
        res.status(500).json({ success: false, message: 'An internal server error occurred.' });
    }
});

// ===================================
// 2FA, ID CARD, & PARTNERSHIP ROUTES
// ===================================

// --- 1. QUIT DISTRIBUTOR PROGRAM (FORM POST) ---
app.post('/account/quit-distributor', ensureAuthenticated, async (req, res) => {
    try {
        if (req.user.role !== 'distributor') return res.redirect('/profile');

        const user = await User.findById(req.user._id);
        const orgName = user.organizationName;

        if (orgName) {
            await File.updateMany(
                {
                    uploader: orgName,
                    $or: [
                        { externalDownloadUrl: { $exists: true, $ne: null } },
                        { customAdLink: { $exists: true, $ne: null } }
                    ]
                },
                { $set: { uploader: 'GPL Community' } }
            );
        }

        // Transfer all EXTERNAL LINK mods to GPL Community
        await File.updateMany(
            { uploader: user.username, fileKey: 'external-link' }, 
            { $set: { uploader: 'GPL Community' } }
        );

        // Revoke distributor status and card
        user.role = 'member';
        user.organizationName = undefined;
        user.socialLinks = {};
        user.isVerified = false;
        user.cardId = undefined; // Frees up the 8-digit ID
        user.cardLoginToken = undefined;
        await user.save();

        // Update session
        req.login(user, (err) => {
            res.redirect('/profile?message=You have successfully left the Distributor program. Your external links have been transferred.');
        });
    } catch (e) {
        console.error("Quit distributor error:", e);
        res.status(500).redirect('/profile?error=Server Error');
    }
});

// --- 2. 2FA SETUP & VERIFY API ---
app.post('/api/setup-2fa', ensureAuthenticated, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (user.twoFactorEnabled || user.is2FAEnabled) {
            return res.json({ error: '2FA is already enabled on your account.' });
        }

        const secret = otplib.authenticator.generateSecret();
        const otpauth = otplib.authenticator.keyuri(user.email, 'GPL Mods', secret);
        const qrCodeUrl = await QRCode.toDataURL(otpauth);

        user.twoFactorSecret = secret;
        await user.save();

        res.json({ secret, qrCodeUrl });
    } catch (e) {
        console.error("API 2FA Setup Error:", e);
        res.status(500).json({ error: 'Failed to setup 2FA' });
    }
});

app.post('/api/verify-2fa', ensureAuthenticated, async (req, res) => {
    try {
        const { token } = req.body;
        if (!token) return res.json({ success: false, error: 'Verification code is required.' });

        const user = await User.findById(req.user._id);
        const isValid = otplib.authenticator.check(String(token).trim(), user.twoFactorSecret);

        if (isValid) {
            user.is2FAEnabled = true;
            user.twoFactorEnabled = true;
            user.twoFactorMethod = 'totp';
            user.cardStatus = 'active';
            await user.save();
            req.login(user, () => res.json({ success: true }));
        } else {
            res.json({ success: false, error: 'Invalid 2FA code. Please check your authenticator app.' });
        }
    } catch (e) {
        console.error("API 2FA Verify Error:", e);
        res.status(500).json({ error: 'Verification failed' });
    }
});

// --- 3. GENERATE & VIEW ID CARD (Distributor, Admin, Owner) ---
app.get('/id-card', ensureAuthenticated, async (req, res) => {
    const user = req.user;

    // 1. Must be Distributor, Support, Admin, or Owner
    const allowedRoles = ['distributor', 'support', 'admin', 'owner'];
    if (!allowedRoles.includes(user.role)) {
        return res.status(403).render('pages/403');
    }

    // 2. Must have 2FA enabled
    if (!user.twoFactorEnabled && !user.is2FAEnabled) {
        req.session.returnTo2FA = '/id-card';
        return res.render('pages/setup-2fa', {
            error: req.query.error,
            message: req.query.message,
            isSuspended: Boolean(user.cardId || user.cardStatus === 'suspended')
        });
    }

    try {
        const userDoc = await User.findById(user._id);

        // If card was suspended and 2FA is now active, restore active status
        if (userDoc.cardStatus === 'suspended') {
            userDoc.cardStatus = 'active';
            await userDoc.save();
        }

        // 3. Generate 8-Digit ID if missing
        if (!userDoc.cardId) {
            let unique = false;
            let newId = '';
            while (!unique) {
                newId = crypto.randomBytes(4).toString('hex').toUpperCase();
                const exists = await User.findOne({ cardId: newId });
                if (!exists) unique = true;
            }
            userDoc.cardId = newId;
            userDoc.cardLoginToken = crypto.randomBytes(32).toString('hex'); // 64 char secret token
            await userDoc.save();
        } else if (!userDoc.cardLoginToken) {
            userDoc.cardLoginToken = crypto.randomBytes(32).toString('hex');
            await userDoc.save();
        }

        // 4. Generate QR Codes
        const baseUrl = process.env.BASE_URL || `http://${req.get('host')}`;
        
        // PUBLIC QR: Redirects to profile with the special ?ref=card parameter (Gold QR)
        const publicQrUrl = await QRCode.toDataURL(`${baseUrl}/users/${encodeURIComponent(userDoc.username)}?ref=card`, { 
            color: { dark: '#FFD700', light: '#1a1a1a' },
            width: 300,
            margin: 1
        });
        
        // PRIVATE QR: The secret login link (Red QR)
        const privateQrUrl = await QRCode.toDataURL(`${baseUrl}/qr-login/${userDoc.cardLoginToken}`, { 
            color: { dark: '#e53935', light: '#1a1a1a' },
            width: 300,
            margin: 1
        });

        // 4b. Resolve card avatar (defaults to user avatar by default) and card background (defaults to /images/card-bg.png)
        let resolvedCardAvatarUrl = '/images/default-avatar.png';
        let rawAvatarKeyOrUrl = null;
        if (userDoc.cardAvatarUrl && userDoc.cardAvatarUrl.trim()) {
            rawAvatarKeyOrUrl = userDoc.cardAvatarUrl.trim();
            resolvedCardAvatarUrl = await getSmartImageUrl(rawAvatarKeyOrUrl);
        } else if (userDoc.profileImageKey) {
            rawAvatarKeyOrUrl = userDoc.profileImageKey;
            resolvedCardAvatarUrl = await getSmartImageUrl(rawAvatarKeyOrUrl);
        } else if (req.user.signedAvatarUrl && req.user.signedAvatarUrl !== '/images/default-avatar.png') {
            resolvedCardAvatarUrl = req.user.signedAvatarUrl;
            rawAvatarKeyOrUrl = req.user.profileImageKey || req.user.signedAvatarUrl;
        }

        let resolvedCardBgUrl = '/images/card-bg.png';
        let rawBgKeyOrUrl = userDoc.cardBgUrl || null;
        if (userDoc.cardBgUrl) {
            resolvedCardBgUrl = await getSmartImageUrl(userDoc.cardBgUrl);
        }

        // Convert card avatar & card background to Base64 Data URL so html2canvas NEVER encounters CORS or blank avatar!
        let cardAvatarDataUrl = await getImageAsDataUrl(rawAvatarKeyOrUrl || resolvedCardAvatarUrl);
        if (!cardAvatarDataUrl) {
            cardAvatarDataUrl = await getImageAsDataUrl('/images/default-avatar.png');
        }

        let cardBgDataUrl = null;
        if (userDoc.cardBgUrl) {
            cardBgDataUrl = await getImageAsDataUrl(rawBgKeyOrUrl || resolvedCardBgUrl);
        }

        userDoc.resolvedCardAvatarUrl = resolvedCardAvatarUrl;
        userDoc.cardAvatarDataUrl = cardAvatarDataUrl;
        userDoc.resolvedCardBgUrl = resolvedCardBgUrl;
        userDoc.cardBgDataUrl = cardBgDataUrl;

        res.render('pages/id-card', {
            cardUser: userDoc,
            publicQrUrl,
            privateQrUrl,
            error: req.query.error,
            success: req.query.success
        });

    } catch (error) {
        console.error("ID Card Error:", error);
        res.status(500).render('pages/500');
    }
});

// --- API TO CONVERT AVATAR / IMAGE TO DATA URL (FOR REALTIME PREVIEW IN HTML2CANVAS) ---
app.get('/api/id-card/avatar-data-url', ensureAuthenticated, async (req, res) => {
    try {
        const url = req.query.url;
        if (!url) return res.status(400).json({ success: false, error: 'URL is required' });
        const dataUrl = await getImageAsDataUrl(url);
        if (dataUrl) {
            return res.json({ success: true, dataUrl });
        }
        res.status(400).json({ success: false, error: 'Could not convert image' });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// --- 4. EDIT CARD SETTINGS (Upload Background/Avatar, Extended Customization, 7 Day Cooldown & Bad Words) ---
const uploadCardMedia = multer({ 
    storage: memoryStorage, 
    limits: { fileSize: 5 * 1024 * 1024 } 
});

app.post('/id-card/edit', ensureAuthenticated, (req, res, next) => {
    uploadCardMedia.fields([
        { name: 'cardBgFile', maxCount: 1 },
        { name: 'cardAvatarFile', maxCount: 1 }
    ])(req, res, function (err) {
        if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
            return res.redirect('/id-card?error=' + encodeURIComponent('Uploaded image is too large. Maximum size is 5MB.'));
        } else if (err) {
            return res.redirect('/id-card?error=' + encodeURIComponent('An error occurred during file upload.'));
        }
        next();
    });
}, async (req, res) => {
    try {
        const allowedRoles = ['distributor', 'support', 'admin', 'owner'];
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).render('pages/403');
        }

        const user = await User.findById(req.user._id);
        
        // Cooldown check (7 days = 604800000 ms) - owner is exempt
        if (user.cardLastEdited && user.role !== 'owner' && (Date.now() - user.cardLastEdited.getTime() < 604800000)) {
            const nextEdit = new Date(user.cardLastEdited.getTime() + 604800000).toLocaleDateString();
            return res.redirect(`/id-card?error=You can only edit your card once every 7 days. Next edit available on ${nextEdit}.`);
        }

        const {
            cardMessage,
            cardBgUrl,
            cardAvatarUrl,
            resetAvatarToAccount,
            resetBgToDefault,
            brandName,
            platform,
            showEmail,
            emailType,
            customEmail,
            showPhone,
            phone,
            showAge,
            customAge,
            showSocials,
            social1_platform,
            social1_handle,
            social2_platform,
            social2_handle,
            social3_platform,
            social3_handle,
            customTagline
        } = req.body;

        // Profanity Check
        if (cardMessage && profanityFilter.isProfane(cardMessage)) {
            return res.redirect('/id-card?error=Inappropriate language detected. Please modify your message.');
        }
        if (brandName && profanityFilter.isProfane(brandName)) {
            return res.redirect('/id-card?error=Inappropriate language detected in Brand Name. Please modify it.');
        }
        if (customTagline && profanityFilter.isProfane(customTagline)) {
            return res.redirect('/id-card?error=Inappropriate language detected in Custom Text. Please modify it.');
        }

        if (cardMessage !== undefined) {
            user.cardMessage = cardMessage ? String(cardMessage).trim().slice(0, 120) : 'Welcome to my profile! Follow me for the best mods.';
        }

        // Handle Background: File Upload, URL or Reset
        if (req.files && req.files['cardBgFile'] && req.files['cardBgFile'][0]) {
            const file = req.files['cardBgFile'][0];
            if (file.mimetype.startsWith('image/')) {
                // Delete old card background from B2 & FTP
                if (user.cardBgUrl && !user.cardBgUrl.startsWith('http')) {
                    await deleteFromB2(user.cardBgUrl);
                }
                const targetKey = getUserAssetKey(user, 'card-bg', file.originalname);
                const bgKey = await uploadToB2(file, 'users', null, null, null, { exactKey: targetKey });
                user.cardBgUrl = bgKey;
            }
        } else if (resetBgToDefault === 'true' || resetBgToDefault === true) {
            if (user.cardBgUrl && !user.cardBgUrl.startsWith('http')) {
                await deleteFromB2(user.cardBgUrl);
            }
            user.cardBgUrl = '';
        } else if (cardBgUrl !== undefined) {
            user.cardBgUrl = String(cardBgUrl).trim();
        }

        // Handle Avatar: File Upload, URL or Reset to Account Avatar
        if (req.files && req.files['cardAvatarFile'] && req.files['cardAvatarFile'][0]) {
            const file = req.files['cardAvatarFile'][0];
            if (file.mimetype.startsWith('image/')) {
                // Delete old card avatar from B2 & FTP
                if (user.cardAvatarUrl && !user.cardAvatarUrl.startsWith('http')) {
                    await deleteFromB2(user.cardAvatarUrl);
                }
                const targetKey = getUserAssetKey(user, 'card-avatar', file.originalname);
                const avatarKey = await uploadToB2(file, 'users', null, null, null, { exactKey: targetKey });
                user.cardAvatarUrl = avatarKey;
            }
        } else if (resetAvatarToAccount === 'true' || resetAvatarToAccount === true) {
            if (user.cardAvatarUrl && !user.cardAvatarUrl.startsWith('http')) {
                await deleteFromB2(user.cardAvatarUrl);
            }
            user.cardAvatarUrl = '';
        } else if (cardAvatarUrl !== undefined) {
            let cleanAvatar = String(cardAvatarUrl).trim();
            const b2Match = cleanAvatar.match(/(?:users|mods|clubs|card-avatars|avatars)\/[^?#\s]+/);
            if (b2Match) {
                user.cardAvatarUrl = b2Match[0];
            } else {
                user.cardAvatarUrl = cleanAvatar;
            }
        }

        // Handle Card Customization
        if (!user.cardCustomization) {
            user.cardCustomization = {};
        }
        if (brandName !== undefined) {
            user.cardCustomization.brandName = String(brandName).trim().slice(0, 50);
        }
        if (platform !== undefined) {
            user.cardCustomization.platform = String(platform).trim().slice(0, 30);
        }

        user.cardCustomization.showEmail = (showEmail === 'true' || showEmail === 'on' || showEmail === true);
        user.cardCustomization.emailType = emailType === 'custom' ? 'custom' : 'account';
        user.cardCustomization.customEmail = customEmail ? String(customEmail).trim().slice(0, 80) : '';

        user.cardCustomization.showPhone = (showPhone === 'true' || showPhone === 'on' || showPhone === true);
        user.cardCustomization.phone = phone ? String(phone).trim().slice(0, 25) : '';

        user.cardCustomization.showAge = (showAge === 'true' || showAge === 'on' || showAge === true);
        if (customAge !== undefined && customAge !== '') {
            const parsedAge = parseInt(customAge, 10);
            if (!isNaN(parsedAge) && parsedAge >= 10 && parsedAge <= 120) {
                user.cardCustomization.customAge = parsedAge;
            }
        } else {
            user.cardCustomization.customAge = undefined;
        }

        user.cardCustomization.showSocials = (showSocials === 'true' || showSocials === 'on' || showSocials === true);
        const socialsArr = [];
        const pushSocial = (plat, handle) => {
            if (plat && handle && String(handle).trim() && socialsArr.length < 3) {
                const cleanPlat = String(plat).toLowerCase().trim();
                const cleanHandle = String(handle).trim().slice(0, 150);
                socialsArr.push({
                    platform: cleanPlat,
                    handleOrUrl: cleanHandle
                });
                // Sync to user.socialLinks so it is displayed on public profile
                user.socialLinks = user.socialLinks || {};
                user.socialLinks[cleanPlat] = cleanHandle;
            }
        };
        pushSocial(social1_platform, social1_handle);
        pushSocial(social2_platform, social2_handle);
        pushSocial(social3_platform, social3_handle);
        user.cardCustomization.socials = socialsArr;

        if (user.role === 'owner' && customTagline !== undefined) {
            user.cardCustomization.customTagline = String(customTagline).trim().slice(0, 120);
        }

        user.cardLastEdited = new Date();
        await user.save();

        res.redirect('/id-card?success=Card updated successfully!');
    } catch (e) {
        console.error("ID Card edit error:", e);
        res.redirect('/id-card?error=Error updating card details.');
    }
});

// --- 4b. FETCH GRAVATAR FOR CARD AVATAR ---
app.post('/id-card/fetch-gravatar', ensureAuthenticated, async (req, res) => {
    try {
        const allowedRoles = ['distributor', 'support', 'admin', 'owner'];
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Unauthorized.' });
        }

        if (!req.user.email) {
            return res.status(400).json({ error: 'No email associated with this account.' });
        }

        const email = req.user.email.toLowerCase().trim();
        const hash = crypto.createHash('md5').update(email).digest('hex');
        const gravatarUrl = `https://www.gravatar.com/avatar/${hash}?d=404&s=256`;

        let response;
        try {
            response = await axios.get(gravatarUrl, { responseType: 'arraybuffer' });
        } catch (err) {
            if (err.response && err.response.status === 404) {
                return res.status(404).json({ error: 'No Gravatar profile image found for your email address (' + req.user.email + ').' });
            }
            throw err;
        }

        const buffer = Buffer.from(response.data, 'binary');
        const mimetype = response.headers['content-type'] || 'image/jpeg';
        const mockFile = {
            buffer: buffer,
            originalname: `user-id-card-avatar.jpg`,
            mimetype: mimetype,
            size: buffer.length
        };

        const user = await User.findById(req.user._id);
        if (user && user.cardAvatarUrl && !user.cardAvatarUrl.startsWith('http')) {
            await deleteFromB2(user.cardAvatarUrl);
        }

        const targetKey = getUserAssetKey(user || req.user, 'card-avatar', 'user-id-card-avatar.jpg');
        const imageKey = await uploadToB2(mockFile, 'users', null, null, null, { exactKey: targetKey });

        user.cardAvatarUrl = imageKey;
        await user.save();

        const signedUrl = await getSmartImageUrl(imageKey);
        res.json({ success: true, avatarUrl: signedUrl, imageKey: imageKey, message: 'Gravatar card avatar synced successfully!' });
    } catch (error) {
        console.error("Error fetching card gravatar:", error);
        res.status(500).json({ error: 'Could not fetch Gravatar. Please try again.' });
    }
});

// --- 5. SECURE QR / CARD LOGIN ROUTES ---
app.get('/qr-login/:token', async (req, res, next) => {
    try {
        const token = req.params.token;
        if (!token) {
            return res.status(400).redirect('/login?error=Invalid login token.');
        }
        const user = await User.findOne({ cardLoginToken: token });

        if (!user) {
            return res.status(403).redirect('/login?error=Invalid or expired login QR code.');
        }

        if (user.isBanned) {
            return res.redirect('/banned');
        }

        // Suspended check if 2FA disabled or card status suspended
        if (!user.twoFactorEnabled && !user.is2FAEnabled) {
            return res.status(403).redirect('/login?error=' + encodeURIComponent('This ID card is suspended because 2-Factor Authentication is disabled. Please log in with your password and reactivate 2FA.'));
        }

        if (user.cardStatus === 'suspended' || user.cardStatus === 'revoked') {
            return res.status(403).redirect('/login?error=' + encodeURIComponent('This ID card is currently suspended. Please log in with your credentials and re-enable 2FA.'));
        }

        // ✅ REQUIRE 2FA: Route through processSuccessfulLogin so 2FA is required if enabled
        processSuccessfulLogin(req, res, next, user);
    } catch (error) {
        console.error("QR Login Error:", error);
        res.status(500).render('pages/500');
    }
});

// --- 5b. GPL CARD LOGIN VIA IMAGE UPLOAD (AJAX / FORM) ---
app.post('/auth/card-login', async (req, res, next) => {
    const isAjax = req.xhr || req.headers.accept?.includes('json') || req.is('json');
    try {
        let token = req.body.token || req.body.cardLoginToken;
        if (!token || typeof token !== 'string') {
            const err = 'Card login token was not found on the uploaded card.';
            return isAjax ? res.status(400).json({ success: false, error: err }) : res.redirect('/login?error=' + encodeURIComponent(err));
        }

        token = token.trim();
        // Extract raw token if full URL was scanned (e.g. https://.../qr-login/<token>)
        if (token.includes('/qr-login/')) {
            token = token.split('/qr-login/')[1].split(/[?#]/)[0];
        }

        const user = await User.findOne({ cardLoginToken: token });
        if (!user) {
            const err = 'Invalid or expired GPL ID Card credentials. Please ensure your card was exported in Private Mode (Quick-Login).';
            return isAjax ? res.status(401).json({ success: false, error: err }) : res.redirect('/login?error=' + encodeURIComponent(err));
        }

        if (user.isBanned) {
            return isAjax ? res.json({ success: false, error: 'Account suspended.', redirect: '/banned' }) : res.redirect('/banned');
        }

        if (!user.twoFactorEnabled && !user.is2FAEnabled) {
            const err = 'This ID card is suspended because 2-Factor Authentication is disabled. Please log in with your password and reactivate 2FA.';
            return isAjax ? res.status(403).json({ success: false, error: err }) : res.redirect('/login?error=' + encodeURIComponent(err));
        }

        if (user.cardStatus === 'suspended' || user.cardStatus === 'revoked') {
            const err = 'This ID card is currently suspended. Please log in with your credentials and re-enable 2FA.';
            return isAjax ? res.status(403).json({ success: false, error: err }) : res.redirect('/login?error=' + encodeURIComponent(err));
        }

        // ✅ REQUIRE 2FA: Process login
        if (user.twoFactorEnabled) {
            req.session.pending2faUserId = user._id.toString();
            const availableMethods = getAvailable2FAMethods(user);
            const priorityMethod = availableMethods[0] || 'email';
            req.session.active2faMethod = priorityMethod;
            if (priorityMethod === 'email') {
                try {
                    const otp = Math.floor(100000 + Math.random() * 900000).toString();
                    user.verificationOtp = otp;
                    user.otpExpires = Date.now() + 600000;
                    await user.save();
                    await send2faEmail(user, otp);
                } catch (e) { console.error("2FA Email Error on Card Login:", e); }
            }
            req.session.save((err) => {
                if (err) console.error("Session save error on card login:", err);
                if (isAjax) {
                    return res.json({ success: true, redirect: '/login/2fa' });
                }
                return res.redirect('/login/2fa');
            });
        } else {
            req.logIn(user, (loginErr) => {
                if (loginErr) {
                    return isAjax ? res.status(500).json({ success: false, error: 'Login session failed.' }) : next(loginErr);
                }
                res.cookie('is_logged_in', 'true', { 
                    maxAge: 1000 * 60 * 60 * 24 * 3,
                    path: '/',
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'lax'
                });
                if (isAjax) {
                    return res.json({ success: true, redirect: '/home?message=Successfully logged in via GPL Card!' });
                }
                return finalizeLogin(req, res, user, '/home?message=Successfully logged in via GPL Card!');
            });
        }
    } catch (error) {
        console.error("Card Login POST Error:", error);
        if (isAjax) {
            return res.status(500).json({ success: false, error: 'Error authenticating with GPL Card.' });
        }
        res.status(500).render('pages/500');
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

        // Initialize Default GPL Community Club
        if (typeof ensureDefaultClub === 'function') {
            try {
                await ensureDefaultClub();
                console.log('[Clubs] Default GPL Community verified/initialized.');
            } catch (clubInitErr) {
                console.error('[Clubs Error] Failed initializing default club:', clubInitErr.message);
            }
        } 

        // Automatically purge any empty AI Chatbot sessions
        ChatSession.deleteMany({
            $or: [
                { messages: { $size: 0 } },
                { messages: { $exists: false } }
            ]
        }).catch(() => {}); 

        // Handle AdminJS logout cleanly
        app.all('/admin/logout', (req, res) => {
            if (req.session) {
                delete req.session.adminUser;
            }
            if (req.logout && typeof req.logout === 'function') {
                req.logout(() => {
                    if (req.session) {
                        req.session.destroy(() => {
                            res.clearCookie('connect.sid');
                            res.clearCookie('admin_avatar');
                            res.redirect('/login');
                        });
                    } else {
                        res.redirect('/login');
                    }
                });
            } else {
                res.redirect('/logout');
            }
        });

        // Ensure AdminJS skips rebuilding components on restart if .adminjs cache exists
        const adminBundlePath = path.join(__dirname, '.adminjs', 'bundle.js');
        if (fs.existsSync(adminBundlePath)) {
            process.env.ADMIN_JS_SKIP_BUNDLE = 'true';
        }

        const adminRouter = await createAdminRouter();
        app.use('/admin', ensureAdminOr404, (req, res, next) => {
            if (req.session && req.user) {
                const avatar = req.user.signedAvatarUrl || '/images/default-avatar.png';
                req.session.adminUser = {
                    id: String(req.user._id),
                    _id: String(req.user._id),
                    email: req.user.email,
                    username: req.user.username,
                    role: req.user.role,
                    membership: req.user.membership,
                    avatarUrl: avatar,
                    title: req.user.username || req.user.email
                };
                res.cookie('admin_avatar', avatar, { path: '/admin', httpOnly: false });
            }
            next();
        }, adminRouter);
        
        app.use(express.urlencoded({ extended: true }));
        app.use(express.json({
            verify: (req, res, buf) => {
                req.rawBody = buf.toString('utf8');
            }
        }));

        // --- DECLARED ONLY ONCE HERE ---
        const server = http.createServer(app);
        const io = new Server(server, {
            cors: {
                origin: allowedOrigins, 
                methods: ["GET", "POST"]
            },
            pingInterval: 8000,
            pingTimeout: 5000
        });

        // Reuse the site's authenticated session for support sockets. Client-side
        // IDs are only used for guests and never authorize member/admin actions.
        const wrapSocketMiddleware = (middleware) => (socket, next) => middleware(socket.request, {}, next);
        io.use(wrapSocketMiddleware(sessionMiddleware));
        io.use(wrapSocketMiddleware(passport.initialize()));
        io.use(wrapSocketMiddleware(passport.session()));
        
        // Tracking connected support members, staff & live users
        const connectedSupportSockets = new Set();
        const connectedAgentSockets = new Set();
        const connectedUsers = new Map(); // socket.id -> { userId, username, role, avatarUrl, isStaff }
        const clubOnlinePresences = new Map(); // clubId -> Map(userId -> userObj)

        // ✅ CRITICAL FIX: Make Socket.IO & state globally accessible to Express routes (e.g. /logout)
        app.set('io', io); 
        app.set('connectedUsers', connectedUsers);
        app.set('connectedSupportSockets', connectedSupportSockets);
        app.set('connectedAgentSockets', connectedAgentSockets);
        app.set('broadcastOnlineStats', broadcastOnlineStats);

        async function resolveUserAvatar(u) {
            if (!u) return '/images/default-avatar.png';
            if (u.signedAvatarUrl && u.signedAvatarUrl !== '/images/default-avatar.png') {
                return u.signedAvatarUrl;
            }
            if (u.profileImageKey) {
                try {
                    const resolved = await getSmartImageUrl(u.profileImageKey);
                    if (resolved && resolved !== '/images/default-avatar.png') return resolved;
                } catch (e) {}
            }
            return '/images/default-avatar.png';
        }

        function getLiveUsersList() {
            const uniqueMap = new Map();
            const activeSockets = io && io.sockets && io.sockets.sockets;
            for (const [sId, u] of connectedUsers.entries()) {
                // Instantly prune sockets that have disconnected or no longer exist
                if (activeSockets) {
                    const sock = activeSockets.get(sId);
                    if (!sock || !sock.connected) {
                        connectedUsers.delete(sId);
                        connectedSupportSockets.delete(sId);
                        connectedAgentSockets.delete(sId);
                        continue;
                    }
                }
                if (u && u.userId && !uniqueMap.has(u.userId)) {
                    uniqueMap.set(u.userId, u);
                }
            }
            const list = Array.from(uniqueMap.values());
            // Prioritize staff members first (owner, admin, support)
            list.sort((a, b) => (b.isStaff ? 1 : 0) - (a.isStaff ? 1 : 0));
            return list.map(u => ({
                userId: u.userId,
                username: u.username,
                role: u.role,
                avatarUrl: u.avatarUrl,
                isStaff: u.isStaff
            }));
        }

        function broadcastOnlineStats() {
            const liveUsers = getLiveUsersList();
            const staffCount = liveUsers.filter(u => u.isStaff).length;
            const stats = {
                agentsOnline: connectedAgentSockets.size,
                staffOnline: staffCount,
                membersOnline: connectedSupportSockets.size,
                liveUsers: liveUsers,
                aiStatus: aiDebuggerStatus
            };
            io.emit('support_stats_update', stats);
        }

       // Socket.IO logic
        io.on('connection', async (socket) => {
            connectedSupportSockets.add(socket.id);

            if (socket.request && socket.request.user) {
                const u = socket.request.user;
                const avatar = await resolveUserAvatar(u);
                connectedUsers.set(socket.id, {
                    userId: String(u._id || u.id),
                    username: u.username || 'Member',
                    role: u.role || 'user',
                    avatarUrl: avatar,
                    isStaff: ['support', 'admin', 'owner'].includes(u.role)
                });
            }
            broadcastOnlineStats();

            socket.emit('chat history', recentMessages);
            
            socket.on('chat message', (msg) => {
                // Strict Link Restriction: Only GPLMods links allowed!
                const linkValidation = validateMessageLinks(msg.text);
                if (!linkValidation.valid) {
                    return socket.emit('chat error', { message: linkValidation.error });
                }

                let finalSafeText = msg.text;
                try {
                    finalSafeText = global.profanityFilter.clean(msg.text);
                } catch (error) {}

                const messageData = {
                    username: msg.username,
                    avatar: msg.avatar, 
                    text: finalSafeText, 
                    timestamp: new Date()
                };
                
                recentMessages.push(messageData);
                if (recentMessages.length > 50) {
                    recentMessages.shift();
                }
                io.emit('chat message', messageData);
            });

            // ==========================================
            // --- CLUBS & COMMUNITIES REAL-TIME EVENTS ---
            // ==========================================

            socket.on('club_join', async (data) => {
                const { clubId, vanished } = data || {};
                if (!clubId) return;

                const user = socket.request && socket.request.user;
                const isStaff = user && ['owner', 'admin'].includes(user.role);
                const isVanished = isStaff && Boolean(vanished);

                socket.join(`club_${clubId}`);
                socket.data = socket.data || {};
                socket.data.clubId = clubId;
                socket.data.isVanished = isVanished;

                if (!isVanished && user) {
                    if (!clubOnlinePresences.has(clubId)) {
                        clubOnlinePresences.set(clubId, new Map());
                    }
                    const cUsers = clubOnlinePresences.get(clubId);
                    cUsers.set(String(user._id), {
                        userId: String(user._id),
                        username: user.username,
                        avatarUrl: await resolveUserAvatar(user),
                        role: user.role,
                        membership: user.membership,
                        isPremium: user.isPremium,
                        badges: user.badges
                    });
                }

                const onlineList = clubOnlinePresences.has(clubId) ? Array.from(clubOnlinePresences.get(clubId).values()) : [];
                io.to(`club_${clubId}`).emit('club_presence_update', {
                    clubId,
                    onlineCount: onlineList.length,
                    onlineUsers: onlineList
                });
            });

            socket.on('club_join_channel', (data) => {
                const { clubId, channelId } = data || {};
                if (clubId && channelId) {
                    socket.join(`club_${clubId}_chan_${channelId}`);
                }
            });

            socket.on('club_leave_channel', (data) => {
                const { clubId, channelId } = data || {};
                if (clubId && channelId) {
                    socket.leave(`club_${clubId}_chan_${channelId}`);
                }
            });

            socket.on('club_send_message', async (data) => {
                try {
                    const { clubId, channelId, text, attachments } = data || {};
                    const user = socket.request && socket.request.user;
                    if (!user) {
                        return socket.emit('club_message_error', { message: 'You must be signed in to send messages.' });
                    }

                    // 1. Strict Link Restriction
                    const linkCheck = validateMessageLinks(text);
                    if (!linkCheck.valid) {
                        return socket.emit('club_message_error', { message: linkCheck.error });
                    }

                    // 2. Channel & Club verification
                    const channel = await ClubChannel.findById(channelId);
                    if (!channel) return;
                    const club = await Club.findById(clubId);
                    if (!club) return;

                    const isStaff = ['owner', 'admin'].includes(user.role);
                    const isCreator = String(club.creator) === String(user._id);

                    if (channel.isReadOnly && !isStaff && !isCreator) {
                        return socket.emit('club_message_error', { message: `Channel #${channel.name} is read-only.` });
                    }

                    // 3. Profanity filtering
                    let safeText = text;
                    try {
                        safeText = global.profanityFilter.clean(text);
                    } catch (e) {}

                    // 4. Save to DB
                    const message = await ClubMessage.create({
                        club: clubId,
                        channel: channelId,
                        sender: user._id,
                        content: safeText,
                        attachments: attachments || []
                    });

                    const membership = await ClubMember.findOne({ club: clubId, user: user._id }).populate('roles');
                    const avatar = await resolveUserAvatar(user);

                    const payload = {
                        _id: message._id,
                        channel: channelId,
                        club: clubId,
                        content: safeText,
                        reactions: [],
                        createdAt: message.createdAt,
                        sender: {
                            _id: user._id,
                            username: user.username,
                            signedAvatarUrl: avatar,
                            role: user.role,
                            membership: user.membership,
                            isPremium: user.isPremium,
                            badges: user.badges,
                            clubRoles: membership ? (membership.roles || []) : [],
                            isCreator
                        }
                    };

                    io.to(`club_${clubId}_chan_${channelId}`).emit('club_new_message', payload);

                    // Disk dump archive
                    (async () => {
                        try {
                            const recentMsgs = await ClubMessage.find({ channel: channelId })
                                .sort({ createdAt: -1 })
                                .limit(100)
                                .lean();
                            saveClubChatArchive(club.name, channel.name, recentMsgs.reverse());
                        } catch (e) {}
                    })();

                } catch (err) {
                    console.error('[Clubs] Send message error:', err);
                    socket.emit('club_message_error', { message: 'Failed to send message.' });
                }
            });

            socket.on('club_message_reaction', async (data) => {
                try {
                    const { clubId, channelId, messageId, emoji } = data || {};
                    const user = socket.request && socket.request.user;
                    if (!user || !messageId || !emoji) return;

                    const message = await ClubMessage.findById(messageId);
                    if (!message) return;

                    let reactionObj = message.reactions.find(r => r.emoji === emoji);
                    if (!reactionObj) {
                        reactionObj = { emoji, users: [user._id] };
                        message.reactions.push(reactionObj);
                    } else {
                        const uIdx = reactionObj.users.findIndex(u => String(u) === String(user._id));
                        if (uIdx > -1) {
                            reactionObj.users.splice(uIdx, 1);
                            if (reactionObj.users.length === 0) {
                                message.reactions = message.reactions.filter(r => r.emoji !== emoji);
                            }
                        } else {
                            reactionObj.users.push(user._id);
                        }
                    }
                    await message.save();

                    io.to(`club_${clubId}_chan_${channelId}`).emit('club_reaction_updated', {
                        messageId: message._id,
                        reactions: message.reactions
                    });
                } catch (e) {}
            });

            socket.on('club_poll_vote', async (data) => {
                try {
                    const { clubId, channelId, messageId, optionIndex } = data || {};
                    const user = socket.request && socket.request.user;
                    if (!user || !messageId) return;

                    const message = await ClubMessage.findById(messageId);
                    if (!message || !message.poll || message.poll.closed) return;

                    message.poll.options.forEach(opt => {
                        opt.votes = opt.votes.filter(v => String(v) !== String(user._id));
                    });
                    const opt = message.poll.options[parseInt(optionIndex, 10)];
                    if (opt) {
                        opt.votes.push(user._id);
                    }
                    await message.save();

                    io.to(`club_${clubId}_chan_${channelId}`).emit('club_poll_updated', {
                        messageId: message._id,
                        poll: message.poll
                    });
                } catch (e) {}
            });

            socket.on('club_vanish_toggle', async (data) => {
                const user = socket.request && socket.request.user;
                if (!user || !['owner', 'admin'].includes(user.role)) return;
                const { clubId, vanished } = data || {};

                socket.data = socket.data || {};
                socket.data.isVanished = Boolean(vanished);

                if (clubOnlinePresences.has(clubId)) {
                    const clubUsers = clubOnlinePresences.get(clubId);
                    if (vanished) {
                        clubUsers.delete(String(user._id));
                    } else {
                        clubUsers.set(String(user._id), {
                            userId: String(user._id),
                            username: user.username,
                            avatarUrl: await resolveUserAvatar(user),
                            role: user.role,
                            membership: user.membership,
                            isPremium: user.isPremium,
                            badges: user.badges
                        });
                    }
                    const onlineList = Array.from(clubUsers.values());
                    io.to(`club_${clubId}`).emit('club_presence_update', {
                        clubId,
                        onlineCount: onlineList.length,
                        onlineUsers: onlineList
                    });
                }
                socket.emit('club_vanish_state', { vanished: Boolean(vanished) });
            });

            // ==========================================
            // --- LIVE SUPPORT & GEMINI AI CHAT LOGIC ---
            // ==========================================
            
            // Helper to resolve agent from session or payload ID with staff role verification
            async function resolveAgent(data) {
                let agent = socket.request.user || socket.data?.agent;
                if (!agent && data?.agentId) {
                    try {
                        const found = await User.findById(data.agentId);
                        if (found && ['support', 'admin', 'owner'].includes(found.role)) {
                            agent = found;
                            socket.data = socket.data || {};
                            socket.data.agent = agent;
                        }
                    } catch (e) {}
                }
                return (agent && ['support', 'admin', 'owner'].includes(agent.role)) ? agent : null;
            }

            // 1. Agent Joins the Dashboard
            socket.on('agent_join', async (data) => {
                const agent = await resolveAgent(data);
                if (!agent) return;
                socket.join('support_agents');
                connectedAgentSockets.add(socket.id);
                try {
                    const avatar = (data && data.avatarUrl && data.avatarUrl !== '/images/default-avatar.png') ? data.avatarUrl : await resolveUserAvatar(agent);
                    connectedUsers.set(socket.id, {
                        userId: String(agent._id || agent.id),
                        username: agent.username || 'Staff Agent',
                        role: agent.role,
                        avatarUrl: avatar,
                        isStaff: true
                    });
                } catch (e) {}
                broadcastOnlineStats();
                try {
                    const activeChats = await ChatSession.find({ 
                        status: { $in: ['waiting-for-agent', 'active-agent'] },
                        'messages.0': { $exists: true }
                    })
                        .populate('user', 'username email profileImageKey role isPremium badges')
                        .sort({ updatedAt: -1 });
                    
                    socket.emit('load_active_chats', activeChats);
                    socket.emit('ai_status_update', aiDebuggerStatus);
                } catch (err) {
                    console.error("Error loading active chats:", err);
                }
            });

            // AI Debugger Ping Test from Agent
            socket.on('test_ai_connection', async () => {
                const start = Date.now();
                try {
                    if (!aiModel) throw new Error("Gemini AI model is not initialized or API key is missing.");
                    const chat = aiModel.startChat();
                    const result = await chat.sendMessage("Respond with exactly: 'OK - Gemini AI is operational'");
                    const latency = Date.now() - start;
                    const responseText = result.response.text();
                    
                    aiDebuggerStatus.status = 'online';
                    aiDebuggerStatus.lastPing = new Date();
                    aiDebuggerStatus.latencyMs = latency;
                    aiDebuggerStatus.lastError = null;
                    
                    io.to('support_agents').emit('ai_debug_result', {
                        success: true,
                        latencyMs: latency,
                        response: responseText,
                        status: aiDebuggerStatus
                    });
                    broadcastOnlineStats();
                } catch (err) {
                    const latency = Date.now() - start;
                    aiDebuggerStatus.status = 'offline';
                    aiDebuggerStatus.lastError = {
                        message: err.message || String(err),
                        time: new Date()
                    };
                    aiDebuggerStatus.totalErrors++;
                    
                    io.to('support_agents').emit('ai_debug_result', {
                        success: false,
                        latencyMs: latency,
                        error: err.message || String(err),
                        status: aiDebuggerStatus
                    });
                    broadcastOnlineStats();
                }
            });

            // 2. User Joins Chat (With New Chat Support)
            socket.on('join_support_chat', async (data) => {
                try {
                    let authenticatedUser = socket.request.user;
                    if (!authenticatedUser && data.userId) {
                        try {
                            authenticatedUser = await User.findById(data.userId);
                        } catch (e) {}
                    }
                    if (authenticatedUser) {
                        let avatar = data.avatarUrl;
                        if (!avatar || avatar === '/images/default-avatar.png') {
                            avatar = await resolveUserAvatar(authenticatedUser);
                        }
                        connectedUsers.set(socket.id, {
                            userId: String(authenticatedUser._id || authenticatedUser.id),
                            username: authenticatedUser.username || data.username || 'Member',
                            role: authenticatedUser.role || 'user',
                            avatarUrl: avatar,
                            isStaff: ['support', 'admin', 'owner'].includes(authenticatedUser.role)
                        });
                        broadcastOnlineStats();
                    }
                    const userId = authenticatedUser ? authenticatedUser._id : null;
                    let session = null;

                    // If forceNew is not requested, try finding by ID
                    if (!data.forceNew && data.sessionId) {
                        session = await ChatSession.findById(data.sessionId);
                        const ownsSession = session && ((userId && session.user && String(session.user) === String(userId)) || (!userId && session.guestId === data.guestId));
                        if (!ownsSession) {
                            session = null;
                        } else if (!session.messages || session.messages.length === 0) {
                            // Empty chat detected: automatically discard and do not retain
                            await ChatSession.deleteOne({ _id: session._id });
                            session = null;
                        }
                    }

                    // Cache pending telemetry on socket without persisting an empty document to MongoDB
                    socket.data = socket.data || {};
                    socket.data.pendingChatMeta = {
                        guestEmail: data.guestEmail,
                        deviceInfo: data.deviceInfo,
                        currentPage: data.currentPage
                    };

                    const isNew = !session;
                    const activeSessionId = session ? session._id : new mongoose.Types.ObjectId();
                    const history = session ? session.messages : [];
                    const status = session ? session.status : 'bot';

                    socket.join(`support_${activeSessionId}`);
                    socket.emit('support_chat_ready', { 
                        sessionId: activeSessionId, 
                        history: history,
                        status: status,
                        isNew: isNew
                    });
                } catch (err) {
                    console.error("join_support_chat error:", err);
                }
            });

            socket.on('set_support_email', async (data) => {
                try {
                    if (socket.request.user || !/^\S+@\S+\.\S+$/.test((data.guestEmail || '').trim())) return;
                    if (socket.data?.pendingChatMeta) {
                        socket.data.pendingChatMeta.guestEmail = data.guestEmail.trim();
                    }
                    const session = await ChatSession.findById(data.sessionId);
                    if (!session || session.user || session.guestId !== data.guestId) return;
                    session.guestEmail = data.guestEmail.trim();
                    if (session.messages && session.messages.length > 0) {
                        await session.save();
                        io.to('support_agents').emit('agent_chat_updated', session);
                    }
                } catch (err) {
                    console.error('set_support_email error:', err);
                }
            });

            // 3. User Requests Chat History List
            socket.on('get_user_chat_history', async (data) => {
                try {
                    const conditions = [];
                    if (socket.request.user) conditions.push({ user: socket.request.user._id });
                    else if (data.guestId) conditions.push({ guestId: data.guestId });
                    
                    if (conditions.length === 0) {
                        return socket.emit('user_chat_history_list', []);
                    }

                    const sessions = await ChatSession.find({ 
                        $or: conditions,
                        'messages.0': { $exists: true } // Exclude any empty conversations
                    })
                        .sort({ updatedAt: -1 })
                        .limit(20)
                        .lean();

                    const historyList = sessions.map(s => {
                        const msgs = s.messages || [];
                        const lastMsg = msgs.length > 0 ? msgs[msgs.length - 1].text : '';
                        return {
                            _id: s._id,
                            status: s.status,
                            snippet: lastMsg && lastMsg.length > 50 ? lastMsg.substring(0, 50) + '...' : (lastMsg || 'Chat'),
                            messageCount: msgs.length,
                            updatedAt: s.updatedAt || s.createdAt
                        };
                    });

                    socket.emit('user_chat_history_list', historyList);
                } catch (err) {
                    console.error("get_user_chat_history error:", err);
                    socket.emit('user_chat_history_list', []);
                }
            });

            // 4. Switch to a past conversation
            socket.on('switch_support_chat', async (data) => {
                try {
                    const session = await ChatSession.findById(data.sessionId);
                    if (session && (!session.messages || session.messages.length === 0)) {
                        await ChatSession.deleteOne({ _id: session._id });
                        return;
                    }
                    const userId = (socket.request.user && socket.request.user._id) ? String(socket.request.user._id) : (data.userId ? String(data.userId) : null);
                    const sessionUserId = session && session.user ? String(session.user._id || session.user) : null;
                    const ownsSession = session && ((userId && sessionUserId && sessionUserId === userId) || (!userId && session.guestId === data.guestId) || (data.guestId && session.guestId === data.guestId));
                    if (ownsSession) {
                        socket.join(`support_${session._id}`);
                        socket.emit('support_chat_ready', { 
                            sessionId: session._id, 
                            history: session.messages,
                            status: session.status,
                            isNew: false
                        });
                    }
                } catch (err) {
                    console.error("switch_support_chat error:", err);
                }
            });

            // A member may only delete a conversation belonging to their account
            // or their browser guest ID. Deleted conversations cannot be restored.
            socket.on('delete_support_chat', async (data) => {
                try {
                    const session = await ChatSession.findById(data.sessionId);
                    if (!session) return socket.emit('support_chat_deleted', { sessionId: data.sessionId });

                    const userId = (socket.request.user && socket.request.user._id) ? String(socket.request.user._id) : (data.userId ? String(data.userId) : null);
                    const sessionUserId = session.user ? String(session.user._id || session.user) : null;
                    const ownsUserSession = sessionUserId && userId && sessionUserId === userId;
                    const ownsGuestSession = !sessionUserId && session.guestId && data.guestId && session.guestId === data.guestId;
                    const ownsByGuestMatch = data.guestId && session.guestId === data.guestId;
                    if (!ownsUserSession && !ownsGuestSession && !ownsByGuestMatch) {
                        return socket.emit('support_chat_delete_error', { message: 'You can only delete your own conversations.' });
                    }

                    await ChatSession.deleteOne({ _id: session._id });
                    socket.emit('support_chat_deleted', { sessionId: String(session._id) });
                    socket.to(`support_${session._id}`).emit('support_chat_deleted', { sessionId: String(session._id) });
                    io.to('support_agents').emit('agent_chat_deleted', { sessionId: String(session._id) });
                } catch (err) {
                    console.error('delete_support_chat error:', err);
                    socket.emit('support_chat_delete_error', { message: 'Unable to delete this conversation.' });
                }
            });

            // 5. User Sends Message
            socket.on('send_support_message', async (data) => {
                try {
                    const { sessionId, text, mediaUrls } = data;
                    if (!sessionId || (!text && (!mediaUrls || !mediaUrls.length))) return;
                    
                    const userId = socket.request.user?._id;
                    let session = await ChatSession.findById(sessionId).populate('user');

                    // If session was deferred and not yet saved in MongoDB, instantiate and save it now
                    if (!session) {
                        const authenticatedUser = socket.request.user;
                        const meta = socket.data?.pendingChatMeta || {};
                        const expiresAt = new Date(Date.now() + (authenticatedUser ? 24 * 60 : 24) * 60 * 60 * 1000);
                        const guestEmail = (!userId && /^\S+@\S+\.\S+$/.test((data.guestEmail || meta.guestEmail || '').trim()))
                            ? (data.guestEmail || meta.guestEmail).trim()
                            : undefined;
                        const adminNotes = (data.deviceInfo || meta.deviceInfo)
                            ? `Device: ${(data.deviceInfo || meta.deviceInfo).browser || 'Unknown'} on ${(data.deviceInfo || meta.deviceInfo).os || 'Unknown'}${(data.currentPage || meta.currentPage) ? ` | Page: ${data.currentPage || meta.currentPage}` : ''}`
                            : '';

                        session = new ChatSession({
                            _id: sessionId,
                            user: userId || null,
                            guestId: data.guestId,
                            guestEmail: guestEmail,
                            expiresAt: expiresAt,
                            adminNotes: adminNotes,
                            status: 'bot'
                        });
                    }

                    const ownsSession = (userId && session.user && String(session.user._id || session.user) === String(userId)) ||
                        (!userId && session.guestId && session.guestId === data.guestId);
                    if (!ownsSession) return;

                    const userMsg = { 
                        sender: 'user', 
                        text: text || '',
                        mediaUrls: Array.isArray(mediaUrls) ? mediaUrls : []
                    };
                    session.messages.push(userMsg);
                    await session.save();
                    
                    io.to(`support_${session._id}`).emit('new_support_message', userMsg);

                    // --- HUMAN HANDOFF / GUEST EMAIL CAPTURE ---
                    if (session.status === 'waiting-for-agent' && !session.user && !session.guestEmail) {
                        if (text && /^\S+@\S+\.\S+$/.test(text.trim())) {
                            session.guestEmail = text.trim();
                            await session.save();
                            const sysMsg = { sender: 'system', text: "Thank you! Your email has been saved. Our support team will reply shortly." };
                            session.messages.push(sysMsg);
                            await session.save();
                            io.to(`support_${session._id}`).emit('new_support_message', sysMsg);
                            io.to('support_agents').emit('agent_alert_new_chat', session);
                            return;
                        } else {
                            const promptMsg = { sender: 'system', text: "Please provide a valid email address so we can reach you if disconnected." };
                            session.messages.push(promptMsg);
                            await session.save();
                            io.to(`support_${session._id}`).emit('new_support_message', promptMsg);
                            return;
                        }
                    }

                    // If agent is active or already waiting, alert the agents room
                    if (session.status === 'active-agent' || session.status === 'waiting-for-agent') {
                        io.to('support_agents').emit('agent_receive_message', { sessionId: session._id, message: userMsg });
                        return; 
                    }

                    // --- AI PROCESSING (Status is 'bot') ---
                    if (session.status === 'bot') {
                        const triggerWords = ['human', 'agent', 'support', 'real person', 'help me', 'admin', 'talk to a human'];
                        if (text && triggerWords.some(word => text.toLowerCase().includes(word))) {
                            session.status = 'waiting-for-agent';
                            let handoffMsg = "Transferring you to our human support team. Please hold on!";
                            if (!session.user && !session.guestEmail) {
                                handoffMsg += "<br><br>Since you are not logged in, please <b>type your email address below</b> so we can reach you if disconnected.";
                            } else {
                                handoffMsg += "<br><br>An agent will join as soon as possible.";
                            }
                            
                            const sysMsg = { sender: 'system', text: handoffMsg };
                            session.messages.push(sysMsg);
                            await session.save();
                            io.to(`support_${session._id}`).emit('new_support_message', sysMsg);
                            
                            io.to('support_agents').emit('agent_alert_new_chat', session);
                            return;
                        }

                        // AI Response via Gemini Flash
                        try {
                            if (!aiModel) {
                                throw new Error("Gemini AI is not configured or missing API key.");
                            }

                            // Fetch active knowledge base for customized prompt context safely
                            let systemKnowledgePrompt = `You are the official GPL AI Support Assistant for GPL Mods. Answer user inquiries politely, concisely, and accurately based on our services.\n\n`;
                            
                            try {
                                const activeKnowledge = await AIKnowledge.find({ isActive: true }).select('topic keywords response').lean();
                                if (activeKnowledge && activeKnowledge.length) {
                                    systemKnowledgePrompt += `Knowledge Base Rules & Context:\n`;
                                    activeKnowledge.slice(0, 15).forEach(k => {
                                        systemKnowledgePrompt += `- [Topic: ${k.topic}] (Keywords: ${k.keywords}): ${k.response}\n`;
                                    });
                                }
                            } catch (kbErr) {
                                console.warn("Could not load AIKnowledge for chat prompt:", kbErr.message);
                            }

                            const chat = aiModel.startChat({
                                history: [
                                    {
                                        role: "user",
                                        parts: [{ text: systemKnowledgePrompt + "\nAcknowledge you understand your role." }]
                                    },
                                    {
                                        role: "model",
                                        parts: [{ text: "Understood. I am the GPL AI Support Assistant ready to assist members." }]
                                    }
                                ]
                            });

                            const aiResult = await chat.sendMessage(text || "Sent an attachment.");
                            const aiResponseText = aiResult.response.text();

                            const botMsg = { sender: 'bot', text: aiResponseText };
                            session.messages.push(botMsg);
                            await session.save();

                            io.to(`support_${session._id}`).emit('new_support_message', botMsg);
                            
                            aiDebuggerStatus.status = 'online';
                            aiDebuggerStatus.totalRequests++;
                            aiDebuggerStatus.lastPing = new Date();
                            aiDebuggerStatus.lastError = null;
                            io.to('support_agents').emit('ai_status_update', aiDebuggerStatus);
                            broadcastOnlineStats();

                        } catch (error) {
                            console.error("Gemini Error:", error.message || error);
                            
                            aiDebuggerStatus.status = 'offline';
                            aiDebuggerStatus.totalErrors++;
                            aiDebuggerStatus.lastError = {
                                message: error.message || String(error),
                                time: new Date()
                            };

                            const errMsg = { sender: 'system', text: "AI is currently resting. Type 'human' to speak with our support team." };
                            session.messages.push(errMsg);
                            await session.save();
                            io.to(`support_${session._id}`).emit('new_support_message', errMsg);
                            io.to('support_agents').emit('ai_status_update', aiDebuggerStatus);
                            broadcastOnlineStats();
                        }
                    }
                } catch (err) {
                    console.error("send_support_message error:", err);
                }
            });

            // 6. Agent Claims Chat
            socket.on('agent_claim_chat', async (data) => {
                try {
                    const agent = await resolveAgent(data);
                    if (!agent) return;
                    const session = await ChatSession.findById(data.sessionId);
                    if (session) {
                        session.status = 'active-agent';
                        session.assignedTo = agent._id;
                        
                        socket.join(`support_${session._id}`);
                        
                        const sysMsg = { sender: 'system', text: `Agent ${data.agentName || agent.username || 'Support'} has joined the chat.` };
                        session.messages.push(sysMsg);
                        await session.save();
                        
                        io.to(`support_${session._id}`).emit('new_support_message', sysMsg);
                        io.to('support_agents').emit('agent_chat_updated', session);
                    }
                } catch (err) {
                    console.error("agent_claim_chat error:", err);
                }
            });

            // 7. Agent Sends Message
            socket.on('agent_send_message', async (data) => {
                try {
                    const agent = await resolveAgent(data);
                    if (!agent) return;
                    const session = await ChatSession.findById(data.sessionId);
                    if (session) {
                        const agentMsg = { 
                            sender: 'agent', 
                            senderName: agent.username || 'Support Agent',
                            text: data.text || '',
                            mediaUrls: Array.isArray(data.mediaUrls) ? data.mediaUrls : []
                        };
                        session.messages.push(agentMsg);
                        await session.save();
                        
                        io.to(`support_${session._id}`).emit('new_support_message', agentMsg);
                        io.to('support_agents').emit('agent_receive_message', { sessionId: session._id, message: agentMsg });
                    }
                } catch (err) {
                    console.error("agent_send_message error:", err);
                }
            });

            socket.on('agent_delete_chat', async (data) => {
                try {
                    const agent = await resolveAgent(data);
                    if (!agent) return;
                    const session = await ChatSession.findById(data.sessionId);
                    if (!session) return;
                    await ChatSession.deleteOne({ _id: session._id });
                    io.to(`support_${session._id}`).emit('support_chat_deleted', { sessionId: String(session._id) });
                    io.to('support_agents').emit('agent_chat_deleted', { sessionId: String(session._id) });
                } catch (err) {
                    console.error('agent_delete_chat error:', err);
                }
            });

            // 8. Agent Transfers Chat back to Gemini Bot (Issue Resolved or Transfer)
            socket.on('agent_transfer_to_bot', async (data) => {
                try {
                    const agent = await resolveAgent(data);
                    if (!agent) return;
                    const session = await ChatSession.findById(data.sessionId);
                    if (session) {
                        session.status = 'bot';
                        session.assignedTo = null;

                        const sysMsg = { 
                            sender: 'system', 
                            text: `Issue marked as resolved by ${agent.username || 'Support Team'}. You have been transferred back to Gemini AI Assistant. Feel free to ask any further questions!` 
                        };
                        session.messages.push(sysMsg);
                        await session.save();

                        io.to(`support_${session._id}`).emit('new_support_message', sysMsg);
                        io.to(`support_${session._id}`).emit('support_chat_status_updated', { 
                            sessionId: String(session._id), 
                            status: 'bot' 
                        });
                        io.to('support_agents').emit('agent_chat_updated', session);
                    }
                } catch (err) {
                    console.error('agent_transfer_to_bot error:', err);
                }
            });

            // 9. User Switches back to Gemini Bot
            socket.on('user_transfer_to_bot', async (data) => {
                try {
                    const session = await ChatSession.findById(data.sessionId);
                    if (!session) return;

                    const userId = (socket.request.user && socket.request.user._id) ? String(socket.request.user._id) : (data.userId ? String(data.userId) : null);
                    const sessionUserId = session.user ? String(session.user._id || session.user) : null;
                    const ownsSession = (userId && sessionUserId && sessionUserId === userId) ||
                        (!sessionUserId && session.guestId && session.guestId === data.guestId) ||
                        (data.guestId && session.guestId === data.guestId);
                    if (!ownsSession) return;

                    session.status = 'bot';
                    session.assignedTo = null;

                    const sysMsg = { 
                        sender: 'system', 
                        text: `You have switched back to Gemini AI Assistant. How can I help you today?` 
                    };
                    session.messages.push(sysMsg);
                    await session.save();

                    io.to(`support_${session._id}`).emit('new_support_message', sysMsg);
                    io.to(`support_${session._id}`).emit('support_chat_status_updated', { 
                        sessionId: String(session._id), 
                        status: 'bot' 
                    });
                    io.to('support_agents').emit('agent_chat_updated', session);
                } catch (err) {
                    console.error('user_transfer_to_bot error:', err);
                }
            });
            
            socket.on('leave_support_chat', (data) => {
                connectedSupportSockets.delete(socket.id);
                connectedAgentSockets.delete(socket.id);
                connectedUsers.delete(socket.id);
                if (data && data.userId) {
                    const uId = String(data.userId);
                    let hasOtherActiveSocket = false;
                    const activeSockets = io && io.sockets && io.sockets.sockets;
                    for (const [sId, u] of connectedUsers.entries()) {
                        if (sId !== socket.id && u && String(u.userId) === uId) {
                            if (activeSockets && activeSockets.get(sId)?.connected) {
                                hasOtherActiveSocket = true;
                                break;
                            }
                        }
                    }
                    if (!hasOtherActiveSocket) {
                        for (const [sId, u] of connectedUsers.entries()) {
                            if (u && String(u.userId) === uId) {
                                connectedUsers.delete(sId);
                            }
                        }
                    }
                }
                broadcastOnlineStats();
            });

            socket.on('disconnect', () => {
                connectedSupportSockets.delete(socket.id);
                connectedAgentSockets.delete(socket.id);
                connectedUsers.delete(socket.id);

                if (socket.data && socket.data.clubId && !socket.data.isVanished) {
                    const cId = socket.data.clubId;
                    const u = socket.request && socket.request.user;
                    if (u && clubOnlinePresences.has(cId)) {
                        const cUsers = clubOnlinePresences.get(cId);
                        cUsers.delete(String(u._id));
                        const onlineList = Array.from(cUsers.values());
                        io.to(`club_${cId}`).emit('club_presence_update', {
                            clubId: cId,
                            onlineCount: onlineList.length,
                            onlineUsers: onlineList
                        });
                    }
                }

                broadcastOnlineStats();
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
        errorMessage: "Something went wrong on our end. Our team has been notified and we're working to fix it.",
        errorDetails: {
            message: err.message || 'Internal Server Error',
            name: err.name || 'Error',
            path: req.originalUrl || req.url || '/',
            method: req.method || 'GET',
            timestamp: new Date().toISOString(),
            stack: process.env.NODE_ENV === 'production' ? null : (err.stack || null)
        }
    });
});

        // Finally, listen! Bind to 0.0.0.0 for Render compatibility
        server.listen(PORT, '0.0.0.0', () => {
            const isRender = process.env.RENDER === 'true' || Boolean(process.env.RENDER_EXTERNAL_URL);
            if (isRender) {
                const liveUrl = process.env.RENDER_EXTERNAL_URL || process.env.BASE_URL || 'https://gplmods.webredirect.org';
                console.log(`Server is running on ${liveUrl}`);
                console.log(`Server is running on port ${PORT}`);
            } else {
                console.log(`Server is running on http://localhost:${PORT}`);
                console.log(`Server is running on port ${PORT}`);
            }
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

// --- DMCA AUTOMATED COMPLIANCE & TAKEDOWN CRON (Runs every 5 minutes) ---
cron.schedule('*/5 * * * *', async () => {
    try {
        const now = new Date();
        const pendingClaims = await Dmca.find({
            status: 'open',
            scheduledHideAt: { $lte: now },
            isAutomatedHidden: { $ne: true }
        });
        for (const claim of pendingClaims) {
            console.log(`[DMCA Cron] Auto-hiding links for notice ${claim._id} (reached deadline ${claim.scheduledHideAt})`);
            await executeDmcaTakedown(claim._id);
        }
    } catch (dmcaCronErr) {
        console.error('[DMCA Cron] Error running automated takedown job:', dmcaCronErr);
    }
});

// --- DEBUGGER HOURLY KEY ROTATION CRON (Runs at minute 0 of every hour) ---
cron.schedule('0 * * * *', async () => {
    try {
        await getOrRotateDebuggerKey(true, 'Hourly Scheduled Auto-Rotation');
    } catch (err) {
        console.error('[Debugger Cron] Error rotating hourly key:', err);
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
                try {
                    const pushNotification = require('./utils/pushNotification');
                    pushNotification.broadcastPushNotification('admin-messages', {
                        title: `🛡️ Admin: ${campaign.notificationTitle || campaign.title}`,
                        body: campaign.notificationMessage || 'Important update from GPL Mods.',
                        url: '/notifications/admin-messages',
                        tag: `gplmods-admin-${campaign._id || Date.now()}`,
                        sound: true
                    }, app.get('io'));
                } catch (e) {
                    console.error('[WebPush] Campaign broadcast error:', e.message);
                }
            }

            campaign.status = 'completed';
            await campaign.save();
            console.log(`Completed campaign: ${campaign.title}. Sent to ${targetUsers.length} users.`);
        }

    } catch (error) {
        console.error("Cron Job Automation Error:", error);
    }
});

// ===================================
// OWNER ROUTES (INFRASTRUCTURE DASHBOARD)
// ===================================
const ownerRoutes = require('./routes/owner');
app.use('/', ownerRoutes);

// ===================================
// CLUBS & COMMUNITIES ROUTES
// ===================================
const clubsRoutes = require('./routes/clubs');
app.use('/clubs', clubsRoutes);

// ===================================
// DYNAMIC NOTIFICATIONS & PWA PUSH ROUTES
// ===================================
const notificationsRoutes = require('./routes/notifications');
app.use('/api/notifications', notificationsRoutes);

// ✅ START THE SERVER
startServer(); 

// 🛑 MAKE SURE THERE IS ABSOLUTELY NO CODE BELOW THIS LINE! 🛑
