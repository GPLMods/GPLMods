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
const MongoStore = require('connect-mongo');
const axios = require('axios');
const bcrypt = require('bcryptjs');

// AWS SDK v3 Imports
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

// Mongoose Models
const File = require('./models/file');
const User = require('./models/user');
const Review = require('./models/review');

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

const sanitizeFilename = (filename) => {
    return filename.replace(/[^a-zA-Z0-9.-_]/g, '');
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

passport.use(new LocalStrategy({ usernameField: 'email' }, async (email, password, done) => {
    try {
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) { return done(null, false, { message: 'Incorrect email.' }); }
        const isMatch = await user.comparePassword(password);
        if (!isMatch) { return done(null, false, { message: 'Incorrect password.' }); }
        return done(null, user);
    } catch (error) {
        return done(error);
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

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) { return next(); }
    res.redirect('/login');
}

// ===============================
// 6. ROUTES
// ===============================

// --- INDEX PAGE ---
app.get('/', async (req, res) => {
    try {
        const recentFiles = await File.find().sort({ createdAt: -1 }).limit(12);
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
        const filteredFiles = await File.find({ category: cat }).sort({ createdAt: -1 });
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

        if (!Types.ObjectId.isValid(fileId)) {
            return res.status(404).send("File not found (Invalid ID format).");
        }

        const [file, reviews] = await Promise.all([
            File.findById(fileId),
            Review.find({ file: fileId }).sort({ createdAt: -1 })
        ]);

        if (!file) {
            return res.status(404).send("File not found.");
        }

        const iconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ 
            Bucket: process.env.B2_BUCKET_NAME, 
            Key: file.iconKey 
        }), { expiresIn: 3600 });

        const screenshotUrls = await Promise.all(
            file.screenshotKeys.map(key => getSignedUrl(s3Client, new GetObjectCommand({ 
                Bucket: process.env.B2_BUCKET_NAME, 
                Key: key 
            }), { expiresIn: 3600 }))
        );
        
        const fileDataForView = { ...file.toObject(), iconUrl, screenshotUrls };
        
        res.render('pages/download', { 
            file: fileDataForView, 
            reviews: reviews 
        });

    } catch (error) {
        console.error("Error fetching file for download page:", error);
        res.status(500).send("Server error.");
    }
});


// --- AUTHENTICATION ROUTES ---
app.get('/register', (req, res) => res.render('pages/register'));
app.post('/register', async (req, res, next) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) { return res.status(400).send("All fields are required."); }
    try {
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) { return res.status(400).send("User with this email or username already exists."); }
        const newUser = new User({ username, email, password });
        await newUser.save();
        req.login(newUser, (err) => {
            if (err) { return next(err); }
            return res.redirect('/');
        });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).send("Server error during registration.");
    }
});

app.get('/login', (req, res) => res.render('pages/login'));
app.post('/login', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login'
}));

app.get('/logout', (req, res, next) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

// ===================================
// USER PROFILE & ACCOUNT MANAGEMENT
// ===================================

/**
 * GET Route for the User Profile/Dashboard page.
 */
app.get('/profile', ensureAuthenticated, async (req, res) => {
    try {
        // Find all files where the 'uploader' field matches the current user's username.
        const userUploads = await File.find({ uploader: req.user.username })
                                      .sort({ createdAt: -1 });

        res.render('pages/profile', {
            user: req.user,
            uploads: userUploads
        });
    } catch (error) {
        console.error('Error fetching user profile data:', error);
        res.status(500).send('Server Error');
    }
});

/**
 * POST Route to handle account deletion.
 */
app.post('/account/delete', ensureAuthenticated, async (req, res, next) => {
    try {
        const userId = req.user._id;
        const username = req.user.username;

        // 1. Delete all files uploaded by this user
        // (B2 cleanup logic can be added here if needed)
        await File.deleteMany({ uploader: username });

        // 2. Delete all reviews written by this user
        await Review.deleteMany({ user: userId });

        // 3. Delete the user account
        await User.findByIdAndDelete(userId);

        // 4. Log the user out
        req.logout(function(err) {
            if (err) { return next(err); }
            res.redirect('/');
        });

    } catch (error) {
        console.error('Error deleting account:', error);
        res.status(500).send('Could not delete account.');
    }
});


// --- FILE MANAGEMENT ---
app.get('/upload', ensureAuthenticated, (req, res) => {
    res.render('pages/upload');
});

const storage = multer.memoryStorage();
const upload = multer({ storage: storage, limits: { fileSize: 100 * 1024 * 1024 } });

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

    const uploadToB2 = async (file, folder) => {
        const sanitizedFilename = sanitizeFilename(file.originalname);
        const fileName = `${folder}/${Date.now()}-${sanitizedFilename}`;
        const params = { Bucket: process.env.B2_BUCKET_NAME, Key: fileName, Body: file.buffer, ContentType: file.mimetype };
        await s3Client.send(new PutObjectCommand(params));
        return fileName;
    };

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
            console.error("VirusTotal submission failed:", vtError.response?.data);
        }

        const newFile = new File({
            name: softwareName, version: softwareVersion, modDescription, officialDescription,
            iconKey, screenshotKeys, videoUrl, fileKey, originalFilename: modFile[0].originalname,
            category, platforms: Array.isArray(platforms) ? platforms : [platforms],
            tags: tags ? tags.split(',').map(tag => tag.trim()) : [],
            uploader: req.user.username,
            fileSize: modFile[0].size,
            virusTotalAnalysisId: analysisId
        });

        await newFile.save();
        res.redirect(`/mods/${newFile._id}`);
    } catch (error) {
        console.error("Upload process failed:", error);
        res.status(500).send("An error occurred during the upload process.");
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
        console.error("Error processing file download:", error);
        res.status(500).send("Server error.");
    }
});

// --- REVIEW SYSTEM ---
app.post('/reviews/add/:fileId', ensureAuthenticated, async (req, res) => {
    try {
        const fileId = req.params.fileId;
        const { rating, comment } = req.body;

        if (!rating || !comment) {
            return res.status(400).send("Rating and comment are required.");
        }

        const existingReview = await Review.findOne({ file: fileId, user: req.user._id });
        if (existingReview) {
            return res.redirect(`/mods/${fileId}`);
        }

        const newReview = new Review({
            file: fileId,
            user: req.user._id,
            username: req.user.username,
            rating: parseInt(rating),
            comment: comment
        });
        await newReview.save();

        const stats = await Review.aggregate([
            { $match: { file: new Types.ObjectId(fileId) } },
            { 
                $group: { 
                    _id: '$file', 
                    avgRating: { $avg: '$rating' }, 
                    count: { $sum: 1 } 
                } 
            }
        ]);
        
        if (stats.length > 0) {
            await File.findByIdAndUpdate(fileId, {
                averageRating: stats[0].avgRating.toFixed(1),
                ratingCount: stats[0].count
            });
        }
        
        res.redirect(`/mods/${fileId}`);
    } catch (error) {
        console.error("Error submitting review:", error);
        res.status(500).send("Server error.");
    }
});

// ===============================
// 7. START SERVER
// ===============================
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});