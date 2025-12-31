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
const jwt = require('jsonwebtoken'); 
const mailersend = require('mailersend'); 

// AWS SDK v3 Imports
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

// Mongoose Models
const File = require('./models/file');
const User = require('./models/user');
const Review = require('./models/review');
const Report = require('./models/report'); // Added Report model

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
// 3. EMAIL CONFIGURATION (Nodemailer)
// ===============================
const transporter = nodemailer.createTransport({
    service: 'gmail', 
    auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS
    }
});

const sendVerificationEmail = async (user) => {
    const verificationUrl = `${process.env.BASE_URL}/verify-email?token=${user.verificationToken}`;
    
    const mailOptions = {
        from: `"Mod Site Support" <${process.env.EMAIL_USER}>`,
        to: user.email,
        subject: 'Please Verify Your Email',
        html: `<h1>Welcome to our site!</h1>
               <p>Please click the link below to verify your account:</p>
               <a href="${verificationUrl}">${verificationUrl}</a>`
    };

    await transporter.sendMail(mailOptions);
};

// ===============================
// 4. AWS S3 CLIENT (BACKBLAZE B2)
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
// 5. DATABASE CONNECTION
// ===============================
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Successfully connected to MongoDB Atlas!'))
    .catch(error => console.error('Error connecting to MongoDB Atlas:', error));

// ===============================
// 6. SESSION & PASSPORT CONFIG
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

        if (!user.isVerified) {
            return done(null, false, { message: 'Please verify your email before logging in.' });
        }

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

// --- NEW MIDDLEWARE TO CHECK FOR ADMIN ROLE ---
function ensureAdmin(req, res, next) {
    // We assume the user is already authenticated at this point
    if (req.user && req.user.role === 'admin') {
        return next(); // If user is an admin, proceed
    }
    // If not an admin, send an error or redirect
    res.status(403).send("Forbidden: You do not have permission to access this page.");
}

// ===============================
// 7. ROUTES
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
        if (!Types.ObjectId.isValid(fileId)) { return res.status(404).send("File not found."); }

        const [file, reviews] = await Promise.all([
            File.findById(fileId),
            Review.find({ file: fileId }).sort({ createdAt: -1 })
        ]);

        if (!file) { return res.status(404).send("File not found."); }

        const iconUrl = await getSignedUrl(s3Client, new GetObjectCommand({ 
            Bucket: process.env.B2_BUCKET_NAME, Key: file.iconKey 
        }), { expiresIn: 3600 });

        const screenshotUrls = await Promise.all(
            file.screenshotKeys.map(key => getSignedUrl(s3Client, new GetObjectCommand({ 
                Bucket: process.env.B2_BUCKET_NAME, Key: key 
            }), { expiresIn: 3600 }))
        );
        
        res.render('pages/download', { file: { ...file.toObject(), iconUrl, screenshotUrls }, reviews });
    } catch (error) {
        console.error("Error fetching file for download page:", error);
        res.status(500).send("Server error.");
    }
});

// --- AUTHENTICATION ROUTES ---
app.get('/register', (req, res) => res.render('pages/register'));

app.post('/register', async (req, res, next) => {
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

// --- SEARCH ROUTE ---
app.get('/search', async (req, res) => {
    try {
        const query = req.query.q;
        if (!query) { return res.redirect('/'); }
        
        const searchResults = await File.find({
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

// --- USER PROFILE & ACCOUNT MANAGEMENT ---
app.get('/profile', ensureAuthenticated, async (req, res) => {
    try {
        const userUploads = await File.find({ uploader: req.user.username }).sort({ createdAt: -1 });
        res.render('pages/profile', { user: req.user, uploads: userUploads });
    } catch (error) {
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
            console.error("VirusTotal submission failed.");
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
        res.status(500).send("Server error.");
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

// --- REVIEW VOTING ROUTE ---
app.post('/reviews/:reviewId/vote', ensureAuthenticated, async (req, res) => {
    try {
        const reviewId = req.params.reviewId;
        const userId = req.user._id;

        const review = await Review.findById(reviewId);
        if (!review) {
            return res.status(404).send("Review not found.");
        }

        if (review.votedBy.includes(userId)) {
            return res.redirect(`/mods/${review.file}`);
        }

        review.votedBy.push(userId);
        review.isHelpfulCount += 1;
        await review.save();

        res.redirect(`/mods/${review.file}`);

    } catch (error) {
        console.error('Error processing review vote:', error);
        res.status(500).send("Server Error");
    }
});

// ===================================
// 8. FILE REPORTING ROUTES
// ===================================
app.post('/files/:fileId/report', ensureAuthenticated, async (req, res) => {
    try {
        const fileId = req.params.fileId;
        const { reason, additionalComments } = req.body;

        if (!reason) {
            return res.status(400).send("A reason is required to submit a report.");
        }
        
        const fileToReport = await File.findById(fileId);
        if (!fileToReport) {
            return res.status(404).send("File not found.");
        }

        // Check if this user has already reported this specific file
        const existingReport = await Report.findOne({ file: fileId, reportingUser: req.user._id });
        if (existingReport) {
            console.log("User has already reported this file.");
            return res.redirect(`/mods/${fileId}`);
        }

        const newReport = new Report({
            file: fileId,
            reportingUser: req.user._id,
            reportedFileName: fileToReport.name,
            reportingUsername: req.user.username,
            reason: reason,
            additionalComments: additionalComments
        });

        await newReport.save();

        // Redirect back to the mod page with a success message
        res.redirect(`/mods/${fileId}?reported=true`);

    } catch (error) {
        console.error("Error submitting report:", error);
        res.status(500).send("Server Error");
    }
});

// ===================================
// 9. ADMIN ROUTES
// ===================================
app.get('/admin/reports', ensureAuthenticated, ensureAdmin, async (req, res) => {
    try {
        // Find all reports and sort by newest first (open reports first)
        const reports = await Report.find()
                                    .sort({ status: 1, createdAt: -1 })
                                    .populate('file') // Optional: pulls in the full File object
                                    .populate('reportingUser'); // Optional: pulls in the User object

        res.render('pages/admin/reports', {
            reports: reports
        });

    } catch (error) {
        console.error("Error fetching reports for admin page:", error);
        res.status(500).send("Server Error");
    }
});

// ===============================
// 10. START SERVER
// ===============================
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});