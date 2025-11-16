// ===================================================================
// GPL MODS - FINAL, FULL-FEATURED BACKEND SERVER (server.js)
// ===================================================================

// --- 1. SETUP & IMPORTS ---
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// --- A. MAINTENANCE MODE SWITCH ---
const IN_MAINTENANCE_MODE = false; // Set to true to enable "Coming Soon" page


// --- 2. MIDDLEWARE ---
app.use(express.static(path.join(__dirname)));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
    if (IN_MAINTENANCE_MODE && req.path.indexOf('.html') === -1 && req.path !== '/') {
        // Allow assets like CSS/JS to load on the coming soon page
    } else if (IN_MAINTENANCE_MODE && req.path !== '/errors-pages/coming-soon.html') {
        return res.status(503).sendFile(path.join(__dirname, 'errors-pages', 'coming-soon.html'));
    }
    next();
});


// --- 3. DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('SUCCESS: Connected to MongoDB Atlas!'))
    .catch(err => console.error('ERROR: Could not connect to MongoDB Atlas.', err));

// --- 4. DATABASE SCHEMA (UPGRADED) ---
const ModSchema = new mongoose.Schema({
    name: { type: String, required: true },
    slug: { type: String, required: true, unique: true },
    description: { type: String, required: true },
    platform: { type: String, required: true },
    category: { type: String, required: true },
    version: { type: String, required: true },
    fileType: { type: String, required: true, default: 'apk' },
    modType: { type: String, default: 'Mod' },
    modFilePath: { type: String, required: true },
    iconPath: { type: String, required: true },
    isFeatured: { type: Boolean, default: false },
    uploader: { type: String, default: 'Community' },
    downloads: { type: Number, default: 0 },
    ratingValue: { type: Number, default: 4.5, min: 1, max: 5 },
    createdAt: { type: Date, default: Date.now }
});
const Mod = mongoose.model('Mod', ModSchema);

// --- 5. FILE STORAGE ENGINE ---
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const slug = (req.body.name || 'unknown').replace(/\s+/g, '-').toLowerCase();
        const dir = path.join(__dirname, 'uploads', req.body.platform, slug);
        fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const slug = (req.body.name || 'unknown').replace(/\s+/g, '-').toLowerCase();
        const version = req.body.version || '1.0';
        const extension = path.extname(file.originalname);
        cb(null, `${slug}-v${version}-${file.fieldname}${extension}`); // Added fieldname for uniqueness
    }
});
const upload = multer({ storage: storage });


// --- 6. API ROUTES / ENDPOINTS ---

/**
 * @route   POST /upload-mod
 * @desc    Handle the full mod upload process with all details
 */
app.post('/upload-mod', upload.fields([{ name: 'modFile', maxCount: 1 }, { name: 'imageFile', maxCount: 1 }]), async (req, res) => {
    // NOTE: Integrate VirusTotal scan logic here
    try {
        const slug = req.body.name.replace(/\s+/g, '-').toLowerCase();
        const newMod = new Mod({
            name: req.body.name,
            slug: slug,
            description: req.body.description,
            platform: req.body.platform,
            category: req.body.category,
            version: req.body.version,
            fileType: req.body.fileType,
            modType: req.body.modType,
            ratingValue: parseFloat(req.body.ratingValue),
            modFilePath: req.files.modFile[0].path.replace(/\\/g, "/"),
            iconPath: req.files.imageFile[0].path.replace(/\\/g, "/"),
        });
        const savedMod = await newMod.save();
        res.status(201).json({ message: "Mod uploaded successfully!", mod: savedMod });
    } catch (error) {
        console.error("ERROR saving mod:", error);
        res.status(500).json({ message: "Error saving mod. The mod name might already exist." });
    }
});

app.get('/api/mods/homepage/:platform', async (req, res) => { /* ... (same as before) ... */ });
app.get('/api/mods/featured/:platform', async (req, res) => { /* ... (same as before) ... */ });
app.get('/api/mods', async (req, res) => { /* ... (same as before) ... */ });
app.get('/api/mod/:id', async (req, res) => { /* ... (same as before) ... */ });
app.get('/api/download/:id', async (req, res) => { /* ... (same as before) ... */ });


// --- 7. CATCH-ALL ROUTE FOR SERVING FILES AND 404s ---
app.use((req, res, next) => {
    const safePath = path.normalize(req.path).replace(/^(\.\.[\/\\])+/, '');
    const filePath = path.join(__dirname, safePath);
    
    if (fs.existsSync(filePath) && fs.lstatSync(filePath).isFile()) {
        return res.sendFile(filePath);
    }
    
    const htmlFilePath = filePath.endsWith('/') ? path.join(filePath, 'index.html') : filePath + '.html';
    if (fs.existsSync(htmlFilePath)) {
        return res.sendFile(htmlFilePath);
    }

    res.status(404).sendFile(path.join(__dirname, 'errors-pages', 'error-404.html'));
});


// --- 8. FINAL ERROR HANDLER (for 500 Server Errors) ---
app.use((err, req, res, next) => {
    console.error('--- UNHANDLED SERVER ERROR ---');
    console.error(err.stack);
    console.error('-----------------------------');
    if (!res.headersSent) {
        res.status(500).sendFile(path.join(__dirname, 'errors-pages', 'error-500.html'));
    }
});


// --- 9. SERVER INITIALIZATION ---
app.listen(PORT, () => {
    console.log(`GPL Mods server is live and listening on http://localhost:${PORT}`);
});