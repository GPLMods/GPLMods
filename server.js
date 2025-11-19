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
        // Allow assets like CSS/JS to load
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
// UPDATED SCHEMA: Added appDescription and screenshotPaths
const ModSchema = new mongoose.Schema({
    name: { type: String, required: true },
    slug: { type: String, required: true, unique: true },
    description: { type: String, required: true },
    appDescription: { type: String, required: true }, // <-- NEW
    platform: { type: String, required: true },
    category: { type: String, required: true },
    version: { type: String, required: true },
    fileType: { type: String, required: true, default: 'apk' },
    modType: { type: String, default: 'Mod' },
    modFilePath: { type: String, required: true },
    iconPath: { type: String, required: true },
    screenshotPaths: [{ type: String }], // <-- NEW (An array of strings)
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
        if (!req.body.name || !req.body.platform) {
            return cb(new Error("Mod Name and Platform are required to create a directory."));
        }
        const slug = req.body.name.replace(/\s+/g, '-').toLowerCase();
        const dir = path.join(__dirname, 'uploads', req.body.platform, slug);
        fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        if (!req.body.name || !req.body.version) {
            return cb(new Error("Mod Name and Version are required for filename."));
        }
        const slug = req.body.name.replace(/\s+/g, '-').toLowerCase();
        const version = req.body.version;
        const extension = path.extname(file.originalname);
        cb(null, `${slug}-v${version}-${file.fieldname}${extension}`);
    }
});
const upload = multer({ storage: storage });


// --- 6. API ROUTES / ENDPOINTS ---

/**
 * @route   POST /upload-mod
 * @desc    Handle the full mod upload process with all details
 */
// UPDATED ROUTE: Handles new fields 'appDescription' and multiple 'screenshots'
app.post('/upload-mod', upload.fields([
    { name: 'modFile', maxCount: 1 }, 
    { name: 'imageFile', maxCount: 1 },
    { name: 'screenshots', maxCount: 4 } // Allow up to 4 screenshots
]), async (req, res) => {
    
    try {
        if (!req.files || !req.files.modFile || !req.files.imageFile) {
            return res.status(400).json({ message: "Mod file and icon file are required." });
        }
        
        // Map the array of screenshot files to an array of their web-accessible paths
        const screenshotPaths = req.files.screenshots 
            ? req.files.screenshots.map(file => file.path.replace(/\\/g, "/").replace(__dirname, ""))
            : [];

        const slug = req.body.name.replace(/\s+/g, '-').toLowerCase();
        const newMod = new Mod({
            name: req.body.name,
            slug: slug,
            description: req.body.description,
            appDescription: req.body.appDescription, // <-- SAVE NEW FIELD
            platform: req.body.platform,
            category: req.body.category,
            version: req.body.version,
            fileType: req.body.fileType,
            modType: req.body.modType,
            ratingValue: parseFloat(req.body.ratingValue),
            modFilePath: req.files.modFile[0].path.replace(/\\/g, "/").replace(__dirname, ""),
            iconPath: req.files.imageFile[0].path.replace(/\\/g, "/").replace(__dirname, ""),
            screenshotPaths: screenshotPaths // <-- SAVE NEW FIELD
        });

        const savedMod = await newMod.save();
        res.status(201).json({ message: "Mod uploaded successfully!", mod: savedMod });

    } catch (error) {
        console.error("ERROR saving mod:", error);
        res.status(500).json({ message: "Error saving mod. The mod name might already exist." });
    }
});

app.get('/api/mods/homepage/:platform', async (req, res) => {
    try {
        const { platform } = req.params;
        const { sort } = req.query;
        let sortQuery = sort === 'popular' ? { downloads: -1 } : { createdAt: -1 };
        const mods = await Mod.find({ platform }).sort(sortQuery).limit(10);
        res.status(200).json(mods);
    } catch (error) {
        res.status(500).json({ message: "Server error fetching homepage mods." });
    }
});

app.get('/api/mods/featured/:platform', async (req, res) => {
    try {
        const { platform } = req.params;
        const featuredMod = await Mod.findOne({ platform, isFeatured: true });
        res.status(200).json(featuredMod);
    } catch (error) {
        res.status(500).json({ message: "Server error fetching featured mod." });
    }
});

app.get('/api/mods', async (req, res) => {
    try {
        const { platform, sort, page = 1, category } = req.query;
        if (!platform) return res.status(400).json({ message: "Platform is required." });
        const limit = 12;
        const skip = (page - 1) * limit;
        let sortQuery = sort === 'popular' ? { downloads: -1 } : { createdAt: -1 };
        let findQuery = { platform };
        if (category && category !== 'all') findQuery.category = category;

        const mods = await Mod.find(findQuery).sort(sortQuery).skip(skip).limit(limit);
        const totalMods = await Mod.countDocuments(findQuery);
        const startItem = skip + 1;
        const endItem = Math.min(skip + limit, totalMods);
        
        res.status(200).json({ mods, currentPage: parseInt(page), totalPages: Math.ceil(totalMods / limit), totalMods, startItem, endItem });
    } catch (error) {
        res.status(500).json({ message: "Server error fetching paginated mods." });
    }
});

app.get('/api/mod/:id', async (req, res) => {
    try {
        if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: "Invalid Mod ID." });
        }
        const mod = await Mod.findById(req.params.id);
        if (!mod) return res.status(404).json({ message: "Mod not found." });
        res.status(200).json(mod);
    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
});

app.get('/api/download/:id', async (req, res) => {
    try {
       if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
            return res.status(400).json({ message: "Invalid Mod ID." });
        }
       const mod = await Mod.findByIdAndUpdate(req.params.id, { $inc: { downloads: 1 } }, { new: true });
       if (!mod) return res.status(404).json({ message: "Mod not found." });
       res.status(200).json({ filePath: mod.modFilePath });
   } catch (error) {
       res.status(500).json({ message: "Server error." });
   }
});

// --- 7. CATCH-ALL & 8. ERROR HANDLING ---
app.use((req, res, next) => {
    res.status(404).sendFile(path.join(__dirname, 'errors-pages', 'error-404.html'));
});

app.use((err, req, res, next) => {
    console.error('--- UNHANDLED SERVER ERROR ---', err.stack);
    if (!res.headersSent) {
        res.status(500).sendFile(path.join(__dirname, 'errors-pages', 'error-500.html'));
    }
});

// --- 9. SERVER INITIALIZATION ---
app.listen(PORT, () => {
    console.log(`GPL Mods server is live and listening on http://localhost:${PORT}`);
});