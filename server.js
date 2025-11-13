// =================================================================
// GPL MODS - BACKEND SERVER (server.js)
// =================================================================

// --- 1. SETUP & IMPORTS ---
require('dotenv').config(); // Loads environment variables from .env file
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
// We'll add the VirusTotal logic back in later. For now, we focus on DB.

const app = express();
const PORT = process.env.PORT || 3000;

// --- 2. MIDDLEWARE ---
// Serve static files (HTML, CSS, JS) from the root directory
app.use(express.static(path.join(__dirname)));
// Make the 'uploads' folder publicly accessible to display images
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
// Allow the server to understand JSON and URL-encoded form data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


// --- 3. DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('SUCCESS: Connected to MongoDB Atlas!'))
.catch(err => console.error('ERROR: Could not connect to MongoDB Atlas.', err));


// --- 4. DATABASE SCHEMA (THE BLUEPRINT FOR OUR MODS) ---
const ModSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    platform: { type: String, required: true }, // e.g., 'android', 'ios-jailed'
    category: { type: String, required: true },
    version: { type: String, required: true },
    modFilePath: { type: String, required: true }, // Path to the main mod file
    iconPath: { type: String, required: true }, // Path to the icon image
    uploader: { type: String, default: 'Community' }, // Will be user ID later
    downloads: { type: Number, default: 0 },
    rating: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});
const Mod = mongoose.model('Mod', ModSchema);


// --- 5. FILE STORAGE ENGINE (Multer Configuration) ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        // Create a structured folder path: uploads/platform/mod-name
        const platform = req.body.platform || 'general';
        const modName = (req.body.name || 'unknown-mod').replace(/\s+/g, '-').toLowerCase();
        const dir = path.join(__dirname, 'uploads', platform, modName);
        
        // Use fs.promises for modern async/await, or fs.mkdirSync for simplicity
        fs.mkdirSync(dir, { recursive: true }); // `recursive: true` creates parent dirs if they don't exist
        
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        // Create a clean filename: mod-name-v1.2.3.apk
        const version = req.body.version || '1.0';
        const modName = (req.body.name || 'unknown-mod').replace(/\s+/g, '-').toLowerCase();
        const extension = path.extname(file.originalname);
        const newFilename = `${modName}-v${version}${extension}`;
        
        cb(null, newFilename);
    }
});
const upload = multer({ storage: storage });


// --- 6. API ROUTES / ENDPOINTS ---

/**
 * @route   POST /upload-mod
 * @desc    Upload a new mod with its files and save to DB
 */
app.post('/upload-mod', upload.fields([{ name: 'modFile', maxCount: 1 }, { name: 'imageFile', maxCount: 1 }]), async (req, res) => {
    
    // INTEGRATION POINT: This is where you would add the VirusTotal scan for the `modFile`.
    // If the scan fails, you would delete the uploaded files and return an error.
    // For now, we'll proceed as if the file is safe.

    // Check if files were uploaded
    if (!req.files || !req.files.modFile || !req.files.iconFile) {
        return res.status(400).json({ message: "Both a mod file and an icon file are required." });
    }

    try {
        const newMod = new Mod({
            name: req.body.name,
            description: req.body.description,
            platform: req.body.platform,
            category: req.body.category,
            version: req.body.version,
            // Store the web-accessible path, not the full system path
            modFilePath: req.files.modFile[0].path.replace(/\\/g, "/"),
            iconPath: req.files.iconFile[0].path.replace(/\\/g, "/"),
            // uploader will be req.user.id in a real auth system
        });

        const savedMod = await newMod.save(); // Save the record to MongoDB

        console.log('SUCCESS: Mod saved to database:', savedMod.name);
        res.status(201).json({ message: "Mod uploaded and saved successfully!", mod: savedMod });

    } catch (error) {
        console.error("ERROR saving mod to database:", error);
        // Clean up uploaded files if DB save fails
        if (req.files.modFile) fs.unlinkSync(req.files.modFile[0].path);
        if (req.files.iconFile) fs.unlinkSync(req.files.iconFile[0].path);
        res.status(500).json({ message: "An error occurred while saving the mod." });
    }
});


/**
 * @route   GET /api/mods/:platform
 * @desc    Get a list of the latest mods for a specific platform
 */
app.get('/api/mods/:platform', async (req, res) => {
    try {
        const platform = req.params.platform;
        const limit = parseInt(req.query.limit) || 10; // Allow optional limit, default to 10

        const mods = await Mod.find({ platform: platform })
            .sort({ createdAt: -1 }) // Sort by newest first
            .limit(limit);
        
        res.status(200).json(mods);

    } catch (error) {
        console.error(`ERROR fetching mods for platform ${req.params.platform}:`, error);
        res.status(500).json({ message: "Server error while fetching mods." });
    }
});

/**
 * @route   GET /mod/:id
 * @desc    Get data for a single mod page (You will need this for your mod.html)
 */
app.get('/api/mod/:id', async (req, res) => {
     try {
        const mod = await Mod.findById(req.params.id);
        if (!mod) {
            return res.status(404).json({ message: "Mod not found." });
        }
        res.status(200).json(mod);
    } catch (error) {
        console.error(`ERROR fetching mod with ID ${req.params.id}:`, error);
        res.status(500).json({ message: "Server error." });
    }
});


// --- 7. SERVER INITIALIZATION ---
app.listen(PORT, () => {
    console.log(`GPL Mods server is running and listening on http://localhost:${PORT}`);
});