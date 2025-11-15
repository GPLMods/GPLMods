// ===================================================================
// GPL MODS - FULL BACKEND SERVER (server.js)
// ===================================================================

// --- 1. SETUP & IMPORTS ---
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
// Add axios later if you re-integrate the VirusTotal API
// const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// --- 2. MIDDLEWARE ---
app.use(express.static(path.join(__dirname)));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- 3. DATABASE CONNECTION ---
mongoose.connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('SUCCESS: Connected to MongoDB Atlas!'))
.catch(err => console.error('ERROR: Could not connect to MongoDB Atlas.', err));

// --- 4. DATABASE SCHEMA ---
const ModSchema = new mongoose.Schema({
    name: { type: String, required: true },
    slug: { type: String, required: true, unique: true }, // For clean URLs like /mods/android/kinemaster
    description: { type: String, required: true },
    platform: { type: String, required: true },
    category: { type: String, required: true },
    version: { type: String, required: true },
    modFilePath: { type: String, required: true },
    iconPath: { type: String, required: true },
    uploader: { type: String, default: 'Community' },
    downloads: { type: Number, default: 0 },
    rating: { type: Number, default: 4.5 }, // Default rating
    createdAt: { type: Date, default: Date.now }
});
const Mod = mongoose.model('Mod', ModSchema);

// --- 5. FILE STORAGE ENGINE ---
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const slug = (req.body.name || 'unknown-mod').replace(/\s+/g, '-').toLowerCase();
        const dir = path.join(__dirname, 'uploads', req.body.platform, slug);
        fs.mkdirSync(dir, { recursive: true });
        cb(null, dir);
    },
    filename: function (req, file, cb) {
        const slug = (req.body.name || 'unknown-mod').replace(/\s+/g, '-').toLowerCase();
        const version = req.body.version || '1.0';
        const extension = path.extname(file.originalname);
        const newFilename = `${slug}-v${version}${extension}`;
        cb(null, newFilename);
    }
});
const upload = multer({ storage: storage });

// --- 6. API ROUTES / ENDPOINTS ---

/**
 * @route   POST /upload-mod
 * @desc    Handle the full mod upload process
 */
app.post('/upload-mod', upload.fields([{ name: 'modFile', maxCount: 1 }, { name: 'imageFile', maxCount: 1 }]), async (req, res) => {
    // NOTE: Add VirusTotal scan logic here in a real application
    if (!req.files || !req.files.modFile || !req.files.iconFile) {
        return res.status(400).json({ message: "Mod file and icon file are both required." });
    }

    try {
        const slug = req.body.name.replace(/\s+/g, '-').toLowerCase();

        const newMod = new Mod({
            name: req.body.name,
            slug: slug,
            description: req.body.description,
            platform: req.body.platform,
            category: req.body.category,
            version: req.body.version,
            modFilePath: req.files.modFile[0].path.replace(/\\/g, "/"),
            iconPath: req.files.iconFile[0].path.replace(/\\/g, "/"),
        });

        const savedMod = await newMod.save();
        console.log('SUCCESS: Mod saved to database:', savedMod.name);
        res.status(201).json({ message: "Mod uploaded successfully!", mod: savedMod });

    } catch (error) {
        console.error("ERROR saving mod:", error);
        if (req.files.modFile) fs.unlinkSync(req.files.modFile[0].path);
        if (req.files.iconFile) fs.unlinkSync(req.files.iconFile[0].path);
        res.status(500).json({ message: "Error saving mod. It's possible a mod with this name already exists." });
    }
});

/**
 * @route   GET /api/mods/:platform
 * @desc    Get mods for a specific platform, with sorting
 */
app.get('/api/mods/:platform', async (req, res) => {
    try {
        const platform = req.params.platform;
        const sortBy = req.query.sort;
        const limit = parseInt(req.query.limit) || 10;

        let sortQuery = { createdAt: -1 }; // Default: sort by 'new'

        if (sortBy === 'popular') {
            sortQuery = { downloads: -1 }; // Sort by most downloads
        }
        // 'working' is not a database field, so we can't sort by it directly.
        // For 'working', we can just return the newest, assuming all are working.
        // In a real app, you might have a 'verified' field to sort by.

        const mods = await Mod.find({ platform: platform })
            .sort(sortQuery)
            .limit(limit);
        
        res.status(200).json(mods);

    } catch (error) {
        console.error(`ERROR fetching mods for ${req.params.platform}:`, error);
        res.status(500).json({ message: "Server error while fetching mods." });
    }
});

/**
 * @route   GET /api/mod/:id
 * @desc    Get data for a single mod page
 */
app.get('/api/mod/:id', async (req, res) => {
     try {
        const mod = await Mod.findById(req.params.id);
        if (!mod) {
            return res.status(404).json({ message: "Mod not found." });
        }
        res.status(200).json(mod);
    } catch (error) {
        res.status(500).json({ message: "Server error." });
    }
});

/**
 * @route   GET /api/download/:id
 * @desc    Track a download and return the file path
 */
app.get('/api/download/:id', async (req, res) => {
    try {
       const mod = await Mod.findByIdAndUpdate(
           req.params.id, 
           { $inc: { downloads: 1 } }, // Atomically increment the download count by 1
           { new: true } // Return the updated document
       );

       if (!mod) {
           return res.status(404).json({ message: "Mod not found." });
       }
       
       // In a real app, you might redirect to a file storage URL (like AWS S3)
       // For this setup, we're just confirming the download and sending back the path.
       res.status(200).json({ filePath: mod.modFilePath });

   } catch (error) {
       console.error(`ERROR tracking download for ${req.params.id}:`, error);
       res.status(500).json({ message: "Server error." });
   }
});

// --- CATCH-ALL FOR ROUTING ---
// This is important for a Single Page Application feel. It makes sure if a user refreshes
// on a page like /pages/about.html, the server knows to send that file.
app.get('*', (req, res) => {
    // Construct the file path, but check if it's a valid HTML file to prevent errors
    const filePath = path.join(__dirname, req.path);
    if (path.extname(req.path) === '.html' && fs.existsSync(filePath)) {
        res.sendFile(filePath);
    } else if (fs.existsSync(filePath) && fs.lstatSync(filePath).isFile()) {
        res.sendFile(filePath); // Serve other files like images if requested directly
    }
    else {
        // If the path doesn't match a file, send the main index.html
        // Or a 404 page
        res.sendFile(path.join(__dirname, 'index.html'));
    }
});


// --- 7. SERVER INITIALIZATION ---
app.listen(PORT, () => {
    console.log(`GPL Mods server is now live and listening on http://localhost:${PORT}`);
});