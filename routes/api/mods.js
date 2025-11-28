// ===================================================================
// API ROUTES for MODS (/api/mods)
// ===================================================================

const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const path = require('path');
const fs = require('fs');

// --- MIDDLEWARE & MODELS ---
const authMiddleware = require('../../middleware/auth');
const Mod = require('../../models/Mod');

// --- MULTER FILE STORAGE CONFIG (Moved here for organization) ---
const multer = require('multer');
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (!req.body.name || !req.body.platform) {
            return cb(new Error("Mod Name and Platform are required to create a directory."));
        }
        const slug = req.body.name.replace(/\s+/g, '-').toLowerCase();
        const dir = path.join(__dirname, '..', '..', 'uploads', req.body.platform, slug); // Correct pathing from /routes/api
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


// ================== PROTECTED ROUTES (Require Login) ==================

/**
 * @route   POST /api/mods
 * @desc    Upload a new mod
 * @access  Private
 */
router.post('/', [authMiddleware, upload.fields([
    { name: 'modFile', maxCount: 1 }, 
    { name: 'imageFile', maxCount: 1 },
    { name: 'screenshots', maxCount: 4 }
])], async (req, res) => {
    try {
        if (!req.files || !req.files.modFile || !req.files.imageFile) {
            return res.status(400).json({ message: "Mod file and icon file are required." });
        }

        const slug = req.body.name.replace(/\s+/g, '-').toLowerCase();
        
        // Check if a mod with this slug already exists to prevent duplicates
        if (await Mod.findOne({ slug })) {
            return res.status(400).json({ message: "A mod with this name already exists. Please choose a different name." });
        }

        const screenshotPaths = req.files.screenshots 
            ? req.files.screenshots.map(file => file.path.replace(/\\/g, "/").replace(path.join(__dirname, '..', '..'), ''))
            : [];

        const newMod = new Mod({
            name: req.body.name, slug, description: req.body.description, appDescription: req.body.appDescription,
            platform: req.body.platform, category: req.body.category, version: req.body.version,
            fileType: req.body.fileType, modType: req.body.modType, ratingValue: parseFloat(req.body.ratingValue),
            modFilePath: req.files.modFile[0].path.replace(/\\/g, "/").replace(path.join(__dirname, '..', '..'), ''),
            iconPath: req.files.imageFile[0].path.replace(/\\/g, "/").replace(path.join(__dirname, '..', '..'), ''),
            screenshotPaths: screenshotPaths,
            uploader: req.user.id // Assign the logged-in user as the uploader
        });

        const savedMod = await newMod.save();
        res.status(201).json({ message: "Mod uploaded successfully and is pending review!", mod: savedMod });
    } catch (error) {
        console.error("ERROR saving mod:", error);
        res.status(500).json({ message: "Server error during upload process." });
    }
});

/**
 * @route   GET /api/mods/my-uploads
 * @desc    Get all mods uploaded by the currently logged-in user
 * @access  Private
 */
router.get('/my-uploads', authMiddleware, async (req, res) => {
    try {
        const mods = await Mod.find({ uploader: req.user.id }).sort({ createdAt: -1 });
        res.json(mods);
    } catch (err) {
        res.status(500).send('Server Error');
    }
});


/**
 * @route   DELETE /api/mods/:id
 * @desc    Delete a mod uploaded by the user
 * @access  Private
 */
router.delete('/:id', authMiddleware, async (req, res) => {
    try {
        const mod = await Mod.findById(req.params.id);
        if (!mod) return res.status(404).json({ message: 'Mod not found' });
        
        // Check if the logged-in user is the one who uploaded the mod
        if (mod.uploader.toString() !== req.user.id) {
            return res.status(401).json({ message: 'User not authorized' });
        }
        
        // Optional: Delete the actual files from the server's storage
        if (fs.existsSync(path.join(__dirname, '..', '..', mod.modFilePath))) fs.unlinkSync(path.join(__dirname, '..', '..', mod.modFilePath));
        if (fs.existsSync(path.join(__dirname, '..', '..', mod.iconPath))) fs.unlinkSync(path.join(__dirname, '..', '..', mod.iconPath));
        mod.screenshotPaths.forEach(p => {
             if (fs.existsSync(path.join(__dirname, '..', '..', p))) fs.unlinkSync(path.join(__dirname, '..', '..', p));
        });

        await mod.deleteOne(); // Use this Mongoose 6+ method
        
        res.json({ message: 'Mod removed successfully' });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
});

// Add PUT /api/mods/:id for editing mods here...

// ================== PUBLIC ROUTES (No Login Required) ==================

router.get('/homepage/:platform', async (req, res) => { /* ... (same as before) ... */ });
router.get('/featured/:platform', async (req, res) => { /* ... (same as before) ... */ });
router.get('/', async (req, res) => { /* ... (This is your main paginated /api/mods endpoint) ... */ });
router.get('/:id', async (req, res) => { /* ... (This is your /api/mods/:id for a single mod) ... */ });
router.get('/download/:id', async (req, res) => { /* ... (This is your /api/mods/download/:id) ... */ });

module.exports = router;