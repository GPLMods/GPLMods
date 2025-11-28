const express = require('express');
const router = express.Router();
const authMiddleware = require('../../middleware/auth');
const User = require('../../models/User');
const Mod = require('../../models/Mod');

// @route   GET /api/users/me
// @desc    Get the logged-in user's profile
router.get('/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        const mods = await Mod.find({ uploader: req.user.id }).sort({ createdAt: -1 });
        const totalDownloads = mods.reduce((acc, mod) => acc + mod.downloads, 0);

        res.json({ user, mods, totalDownloads });
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

// @route   GET /api/users/:username
// @desc    Get a public user profile by username
router.get('/:username', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.params.username }).select('-password');
        if (!user) return res.status(404).json({ message: "User not found." });

        const mods = await Mod.find({ uploader: user.id, status: 'live' }).sort({ createdAt: -1 });
        const totalDownloads = mods.reduce((acc, mod) => acc + mod.downloads, 0);

        res.json({ user, mods, totalDownloads });
    } catch (err) {
        res.status(500).send('Server Error');
    }
});

// Add PUT (update) and DELETE routes here later

module.exports = router;