// routes/api/auth.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('../../models/User'); // We need to create this file next

// @route   POST /api/auth/register
// @desc    Register a new user and send verification email
router.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: "Please enter all fields." });
    }
    
    const disallowedDomains = ['temp-mail.org', '10minutemail.com'];
    if (disallowedDomains.includes(email.split('@')[1])) {
        return res.status(400).json({ message: "Temporary email services are not allowed." });
    }

    try {
        if (await User.findOne({ email })) return res.status(400).json({ message: "User with this email already exists." });
        if (await User.findOne({ username })) return res.status(400).json({ message: "Username is already taken." });
        
        const user = new User({ username, email, password });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        
        const verificationToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1d' });
        user.emailVerificationToken = verificationToken;
        await user.save();

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
        });
        const verificationUrl = `https://gpl-mods-service.onrender.com/api/auth/verify-email?token=${verificationToken}`;
        await transporter.sendMail({
            from: `"GPL Mods" <${process.env.EMAIL_USER}>`, to: user.email, subject: 'Verify Your Email for GPL Mods',
            html: `<h3>Welcome to GPL Mods!</h3><p>Please click the link below to verify your account:</p><a href="${verificationUrl}">${verificationUrl}</a>`
        });
        
        res.status(201).json({ message: "Registration successful! Please check your email to activate your account." });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error during registration.');
    }
});

// @route   GET /api/auth/verify-email
// @desc    Handle email verification from the link
router.get('/verify-email', async (req, res) => {
    try {
        const token = req.query.token;
        if (!token) return res.status(400).send('Verification token is missing.');
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);

        if (!user) return res.status(400).send('Invalid token. User not found.');
        if (user.isVerified) return res.redirect('/accounts/login-signup.html?message=Account already verified. Please log in.');

        user.isVerified = true;
        user.emailVerificationToken = undefined;
        await user.save();
        
        res.redirect('/accounts/login-signup.html?message=Email successfully verified! You can now log in.');
    } catch (err) {
        res.status(400).send('Email verification failed. The link may have expired or is invalid.');
    }
});

// @route   POST /api/auth/login
// @desc    Authenticate user and return a JWT
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Please enter all fields." });

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: "Invalid credentials." });
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: "Invalid credentials." });
        
        if (!user.isVerified) return res.status(401).json({ message: "Account not verified. Please check your email." });

        const payload = { user: { id: user.id } };
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' }, (err, token) => {
            if (err) throw err;
            res.json({ token });
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error during login.');
    }
});

module.exports = router;