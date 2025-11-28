// ===================================================================
// API ROUTES for AUTHENTICATION (/api/auth)
// ===================================================================

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const User = require('../../models/User'); // Make sure this path is correct

// @route   POST /api/auth/register
// @desc    Register a new user and send verification email
router.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ message: "Please enter all fields." });
    }
    
    // Basic validation for email format and password length
    if (password.length < 6) {
        return res.status(400).json({ message: "Password must be at least 6 characters." });
    }
    
    const disallowedDomains = ['temp-mail.org', '10minutemail.com', 'mailinator.com']; // Add more temp mail services
    const emailDomain = email.split('@')[1];
    if (disallowedDomains.includes(emailDomain)) {
        return res.status(400).json({ message: "Temporary email services are not allowed." });
    }
    const allowedProviders = ['gmail.com', 'yahoo.com', 'icloud.com', 'outlook.com', 'hotmail.com'];
    if (!allowedProviders.includes(emailDomain)) {
        return res.status(400).json({ message: "Please use a valid email provider (Gmail, Yahoo, iCloud, Outlook)." });
    }

    try {
        if (await User.findOne({ email })) return res.status(400).json({ message: "User with this email already exists." });
        if (await User.findOne({ username })) return res.status(400).json({ message: "Username is already taken." });
        
        let user = new User({ username, email, password });

        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);
        
        const verificationToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1d' });
        user.emailVerificationToken = verificationToken;
        await user.save();

        const transporter = nodemailer.createTransport({
            service: 'gmail', // Ensure your .env is set up for this service
            auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
        });

        // Use your live Render URL here
        const verificationUrl = `https://gpl-mods-service.onrender.com/api/auth/verify-email?token=${verificationToken}`;
        
        await transporter.sendMail({
            from: `"GPL Mods" <${process.env.EMAIL_USER}>`,
            to: user.email,
            subject: 'Verify Your Email for GPL Mods',
            html: `<h3>Welcome to GPL Mods!</h3><p>Please click the following link to verify your email address:</p><p><a href="${verificationUrl}">${verificationUrl}</a></p><p>This link will expire in 24 hours.</p>`
        });
        
        res.status(201).json({ message: "Registration successful! Please check your email to activate your account." });

    } catch (err) {
        console.error("Registration Error:", err.message);
        res.status(500).send('Server error during registration.');
    }
});

// @route   GET /api/auth/verify-email
// @desc    Handle email verification from the link
router.get('/verify-email', async (req, res) => {
    try {
        const { token } = req.query;
        if (!token) return res.status(400).send('<h1>Error</h1><p>Verification token is missing.</p>');
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);

        if (!user) return res.status(400).send('<h1>Error</h1><p>Invalid token. User not found.</p>');
        if (user.isVerified) return res.redirect('/accounts/login-signup.html?message=Account already verified. Please log in.');

        user.isVerified = true;
        user.emailVerificationToken = undefined; // Clear the token
        await user.save();
        
        res.redirect('/accounts/login-signup.html?message=Email successfully verified! You can now log in.');
    } catch (err) {
        console.error("Verification Error:", err.message);
        res.status(400).send('<h1>Verification Failed</h1><p>The link may have expired or is invalid. Please try registering again.</p>');
    }
});

// @route   POST /api/auth/login
// @desc    Authenticate user and return a JWT
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Please enter all fields." });

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: "Invalid email or password." });
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: "Invalid email or password." });
        
        if (!user.isVerified) return res.status(401).json({ message: "Account not verified. Please check your email for the activation link." });

        const payload = { user: { id: user.id } }; // The "passport" data
        jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: '7d' }, (err, token) => {
            if (err) throw err;
            res.json({ token, username: user.username }); // Send back the token and username
        });
    } catch (err) {
        console.error("Login Error:", err.message);
        res.status(500).send('Server error during login.');
    }
});

module.exports = router;