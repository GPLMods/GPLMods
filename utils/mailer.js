const axios = require('axios');

// --- VERIFICATION OTP EMAIL ---
exports.sendVerificationEmail = async (user) => {
    try {
        const otpCode = user.verificationOtp;

        const payload = {
            api_key: process.env.SMTP2GO_API_KEY,
            to: [user.email],
            sender: process.env.EMAIL_FROM,
            subject: 'Your GPL Mods Verification Code',
            text_body: `Your GPL Mods verification code is: ${otpCode}`,
            html_body: `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
                    <h2>Welcome to GPL Mods!</h2>
                    <p>Your verification code is below. Enter this code to complete your registration.</p>
                    <p style="font-size: 2.5em; font-weight: bold; letter-spacing: 5px; color: #FFD700;">${otpCode}</p>
                    <p>This code will expire in 10 minutes.</p>
                </div>
            `
        };

        await axios.post('https://api.smtp2go.com/v3/email/send', payload);
        console.log(`OTP email sent successfully to ${user.email}`);

    } catch (error) {
        console.error("SMTP2GO Verification Error:", error.response ? error.response.data : error.message);
    }
};

// --- PASSWORD RESET EMAIL ---
exports.sendPasswordResetEmail = async (user, resetURL) => {
    try {
        const payload = {
            api_key: process.env.SMTP2GO_API_KEY,
            to:[user.email],
            sender: process.env.EMAIL_FROM,
            subject: 'Your GPL Mods Password Reset Request',
            text_body: `A password reset was requested for your account. Visit the following link to reset it: ${resetURL}`,
            html_body: `
                <div style="font-family: Arial, sans-serif; text-align: center; padding: 20px;">
                    <h2>Password Reset Request</h2>
                    <p>You are receiving this email because a password reset was requested for your account at GPL Mods.</p>
                    <p>Please click the link below to set a new password. This link is valid for one hour.</p>
                    <a href="${resetURL}" style="display: inline-block; padding: 10px 20px; background-color: #FFD700; color: #0a0a0a; text-decoration: none; border-radius: 5px; font-weight: bold; margin-top: 15px;">Reset My Password</a>
                    <p style="margin-top: 20px; font-size: 0.9em; color: #888;">If you did not request a password reset, you can safely ignore this email.</p>
                </div>
            `
        };

        await axios.post('https://api.smtp2go.com/v3/email/send', payload);
        console.log(`Password reset email sent successfully to ${user.email}`);

    } catch (error) {
        console.error("SMTP2GO Password Reset Error:", error.response ? error.response.data : error.message);
    }
};