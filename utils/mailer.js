const s2g = require('smtp2go-nodejs');

// Create the options object with the API key to be used in every send call.
const options = {
    api_key: process.env.SMTP2GO_API_KEY
};

/**
 * Sends a 6-digit OTP for user account verification using SMTP2GO.
 * @param {object} user - The user object from your database.
 */
exports.sendVerificationEmail = async (user) => {
    try {
        // The OTP is generated elsewhere in the app; we just send it.
        const otpCode = user.verificationOtp;

        const msg = {
            sender: process.env.EMAIL_FROM,
            to: [user.email],
            subject: 'Your GPL Mods Verification Code',
            html_body: `
                <div style="font-family: Poppins, sans-serif; text-align: center; padding: 20px;">
                    <h2>Welcome to GPL Mods!</h2>
                    <p>Your verification code is below. Enter this code in your browser to complete your registration.</p>
                    <p style="font-size: 2.5em; font-weight: 600; letter-spacing: 5px; color: #FFD700; margin: 20px 0;">
                        ${otpCode}
                    </p>
                    <p>This code will expire in 10 minutes.</p>
                    <p style="color: #c0c0c0; font-size: 0.9em;">If you did not request this, you can safely ignore this email.</p>
                </div>
            `,
            text_body: `Your GPL Mods verification code is: ${otpCode}`
        };
        
        // Pass both the message and the options object to the send function.
        await s2g.send(msg, options);
        console.log(`OTP email sent to ${user.email} via SMTP2GO!`);
        
    } catch (error) {
        console.error("Error sending OTP email via SMTP2GO:", error);
    }
};


/**
 * Sends a password reset email using SMTP2GO.
 * @param {object} user - The user object from your database.
 * @param {string} resetURL - The full password reset URL with the token.
 */
exports.sendPasswordResetEmail = async (user, resetURL) => {
    try {
        const msg = {
            sender: process.env.EMAIL_FROM,
            to: [user.email],
            subject: 'Your GPL Mods Password Reset Request',
            html_body: `
                <h2>Password Reset Request</h2>
                <p>You are receiving this email because a password reset was requested for your account at GPL Mods.</p>
                <p>Please click the link below to set a new password. This link is valid for one hour.</p>
                <a href="${resetURL}" style="padding: 10px 15px; background-color: #FFD700; color: #0a0a0a; text-decoration: none; border-radius: 5px;">Reset My Password</a>
                <p>If you did not request a password reset, you can safely ignore this email.</p>
            `,
            text_body: `A password reset was requested for your account. Visit the following link to reset it: ${resetURL}`
        };

        // Pass both the message and the options object here as well.
        const response = await s2g.send(msg, options);
        console.log('Password reset email sent successfully via SMTP2GO!');
        console.log(response);

    } catch (error) {
        console.error("Error sending password reset email via SMTP2GO:", error);
    }
};