const s2g = require('smtp2go-nodejs');

// We will create the options object that will be used in every send call.
// This is the new, correct way to provide the API key.
const options = {
    api_key: process.env.SMTP2GO_API_KEY
};


/**
 * Sends a user account verification email using SMTP2GO.
 * @param {object} user - The user object from your database.
 */
exports.sendVerificationEmail = async (user) => {
    try {
        const verificationUrl = `http://localhost:${process.env.PORT || 3000}/verify-email?token=${user.verificationToken}`; // NOTE: You'll want to change localhost to your live URL

        const msg = {
            sender: process.env.EMAIL_FROM,
            to: [user.email],
            subject: 'Please Verify Your Email for GPL Mods',
            html_body: `
                <h2>Welcome to GPL Mods!</h2>
                <p>Thank you for registering. Please click the link below to verify your email address:</p>
                <a href="${verificationUrl}" style="padding: 10px 15px; background-color: #FFD700; color: #0a0a0a; text-decoration: none; border-radius: 5px;">Verify My Email</a>
                <p>If you did not register for an account, please ignore this email.</p>
            `,
            text_body: `Welcome to GPL Mods! Please visit the following link to verify your email: ${verificationUrl}`
        };
        
        // Pass BOTH the message AND the options object to the send function.
        const response = await s2g.send(msg, options);
        console.log('Verification email sent successfully via SMTP2GO!');
        console.log(response);

    } catch (error) {
        console.error("Error sending email via SMTP2GO:", error);
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

        // Pass BOTH the message AND the options object here as well.
        const response = await s2g.send(msg, options);
        console.log('Password reset email sent successfully via SMTP2GO!');
        console.log(response);

    } catch (error) {
        console.error("Error sending password reset email via SMTP2GO:", error);
    }
};