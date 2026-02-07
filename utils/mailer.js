const s2g = require('smtp2go-nodejs');

// --- 1. CONFIGURATION ---

// We use the API Key from our .env file.
// Ensure SMTP2GO_API_KEY and EMAIL_FROM are defined in your .env file.
if (!process.env.SMTP2GO_API_KEY) {
    throw new Error("FATAL_ERROR: SMTP2GO_API_KEY is not defined in your .env file.");
}
if (!process.env.EMAIL_FROM) {
    throw new Error("FATAL_ERROR: EMAIL_FROM is not defined in your .env file.");
}

s2g.setApiKey(process.env.SMTP2GO_API_KEY);

/**
 * Helper function to get the correct base URL for production or local development.
 * In your production environment (like Render, Vercel, etc.), set SITE_URL to 'https://gplmods.webredirect.org'.
 * @returns {string} The base URL for email links.
 */
const getBaseUrl = () => {
    return process.env.SITE_URL || `http://localhost:${process.env.PORT || 3000}`;
};


// --- 2. EMAIL FUNCTIONS ---

/**
 * Sends a user account verification email using SMTP2GO.
 * @param {object} user - The user object from your database, containing email and verificationToken.
 */
exports.sendVerificationEmail = async (user) => {
    const verificationUrl = `${getBaseUrl()}/verify-email?token=${user.verificationToken}`;

    const msg = {
        sender: process.env.EMAIL_FROM,
        to: [user.email], // Must be an array
        subject: 'Please Verify Your Email for GPL Mods',
        html_body: `
            <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <h2>Welcome to GPL Mods!</h2>
                <p>Thank you for registering. Please click the button below to verify your email address and activate your account:</p>
                <div style="margin: 30px 0;">
                    <a href="${verificationUrl}" target="_blank" style="display: inline-block; padding: 12px 24px; font-size: 16px; font-weight: bold; background-color: #FFD700; color: #0a0a0a; text-decoration: none; border-radius: 5px;">
                        Verify My Email
                    </a>
                </div>
                <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
                <p style="font-size: 12px; color: #666;">${verificationUrl}</p>
                <p>If you did not register for an account, please ignore this email.</p>
            </div>
        `,
        // It's good practice to include a plain text version for compatibility
        text_body: `Welcome to GPL Mods! Please visit the following link to verify your email: ${verificationUrl}`
    };
    
    try {
        const response = await s2g.send(msg);
        console.log(`Verification email sent successfully to ${user.email} via SMTP2GO!`);
        console.log("SMTP2GO Response:", response);
    } catch (error) {
        console.error("Error sending verification email via SMTP2GO:", error);
        // Re-throw the error so the calling function knows the email failed to send
        throw error;
    }
};


/**
 * Sends a password reset email using SMTP2GO.
 * @param {object} user - The user object from your database, containing the user's email.
 * @param {string} resetToken - The password reset token.
 */
exports.sendPasswordResetEmail = async (user, resetToken) => {
    const resetUrl = `${getBaseUrl()}/reset-password?token=${resetToken}`;

    const msg = {
        sender: process.env.EMAIL_FROM,
        to: [user.email], // Must be an array
        subject: 'Your GPL Mods Password Reset Request',
        html_body: `
            <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <h2>Password Reset Request</h2>
                <p>You are receiving this email because a password reset was requested for your account at GPL Mods.</p>
                <p>Please click the button below to set a new password. This link is valid for a limited time.</p>
                <div style="margin: 30px 0;">
                    <a href="${resetUrl}" target="_blank" style="display: inline-block; padding: 12px 24px; font-size: 16px; font-weight: bold; background-color: #FFD700; color: #0a0a0a; text-decoration: none; border-radius: 5px;">
                        Reset My Password
                    </a>
                </div>
                <p>If you did not request a password reset, you can safely ignore this email.</p>
                <p style="font-size: 12px; color: #666;">Link: ${resetUrl}</p>
            </div>
        `,
        text_body: `A password reset was requested for your account. Visit the following link to reset it: ${resetUrl}`
    };

    try {
        const response = await s2g.send(msg);
        console.log(`Password reset email sent successfully to ${user.email} via SMTP2GO!`);
        console.log("SMTP2GO Response:", response);
    } catch (error) {
        console.error("Error sending password reset email via SMTP2GO:", error);
        // Re-throw the error to ensure the calling process is aware of the failure
        throw error;
    }
};

// You can add more email functions here in the future as your application grows.