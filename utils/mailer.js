const { MailerSend, EmailParams, Sender, Recipient } = require("mailersend");

// --- 1. CONFIGURATION ---

// Validate that required environment variables exist to prevent runtime crashes.
if (!process.env.MAILERSEND_API_KEY) {
    throw new Error("FATAL_ERROR: MAILERSEND_API_KEY is not defined.");
}
if (!process.env.EMAIL_FROM_ADDRESS) {
    throw new Error("FATAL_ERROR: EMAIL_FROM_ADDRESS is not defined.");
}
if (!process.env.EMAIL_FROM_NAME) {
    throw new Error("FATAL_ERROR: EMAIL_FROM_NAME is not defined.");
}

const mailersend = new MailerSend({
    apiKey: process.env.MAILERSEND_API_KEY,
});

// Create the sender object using separate environment variables for clarity
const sentFrom = new Sender(process.env.EMAIL_FROM_ADDRESS, process.env.EMAIL_FROM_NAME);

// Helper function to get the correct base URL for production (Render) or local development
const getBaseUrl = () => {
    return process.env.SITE_URL || `http://localhost:${process.env.PORT || 3000}`;
};

// --- 2. EMAIL FUNCTIONS ---

/**
 * Sends a verification email to a new user
 */
exports.sendVerificationEmail = async (user) => {
    const verificationUrl = `${getBaseUrl()}/verify-email?token=${user.verificationToken}`;
    const recipients = [new Recipient(user.email, user.username)];

    // The plain text content for email clients that don't render HTML
    const textContent = `Welcome to GPL Mods! Thank you for registering. Please copy and paste this link into your browser to verify your email address: ${verificationUrl}`;

    const emailParams = new EmailParams()
        .setFrom(sentFrom)
        .setTo(recipients)
        .setReplyTo(sentFrom) // Added Reply-To for better email deliverability
        .setSubject("Please Verify Your Email for GPL Mods")
        .setHtml(`
            <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <h2>Welcome to GPL Mods!</h2>
                <p>Thank you for registering. Please click the button below to verify your email address and activate your account:</p>
                <div style="margin: 30px 0;">
                    <a href="${verificationUrl}" target="_blank" style="display: inline-block; padding: 12px 24px; font-size: 16px; font-weight: bold; background-color: #FFD700; color: #0a0a0a; text-decoration: none; border-radius: 5px;">
                        Verify My Email
                    </a>
                </div>
                <p>If the button doesn't work, copy and paste this link into your browser:</p>
                <p style="font-size: 12px; color: #666;">${verificationUrl}</p>
                <p>If you did not register for an account, you can safely ignore this email.</p>
            </div>
        `)
        .setText(textContent); // Added plain text version for compatibility

    try {
        const response = await mailersend.email.send(emailParams);
        console.log(`Verification email sent to ${user.email}. Message ID: ${response.headers['x-message-id']}`);
    } catch (error) {
        logMailerSendError(error);
        // Re-throw so the calling function (like your Register route) knows it failed
        throw error;
    }
};

/**
 * Sends a password reset email
 */
exports.sendPasswordResetEmail = async (user, resetToken) => {
    const resetUrl = `${getBaseUrl()}/reset-password?token=${resetToken}`;
    const recipients = [new Recipient(user.email, user.username)];

    // The plain text content for the email
    const textContent = `Password Reset Request for GPL Mods. Please copy and paste this link into your browser to choose a new password: ${resetUrl}`;

    const emailParams = new EmailParams()
        .setFrom(sentFrom)
        .setTo(recipients)
        .setReplyTo(sentFrom) // Added Reply-To for better email deliverability
        .setSubject("Your Password Reset Request for GPL Mods")
        .setHtml(`
            <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <h2>Password Reset Request</h2>
                <p>You are receiving this email because you (or someone else) requested a password reset for your GPL Mods account.</p>
                <p>Please click the button below to choose a new password. This link will expire shortly:</p>
                <div style="margin: 30px 0;">
                    <a href="${resetUrl}" target="_blank" style="display: inline-block; padding: 12px 24px; font-size: 16px; font-weight: bold; background-color: #FFD700; color: #0a0a0a; text-decoration: none; border-radius: 5px;">
                        Reset My Password
                    </a>
                </div>
                <p>If you did not request this, please ignore this email and your password will remain unchanged.</p>
                <p style="font-size: 12px; color: #666;">Link: ${resetUrl}</p>
            </div>
        `)
        .setText(textContent); // Added plain text version for compatibility

    try {
        const response = await mailersend.email.send(emailParams);
        console.log(`Password reset email sent to ${user.email}. Message ID: ${response.headers['x-message-id']}`);
    } catch (error) {
        logMailerSendError(error);
        throw error;
    }
};

// --- 3. HELPER FUNCTIONS ---

/**
 * Safely logs MailerSend API errors without crashing the server
 */
function logMailerSendError(error) {
    console.error("\n--- MAILERSEND API ERROR ---");
    // MailerSend often returns errors in the .body property
    if (error.body) {
        console.error(JSON.stringify(error.body, null, 2));
    } else {
        console.error(error);
    }
    console.error("--------------------------\n");
}