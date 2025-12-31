const { MailerSend, EmailParams, Sender, Recipient } = require("mailer send");

// --- 1. CONFIGURATION (No changes needed) ---

// Validate that environment variables exist.
if (!process.env.MAILERSEND_API_KEY) {
    throw new Error("FATAL_ERROR: MAILERSEND_API_KEY is not defined in your environment variables.");
}
if (!process.env.EMAIL_FROM) {
    throw new Error("FATAL_ERROR: EMAIL_FROM is not defined in your environment variables.");
}
if (!process.env.SITE_URL) {
    // Add this to your .env on Render: SITE_URL="https://gplmods.onrender.com"
    console.warn("WARNING: SITE_URL is not defined. Email links will default to localhost.");
}


const mailersend = new MailerSend({
    apiKey: process.env.MAILERSEND_API_KEY,
});

const sentFrom = new Sender(process.env.EMAIL_FROM, "GPL Mods Team");

// A helper function to get the correct base URL for production or development
const getBaseUrl = () => {
    return process.env.SITE_URL || `http://localhost:${process.env.PORT || 3000}`;
}


// --- 2. VERIFICATION EMAIL FUNCTION (Error handling is updated) ---

exports.sendVerificationEmail = async (user) => {
    const verificationUrl = `${getBaseUrl()}/verify-email?token=${user.verificationToken}`;
    const recipients = [ new Recipient(user.email, user.username) ];

    const emailParams = new EmailParams()
        .setFrom(sentFrom)
        .setTo(recipients)
        .setSubject("Please Verify Your Email for GPL Mods")
        .setHtml(`
            <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                <h2>Welcome to GPL Mods!</h2>
                <p>Thank you for registering. Please click the button below to verify your email address and activate your account:</p>
                <a href="${verificationUrl}" target="_blank" style="display: inline-block; padding: 12px 24px; margin: 20px 0; font-size: 16px; font-weight: bold; background-color: #FFD700; color: #0a0a0a; text-decoration: none; border-radius: 5px;">
                    Verify My Email
                </a>
                <p>If you did not register for an account on GPL Mods, you can safely ignore this email.</p>
            </div>
        `);

    try {
        const response = await mailersend.email.send(emailParams);
        console.log(`Verification email sent to ${user.email}. Message ID: ${response.headers['x-message-id']}`);
    } catch (error) {
        logMailerSendError(error);
        // --- CHANGED: Re-throw the error so server.js knows it failed. ---
        throw error;
    }
};

// --- 3. PASSWORD RESET EMAIL FUNCTION (Error handling is updated) ---

exports.sendPasswordResetEmail = async (user, resetToken) => {
    const resetUrl = `${getBaseUrl()}/reset-password?token=${resetToken}`;
    const recipients = [ new Recipient(user.email, user.username) ];

    const emailParams = new EmailParams()
        .setFrom(sentFrom)
        .setTo(recipients)
        .setSubject("Your Password Reset Request for GPL Mods")
        .setHtml(/* ... your email HTML ... */);

    try {
        const response = await mailersend.email.send(emailParams);
        console.log(`Password reset email sent to ${user.email}. Message ID: ${response.headers['x-message-id']}`);
    } catch (error) {
        logMailerSendError(error);
        // --- CHANGED: Re-throw the error so the caller function knows it failed. ---
        throw error;
    }
};

// --- 4. HELPER FUNCTION (This is the corrected part) ---

// --- CHANGED: A safer, more robust error logger ---
function logMailerSendError(error) {
    console.error("\n--- MAILERSEND API ERROR ---");
    // This safely logs WHATEVER error MailerSend returns, without crashing.
    console.error(error.body || error);
    console.error("--------------------------\n");
}