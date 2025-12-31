// utils/mailer.js
const { MailerSend, EmailParams, Sender, Recipient } = require("mailersend");

// --- 1. CONFIGURATION AND VALIDATION (No Changes Needed) ---

// Validate that the API key exists. If not, stop the application.
if (!process.env.MAILERSEND_API_KEY) {
    throw new Error("FATAL_ERROR: MAILERSEND_API_KEY is not defined in your .env file.");
}
if (!process.env.EMAIL_FROM) {
    throw new Error("FATAL_ERROR: EMAIL_FROM is not defined in your .env file.");
}

// Initialize the MailerSend client.
const mailersend = new MailerSend({
    apiKey: process.env.MAILERSEND_API_KEY,
});

// Define the reusable sender object from your verified domain.
const sentFrom = new Sender(process.env.EMAIL_FROM, "GPL Mods Team");

// --- 2. VERIFICATION EMAIL FUNCTION (Your existing code, unchanged) ---

exports.sendVerificationEmail = async (user) => {
    // Construct the unique verification URL.
    const verificationUrl = `http://localhost:${process.env.PORT || 3000}/verify-email?token=${user.verificationToken}`;

    // Define recipients.
    const recipients = [ new Recipient(user.email, user.username) ];

    // Define the email payload.
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
                <hr>
                <p style="font-size: 0.8em; color: #888;">If you're having trouble, copy and paste this URL into your browser:<br>${verificationUrl}</p>
            </div>
        `);

    // Send the email and handle logging.
    try {
        const response = await mailersend.email.send(emailParams);
        console.log(`Verification email sent to ${user.email}. Message ID: ${response.headers['x-message-id']}`);
    } catch (error) {
        logMailerSendError(error);
    }
};

// --- 3. PASSWORD RESET EMAIL FUNCTION (New addition for future use) ---

exports.sendPasswordResetEmail = async (user, resetToken) => {
    // Construct the unique password reset URL.
    const resetUrl = `http://localhost:${process.env.PORT || 3000}/reset-password?token=${resetToken}`;
    
    // Define recipients.
    const recipients = [ new Recipient(user.email, user.username) ];

    // Define the email payload.
    const emailParams = new EmailParams()
        .setFrom(sentFrom)
        .setTo(recipients)
        .setSubject("Your Password Reset Request for GPL Mods")
        .setHtml(`
             <div style="font-family: Arial, sans-serif; line-height: 1.6;">
                <h2>Password Reset Request</h2>
                <p>We received a request to reset the password for your account. Please click the button below to set a new password:</p>
                <a href="${resetUrl}" target="_blank" style="display: inline-block; padding: 12px 24px; margin: 20px 0; font-size: 16px; font-weight: bold; background-color: #FFD700; color: #0a0a0a; text-decoration: none; border-radius: 5px;">
                    Reset Password
                </a>
                <p>This password reset link will expire in 1 hour.</p>
                <p>If you did not request a password reset, you can safely ignore this email. No changes will be made to your account.</p>
            </div>
        `);

    // Send the email and handle logging.
    try {
        const response = await mailersend.email.send(emailParams);
        console.log(`Password reset email sent to ${user.email}. Message ID: ${response.headers['x-message-id']}`);
    } catch (error) {
        logMailerSendError(error);
    }
};

// --- 4. HELPER FUNCTION (To avoid code duplication) ---

// Centralized error logger.
function logMailerSendError(error) {
    console.error("\n--- MAILERSEND API ERROR ---");
    // MailerSend SDK stores detailed errors in error.body
    if (error.body && error.body.errors) {
        error.body.errors.forEach(err => console.error("Message:", err.message));
    } else {
         console.error("Full Error:", error);
    }
    console.error("--------------------------\n");
}