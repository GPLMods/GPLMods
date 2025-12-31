// utils/mailer.js
const { MailerSend, EmailParams, Sender, Recipient } = require("mailersend");

// 1. Validate API Key and Initialize MailerSend
if (!process.env.MAILERSEND_API_KEY) {
    throw new Error("FATAL_ERROR: MAILERSEND_API_KEY is not defined in your .env file.");
}
const mailersend = new MailerSend({
    apiKey: process.env.MAILERSEND_API_KEY,
});

// 2. Define the "from" address (Sender)
const sentFrom = new Sender(process.env.EMAIL_FROM, "GPL Mods Team");

// 3. The Main Function to Send the Verification Email (Refactored)
exports.sendVerificationEmail = async (user) => {
    // Construct the unique verification URL for the user.
    const verificationUrl = `http://localhost:${process.env.PORT || 3000}/verify-email?token=${user.verificationToken}`;

    // Define the recipient of the email.
    const recipients = [
        new Recipient(user.email, user.username)
    ];

    // Build the email's parameters using the official SDK's builder pattern.
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
                <p style="font-size: 0.8em; color: #888;">If you're having trouble with the button, copy and paste this URL into your browser:<br>${verificationUrl}</p>
            </div>
        `);

    try {
        console.log("Attempting to send verification email via MailerSend...");
        const response = await mailersend.email.send(emailParams);
        console.log("Email sent successfully via MailerSend!");
        console.log("Message ID:", response.headers['x-message-id']);
    } catch (error) {
        console.error("\n--- MAILERSEND API ERROR ---");
        console.error("Status Code:", error.statusCode);
        console.error("Error Body:", error.body);
        console.error("--------------------------\n");
    }
};