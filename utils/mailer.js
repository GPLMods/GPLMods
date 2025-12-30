const { MailerSend, EmailParams, Sender, Recipient } = require("mailersend");

// 1. Initialize MailerSend with the API key from your .env file
const mailersend = new MailerSend({
    apiKey: process.env.MAILERSEND_API_KEY,
});

// 2. Define the "from" address using a Sender object
// The email address MUST be from a domain you have verified in MailerSend.
const sentFrom = new Sender(process.env.EMAIL_FROM, "GPL Mods Team");

// 3. The main function to send the verification email
exports.sendVerificationEmail = async (user) => {
    try {
        const verificationUrl = `http://localhost:${process.env.PORT || 3000}/verify-email?token=${user.verificationToken}`;

        // Create the recipient object
        const recipients = [
            new Recipient(user.email, user.username)
        ];

        // Create the email parameters
        const emailParams = new EmailParams()
            .setFrom(sentFrom)
            .setTo(recipients)
            .setSubject("Please Verify Your Email for GPL Mods")
            .setHtml(`
                <h2>Welcome to GPL Mods!</h2>
                <p>Thank you for registering. Please click the link below to verify your email address:</p>
                <a href="${verificationUrl}" style="padding: 10px 15px; background-color: #FFD700; color: #0a0a0a; text-decoration: none; border-radius: 5px;">Verify My Email</a>
                <p>If you did not register for an account, please ignore this email.</p>
            `);
        
        // Use the MailerSend SDK to send the email
        const { body, statusCode } = await mailersend.email.send(emailParams);

        console.log(`Email sent successfully via MailerSend! Status Code: ${statusCode}`);
        console.log('Response Body:', body);

    } catch (error) {
        console.error("Error sending email via MailerSend:", error.body);
    }
};