const nodemailer = require('nodemailer');

// This function creates a test account on Ethereal for us.
// In a real application, you'd have these credentials in your .env file from a service like SendGrid.
async function getTestAccountInfo() {
    let testAccount = await nodemailer.createTestAccount();
    console.log("=========================================");
    console.log("ETHEREAL EMAIL TEST ACCOUNT - USE FOR .ENV");
    console.log("USER:", testAccount.user);
    console.log("PASS:", testAccount.pass);
    console.log("=========================================");
    process.env.EMAIL_USER = testAccount.user;
    process.env.EMAIL_PASS = testAccount.pass;
}

// Initialize the mailer setup when the application starts
getTestAccountInfo();

const transporter = () => nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: parseInt(process.env.EMAIL_PORT),
    secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

exports.sendVerificationEmail = async (user) => {
    const verificationUrl = `http://localhost:${process.env.PORT}/verify-email?token=${user.verificationToken}`;

    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: user.email,
        subject: 'Please Verify Your Email for GPL Mods',
        html: `
            <h2>Welcome to GPL Mods!</h2>
            <p>Thank you for registering. Please click the link below to verify your email address:</p>
            <a href="${verificationUrl}" style="padding: 10px 15px; background-color: #FFD700; color: #0a0a0a; text-decoration: none; border-radius: 5px;">Verify My Email</a>
            <p>If you did not register for an account, please ignore this email.</p>
        `,
    };
    
    let emailTransporter = transporter();
    let info = await emailTransporter.sendMail(mailOptions);
    
    console.log('Verification email sent: %s', info.messageId);
    // Preview only available when sending through an Ethereal account
    console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
};```

---

### **Step 5: Integrate Email Logic into `server.js`**

Now, we will modify the registration and login routes to use our new verification system.

**1. Add New Imports at the Top of `server.js`:**
```javascript
// ... after other imports
const jwt = require('jsonwebtoken');
const { sendVerificationEmail } = require('./utils/mailer');