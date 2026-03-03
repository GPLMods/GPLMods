const axios = require('axios');

exports.sendVerificationEmail = async (user) => {
    try {
        const otpCode = user.verificationOtp;

        const payload = {
            api_key: process.env.SMTP2GO_API_KEY,
            to: [user.email],
            sender: process.env.EMAIL_FROM, // Ensure this is a verified sender in SMTP2GO
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
        console.error("SMTP2GO Error:", error.response ? error.response.data : error.message);
    }
};