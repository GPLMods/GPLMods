const axios = require('axios');

/**
 * ============================================================================
 * MASTER EMAIL TEMPLATE
 * This helper function wraps all emails in your custom Dark/Gold branding.
 * ============================================================================
 */
const getBrandedEmailHtml = (content) => `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin: 0; padding: 0; background-color: #0a0a0a; font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; color: #f5f5f5; -webkit-font-smoothing: antialiased;">
    <table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="background-color: #0a0a0a; padding: 40px 20px;">
        <tr>
            <td align="center">
                <!-- Main Email Container -->
                <table width="100%" max-width="600" cellpadding="0" cellspacing="0" role="presentation" style="max-width: 600px; background-color: #1a1a1a; border-radius: 12px; border: 1px solid #333333; overflow: hidden;">
                    
                    <!-- Header Area -->
                    <tr>
                        <td align="center" style="padding: 35px 20px; background-color: #111111; border-bottom: 2px solid #FFD700;">
                            <!-- Optional: If you want to use your actual logo image, uncomment the line below and replace the URL -->
                            <!-- <img src="https://gplmods.webredirect.org/images/your-logo.png" alt="GPL Mods" style="height: 60px; display: block; margin-bottom: 10px;" /> -->
                            
                            <h1 style="margin: 0; color: #FFD700; font-size: 32px; letter-spacing: 2px; text-transform: uppercase; text-shadow: 0 0 15px rgba(255,215,0,0.3);">
                                GPL Mods
                            </h1>
                        </td>
                    </tr>
                    
                    <!-- Content Area -->
                    <tr>
                        <td style="padding: 40px 30px;">
                            ${content}
                        </td>
                    </tr>
                    
                    <!-- Footer Area -->
                    <tr>
                        <td align="center" style="padding: 25px; background-color: #111111; border-top: 1px solid #2a2a2a; font-size: 12px; color: #888888; line-height: 1.6;">
                            <p style="margin: 0 0 10px 0;">&copy; ${new Date().getFullYear()} GPL Mods. All rights reserved.</p>
                            <p style="margin: 0;">This is an automated security message, please do not reply directly to this email.</p>
                            <p style="margin: 15px 0 0 0;">
                                <a href="https://gplmods.webredirect.org" style="color: #FFD700; text-decoration: none; font-weight: bold;">Visit GPL Mods</a>
                            </p>
                        </td>
                    </tr>

                </table>
            </td>
        </tr>
    </table>
</body>
</html>
`;

// ============================================================================
// --- VERIFICATION OTP EMAIL ---
// ============================================================================
exports.sendVerificationEmail = async (user) => {
    try {
        const otpCode = user.verificationOtp;

        // The specific content for the Verification email
        const emailContent = `
            <h2 style="margin: 0 0 20px 0; color: #ffffff; font-size: 24px; text-align: center;">Welcome to the community!</h2>
            <p style="margin: 0 0 20px 0; color: #c0c0c0; font-size: 16px; line-height: 1.6; text-align: center;">
                Thank you for registering at GPL Mods. To complete your registration and secure your account, please enter the verification code below:
            </p>
            
            <!-- Styled OTP Box -->
            <div style="text-align: center; margin: 40px 0;">
                <span style="display: inline-block; padding: 20px 40px; background-color: #0a0a0a; border: 2px dashed #FFD700; color: #FFD700; font-size: 38px; font-weight: bold; letter-spacing: 12px; border-radius: 10px; box-shadow: 0 0 20px rgba(255,215,0,0.1);">
                    ${otpCode}
                </span>
            </div>
            
            <p style="margin: 0; color: #888888; font-size: 14px; text-align: center;">
                For security reasons, this code will expire in <strong>10 minutes</strong>.
            </p>
        `;

        const payload = {
            api_key: process.env.SMTP2GO_API_KEY,
            to: [user.email],
            sender: process.env.EMAIL_FROM,
            subject: 'Your GPL Mods Verification Code',
            text_body: `Welcome to GPL Mods! Your verification code is: ${otpCode}. This code expires in 10 minutes.`,
            html_body: getBrandedEmailHtml(emailContent) // Wrap content in the master template
        };

        await axios.post('https://api.smtp2go.com/v3/email/send', payload);
        console.log(`OTP email sent successfully to ${user.email}`);

    } catch (error) {
        console.error("SMTP2GO Verification Error:", error.response ? error.response.data : error.message);
    }
};

// ============================================================================
// --- PASSWORD RESET EMAIL ---
// ============================================================================
exports.sendPasswordResetEmail = async (user, resetURL) => {
    try {
        // The specific content for the Password Reset email
        const emailContent = `
            <h2 style="margin: 0 0 20px 0; color: #ffffff; font-size: 24px; text-align: center;">Password Reset Request</h2>
            <p style="margin: 0 0 25px 0; color: #c0c0c0; font-size: 16px; line-height: 1.6; text-align: center;">
                We received a request to reset the password for your GPL Mods account. If you made this request, please click the button below to securely set a new password.
            </p>
            
            <!-- Styled Call-to-Action Button -->
            <div style="text-align: center; margin: 40px 0;">
                <a href="${resetURL}" style="display: inline-block; padding: 16px 35px; background-color: #FFD700; color: #0a0a0a; text-decoration: none; border-radius: 30px; font-size: 16px; font-weight: bold; text-transform: uppercase;">
                    Reset My Password
                </a>
            </div>
            
            <p style="margin: 0; color: #888888; font-size: 14px; line-height: 1.6; text-align: center;">
                If you did not request this password reset, you can safely ignore this email. Your password will remain unchanged. This secure link is valid for <strong>1 hour</strong>.
            </p>
        `;

        const payload = {
            api_key: process.env.SMTP2GO_API_KEY,
            to: [user.email],
            sender: process.env.EMAIL_FROM,
            subject: 'Your GPL Mods Password Reset Request',
            text_body: `A password reset was requested for your GPL Mods account. Visit the following link to reset it: ${resetURL} (Valid for 1 hour). If you didn't request this, ignore this email.`,
            html_body: getBrandedEmailHtml(emailContent) // Wrap content in the master template
        };

        await axios.post('https://api.smtp2go.com/v3/email/send', payload);
        console.log(`Password reset email sent successfully to ${user.email}`);

    } catch (error) {
        console.error("SMTP2GO Password Reset Error:", error.response ? error.response.data : error.message);
    }
};