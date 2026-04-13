const axios = require('axios');
const Subscriber = require('../models/subscriber');
const User = require('../models/user');
const NewsletterCampaign = require('../models/newsletterCampaign');

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
                        <td align="center" style="padding: 0; background-color: #111111; border-bottom: 2px solid #FFD700;">
                            <!-- The Wider Image Banner -->
                            <a href="https://gplmods.webredirect.org" target="_blank">
                                <img src="https://gplmods.webredirect.org/images/email-banner.png" alt="GPL Mods" style="display: block; width: 100%; max-width: 600px; height: auto; border: 0;" />
                            </a>
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
/**
 * Background process to handle sending mass emails safely.
 */
exports.processNewsletterCampaign = async (campaignId) => {
    try {
        const campaign = await NewsletterCampaign.findById(campaignId);
        if (!campaign || campaign.status !== 'sending') return;

        console.log(`[NEWSLETTER] Starting campaign: ${campaign.subject}`);

        // 1. Gather the Audience
        let targetEmails = [];
        
        if (campaign.audience === 'test-admin-only') {
            // Find all admins and send to them
            const admins = await User.find({ role: 'admin' });
            targetEmails = admins.map(admin => admin.email);
        } 
        else if (campaign.audience === 'all-subscribers') {
            const subs = await Subscriber.find({ isSubscribed: true });
            targetEmails = subs.map(sub => sub.email);
        }
        else if (campaign.audience === 'premium-only') {
            const premiumUsers = await User.find({ membership: 'premium' });
            targetEmails = premiumUsers.map(user => user.email);
        }
        // Add other audience logic as needed...

        if (targetEmails.length === 0) {
            campaign.status = 'failed';
            campaign.adminNotes = 'No valid email addresses found for the selected audience.';
            await campaign.save();
            return;
        }

        // 2. Select the Template and Build the HTML
        let emailHtml = '';
        const baseStyle = `font-family: 'Arial', sans-serif; background-color: #0a0a0a; color: #f5f5f5; padding: 30px; border-radius: 10px; max-width: 600px; margin: 0 auto; border-top: 4px solid #FFD700;`;
        const btnStyle = `display: inline-block; background-color: #FFD700; color: #0a0a0a; padding: 12px 25px; text-decoration: none; font-weight: bold; border-radius: 25px; margin-top: 20px;`;

        if (campaign.template === 'new-mod-alert') {
            emailHtml = `
                <div style="${baseStyle}">
                    <h2 style="color: #FFD700; text-align: center;">🚀 New Mod Alert!</h2>
                    <div style="font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                        ${campaign.content}
                    </div>
                    ${campaign.callToActionUrl ? `<div style="text-align: center;"><a href="${campaign.callToActionUrl}" style="${btnStyle}">${campaign.callToActionText}</a></div>` : ''}
                </div>
            `;
        } 
        else if (campaign.template === 'special-announcement') {
            emailHtml = `
                <div style="${baseStyle} border-top-color: #2196F3;">
                    <h2 style="color: #2196F3; text-align: center;">📢 Important Announcement</h2>
                    <div style="font-size: 16px; line-height: 1.6; margin-bottom: 20px; background: #1a1a1a; padding: 20px; border-radius: 8px; border-left: 3px solid #2196F3;">
                        ${campaign.content}
                    </div>
                    ${campaign.callToActionUrl ? `<div style="text-align: center;"><a href="${campaign.callToActionUrl}" style="${btnStyle}">${campaign.callToActionText}</a></div>` : ''}
                </div>
            `;
        }
        else { // standard-update
            emailHtml = `
                <div style="${baseStyle}">
                    <h2 style="color: #ffffff; text-align: center;">GPL Mods Update</h2>
                    <div style="font-size: 16px; line-height: 1.6; margin-bottom: 20px;">
                        ${campaign.content}
                    </div>
                    ${campaign.callToActionUrl ? `<div style="text-align: center;"><a href="${campaign.callToActionUrl}" style="${btnStyle}">${campaign.callToActionText}</a></div>` : ''}
                </div>
            `;
        }

        // Add an Unsubscribe footer
        const unsubscribeUrl = `https://gplmods.webredirect.org/unsubscribe`; // You would build this route later
        emailHtml += `
            <div style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #333; font-size: 12px; color: #888;">
                You received this because you subscribed to updates from GPL Mods.<br>
                <a href="${unsubscribeUrl}" style="color: #888; text-decoration: underline;">Unsubscribe</a>
            </div>
        `;

        // 3. Send the Emails in Batches (to respect SMTP limits)
        let successCount = 0;
        
        // NOTE: For massive lists (10k+), you MUST use an email provider's "Bulk/List Send" API endpoint,
        // rather than looping and sending individually like this. 
        // For SMTP2GO with smaller lists (a few hundred), this loop is okay.
        for (const email of targetEmails) {
            try {
                const msg = {
                    sender: process.env.EMAIL_FROM,
                    to: [email],
                    subject: campaign.subject,
                    html_body: emailHtml,
                    text_body: `GPL Mods Update:\n\n${campaign.content.replace(/<[^>]+>/g, '')}\n\n${campaign.callToActionUrl || ''}`
                };
                
                await s2g.send(msg, options);
                successCount++;
                
                // Small delay to prevent rate-limiting (e.g., 50ms)
                await new Promise(resolve => setTimeout(resolve, 50)); 
                
            } catch (sendErr) {
                console.error(`Failed to send newsletter to ${email}:`, sendErr);
            }
        }

        // 4. Update the campaign status
        campaign.status = 'sent';
        campaign.sentCount = successCount;
        await campaign.save();

        console.log(`[NEWSLETTER] Campaign finished. Sent ${successCount}/${targetEmails.length} emails.`);

    } catch (error) {
        console.error("[NEWSLETTER] Critical error processing campaign:", error);
        // Attempt to mark as failed
        try {
            await NewsletterCampaign.findByIdAndUpdate(campaignId, { status: 'failed', adminNotes: error.message });
        } catch (e) {}
    }
};