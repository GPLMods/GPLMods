const axios = require('axios');
const Subscriber = require('../../models/subscriber');
const User = require('../../models/user');
const NewsletterCampaign = require('../../models/newsletterCampaign');
const { reserveApiQuotaSet, releaseApiQuotaSet, disableApiQuotaOnError } = require('../apiQuota');

async function sendSmtpEmail(payload) {
    const quota = await reserveApiQuotaSet('smtp2go', 'emails', 1, ['hourly', 'daily', 'monthly']);
    if (!quota.allowed) throw new Error(`SMTP2GO quota unavailable: ${quota.reason}`);

    try {
        await axios.post('https://api.smtp2go.com/v3/email/send', payload);
    } catch (error) {
        await releaseApiQuotaSet(quota.reservations);
        await Promise.all([
            disableApiQuotaOnError('smtp2go', 'hourly', error, 'emails'),
            disableApiQuotaOnError('smtp2go', 'daily', error, 'emails'),
            disableApiQuotaOnError('smtp2go', 'monthly', error, 'emails')
        ]);
        throw error;
    }
}

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
                <table width="100%" max-width="600" cellpadding="0" cellspacing="0" role="presentation" style="max-width: 600px; background-color: #1a1a1a; border-radius: 12px; border: 1px solid #333333; overflow: hidden;">
                    <tr>
                        <td align="center" style="padding: 0; background-color: #111111; border-bottom: 2px solid #FFD700;">
                            <a href="https://gplmods.webredirect.org" target="_blank">
                                <img src="https://gplmods.webredirect.org/images/email-banner.png" alt="GPL Mods" style="display: block; width: 100%; max-width: 600px; height: auto; border: 0;" />
                            </a>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 40px 30px;">
                            ${content}
                        </td>
                    </tr>
                    <tr>
                        <td align="center" style="padding: 25px 30px; background-color: #111111; border-top: 1px solid #2a2a2a; font-size: 12px; color: #888888; line-height: 1.6;">
                            <!-- Professional Brand Icons (1. Gravatar, 2. Globe, 3. GitHub) -->
                            <table cellpadding="0" cellspacing="0" border="0" role="presentation" style="margin: 0 auto 16px auto;">
                                <tr>
                                    <td align="center" style="padding: 0 10px;">
                                        <a href="https://gravatar.com" target="_blank" title="Gravatar" style="text-decoration: none; display: inline-block;">
                                            <img src="https://gplmods.webredirect.org/images/mail-icons/gravatar.png" alt="Gravatar" width="24" height="24" style="display: block; width: 24px; height: 24px; border: 0; border-radius: 50%; opacity: 0.85;" />
                                        </a>
                                    </td>
                                    <td align="center" style="padding: 0 10px;">
                                        <a href="https://gplmods.webredirect.org" target="_blank" title="GPL Mods Official Site" style="text-decoration: none; display: inline-block;">
                                            <img src="https://gplmods.webredirect.org/images/mail-icons/globe.png" alt="Official Website" width="24" height="24" style="display: block; width: 24px; height: 24px; border: 0; opacity: 0.85;" />
                                        </a>
                                    </td>
                                    <td align="center" style="padding: 0 10px;">
                                        <a href="https://github.com/GPLMods-Team" target="_blank" title="GPL Mods GitHub" style="text-decoration: none; display: inline-block;">
                                            <img src="https://gplmods.webredirect.org/images/mail-icons/github.png" alt="GitHub" width="24" height="24" style="display: block; width: 24px; height: 24px; border: 0; opacity: 0.85;" />
                                        </a>
                                    </td>
                                </tr>
                            </table>

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

exports.sendVerificationEmail = async (user) => {
    try {
        const otpCode = user.verificationOtp;
        const emailContent = `
            <h2 style="margin: 0 0 20px 0; color: #ffffff; font-size: 24px; text-align: center;">Welcome to the community!</h2>
            <p style="margin: 0 0 20px 0; color: #c0c0c0; font-size: 16px; line-height: 1.6; text-align: center;">
                Thank you for registering at GPL Mods. To complete your registration and secure your account, please enter the verification code below:
            </p>
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
            html_body: getBrandedEmailHtml(emailContent)
        };

        await sendSmtpEmail(payload);
        console.log(`OTP email sent successfully to ${user.email}`);
    } catch (error) {
        console.error("SMTP2GO Verification Error:", error.response ? error.response.data : error.message);
    }
};

exports.sendPasswordResetEmail = async (user, resetURL) => {
    try {
        const emailContent = `
            <h2 style="margin: 0 0 20px 0; color: #ffffff; font-size: 24px; text-align: center;">Password Reset Request</h2>
            <p style="margin: 0 0 25px 0; color: #c0c0c0; font-size: 16px; line-height: 1.6; text-align: center;">
                We received a request to reset the password for your GPL Mods account. If you made this request, please click the button below to securely set a new password.
            </p>
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
            html_body: getBrandedEmailHtml(emailContent)
        };

        await sendSmtpEmail(payload);
        console.log(`Password reset email sent successfully to ${user.email}`);
    } catch (error) {
        console.error("SMTP2GO Password Reset Error:", error.response ? error.response.data : error.message);
    }
};

exports.sendLoginAlertEmail = async (user, deviceInfo, ipAddress, token, req) => {
    try {
        const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
        const acceptUrl = `${baseUrl}/security/login/accept/${encodeURIComponent(token)}`;
        const denyUrl = `${baseUrl}/security/login/deny/${encodeURIComponent(token)}`;
        const emailContent = `
            <h2 style="margin: 0 0 20px 0; color: #ffffff; font-size: 24px; text-align: center;">New Login Detected</h2>
            <p style="color: #c0c0c0; font-size: 16px; line-height: 1.6;">Hi <strong>${user.username}</strong>, we noticed a new login to your GPL Mods account.</p>
            <p style="color: #c0c0c0; line-height: 1.6;"><strong>Device:</strong> ${deviceInfo}<br><strong>IP address:</strong> ${ipAddress}<br><strong>Time:</strong> ${new Date().toLocaleString()}</p>
            <div style="text-align: center; margin: 35px 0;">
                <a href="${acceptUrl}" style="display: inline-block; padding: 13px 22px; background: #43a047; color: #fff; text-decoration: none; border-radius: 6px; font-weight: bold; margin-right: 8px;">It was me</a>
                <a href="${denyUrl}" style="display: inline-block; padding: 13px 22px; background: #e53935; color: #fff; text-decoration: none; border-radius: 6px; font-weight: bold;">Not me</a>
            </div>
            <p style="color: #888; font-size: 14px; line-height: 1.6; text-align: center;">
                If you did not sign in, deny this session and change your password immediately.<br>
                This security confirmation link is valid for <strong>1 hour</strong>. You can also change your response within that hour.
            </p>
        `;
        await sendSmtpEmail({
            api_key: process.env.SMTP2GO_API_KEY,
            to: [user.email],
            sender: process.env.EMAIL_FROM,
            subject: 'New Login to your GPL Mods Account',
            text_body: `New login from ${deviceInfo} (${ipAddress}). Confirm: ${acceptUrl} | Deny: ${denyUrl} (Links valid for 1 hour).`,
            html_body: getBrandedEmailHtml(emailContent)
        });
    } catch (error) {
        console.error('SMTP2GO Login Alert Error:', error.response ? error.response.data : error.message);
    }
};

exports.sendFailedAttemptEmail = async (user, req) => {
    try {
        const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
        const resetUrl = `${baseUrl}/forgot-password`;
        const emailContent = `
            <h2 style="margin: 0 0 20px 0; color: #e53935; font-size: 24px; text-align: center;">Security Alert</h2>
            <p style="color: #c0c0c0; font-size: 16px; line-height: 1.6;">Hi <strong>${user.username}</strong>, someone recently attempted to log in to your account with an incorrect password five times.</p>
            <div style="text-align: center; margin: 35px 0;"><a href="${resetUrl}" style="display: inline-block; padding: 14px 25px; background: #FFD700; color: #0a0a0a; text-decoration: none; border-radius: 6px; font-weight: bold;">Reset My Password</a></div>
        `;
        await sendSmtpEmail({
            api_key: process.env.SMTP2GO_API_KEY,
            to: [user.email],
            sender: process.env.EMAIL_FROM,
            subject: 'SECURITY ALERT: Failed Login Attempts',
            text_body: `Security alert: five failed login attempts on your account. Reset your password here: ${resetUrl}`,
            html_body: getBrandedEmailHtml(emailContent)
        });
    } catch (error) {
        console.error('SMTP2GO Failed Attempt Error:', error.response ? error.response.data : error.message);
    }
};

exports.sendDeletionOtpEmail = async (user, otp) => {
    try {
        const emailContent = `
            <h2 style="margin: 0 0 20px 0; color: #e53935; font-size: 24px; text-align: center;">Account Deletion Request</h2>
            <p style="margin: 0 0 20px 0; color: #c0c0c0; font-size: 16px; line-height: 1.6; text-align: center;">
                Hi <strong>${user.username}</strong>, we received a request to permanently delete your GPL Mods account. If you initiated this, please enter the confirmation code below. <strong style="color: #e53935;">This action is permanent and irreversible.</strong>
            </p>
            <div style="text-align: center; margin: 40px 0;">
                <span style="display: inline-block; padding: 20px 40px; background-color: #0a0a0a; border: 2px dashed #e53935; color: #e53935; font-size: 38px; font-weight: bold; letter-spacing: 12px; border-radius: 10px; box-shadow: 0 0 20px rgba(229,57,53,0.2);">
                    ${otp}
                </span>
            </div>
            <p style="margin: 0; color: #888888; font-size: 14px; text-align: center;">
                For security reasons, this code will expire in <strong>10 minutes</strong>. If you did not request this deletion, please secure your account immediately.
            </p>
        `;

        const payload = {
            api_key: process.env.SMTP2GO_API_KEY,
            to: [user.email],
            sender: process.env.EMAIL_FROM,
            subject: 'GPL Mods - Account Deletion Confirmation Code',
            text_body: `Your account deletion code is: ${otp}. This code expires in 10 minutes. If you did not request this, please change your password immediately.`,
            html_body: getBrandedEmailHtml(emailContent)
        };

        await sendSmtpEmail(payload);
        console.log(`Deletion OTP email sent successfully to ${user.email}`);
    } catch (error) {
        console.error("SMTP2GO Deletion OTP Error:", error.response ? error.response.data : error.message);
    }
};

exports.send2faEmail = async (user, otp) => {
    try {
        const emailContent = `
            <h2 style="margin: 0 0 20px 0; color: #ffffff; font-size: 24px; text-align: center;">Your 2FA Security Code</h2>
            <p style="margin: 0 0 20px 0; color: #c0c0c0; font-size: 16px; line-height: 1.6; text-align: center;">
                Please enter the security verification code below to complete your login securely:
            </p>
            <div style="text-align: center; margin: 40px 0;">
                <span style="display: inline-block; padding: 20px 40px; background-color: #0a0a0a; border: 2px dashed #FFD700; color: #FFD700; font-size: 38px; font-weight: bold; letter-spacing: 12px; border-radius: 10px; box-shadow: 0 0 20px rgba(255,215,0,0.1);">
                    ${otp}
                </span>
            </div>
            <p style="margin: 0; color: #888888; font-size: 14px; text-align: center;">
                This security code is valid for <strong>10 minutes</strong>.
            </p>
        `;

        const payload = {
            api_key: process.env.SMTP2GO_API_KEY,
            to: [user.email],
            sender: process.env.EMAIL_FROM,
            subject: 'GPL Mods - Your Login Code',
            text_body: `Your 2FA login code is: ${otp}. Valid for 10 minutes.`,
            html_body: getBrandedEmailHtml(emailContent)
        };

        await sendSmtpEmail(payload);
        console.log(`2FA OTP email sent successfully to ${user.email}`);
    } catch (error) {
        console.error("SMTP2GO 2FA Error:", error.response ? error.response.data : error.message);
    }
};

exports.processNewsletterCampaign = async (campaignId) => {
    try {
        const campaign = await NewsletterCampaign.findById(campaignId);
        if (!campaign || campaign.status !== 'sending') return;

        console.log(`[NEWSLETTER] Starting campaign: ${campaign.subject}`);

        let targetEmails = [];
        if (campaign.audience === 'test-admin-only') {
            const admins = await User.find({ role: 'admin' });
            targetEmails = admins.map(admin => admin.email);
        } else if (campaign.audience === 'all-subscribers') {
            const subs = await Subscriber.find({ isSubscribed: true });
            targetEmails = subs.map(sub => sub.email);
        } else if (campaign.audience === 'premium-only') {
            const premiumUsers = await User.find({ membership: 'premium' });
            targetEmails = premiumUsers.map(user => user.email);
        }

        if (targetEmails.length === 0) {
            campaign.status = 'failed';
            campaign.adminNotes = 'No valid email addresses found for the selected audience.';
            await campaign.save();
            return;
        }

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
        } else if (campaign.template === 'special-announcement') {
            emailHtml = `
                <div style="${baseStyle} border-top-color: #2196F3;">
                    <h2 style="color: #2196F3; text-align: center;">📢 Important Announcement</h2>
                    <div style="font-size: 16px; line-height: 1.6; margin-bottom: 20px; background: #1a1a1a; padding: 20px; border-radius: 8px; border-left: 3px solid #2196F3;">
                        ${campaign.content}
                    </div>
                    ${campaign.callToActionUrl ? `<div style="text-align: center;"><a href="${campaign.callToActionUrl}" style="${btnStyle}">${campaign.callToActionText}</a></div>` : ''}
                </div>
            `;
        } else {
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

        const unsubscribeUrl = `https://gplmods.webredirect.org/unsubscribe`;
        emailHtml += `
            <div style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #333; font-size: 12px; color: #888;">
                <table cellpadding="0" cellspacing="0" border="0" role="presentation" style="margin: 0 auto 15px auto;">
                    <tr>
                        <td align="center" style="padding: 0 8px;">
                            <a href="https://gravatar.com" target="_blank" title="Gravatar" style="text-decoration: none; display: inline-block;">
                                <img src="https://gplmods.webredirect.org/images/mail-icons/gravatar.png" alt="Gravatar" width="22" height="22" style="display: block; width: 22px; height: 22px; border: 0; border-radius: 50%; opacity: 0.85;" />
                            </a>
                        </td>
                        <td align="center" style="padding: 0 8px;">
                            <a href="https://discord.gg/GfM45GgB" target="_blank" title="GPL Mods Official Discord Server" style="text-decoration: none; display: inline-block;">
                                <img src="https://gplmods.webredirect.org/images/mail-icons/discord.png" alt="Official Discord Server" width="22" height="22" style="display: block; width: 22px; height: 22px; border: 0; opacity: 0.85;" />
                            </a>
                        </td>
                        <td align="center" style="padding: 0 8px;">
                            <a href="https://github.com/GPLMods-Team" target="_blank" title="GPL Mods GitHub" style="text-decoration: none; display: inline-block;">
                                <img src="https://gplmods.webredirect.org/images/mail-icons/github.png" alt="GitHub" width="22" height="22" style="display: block; width: 22px; height: 22px; border: 0; opacity: 0.85;" />
                            </a>
                        </td>
                    </tr>
                </table>
                You received this because you subscribed to updates from GPL Mods.<br>
                <a href="${unsubscribeUrl}" style="color: #888; text-decoration: underline;">Unsubscribe</a>
            </div>
        `;

        let successCount = 0;
        for (const email of targetEmails) {
            try {
                const payload = {
                    api_key: process.env.SMTP2GO_API_KEY,
                    to: [email],
                    sender: process.env.EMAIL_FROM,
                    subject: campaign.subject,
                    html_body: emailHtml,
                    text_body: `GPL Mods Update:\n\n${campaign.content.replace(/<[^>]+>/g, '')}\n\n${campaign.callToActionUrl || ''}`
                };
                await sendSmtpEmail(payload);
                successCount++;
                await new Promise(resolve => setTimeout(resolve, 50));
            } catch (sendErr) {
                console.error(`Failed to send newsletter to ${email}:`, sendErr);
            }
        }

        campaign.status = 'sent';
        campaign.sentCount = successCount;
        await campaign.save();

        console.log(`[NEWSLETTER] Campaign finished. Sent ${successCount}/${targetEmails.length} emails.`);

    } catch (error) {
        console.error("[NEWSLETTER] Critical error processing campaign:", error);
        try {
            await NewsletterCampaign.findByIdAndUpdate(campaignId, { status: 'failed', adminNotes: error.message });
        } catch (e) { }
    }
};

/**
 * Send confirmation email when a user submits a support ticket
 */
exports.sendTicketConfirmationEmail = async (ticket, userEmail, userName = 'Community Member') => {
    try {
        if (!userEmail) return;

        const ticketRef = ticket._id ? String(ticket._id).slice(-8).toUpperCase() : 'NEW';
        const emailContent = `
            <div style="border-left: 4px solid #FFD700; padding-left: 15px; margin-bottom: 25px;">
                <h2 style="margin: 0 0 10px 0; color: #ffffff; font-size: 22px;">Support Ticket Received #${ticketRef}</h2>
                <span style="display: inline-block; background-color: #2196F3; color: #ffffff; font-size: 11px; font-weight: bold; padding: 4px 10px; border-radius: 12px; text-transform: uppercase;">
                    Category: ${ticket.category || 'General'}
                </span>
            </div>
            <p style="color: #c0c0c0; font-size: 15px; line-height: 1.6;">
                Hi <strong>${userName}</strong>, thank you for reaching out to GPL Mods Support. We have received your request and our team is actively reviewing it.
            </p>
            <div style="background-color: #141414; border: 1px solid #2a2a2a; border-radius: 8px; padding: 18px; margin: 25px 0;">
                <div style="color: #888888; font-size: 12px; text-transform: uppercase; margin-bottom: 6px;">Subject</div>
                <div style="color: #ffffff; font-weight: bold; font-size: 16px; margin-bottom: 12px;">${ticket.subject}</div>
                <div style="color: #888888; font-size: 12px; text-transform: uppercase; margin-bottom: 6px;">Message Preview</div>
                <div style="color: #c0c0c0; font-size: 14px; line-height: 1.5; font-style: italic;">
                    "${(ticket.message || '').slice(0, 300)}${(ticket.message && ticket.message.length > 300) ? '...' : ''}"
                </div>
            </div>
            <p style="color: #888888; font-size: 13px; line-height: 1.6;">
                Replies from our support specialists will appear directly in your <strong>GPL Mods Notifications</strong> and will be emailed to this address.
            </p>
            <div style="text-align: center; margin: 30px 0 10px 0;">
                <a href="https://gplmods.webredirect.org/notifications" style="display: inline-block; padding: 12px 28px; background-color: #FFD700; color: #0a0a0a; text-decoration: none; border-radius: 25px; font-weight: bold; font-size: 14px;">
                    View Your Notifications
                </a>
            </div>
        `;

        const payload = {
            api_key: process.env.SMTP2GO_API_KEY,
            to: [userEmail],
            sender: process.env.EMAIL_FROM,
            subject: `[Support Ticket #${ticketRef}] We have received your request: ${ticket.subject}`,
            text_body: `Hi ${userName},\n\nWe have received your support ticket #${ticketRef}: "${ticket.subject}".\n\nOur team is reviewing your message and will respond via your GPL Mods notifications.`,
            html_body: getBrandedEmailHtml(emailContent)
        };

        await sendSmtpEmail(payload);
        console.log(`Support ticket confirmation email sent successfully to ${userEmail} (#${ticketRef})`);
    } catch (error) {
        console.error("SMTP2GO Support Ticket Email Error:", error.response ? error.response.data : error.message);
    }
};

/**
 * Send DMCA notice submission acknowledgment to the claimant
 */
exports.sendDmcaReportConfirmationEmail = async (dmca, claimantEmail, claimantName = 'Copyright Claimant') => {
    try {
        if (!claimantEmail) return;

        const dmcaRef = dmca._id ? String(dmca._id).slice(-8).toUpperCase() : 'DMCA';
        const reportedCount = (dmca.infringingUrls && dmca.infringingUrls.length) || (dmca.reportedFiles && dmca.reportedFiles.length) || 1;
        const emailContent = `
            <div style="border-left: 4px solid #e53935; padding-left: 15px; margin-bottom: 25px;">
                <h2 style="margin: 0 0 10px 0; color: #ffffff; font-size: 22px;">DMCA Notice Acknowledgment #${dmcaRef}</h2>
                <span style="display: inline-block; background-color: #e53935; color: #ffffff; font-size: 11px; font-weight: bold; padding: 4px 10px; border-radius: 12px; text-transform: uppercase;">
                    Notice of Copyright Claim
                </span>
            </div>
            <p style="color: #c0c0c0; font-size: 15px; line-height: 1.6;">
                Dear <strong>${claimantName}</strong>,
            </p>
            <p style="color: #c0c0c0; font-size: 15px; line-height: 1.6;">
                This automated confirmation acknowledges receipt of your Digital Millennium Copyright Act (DMCA) notice submitted on behalf of <strong>${dmca.copyrightHolder || claimantName}</strong>.
            </p>
            <div style="background-color: #141414; border: 1px solid #2a2a2a; border-radius: 8px; padding: 18px; margin: 25px 0;">
                <div style="color: #888888; font-size: 12px; text-transform: uppercase; margin-bottom: 6px;">Notice ID</div>
                <div style="color: #FFD700; font-weight: bold; font-size: 16px; margin-bottom: 12px;">#${dmcaRef}</div>
                <div style="color: #888888; font-size: 12px; text-transform: uppercase; margin-bottom: 6px;">Reported Items</div>
                <div style="color: #ffffff; font-size: 14px; margin-bottom: 12px;">${reportedCount} URL(s) submitted for copyright review</div>
                <div style="color: #888888; font-size: 12px; text-transform: uppercase; margin-bottom: 6px;">Original Work / Proof URL</div>
                <div style="color: #2196F3; font-size: 13px; word-break: break-all;">${dmca.originalWorkUrl || 'Provided in submission'}</div>
            </div>
            <p style="color: #c0c0c0; font-size: 14px; line-height: 1.6;">
                <strong>What happens next?</strong><br>
                Our legal compliance team reviews notices for validity. If the reported items are confirmed on our platform, automated link protection and takedown measures will activate within 24 hours of verification in accordance with 17 U.S.C. &sect; 512(c).
            </p>
            <p style="color: #888888; font-size: 12px; line-height: 1.5; margin-top: 20px;">
                Reference ID: ${dmcaRef} &bull; GPL Mods Copyright & Intellectual Property Operations
            </p>
        `;

        const payload = {
            api_key: process.env.SMTP2GO_API_KEY,
            to: [claimantEmail],
            sender: process.env.EMAIL_FROM,
            subject: `[DMCA Notice #${dmcaRef}] Official Acknowledgment of Copyright Infringement Claim`,
            text_body: `Dear ${claimantName},\n\nWe have received your DMCA takedown claim #${dmcaRef} for ${dmca.copyrightHolder || claimantName}.\n\nOur compliance team is verifying the notice and will take necessary legal action within 24 hours.`,
            html_body: getBrandedEmailHtml(emailContent)
        };

        await sendSmtpEmail(payload);
        console.log(`DMCA confirmation email sent successfully to ${claimantEmail} (#${dmcaRef})`);
    } catch (error) {
        console.error("SMTP2GO DMCA Email Error:", error.response ? error.response.data : error.message);
    }
};

/**
 * Send subscription confirmation email upon successful membership payment/activation
 */
exports.sendSubscriptionStatusEmail = async (user, orderDetails = {}) => {
    try {
        if (!user || !user.email) return;

        const isLite = orderDetails.tier === 'lite' || user.membership === 'lite';
        const planName = orderDetails.planName || (isLite ? 'GPL Lite' : 'GPL Plus');
        const badgeColor = isLite ? '#2196F3' : '#FFD700';
        const expiresAt = user.membershipExpiresAt ? new Date(user.membershipExpiresAt).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' }) : 'Lifetime / Active';

        const perksHtml = isLite ? `
            <li style="margin-bottom: 8px; color: #ffffff;">&check; <strong>No Popunder Ads</strong> on downloads</li>
            <li style="margin-bottom: 8px; color: #ffffff;">&check; <strong>Lightning Fast</strong> download speeds</li>
            <li style="margin-bottom: 8px; color: #ffffff;">&check; <strong>5 Upload Slots</strong> with rolling weekly resets</li>
            <li style="margin-bottom: 8px; color: #ffffff;">&check; <strong>600MB Max File Size</strong> for mods</li>
            <li style="margin-bottom: 8px; color: #ffffff;">&check; <strong>Priority Support</strong> queue</li>
        ` : `
            <li style="margin-bottom: 8px; color: #ffffff;">&check; <strong>100% Ad-Free Experience</strong> (no video ads, no popunders)</li>
            <li style="margin-bottom: 8px; color: #ffffff;">&check; <strong>10 Upload Slots</strong> with immediate live refunds</li>
            <li style="margin-bottom: 8px; color: #ffffff;">&check; <strong>2GB Max File Size</strong> for all mods</li>
            <li style="margin-bottom: 8px; color: #ffffff;">&check; <strong>Ad-Free YouTube/YTMusic Player</strong> in background</li>
            <li style="margin-bottom: 8px; color: #ffffff;">&check; <strong>1-Click Installs</strong> (AltStore, Sileo, etc.)</li>
            <li style="margin-bottom: 8px; color: #ffffff;">&check; <strong>VIP Priority Support</strong> queue</li>
        `;

        const emailContent = `
            <div style="text-align: center; margin-bottom: 30px;">
                <span style="display: inline-block; background-color: ${badgeColor}; color: #0a0a0a; font-size: 13px; font-weight: bold; padding: 6px 16px; border-radius: 20px; text-transform: uppercase; letter-spacing: 1px;">
                    ${planName} Activated
                </span>
                <h2 style="margin: 15px 0 10px 0; color: #ffffff; font-size: 26px;">Welcome to ${planName}!</h2>
                <p style="color: #c0c0c0; font-size: 15px; margin: 0;">Hi <strong>${user.username}</strong>, your membership is now active.</p>
            </div>
            <div style="background-color: #141414; border: 1px solid #2a2a2a; border-radius: 10px; padding: 20px; margin: 25px 0;">
                <table width="100%" cellpadding="6" cellspacing="0" style="color: #c0c0c0; font-size: 14px;">
                    <tr>
                        <td style="color: #888888;">Plan Tier:</td>
                        <td align="right" style="color: #ffffff; font-weight: bold;">${planName}</td>
                    </tr>
                    ${orderDetails.amount ? `
                    <tr>
                        <td style="color: #888888;">Amount Paid:</td>
                        <td align="right" style="color: #ffffff; font-weight: bold;">${orderDetails.currency || 'INR'} ${orderDetails.amount}</td>
                    </tr>
                    ` : ''}
                    <tr>
                        <td style="color: #888888;">Valid Until:</td>
                        <td align="right" style="color: #FFD700; font-weight: bold;">${expiresAt}</td>
                    </tr>
                    ${orderDetails.orderId ? `
                    <tr>
                        <td style="color: #888888;">Order / Receipt:</td>
                        <td align="right" style="color: #888888; font-family: monospace;">#${String(orderDetails.orderId).slice(-10)}</td>
                    </tr>
                    ` : ''}
                </table>
            </div>
            <div style="margin: 25px 0;">
                <h4 style="color: #ffffff; font-size: 15px; margin-bottom: 12px;">Your Unlocked Perks:</h4>
                <ul style="padding-left: 20px; line-height: 1.6; margin: 0;">
                    ${perksHtml}
                </ul>
            </div>
            <div style="text-align: center; margin: 35px 0 10px 0;">
                <a href="https://gplmods.webredirect.org" style="display: inline-block; padding: 14px 32px; background-color: ${badgeColor}; color: #0a0a0a; text-decoration: none; border-radius: 25px; font-weight: bold; font-size: 15px;">
                    Explore GPL Mods with Your Perks
                </a>
            </div>
        `;

        const payload = {
            api_key: process.env.SMTP2GO_API_KEY,
            to: [user.email],
            sender: process.env.EMAIL_FROM,
            subject: `🎉 Your ${planName} Membership is Active!`,
            text_body: `Hi ${user.username},\n\nYour ${planName} membership is now active! Valid until: ${expiresAt}.\n\nVisit GPL Mods to enjoy your new perks.`,
            html_body: getBrandedEmailHtml(emailContent)
        };

        await sendSmtpEmail(payload);
        console.log(`Subscription status email sent successfully to ${user.email} for ${planName}`);
    } catch (error) {
        console.error("SMTP2GO Subscription Status Email Error:", error.response ? error.response.data : error.message);
    }
};

