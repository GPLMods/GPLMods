const express = require('express');
const axios = require('axios');
const mongoose = require('mongoose');
const crypto = require('crypto');
const router = express.Router();
const improvmx = require('../utils/improvmx');
const User = require('../models/user');

// Utility for wrapping async routes
const catchAsync = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// ==========================================
// RENDER API
// ==========================================
// We use the webhook URL directly for deployment
const RENDER_DEPLOY_HOOK = 'https://api.render.com/deploy/srv-d561qkm3jp1c73a5tl7g?key=HiA80IuR70k';
const RENDER_API_KEY = process.env.RENDER_API_KEY || 'rnd_5lZTmeZn5slDHGX4KVyucX8tfqK92';

router.post('/api/owner/render/deploy', catchAsync(async (req, res) => {
    try {
        const response = await axios.get(RENDER_DEPLOY_HOOK);
        res.json({ success: true, message: 'Deployment triggered successfully on Render.', data: response.data });
    } catch (err) {
        console.error('Render Deploy Error:', err.message);
        res.status(500).json({ success: false, message: 'Failed to trigger Render deployment.', error: err.message });
    }
}));

// ==========================================
// CLOUDFLARE API
// ==========================================
// Stubbed for future integration
router.post('/api/owner/cloudflare/purge', catchAsync(async (req, res) => {
    setTimeout(() => {
        res.json({ success: true, message: 'Cloudflare cache purge simulated successfully.' });
    }, 1000);
}));

router.post('/api/owner/cloudflare/reload', catchAsync(async (req, res) => {
    setTimeout(() => {
        res.json({ success: true, message: 'Cloudflare Workers reload simulated successfully.' });
    }, 1000);
}));

// ==========================================
// FAILBACK.JS CDN
// ==========================================
router.post('/api/owner/failback/sync', catchAsync(async (req, res) => {
    setTimeout(() => {
        res.json({ success: true, message: 'Failback.JS manual sync simulated successfully.' });
    }, 800);
}));

router.post('/api/owner/failback/reload', catchAsync(async (req, res) => {
    setTimeout(() => {
        res.json({ success: true, message: 'Failback.JS reload simulated successfully.' });
    }, 800);
}));

router.post('/api/owner/failback/restart', catchAsync(async (req, res) => {
    setTimeout(() => {
        res.json({ success: true, message: 'Failback.JS restart simulated successfully.' });
    }, 1500);
}));

// ==========================================
// GPL MODS ANTI-REVOKE DNS
// ==========================================
router.post('/api/owner/dns/sync', catchAsync(async (req, res) => {
    setTimeout(() => {
        res.json({ success: true, message: 'Anti-Revoke DNS sync simulated successfully.' });
    }, 500);
}));

router.post('/api/owner/dns/restart', catchAsync(async (req, res) => {
    setTimeout(() => {
        res.json({ success: true, message: 'Anti-Revoke DNS restart simulated successfully.' });
    }, 1200);
}));

// ==========================================
// IMPROVMX & CUSTOM EMAIL CONTROLS
// ==========================================
router.get('/api/owner/improvmx/status', catchAsync(async (req, res) => {
    const domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org';
    const result = await improvmx.getDomain(domain);
    if (result.success) {
        res.json({
            success: true,
            domain: result.domain.display,
            active: result.domain.active,
            validMx: result.domain.mx ? result.domain.mx.valid : false,
            notificationEmail: result.domain.notification_email,
            whitelabel: result.domain.whitelabel
        });
    } else {
        res.status(result.status || 500).json({
            success: false,
            message: result.message || 'Could not fetch ImprovMX domain status.',
            domain
        });
    }
}));

router.get('/api/owner/improvmx/aliases', catchAsync(async (req, res) => {
    const domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org';
    const result = await improvmx.listAliases(domain);
    if (result.success) {
        res.json({ success: true, aliases: result.aliases, domain });
    } else {
        res.status(500).json({ success: false, message: result.message || 'Failed to list aliases.' });
    }
}));

router.post('/api/owner/improvmx/claim', catchAsync(async (req, res) => {
    let { alias, forwardEmail } = req.body;
    if (!alias) {
        return res.status(400).json({ success: false, message: 'Alias name is required.' });
    }

    alias = alias.toLowerCase().replace(/[^a-z0-9._-]/g, '');
    const forwardTo = forwardEmail || (req.user && req.user.email);
    if (!forwardTo) {
        return res.status(400).json({ success: false, message: 'Forwarding email address is required.' });
    }

    const domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org';
    const result = await improvmx.createAlias(alias, forwardTo, domain);
    if (result.success) {
        // If owner created alias for themselves, optionally associate with user model
        if (req.user && (!req.user.customEmailAlias || req.body.assignToSelf)) {
            await User.findByIdAndUpdate(req.user._id, { customEmailAlias: alias });
        }
        res.json({ 
            success: true, 
            message: `Custom email ${alias}@${domain} created and forwarding to ${forwardTo}!`,
            data: result.data 
        });
    } else {
        res.status(400).json({ success: false, message: result.message || 'Failed to create alias via ImprovMX.' });
    }
}));

router.post('/api/owner/improvmx/smtp', catchAsync(async (req, res) => {
    let { username } = req.body;
    if (!username) {
        username = req.user.customEmailAlias || 'owner';
    }
    username = username.toLowerCase().replace(/[^a-z0-9._-]/g, '');
    const domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org';

    const smtpPassword = crypto.randomBytes(8).toString('hex');
    const result = await improvmx.createSmtpCredential(username, smtpPassword, domain);
    if (result.success) {
        if (req.user && req.user.customEmailAlias === username) {
            await User.findByIdAndUpdate(req.user._id, { hasSmtpAccess: true });
        }
        res.json({
            success: true,
            message: `SMTP Credential created for ${username}@${domain}!`,
            credentials: {
                host: 'smtp.improvmx.com',
                port: 587,
                username: `${username}@${domain}`,
                password: smtpPassword
            }
        });
    } else {
        res.status(400).json({ success: false, message: result.message || 'Failed to create SMTP credentials.' });
    }
}));

router.delete('/api/owner/improvmx/alias/:aliasId', catchAsync(async (req, res) => {
    const domain = process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org';
    const result = await improvmx.deleteAlias(req.params.aliasId, domain);
    if (result.success) {
        res.json({ success: true, message: 'Alias deleted successfully.' });
    } else {
        res.status(400).json({ success: false, message: result.message || 'Failed to delete alias.' });
    }
}));

// ==========================================
// CORE SERVER CONTROLS
// ==========================================
router.post('/api/owner/core/restart', catchAsync(async (req, res) => {
    res.json({ success: true, message: 'Server restart initiated...' });
    setTimeout(() => {
        process.exit(0);
    }, 1000);
}));

router.post('/api/owner/core/shutdown', catchAsync(async (req, res) => {
    res.json({ success: true, message: 'Server shutdown initiated...' });
    setTimeout(() => {
        process.exit(1);
    }, 1000);
}));

router.post('/api/owner/core/disconnect-db', catchAsync(async (req, res) => {
    await mongoose.disconnect();
    res.json({ success: true, message: 'Database disconnected successfully.' });
}));

router.post('/api/owner/core/terminate-data', catchAsync(async (req, res) => {
    if (req.body.confirm !== 'TERMINATE_ALL_DATA') {
        return res.status(400).json({ success: false, message: 'Invalid confirmation string for data termination.' });
    }
    if (mongoose.connection && mongoose.connection.db) {
        await mongoose.connection.db.dropDatabase();
        res.json({ success: true, message: 'CRITICAL: ALL DATABASE DATA HAS BEEN TERMINATED.' });
    } else {
        res.status(500).json({ success: false, message: 'No active database connection found.' });
    }
}));

// ==========================================
// OWNER DASHBOARD VIEW
// ==========================================
router.get('/owner', (req, res) => {
    res.render('pages/owner/dashboard', {
        user: req.user,
        pageTitle: 'Owner Infrastructure Dashboard',
        improvmxDomain: process.env.IMPROVMX_DOMAIN || 'gplmods.webredirect.org'
    });
});

module.exports = router;
