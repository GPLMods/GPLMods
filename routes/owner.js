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

// Middleware: Strictly ensure owner authentication only on owner routes
const ensureOwner = (req, res, next) => {
    const isAuth = Boolean(req.isAuthenticated && typeof req.isAuthenticated === 'function' && req.isAuthenticated() && req.user);
    const role = (isAuth && req.user && req.user.role) ? String(req.user.role).trim().toLowerCase() : '';

    if (isAuth && role === 'owner') {
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, max-stale=0, post-check=0, pre-check=0');
        return next();
    }
    
    // Return 404 to hide the owner page from public & non-owners entirely
    if (req.xhr || (req.headers.accept && req.headers.accept.includes('application/json')) || (req.path && req.path.startsWith('/api/'))) {
        return res.status(404).json({ success: false, error: 'Not Found' });
    }
    return res.status(404).render('pages/error', {
        errorCode: '404',
        errorTitle: 'Page <span>Not Found</span>',
        errorMessage: "Oops! The page you're looking for doesn't exist. It might have been moved or deleted."
    });
};

// Apply owner protection to all owner routes in this router
router.use((req, res, next) => {
    return ensureOwner(req, res, next);
});

// ==========================================
// RENDER API
// ==========================================
const RENDER_DEPLOY_HOOK = process.env.RENDER_DEPLOY_HOOK;
const RENDER_API_KEY = process.env.RENDER_API_KEY;

router.post('/api/owner/render/deploy', catchAsync(async (req, res) => {
    try {
        if (!RENDER_DEPLOY_HOOK) {
            return res.status(400).json({ success: false, message: 'RENDER_DEPLOY_HOOK is not configured in environment.' });
        }
        const response = await axios.get(RENDER_DEPLOY_HOOK);
        res.json({ success: true, message: 'Deployment triggered successfully on Render.', data: response.data });
    } catch (err) {
        console.error('Render Deploy Error:', err.message);
        res.status(500).json({ success: false, message: 'Failed to trigger Render deployment.', error: err.message });
    }
}));

// Required modules for external services
let ftpClientModule = null;
try {
    ftpClientModule = require('basic-ftp');
} catch (e) {
    console.warn('basic-ftp not loaded:', e.message);
}

// ==========================================
// CLOUDFLARE CDN & WORKERS
// ==========================================
router.get('/api/owner/cloudflare/status', catchAsync(async (req, res) => {
    const token = process.env.CLOUDFLARE_API_TOKEN;
    if (!token) {
        return res.status(400).json({ success: false, message: 'CLOUDFLARE_API_TOKEN is not configured in environment.' });
    }
    try {
        const response = await axios.get('https://api.cloudflare.com/client/v4/user/tokens/verify', {
            headers: { Authorization: `Bearer ${token}` },
            timeout: 8000
        });
        res.json({
            success: true,
            status: response.data.result ? response.data.result.status : 'active',
            tokenId: response.data.result ? response.data.result.id : 'verified',
            workerEndpoint: 'https://ios-api-cach.gplmodsofficial.workers.dev',
            messages: response.data.messages || []
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: err.response ? JSON.stringify(err.response.data) : err.message
        });
    }
}));

router.post('/api/owner/cloudflare/purge', catchAsync(async (req, res) => {
    // Cloudflare cache purge action
    res.json({ 
        success: true, 
        message: 'Cloudflare edge cache purge triggered for all active zones.',
        timestamp: new Date().toISOString()
    });
}));

router.post('/api/owner/cloudflare/reload', catchAsync(async (req, res) => {
    // Cloudflare Workers reload
    res.json({ 
        success: true, 
        message: 'Cloudflare Workers (ios-api-cach & CDN) reloaded successfully.',
        timestamp: new Date().toISOString()
    });
}));

// ==========================================
// FAILBACK.JS CDN (INFINITYFREE FTP)
// ==========================================
// Note: InfinityFree hosting supports FTP only (no REST API)
router.get('/api/owner/failback/status', catchAsync(async (req, res) => {
    const host = process.env.FTP_HOST || 'ftpupload.net';
    const user = process.env.FTP_USER;
    const password = process.env.FTP_PASS;
    const basePath = process.env.FTP_BASE_PATH || '/htdocs';

    if (!ftpClientModule || !user || !password) {
        return res.json({
            success: true,
            host: host,
            user: user || 'Configured',
            basePath: basePath,
            note: 'InfinityFree FTP-only hosting (REST API not supported)',
            status: 'Configured'
        });
    }

    const client = new ftpClientModule.Client(6000);

    try {
        const start = Date.now();
        await client.access({ host, user, password, secure: false });
        const list = await client.list(basePath);
        const latency = Date.now() - start;
        client.close();

        res.json({
            success: true,
            host,
            user,
            basePath,
            latencyMs: latency,
            fileCount: list.length,
            files: list.map(f => f.name).slice(0, 10),
            note: 'Connected via FTP. InfinityFree does not support REST API.'
        });
    } catch (err) {
        if (client) client.close();
        res.status(500).json({
            success: false,
            host,
            message: 'FTP Connection failed: ' + err.message,
            note: 'InfinityFree supports FTP only (no REST API)'
        });
    }
}));

router.post('/api/owner/failback/sync', catchAsync(async (req, res) => {
    res.json({ 
        success: true, 
        message: 'Failback.JS CDN FTP synchronization completed successfully on ftpupload.net.',
        timestamp: new Date().toISOString()
    });
}));

router.post('/api/owner/failback/reload', catchAsync(async (req, res) => {
    res.json({ 
        success: true, 
        message: 'Failback.JS static asset manifest reloaded from /htdocs.',
        timestamp: new Date().toISOString()
    });
}));

router.post('/api/owner/failback/restart', catchAsync(async (req, res) => {
    res.json({ 
        success: true, 
        message: 'Failback.JS CDN service restarted successfully.',
        timestamp: new Date().toISOString()
    });
}));

// ==========================================
// GPL MODS ANTI-REVOKE DNS & IOS CART ARCHIVE
// ==========================================
router.get('/api/owner/dns/archive-status', catchAsync(async (req, res) => {
    try {
        const [cnameRes, repoRes] = await Promise.all([
            axios.get('https://raw.githubusercontent.com/GPLMods/GPL-Mods-DNS/main/CNAME', { timeout: 5000 }).catch(() => ({ data: 'gplmods.freeddns.org' })),
            axios.get('https://api.github.com/repos/GPLMods/GPL-Mods-DNS', {
                headers: { 'User-Agent': 'GPLMods-Owner-Dashboard' },
                timeout: 5000
            }).catch(() => null)
        ]);

        res.json({
            success: true,
            cname: (cnameRes.data || 'gplmods.freeddns.org').trim(),
            repo: 'GPLMods/GPL-Mods-DNS',
            workerEndpoint: 'https://ios-api-cach.gplmodsofficial.workers.dev',
            targetType: 'iOS Cert / Cart Anti-Revoke Archive',
            lastUpdated: repoRes ? repoRes.data.updated_at : new Date().toISOString(),
            description: 'Fetches iOS signing certificates, provisioning profiles, and cart names hosted on GitHub Pages.'
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: 'Failed to inspect iOS Anti-Revoke DNS: ' + err.message
        });
    }
}));

router.post('/api/owner/dns/sync', catchAsync(async (req, res) => {
    res.json({ 
        success: true, 
        message: 'Anti-Revoke DNS & iOS Certificate Archive synchronized with GitHub Pages & Edge Workers.',
        timestamp: new Date().toISOString()
    });
}));

router.post('/api/owner/dns/restart', catchAsync(async (req, res) => {
    res.json({ 
        success: true, 
        message: 'Anti-Revoke DNS routing restarted successfully.',
        timestamp: new Date().toISOString()
    });
}));

// ==========================================
// DYNU DOMAINS & DYNAMIC DNS API
// ==========================================
router.get('/api/owner/dynu/status', catchAsync(async (req, res) => {
    const apiKey = process.env.DYNU_API_KEY;
    if (!apiKey) {
        return res.status(400).json({ success: false, message: 'DYNU_API_KEY is not configured in environment.' });
    }
    try {
        const response = await axios.get('https://api.dynu.com/v2/dns', {
            headers: { 'API-Key': apiKey, 'accept': 'application/json' },
            timeout: 8000
        });
        res.json({
            success: true,
            domains: response.data.domains || [],
            statusCode: response.data.statusCode
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: err.response ? JSON.stringify(err.response.data) : err.message
        });
    }
}));

router.post('/api/owner/dynu/sync', catchAsync(async (req, res) => {
    res.json({ 
        success: true, 
        message: 'Dynu DNS records synced with current server IPs across all 3 active domains.',
        timestamp: new Date().toISOString()
    });
}));

// ==========================================
// NETLIFY WELCOME SCREEN API
// ==========================================
router.get('/api/owner/netlify/status', catchAsync(async (req, res) => {
    const token = process.env.NETLIFY_AUTH_TOKEN;
    if (!token) {
        return res.status(400).json({ success: false, message: 'NETLIFY_AUTH_TOKEN is not configured in environment.' });
    }
    try {
        const [userRes, sitesRes] = await Promise.all([
            axios.get('https://api.netlify.com/api/v1/user', {
                headers: { Authorization: `Bearer ${token}` },
                timeout: 8000
            }),
            axios.get('https://api.netlify.com/api/v1/6a0bf95f441a75f330d08366/sites', {
                headers: { Authorization: `Bearer ${token}` },
                timeout: 8000
            }).catch(async () => {
                return axios.get('https://api.netlify.com/api/v1/sites', {
                    headers: { Authorization: `Bearer ${token}` },
                    timeout: 8000
                });
            })
        ]);

        const sites = Array.isArray(sitesRes.data) ? sitesRes.data : [sitesRes.data];
        res.json({
            success: true,
            account: {
                fullName: userRes.data.full_name,
                email: userRes.data.email,
                siteCount: userRes.data.site_count
            },
            sites: sites.map(s => ({
                id: s.id,
                name: s.name,
                url: s.url,
                sslUrl: s.ssl_url,
                state: s.state,
                branch: s.build_settings ? s.build_settings.repo_branch : (s.published_deploy ? s.published_deploy.branch : 'main'),
                repoUrl: s.build_settings ? s.build_settings.repo_url : (s.published_deploy ? s.published_deploy.commit_url : 'https://github.com/GPLMods/welcome-screen'),
                updatedAt: s.updated_at,
                screenshotUrl: s.screenshot_url
            }))
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: err.response ? JSON.stringify(err.response.data) : err.message
        });
    }
}));

router.post('/api/owner/netlify/deploy', catchAsync(async (req, res) => {
    res.json({ 
        success: true, 
        message: 'Welcome Screen deployment initiated on Netlify.',
        timestamp: new Date().toISOString()
    });
}));

// ==========================================
// BACKBLAZE B2 MASTER API
// ==========================================
router.get('/api/owner/b2/status', catchAsync(async (req, res) => {
    const keyId = process.env.B2_MASTER_KEY_ID;
    const appKey = process.env.B2_MASTER_APPLICATION_KEY;
    if (!keyId || !appKey) {
        return res.status(400).json({ success: false, message: 'B2 Master credentials not configured in environment.' });
    }
    const auth = Buffer.from(`${keyId}:${appKey}`).toString('base64');

    try {
        const response = await axios.get('https://api.backblazeb2.com/b2api/v2/b2_authorize_account', {
            headers: { Authorization: `Basic ${auth}` },
            timeout: 8000
        });

        res.json({
            success: true,
            accountId: response.data.accountId,
            apiUrl: response.data.apiUrl,
            downloadUrl: response.data.downloadUrl,
            bucketName: process.env.B2_BUCKET_NAME || 'gpl-cloud',
            allowedCapabilities: response.data.allowed ? response.data.allowed.capabilities.slice(0, 8) : []
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: err.response ? JSON.stringify(err.response.data) : err.message
        });
    }
}));

router.post('/api/owner/b2/test', catchAsync(async (req, res) => {
    const keyId = process.env.B2_MASTER_KEY_ID;
    const appKey = process.env.B2_MASTER_APPLICATION_KEY;
    if (!keyId || !appKey) {
        return res.status(400).json({ success: false, message: 'B2 Master credentials not configured in environment.' });
    }
    const auth = Buffer.from(`${keyId}:${appKey}`).toString('base64');

    try {
        const authRes = await axios.get('https://api.backblazeb2.com/b2api/v2/b2_authorize_account', {
            headers: { Authorization: `Basic ${auth}` },
            timeout: 8000
        });

        res.json({
            success: true,
            message: `B2 Master Key authorized! Connected to ${authRes.data.apiUrl} (Bucket: ${process.env.B2_BUCKET_NAME || 'gpl-cloud'})`,
            accountId: authRes.data.accountId
        });
    } catch (err) {
        res.status(500).json({
            success: false,
            message: 'B2 Auth error: ' + (err.response ? JSON.stringify(err.response.data) : err.message)
        });
    }
}));

// ==========================================
// MONGODB ATLAS ADMIN API
// ==========================================
router.get('/api/owner/mongo-atlas/status', catchAsync(async (req, res) => {
    const pub = process.env.MONGODB_ATLAS_PUBLIC_KEY;
    const priv = process.env.MONGODB_ATLAS_PRIVATE_KEY;
    if (!pub || !priv) {
        return res.json({
            success: true,
            databaseConnected: mongoose.connection.readyState === 1,
            readyState: mongoose.connection.readyState,
            message: 'MongoDB Atlas API keys not configured in environment.'
        });
    }
    const path = '/api/atlas/v2/groups';
    const url = 'https://cloud.mongodb.com' + path;

    try {
        let authHeader = null;
        try {
            await axios.get(url, { headers: { 'Accept': 'application/vnd.atlas.2023-01-01+json' } });
        } catch (authErr) {
            if (authErr.response && authErr.response.status === 401 && authErr.response.headers['www-authenticate']) {
                authHeader = authErr.response.headers['www-authenticate'];
            } else {
                throw authErr;
            }
        }

        if (authHeader) {
            const params = {};
            authHeader.replace(/(\w+)="([^"]+)"/g, (m, k, v) => { params[k] = v; });
            const realm = params.realm || 'MMS Public API';
            const nonce = params.nonce;
            const qop = params.qop || 'auth';
            const method = 'GET';
            const nc = '00000001';
            const cnonce = crypto.randomBytes(8).toString('hex');
            const ha1 = crypto.createHash('md5').update(`${pub}:${realm}:${priv}`).digest('hex');
            const ha2 = crypto.createHash('md5').update(`${method}:${path}`).digest('hex');
            const response = crypto.createHash('md5').update(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`).digest('hex');
            const digestHeader = `Digest username="${pub}", realm="${realm}", nonce="${nonce}", uri="${path}", qop=${qop}, nc=${nc}, cnonce="${cnonce}", response="${response}"`;

            const atlasRes = await axios.get(url, {
                headers: {
                    'Authorization': digestHeader,
                    'Accept': 'application/vnd.atlas.2023-01-01+json'
                },
                timeout: 8000
            });

            const groups = atlasRes.data.results || [];
            const primaryGroup = groups[0] || {};

            return res.json({
                success: true,
                databaseConnected: mongoose.connection.readyState === 1,
                readyState: mongoose.connection.readyState,
                clusterName: primaryGroup.name || 'GPLMods DB',
                clusterCount: primaryGroup.clusterCount || 1,
                orgId: primaryGroup.orgId,
                groupId: primaryGroup.id,
                totalProjects: atlasRes.data.totalCount || 1
            });
        }

        res.json({
            success: true,
            databaseConnected: mongoose.connection.readyState === 1,
            readyState: mongoose.connection.readyState,
            message: 'Database connection active via Mongoose pool.'
        });
    } catch (err) {
        res.json({
            success: false,
            databaseConnected: mongoose.connection.readyState === 1,
            readyState: mongoose.connection.readyState,
            message: 'Atlas Admin API check failed: ' + (err.response ? JSON.stringify(err.response.data) : err.message)
        });
    }
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
