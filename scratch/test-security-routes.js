// Test stealth security middleware and route hiding logic using native http
const http = require('http');
const express = require('express');

const app = express();
app.set('view engine', 'ejs');
app.set('views', 'views');

// Mock session and user injection
let mockUser = null;
app.use((req, res, next) => {
    req.isAuthenticated = () => Boolean(mockUser);
    req.user = mockUser;
    next();
});

// Stealth Route Shielding Middleware (matching server.js implementation)
app.use((req, res, next) => {
    const rawPath = (req.path || '').toLowerCase();
    const isOwnerRoute = rawPath === '/owner' || rawPath.startsWith('/owner/') || rawPath.startsWith('/api/owner/');
    const isAdminRoute = rawPath === '/admin' || rawPath.startsWith('/admin/') || rawPath.startsWith('/api/admin/') || rawPath === '/.adminjs' || rawPath.startsWith('/.adminjs/');

    if (!isOwnerRoute && !isAdminRoute) {
        return next();
    }

    const isAuth = Boolean(req.isAuthenticated && typeof req.isAuthenticated === 'function' && req.isAuthenticated() && req.user);
    const role = (isAuth && req.user && req.user.role) ? String(req.user.role).trim().toLowerCase() : '';

    if (isOwnerRoute) {
        if (isAuth && role === 'owner') {
            return next();
        }
        if (req.xhr || (req.headers.accept && req.headers.accept.includes('application/json')) || rawPath.startsWith('/api/')) {
            return res.status(404).json({ success: false, error: 'Not Found' });
        }
        return res.status(404).render('pages/error', {
            errorCode: '404',
            errorTitle: 'Page <span>Not Found</span>',
            errorMessage: "Oops! The page you're looking for doesn't exist. It might have been moved or deleted."
        });
    }

    if (isAdminRoute) {
        if (isAuth && (role === 'admin' || role === 'owner')) {
            return next();
        }
        if (req.xhr || (req.headers.accept && req.headers.accept.includes('application/json')) || rawPath.startsWith('/api/')) {
            return res.status(404).json({ success: false, error: 'Not Found' });
        }
        return res.status(404).render('pages/error', {
            errorCode: '404',
            errorTitle: 'Page <span>Not Found</span>',
            errorMessage: "Oops! The page you're looking for doesn't exist. It might have been moved or deleted."
        });
    }

    next();
});

// Mock routes
app.get('/admin', (req, res) => res.send('ADMIN_DASHBOARD'));
app.get('/admin/music', (req, res) => res.send('ADMIN_MUSIC'));
app.get('/api/admin/music/tracks', (req, res) => res.json({ success: true }));
app.get('/owner', (req, res) => res.send('OWNER_DASHBOARD'));
app.get('/api/owner/status', (req, res) => res.json({ success: true, owner: true }));

function doRequest(server, path, headers = {}) {
    const port = server.address().port;
    return new Promise((resolve, reject) => {
        const req = http.request({
            hostname: '127.0.0.1',
            port,
            path,
            method: 'GET',
            headers
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ status: res.statusCode, data, headers: res.headers }));
        });
        req.on('error', reject);
        req.end();
    });
}

async function runTests() {
    const server = http.createServer(app);
    await new Promise(resolve => server.listen(0, resolve));

    try {
        console.log('--- TEST 1: Unauthenticated Public Requests ---');
        mockUser = null;

        let res = await doRequest(server, '/admin');
        console.log('GET /admin (public):', res.status, res.data.includes('404') ? 'PASSED (404 HTML)' : 'FAILED');

        res = await doRequest(server, '/admin/music');
        console.log('GET /admin/music (public):', res.status, res.data.includes('404') ? 'PASSED (404 HTML)' : 'FAILED');

        res = await doRequest(server, '/api/admin/music/tracks', { 'Accept': 'application/json' });
        console.log('GET /api/admin/music/tracks (public API):', res.status, res.data.includes('Not Found') ? 'PASSED (404 JSON)' : 'FAILED');

        res = await doRequest(server, '/owner');
        console.log('GET /owner (public):', res.status, res.data.includes('404') ? 'PASSED (404 HTML)' : 'FAILED');

        res = await doRequest(server, '/api/owner/status', { 'Accept': 'application/json' });
        console.log('GET /api/owner/status (public API):', res.status, res.data.includes('Not Found') ? 'PASSED (404 JSON)' : 'FAILED');

        console.log('\n--- TEST 2: Regular Authenticated User (role: user) ---');
        mockUser = { _id: 'u1', username: 'john', role: 'user' };

        res = await doRequest(server, '/admin');
        console.log('GET /admin (user):', res.status, res.data.includes('404') ? 'PASSED (404 HTML)' : 'FAILED');

        res = await doRequest(server, '/owner');
        console.log('GET /owner (user):', res.status, res.data.includes('404') ? 'PASSED (404 HTML)' : 'FAILED');

        console.log('\n--- TEST 3: Admin User (role: admin) ---');
        mockUser = { _id: 'a1', username: 'admin_user', role: 'admin' };

        res = await doRequest(server, '/admin');
        console.log('GET /admin (admin):', res.status, res.data === 'ADMIN_DASHBOARD' ? 'PASSED (Allowed)' : 'FAILED');

        res = await doRequest(server, '/owner');
        console.log('GET /owner (admin):', res.status, res.data.includes('404') ? 'PASSED (Admin cannot access owner -> 404)' : 'FAILED');

        console.log('\n--- TEST 4: Owner User (role: owner) ---');
        mockUser = { _id: 'o1', username: 'site_owner', role: 'owner' };

        res = await doRequest(server, '/admin');
        console.log('GET /admin (owner):', res.status, res.data === 'ADMIN_DASHBOARD' ? 'PASSED (Allowed)' : 'FAILED');

        res = await doRequest(server, '/owner');
        console.log('GET /owner (owner):', res.status, res.data === 'OWNER_DASHBOARD' ? 'PASSED (Allowed)' : 'FAILED');

        console.log('\n--- TEST 5: Environment Calculation Logic ---');
        function getEnv(reqHost, isRenderEnv) {
            const reqHostNorm = (reqHost || '').toLowerCase().split(':')[0];
            const isLocalHost = reqHostNorm === 'localhost' || reqHostNorm === '127.0.0.1' || reqHostNorm === '::1' || reqHostNorm === '0.0.0.0' || reqHostNorm.startsWith('192.168.') || reqHostNorm.startsWith('10.');
            const isOnline = isRenderEnv || (!isLocalHost && reqHostNorm !== '');
            return isOnline ? 'production' : 'development';
        }

        console.log('localhost:5000 ->', getEnv('localhost:5000', false), '(Expected: development)');
        console.log('127.0.0.1:3000 ->', getEnv('127.0.0.1:3000', false), '(Expected: development)');
        console.log('192.168.1.100:5000 ->', getEnv('192.168.1.100:5000', false), '(Expected: development)');
        console.log('gplmods.com (on Render) ->', getEnv('gplmods.com', true), '(Expected: production)');
        console.log('gplmods.onrender.com ->', getEnv('gplmods.onrender.com', false), '(Expected: production)');
    } finally {
        server.close();
    }
}

runTests().catch(err => {
    console.error('Test error:', err);
    process.exit(1);
});
