/**
 * Cloudflare Worker for GPLMods iOS Store & DNS API Cache
 * 
 * Features:
 * - High-speed edge caching with Cloudflare Cache API
 * - Instant on-demand cache purge via AdminJS or direct secret key request
 * - Dynamic app icon resolution & fallback mapping
 * - Full CORS support
 */

const UPSTREAM_API = 'https://gplmods.onrender.com/api/ios-store';
const PURGE_SECRET = 'gplmods-dns-secret'; // Can also be set via Cloudflare Worker Environment Variable: PURGE_SECRET
const CACHE_TTL_SECONDS = 300; // 5 minutes cache TTL

// Known app icon mappings (case-insensitive)
const ICON_MAP = {
    'altstore': 'icons/altstore.png',
    'cydia': 'icons/cydia.png',
    'droidify': 'icons/droidify.png',
    'esign': 'icons/esign.png',
    'feather': 'icons/feather.png',
    'installer': 'icons/installer.png',
    'ksign': 'icons/ksign.png',
    'livecontainer': 'icons/livecontainer.png',
    'neostore': 'icons/neostore.png',
    'purepkg': 'icons/purepkg.png',
    'saily': 'icons/saily.png',
    'scarlet': 'icons/scarlet.png',
    'sidestore': 'icons/sidestore.png',
    'sileo': 'icons/sileo.png',
    'trollstore': 'icons/trollstore.png',
    'zebra': 'icons/zebra.png'
};

const CORS_HEADERS = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400'
};

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);

        // Handle CORS preflight
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: CORS_HEADERS });
        }

        const configuredSecret = env?.PURGE_SECRET || PURGE_SECRET;
        const upstreamUrl = env?.UPSTREAM_API || UPSTREAM_API;

        // Check for Purge request
        const isPurgePath = url.pathname === '/purge' || url.searchParams.get('purge') === '1';
        const requestSecret = url.searchParams.get('key') || request.headers.get('x-purge-key');

        if (isPurgePath) {
            if (requestSecret !== configuredSecret) {
                return new Response(JSON.stringify({ error: 'Unauthorized purge request' }), {
                    status: 401,
                    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
                });
            }

            const cache = caches.default;
            const cacheKey = new Request(new URL('/', url.origin).toString(), { method: 'GET' });
            const deleted = await cache.delete(cacheKey);

            return new Response(JSON.stringify({
                success: true,
                purged: deleted,
                message: 'Cache purged successfully',
                timestamp: new Date().toISOString()
            }), {
                status: 200,
                headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
            });
        }

        // Standard API Fetch with Cache
        const cache = caches.default;
        const cacheKey = new Request(new URL('/', url.origin).toString(), { method: 'GET' });

        let response = await cache.match(cacheKey);

        if (!response) {
            try {
                // Fetch fresh data from backend Render API
                const upstreamResponse = await fetch(upstreamUrl, {
                    headers: {
                        'Accept': 'application/json',
                        'User-Agent': 'Cloudflare-Worker-GPLMods/1.0'
                    }
                });

                if (!upstreamResponse.ok) {
                    return new Response(JSON.stringify({ error: 'Backend upstream returned status ' + upstreamResponse.status }), {
                        status: upstreamResponse.status,
                        headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
                    });
                }

                const data = await upstreamResponse.json();

                // Enhance and format app icons if missing or relative
                if (data.certificates && Array.isArray(data.certificates)) {
                    data.certificates.forEach(cert => {
                        if (cert.apps && Array.isArray(cert.apps)) {
                            cert.apps.forEach(app => {
                                if (!app.iconUrl || app.iconUrl.trim() === '') {
                                    // Try auto-detection from app name
                                    const appLower = (app.name || '').toLowerCase().replace(/[^a-z0-9]/g, '');
                                    for (const [key, iconPath] of Object.entries(ICON_MAP)) {
                                        if (appLower.includes(key)) {
                                            app.iconUrl = iconPath;
                                            break;
                                        }
                                    }
                                }
                            });
                        }
                    });
                }

                const jsonBody = JSON.stringify(data);

                // Build cached response
                response = new Response(jsonBody, {
                    status: 200,
                    headers: {
                        'Content-Type': 'application/json; charset=utf-8',
                        'Cache-Control': `public, max-age=${CACHE_TTL_SECONDS}, s-maxage=${CACHE_TTL_SECONDS}`,
                        'X-Cache-Status': 'MISS',
                        ...CORS_HEADERS
                    }
                });

                // Store in edge cache
                ctx.waitUntil(cache.put(cacheKey, response.clone()));
            } catch (err) {
                return new Response(JSON.stringify({ error: 'Failed to fetch from backend', details: err.message }), {
                    status: 502,
                    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS }
                });
            }
        } else {
            // Modify header to indicate hit
            const headers = new Headers(response.headers);
            headers.set('X-Cache-Status', 'HIT');
            Object.entries(CORS_HEADERS).forEach(([k, v]) => headers.set(k, v));
            response = new Response(response.body, {
                status: response.status,
                headers: headers
            });
        }

        return response;
    }
};
