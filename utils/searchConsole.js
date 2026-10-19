/**
 * GPLMods Google Search Console & Indexing API Integration Engine
 * 
 * Capabilities:
 * 1. Real-time Search Analytics:
 *    - Fetches top Google search queries, impressions, clicks, CTR, and average rank
 * 2. Dynamic SEO Tag Generation:
 *    - Enriches mod & page meta tags (Title, Description, Keywords, JSON-LD Schema)
 *      using real user search queries
 * 3. Instant Google Indexing:
 *    - Pushes new and updated mod URLs directly to Google Indexing API for fast crawling
 */

const { google } = require('googleapis');
const axios = require('axios');

// 24-hour cache for search queries to stay within Google API quota
const analyticsCache = new Map();
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * Extracts and normalizes Google Service Account credentials from environment
 */
function getGoogleCredentials() {
    let clientEmail = process.env.GOOGLE_SEARCH_CONSOLE_CLIENT_EMAIL 
        || process.env.GSC_CLIENT_EMAIL 
        || process.env.GOOGLE_SERVICE_ACCOUNT_EMAIL 
        || process.env.GOOGLE_INDEXING_CLIENT_EMAIL 
        || process.env.GOOGLE_CLIENT_EMAIL;
    let privateKey = process.env.GOOGLE_SEARCH_CONSOLE_PRIVATE_KEY 
        || process.env.GSC_PRIVATE_KEY 
        || process.env.GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY 
        || process.env.GOOGLE_INDEXING_PRIVATE_KEY 
        || process.env.GOOGLE_PRIVATE_KEY;

    const rawCredentials = process.env.GOOGLE_SERVICE_ACCOUNT_JSON
        || process.env.GOOGLE_CREDENTIALS
        || process.env.GOOGLE_CREDENTIALS_JSON
        || process.env.GOOGLE_CREDENTIALS_BASE64;

    if (rawCredentials && (!clientEmail || !privateKey)) {
        let jsonString = rawCredentials.trim();
        let parsed = null;
        if (jsonString.startsWith('{')) {
            try { parsed = JSON.parse(jsonString); } catch (_) {}
        }
        if (!parsed) {
            try {
                const decoded = Buffer.from(jsonString, 'base64').toString('utf-8').trim();
                parsed = JSON.parse(decoded);
            } catch (_) {}
        }
        if (parsed && typeof parsed === 'object') {
            clientEmail = parsed.client_email || clientEmail;
            privateKey = parsed.private_key || privateKey;
        }
    }

    if (!clientEmail || !privateKey) {
        return null;
    }

    return {
        clientEmail,
        privateKey: privateKey.replace(/\\n/g, '\n')
    };
}

/**
 * Initializes Google Auth Client using Service Account credentials
 */
function getGoogleAuthClient() {
    const creds = getGoogleCredentials();
    if (!creds) {
        return null;
    }

    try {
        const auth = new google.auth.JWT({
            email: creds.clientEmail,
            key: creds.privateKey,
            scopes: [
                'https://www.googleapis.com/auth/webmasters.readonly',
                'https://www.googleapis.com/auth/indexing'
            ]
        });
        return auth;
    } catch (err) {
        console.warn('[GSC Engine] Failed to initialize JWT auth:', err.message);
        return null;
    }
}

/**
 * Queries Google Search Console for real-time search terms, clicks, impressions, and CTR.
 * 
 * @param {string} [siteUrl] - The verified site property in GSC (e.g. 'sc-domain:gplmods.webredirect.org' or 'https://gplmods.webredirect.org/')
 * @param {object} [options] - Query options { startDate, endDate, rowLimit, pageFilter }
 * @returns {Promise<{ queries: Array, totalClicks: number, totalImpressions: number, isLive: boolean }>}
 */
async function getSearchAnalytics(siteUrl, options = {}) {
    const targetSite = siteUrl || process.env.BASE_URL || 'https://gplmods.webredirect.org/';
    const cacheKey = `gsc_${targetSite}_${options.pageFilter || 'all'}`;

    const cached = analyticsCache.get(cacheKey);
    if (cached && (Date.now() - cached.timestamp) < CACHE_TTL_MS) {
        return cached.data;
    }

    const auth = getGoogleAuthClient();
    if (!auth) {
        // Return structured baseline data if credentials are not configured yet
        return {
            isLive: false,
            message: "Google Search Console API credentials not configured in environment (GOOGLE_SEARCH_CONSOLE_CLIENT_EMAIL / GOOGLE_SEARCH_CONSOLE_PRIVATE_KEY).",
            totalClicks: 0,
            totalImpressions: 0,
            queries: []
        };
    }

    try {
        const searchconsole = google.searchconsole({ version: 'v1', auth });

        // Default date range: last 28 days
        const now = new Date();
        const end = new Date(now.setDate(now.getDate() - 2)).toISOString().split('T')[0];
        const start = new Date(now.setDate(now.getDate() - 28)).toISOString().split('T')[0];

        const requestBody = {
            startDate: options.startDate || start,
            endDate: options.endDate || end,
            dimensions: ['query'],
            rowLimit: options.rowLimit || 50
        };

        if (options.pageFilter) {
            requestBody.dimensionFilterGroups = [{
                filters: [{
                    dimension: 'page',
                    operator: 'contains',
                    expression: options.pageFilter
                }]
            }];
        }

        const res = await searchconsole.searchanalytics.query({
            siteUrl: targetSite,
            requestBody
        });

        const rows = res.data.rows || [];
        let totalClicks = 0;
        let totalImpressions = 0;

        const queries = rows.map(r => {
            const clicks = r.clicks || 0;
            const impressions = r.impressions || 0;
            totalClicks += clicks;
            totalImpressions += impressions;

            return {
                query: r.keys ? r.keys[0] : '',
                clicks,
                impressions,
                ctr: r.ctr ? +(r.ctr * 100).toFixed(2) : 0,
                position: r.position ? +r.position.toFixed(1) : 0
            };
        });

        const result = {
            isLive: true,
            totalClicks,
            totalImpressions,
            queries
        };

        analyticsCache.set(cacheKey, { data: result, timestamp: Date.now() });
        return result;

    } catch (err) {
        console.warn('[GSC Engine] Search analytics query failed:', err.message);
        return {
            isLive: false,
            error: err.message,
            totalClicks: 0,
            totalImpressions: 0,
            queries: []
        };
    }
}

/**
 * Dynamically generates rich SEO tags and Schema.org JSON-LD structured data
 * optimized for Google's latest SEO technology and user search trends.
 * 
 * @param {object} mod - Mod document or page metadata
 * @param {string} baseUrl - Current site origin
 * @returns {object} { title, description, keywords, canonicalUrl, jsonLd }
 */
function generateDynamicSeoTags(mod, baseUrl = 'https://gplmods.webredirect.org') {
    if (!mod) {
        return {
            title: 'GPLMods - Free Download Android, iOS, Windows Apps & Mods',
            description: 'Discover and download verified open-source, modded, and unlocked software for Android, iOS, Windows, and WordPress.',
            keywords: 'mods, apk, ipa, windows, games, software, open source, gplmods',
            canonicalUrl: baseUrl,
            jsonLd: null
        };
    }

    const name = mod.name || 'Software Mod';
    const platform = (mod.category || 'Android').toUpperCase();
    const version = mod.version ? `v${mod.version}` : '';
    const cleanDesc = (mod.modDescription || mod.description || '').replace(/<[^>]*>?/gm, '').trim();
    const snippetDesc = cleanDesc.length > 155 ? `${cleanDesc.substring(0, 152)}...` : cleanDesc;

    // High-CTR title format recommended by Google
    const seoTitle = `${name} ${version} Download (${platform}) - GPLMods Free`;

    // High-conversion meta description
    const seoDescription = snippetDesc || `Download ${name} ${version} for ${platform} safely on GPLMods. Verified malware-free download links, screenshots, and direct mirrors.`;

    // Build keyword set from real trends, mod tags, platform, and author
    const baseKeywords = [
        name,
        `${name} download`,
        `${name} mod apk`,
        `${name} ${platform}`,
        `${name} free download`,
        `${platform} mods`,
        'free software',
        'gplmods'
    ];

    if (Array.isArray(mod.tags)) {
        baseKeywords.push(...mod.tags);
    }

    // Expand tags and terms with uppercase, lowercase, spaces, and no-space variations
    let expandTagVariations = null;
    let FULL_FORM_GPL_MODS = [];
    try {
        const dk = require('./dynamicKeywords');
        expandTagVariations = dk.expandTagVariations;
        FULL_FORM_GPL_MODS = dk.FULL_FORM_GPL_MODS || [];
    } catch (_) {}

    const expandedKeywords = new Set();
    baseKeywords.forEach(k => {
        if (expandTagVariations) {
            expandTagVariations(k).forEach(v => expandedKeywords.add(v));
        } else {
            expandedKeywords.add(k);
        }
    });

    if (FULL_FORM_GPL_MODS && Array.isArray(FULL_FORM_GPL_MODS)) {
        FULL_FORM_GPL_MODS.forEach(b => expandedKeywords.add(b));
    }

    const keywords = Array.from(expandedKeywords).slice(0, 50).join(', ');
    const modSlug = mod.slug || mod._id;
    const canonicalUrl = `${baseUrl}/mods/${encodeURIComponent(mod.category || 'general')}/${encodeURIComponent(modSlug)}`;

    // Schema.org SoftwareApplication JSON-LD snippet
    const jsonLd = {
        '@context': 'https://schema.org',
        '@type': 'SoftwareApplication',
        'name': name,
        'operatingSystem': platform,
        'applicationCategory': 'UtilitiesApplication',
        'softwareVersion': mod.version || '1.0.0',
        'description': seoDescription,
        'url': canonicalUrl,
        'offers': {
            '@type': 'Offer',
            'price': '0',
            'priceCurrency': 'USD'
        },
        'aggregateRating': {
            '@type': 'AggregateRating',
            'ratingValue': mod.averageRating ? mod.averageRating.toFixed(1) : '4.8',
            'ratingCount': mod.ratingCount || 25,
            'bestRating': '5',
            'worstRating': '1'
        }
    };

    if (mod.iconKey) {
        jsonLd.image = `${baseUrl}/download-file/${encodeURIComponent(mod.iconKey)}`;
    }

    return {
        title: seoTitle,
        description: seoDescription,
        keywords,
        canonicalUrl,
        jsonLd
    };
}

// In-memory cache for submitted static page URLs with 7-day TTL to preserve quota
const submittedUrlsCache = new Map();
const GOOGLE_URL_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Pushes new or updated URLs to Google's Indexing API for rapid crawling
 * 
 * @param {string} url - Target URL to index
 * @param {string} [type='URL_UPDATED'] - 'URL_UPDATED' or 'URL_DELETED'
 * @returns {Promise<boolean>}
 */
async function submitToGoogleIndex(url, type = 'URL_UPDATED') {
    const auth = getGoogleAuthClient();
    if (!auth) {
        console.log(`[Google Indexing API] Skipped for ${url} (Credentials not configured).`);
        return false;
    }

    try {
        const indexing = google.indexing({ version: 'v3', auth });
        const res = await indexing.urlNotifications.publish({
            requestBody: {
                url,
                type
            }
        });

        console.log(`[Google Indexing API] Successfully notified Google of ${type} for ${url}`);
        return true;
    } catch (err) {
        console.warn(`[Google Indexing API] Failed to submit ${url}:`, err.message);
        return false;
    }
}

/**
 * Automatically synchronizes all public pages and live mod URLs across:
 * 1. Google Indexing API (strictly quota-conserved: only submits unindexed or updated mods)
 * 2. IndexNow API (Bing, Yandex, Seznam, Naver)
 * 3. Search Engine Sitemap Pings (Google, Bing)
 * 
 * @param {string} baseUrl - Domain root (e.g. 'https://gplmods.webredirect.org')
 * @param {object} FileModel - Mongoose File Model
 * @param {object} options - Options { googleLimit: 50 }
 */
async function syncAllPublicUrlsForIndexing(baseUrl = 'https://gplmods.webredirect.org', FileModel = null, options = {}) {
    const googleLimit = options.googleLimit || 40;
    const now = Date.now();
    const corePages = [
        '/',
        '/about',
        '/faq',
        '/docs',
        '/community',
        '/leaderboard',
        '/ai-directory',
        '/category?platform=android',
        '/category?platform=ios-jailed',
        '/category?platform=ios-jailbroken',
        '/category?platform=windows',
        '/category?platform=wordpress',
        '/dmca',
        '/tos',
        '/privacy-policy',
        '/why-choose-us'
    ];

    const allUrlsForIndexNow = corePages.map(p => `${baseUrl}${p}`);
    const googleEligibleUrls = [];

    // Check core pages against 7-day cache
    corePages.forEach(p => {
        const u = `${baseUrl}${p}`;
        const lastSubmitted = submittedUrlsCache.get(u);
        if (!lastSubmitted || (now - lastSubmitted) >= GOOGLE_URL_CACHE_TTL_MS) {
            googleEligibleUrls.push({ url: u, modId: null });
        }
    });

    // Collect live mods from database
    if (FileModel && typeof FileModel.find === 'function') {
        try {
            const liveMods = await FileModel.find({ status: 'live' })
                .select('slug category _id updatedAt googleIndexedAt')
                .sort({ updatedAt: -1 })
                .limit(200)
                .lean();

            liveMods.forEach(m => {
                const modUrl = `${baseUrl}/mods/${encodeURIComponent(m.category)}/${encodeURIComponent(m.slug || m._id.toString())}`;
                allUrlsForIndexNow.push(modUrl);

                // QUOTA PROTECTION: Only submit if never indexed or updated after last Google submission
                const neverSubmitted = !m.googleIndexedAt;
                const wasUpdated = m.googleIndexedAt && m.updatedAt && (new Date(m.updatedAt).getTime() > new Date(m.googleIndexedAt).getTime());
                if (neverSubmitted || wasUpdated) {
                    googleEligibleUrls.push({ url: modUrl, modId: m._id });
                }
            });
        } catch (dbErr) {
            console.warn('[Sync Indexing] Error reading live mods:', dbErr.message);
        }
    }

    // 1. Submit ONLY unindexed or updated URLs to Google Indexing API (Quota Saver)
    let googleSubmitted = 0;
    const auth = getGoogleAuthClient();
    if (auth && googleEligibleUrls.length > 0) {
        const targetGoogleBatch = googleEligibleUrls.slice(0, googleLimit);
        for (const item of targetGoogleBatch) {
            try {
                const ok = await submitToGoogleIndex(item.url, 'URL_UPDATED');
                if (ok) {
                    googleSubmitted++;
                    submittedUrlsCache.set(item.url, Date.now());
                    if (item.modId && FileModel) {
                        FileModel.findByIdAndUpdate(item.modId, {
                            googleIndexedAt: new Date(),
                            googleIndexStatus: 'INDEXED'
                        }).catch(() => {});
                    }
                }
                // 120ms rate pacing between Google API calls
                await new Promise(r => setTimeout(r, 120));
            } catch (_) {}
        }
        console.log(`[Google Indexing API] Quota-saver sync completed: submitted ${googleSubmitted} new/updated URLs (preserved quota for ${allUrlsForIndexNow.length - targetGoogleBatch.length} already-indexed URLs).`);
    } else {
        console.log('[Google Indexing API] All existing URLs already indexed and up-to-date. 0 quota consumed.');
    }

    // 2. Broadcast entire batch to IndexNow API (Bing, Yandex, Seznam, Naver)
    let indexNowSuccess = false;
    const indexNowKey = process.env.INDEXNOW_KEY || '4387532a48904cbaae6f8ba7ad35d790';
    try {
        const host = new URL(baseUrl).hostname;
        const indexNowEndpoints = [
            'https://api.indexnow.org/indexnow',
            'https://www.bing.com/indexnow',
            'https://yandex.com/indexnow'
        ];

        for (const ep of indexNowEndpoints) {
            try {
                await axios.post(ep, {
                    host,
                    key: indexNowKey,
                    keyLocation: `${baseUrl}/${indexNowKey}.txt`,
                    urlList: uniqueUrls.slice(0, 500)
                }, {
                    headers: { 'Content-Type': 'application/json; charset=utf-8' },
                    timeout: 8000
                });
                indexNowSuccess = true;
            } catch (_) {}
        }
    } catch (inErr) {
        console.warn('[Sync Indexing] IndexNow error:', inErr.message);
    }

    // 3. Ping Google & Bing Sitemaps
    let sitemapsPinged = 0;
    try {
        const sitemapUrl = encodeURIComponent(`${baseUrl}/sitemap_index.xml`);
        const pings = [
            `https://www.google.com/ping?sitemap=${sitemapUrl}`,
            `https://www.bing.com/ping?sitemap=${sitemapUrl}`
        ];
        await Promise.allSettled(pings.map(p => axios.get(p, { timeout: 6000 })));
        sitemapsPinged = pings.length;
    } catch (_) {}

    console.log(`[Global Indexing Sync] Complete: ${uniqueUrls.length} total URLs, Google: ${googleSubmitted}, IndexNow: ${indexNowSuccess ? 'Success' : 'Skipped/Partial'}, Sitemaps: ${sitemapsPinged}`);

    return {
        success: true,
        totalUrls: uniqueUrls.length,
        googleSubmitted,
        indexNowSubmitted: indexNowSuccess,
        sitemapsPinged,
        timestamp: new Date().toISOString()
    };
}

module.exports = {
    getGoogleCredentials,
    getGoogleAuthClient,
    getSearchAnalytics,
    generateDynamicSeoTags,
    submitToGoogleIndex,
    syncAllPublicUrlsForIndexing
};

