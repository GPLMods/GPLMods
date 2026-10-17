/**
 * GPLMods Optimized XML Sitemap Engine
 * Powered by the official `sitemap` npm package
 * 
 * Features:
 * - Validated XML compliant with Google Webmaster and Schema.org specs
 * - 1-hour in-memory cache to prevent database hammering by aggressive crawlers
 * - Google Image and Video XML sitemap extensions
 * - Automatic URL encoding and XML entity escaping
 */

const { SitemapStream, streamToPromise, SitemapIndexStream } = require('sitemap');
const { Readable } = require('stream');
const { minify: minifyXml } = require('minify-xml');

// Cache map: key -> { xml: string, timestamp: number }
const sitemapCache = new Map();
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

function getCached(key) {
    const entry = sitemapCache.get(key);
    if (entry && (Date.now() - entry.timestamp) < CACHE_TTL_MS) {
        return entry.xml;
    }
    return null;
}

function setCache(key, xml) {
    let minified = xml;
    try {
        minified = minifyXml(xml);
    } catch (e) {
        // Fallback to unminified if parsing issue
    }
    sitemapCache.set(key, { xml: minified, timestamp: Date.now() });
    return minified;
}

/**
 * Generates the master Sitemap Index pointing to all sub-sitemaps
 */
async function generateSitemapIndex(baseUrl) {
    const cached = getCached('sitemap_index');
    if (cached) return cached;

    const sitemaps = [
        'pages',
        'mods',
        'users',
        'developers',
        'docs',
        'clubs',
        'forum',
        'licenses'
    ];

    const smi = new SitemapIndexStream();
    const readable = Readable.from(
        sitemaps.map(name => ({
            url: `${baseUrl}/sitemap-${name}.xml`,
            lastmod: new Date().toISOString()
        }))
    );

    const stream = readable.pipe(smi);
    const result = await streamToPromise(stream);
    const xml = result.toString('utf-8');

    return setCache('sitemap_index', xml);
}

/**
 * Generates the static pages and categories sitemap
 */
async function generatePagesSitemap(baseUrl) {
    const cached = getCached('sitemap_pages');
    if (cached) return cached;

    const smStream = new SitemapStream({ hostname: baseUrl });

    const staticPages = [
        { url: '/', changefreq: 'daily', priority: 1.0 },
        { url: '/about', changefreq: 'monthly', priority: 0.8 },
        { url: '/faq', changefreq: 'monthly', priority: 0.8 },
        { url: '/dmca', changefreq: 'monthly', priority: 0.6 },
        { url: '/tos', changefreq: 'monthly', priority: 0.6 },
        { url: '/privacy-policy', changefreq: 'monthly', priority: 0.6 },
        { url: '/refund-policy', changefreq: 'monthly', priority: 0.6 },
        { url: '/donate', changefreq: 'monthly', priority: 0.7 },
        { url: '/partnership-policy', changefreq: 'monthly', priority: 0.7 },
        { url: '/distributor-features', changefreq: 'monthly', priority: 0.7 },
        { url: '/why-choose-us', changefreq: 'monthly', priority: 0.8 },
        { url: '/understanding-scans', changefreq: 'monthly', priority: 0.8 },
        { url: '/membership', changefreq: 'weekly', priority: 0.9 },
        { url: '/upload-policy', changefreq: 'monthly', priority: 0.6 },
        { url: '/docs', changefreq: 'weekly', priority: 0.8 },
        { url: '/community', changefreq: 'daily', priority: 0.8 },
        { url: '/leaderboard', changefreq: 'daily', priority: 0.8 },
        { url: '/licenses', changefreq: 'monthly', priority: 0.7 },
        { url: '/request-mod', changefreq: 'weekly', priority: 0.8 },
        { url: '/ai-directory', changefreq: 'daily', priority: 0.9 }
    ];

    const categories = ['android', 'ios-jailed', 'ios-jailbroken', 'windows', 'wordpress'];
    categories.forEach(cat => {
        staticPages.push({
            url: `/category?platform=${encodeURIComponent(cat)}`,
            changefreq: 'daily',
            priority: 0.8
        });
    });

    const readable = Readable.from(staticPages);
    const result = await streamToPromise(readable.pipe(smStream));
    const xml = result.toString('utf-8');

    return setCache('sitemap_pages', xml);
}

/**
 * Generates the live Mods Sitemap with Image & Video extensions
 */
async function generateModsSitemap(baseUrl, FileModel) {
    const cached = getCached('sitemap_mods');
    if (cached) return cached;

    const smStream = new SitemapStream({ hostname: baseUrl });

    const liveMods = await FileModel.find({
        showInSitemap: { $ne: false },
        isLatestVersion: true,
        status: 'live'
    })
        .select('_id category slug name modDescription videoUrl iconKey updatedAt')
        .lean();

    const items = liveMods.map(mod => {
        const item = {
            url: `/mods/${encodeURIComponent(mod.category)}/${encodeURIComponent(mod.slug || mod._id.toString())}`,
            lastmod: mod.updatedAt ? new Date(mod.updatedAt).toISOString() : new Date().toISOString(),
            changefreq: 'daily',
            priority: 0.9
        };

        // Google Image Sitemap extension for mod icon
        if (mod.iconKey) {
            item.img = [{
                url: `${baseUrl}/download-file/${encodeURIComponent(mod.iconKey)}`,
                caption: `${mod.name} Icon`,
                title: mod.name
            }];
        }

        // Google Video Sitemap extension if YouTube link exists
        if (mod.videoUrl && (mod.videoUrl.includes('youtube.com') || mod.videoUrl.includes('youtu.be'))) {
            item.video = [{
                title: `${mod.name} Mod Video Preview`,
                description: mod.modDescription ? mod.modDescription.substring(0, 200) : mod.name,
                player_loc: mod.videoUrl
            }];
        }

        return item;
    });

    const readable = Readable.from(items);
    const result = await streamToPromise(readable.pipe(smStream));
    const xml = result.toString('utf-8');

    return setCache('sitemap_mods', xml);
}

/**
 * Clears the sitemap cache when a new mod is published or updated
 */
function invalidateSitemapCache(key) {
    if (key) {
        sitemapCache.delete(key);
    } else {
        sitemapCache.clear();
    }
}

module.exports = {
    generateSitemapIndex,
    generatePagesSitemap,
    generateModsSitemap,
    invalidateSitemapCache
};
