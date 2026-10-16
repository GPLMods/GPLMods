/**
 * GPLMods Bot & Search Engine Crawler Detection Engine
 * Accurately detects Googlebot, Bingbot, and all major search engine crawlers,
 * SEO audit tools, and social preview scrapers.
 * 
 * Ensures bots have 100% clean, unobstructed access to:
 * - HTML page content and metadata
 * - CSS stylesheets, JavaScript files, and fonts
 * - XML Sitemaps and robots.txt
 * - Debugger exemption (no disable-devtool traps or debugger modals)
 * - Zero intrusive banners, ad overlays, or anti-adblock modals
 */

const { isbot } = require('isbot');

// Comprehensive pattern covering all primary search engines, AI spiders, SEO crawlers, and headless tools
const CRAWLER_REGEX = new RegExp([
    // Google Family
    'googlebot', 'googlebot-image', 'googlebot-news', 'googlebot-video',
    'google-inspectiontool', 'storebot-google', 'googleother', 'adsbot-google',
    'feedfetcher-google', 'mediapartners-google', 'google-read-aloud',

    // Microsoft / Bing Family
    'bingbot', 'msnbot', 'bingpreview', 'adidxbot', 'bing-site-auth',

    // Major Global Search Engines
    'slurp', 'duckduckbot', 'duckduckgo', 'baiduspider', 'yandexbot',
    'yandeximages', 'yandexaccessibilitybot', 'yandexmetrika', 'sogou',
    'exabot', 'qwantify', 'petalbot', 'seznambot', 'naverbot', 'yeti',

    // Apple
    'applebot', 'applebot-extended',

    // Social Media & Messaging Preview Spiders
    'facebookexternalhit', 'facebot', 'facebookcatalog', 'twitterbot',
    'linkedinbot', 'pinterestbot', 'slackbot', 'telegrambot', 'whatsapp',
    'skypeuripreview', 'discordbot', 'redditbot', 'tiktokbot', 'snapchat',

    // AI & Search Indexing Crawlers
    'gptbot', 'chatgpt-user', 'oai-searchbot', 'claudebot', 'claude-web',
    'anthropic-ai', 'perplexitybot', 'bytespider', 'ccbot', 'cohere-ai', 'diffbot',

    // SEO, Quality, Performance & Auditing Tools
    'screaming frog', 'semrushbot', 'ahrefsbot', 'mj12bot', 'dotbot',
    'rogerbot', 'siteauditbot', 'sitebulb', 'lighthouse', 'chrome-lighthouse',
    'pagespeed', 'google-pagespeed', 'headlesschrome', 'w3c_validator',
    'validator.w3.org', 'archive.org_bot', 'ia_archiver'
].join('|'), 'i');

/**
 * Determines whether the given request or User-Agent originates from a bot or search engine crawler.
 * 
 * @param {string} userAgent - The User-Agent string from the client
 * @param {object} [req] - Optional Express request object for header inspections
 * @returns {boolean} True if crawler/bot, false otherwise
 */
function isABot(userAgent, req) {
    // 1. Resolve User-Agent string
    let ua = '';
    if (typeof userAgent === 'string') {
        ua = userAgent;
    } else if (req && typeof req.get === 'function') {
        ua = req.get('User-Agent') || '';
    } else if (userAgent && typeof userAgent === 'object' && userAgent.headers) {
        ua = userAgent.headers['user-agent'] || '';
    }

    // 2. Testing query override (e.g. ?crawler=1 or ?bot=1)
    if (req && req.query && (req.query.crawler === '1' || req.query.bot === '1')) {
        return true;
    }

    // 3. Header-based preview flags sent by bots & prefetchers
    if (req && req.headers) {
        const purpose = (req.headers['purpose'] || req.headers['x-purpose'] || '').toLowerCase();
        if (purpose === 'preview') return true;
        if (req.headers['x-moz'] === 'prefetch') return true;
    }

    if (!ua || typeof ua !== 'string') return false;

    // 4. Primary Regex check for major engines (Googlebot, Bingbot, etc.)
    if (CRAWLER_REGEX.test(ua)) {
        return true;
    }

    // 5. Fallback check with npm isbot package for any generic or regional spiders
    try {
        if (isbot(ua)) {
            return true;
        }
    } catch (e) {
        // Fall open if isbot throws
    }

    return false;
}

/**
 * Helper to identify the specific bot name for logging and diagnostics
 * 
 * @param {string} userAgent 
 * @returns {string|null}
 */
function getBotName(userAgent) {
    if (!userAgent || typeof userAgent !== 'string') return null;
    const ua = userAgent.toLowerCase();
    if (ua.includes('googlebot')) return 'Googlebot';
    if (ua.includes('google-inspectiontool')) return 'Google InspectionTool';
    if (ua.includes('googleother')) return 'GoogleOther';
    if (ua.includes('bingbot')) return 'Bingbot';
    if (ua.includes('bingpreview')) return 'BingPreview';
    if (ua.includes('duckduckbot')) return 'DuckDuckBot';
    if (ua.includes('baiduspider')) return 'Baiduspider';
    if (ua.includes('yandexbot')) return 'YandexBot';
    if (ua.includes('slurp')) return 'Yahoo Slurp';
    if (ua.includes('applebot')) return 'Applebot';
    if (ua.includes('twitterbot')) return 'Twitterbot';
    if (ua.includes('facebookexternalhit')) return 'FacebookBot';
    if (ua.includes('discordbot')) return 'Discordbot';
    if (ua.includes('telegrambot')) return 'TelegramBot';
    if (ua.includes('lighthouse')) return 'Lighthouse';
    if (ua.includes('semrushbot')) return 'SemrushBot';
    if (ua.includes('ahrefsbot')) return 'AhrefsBot';
    if (isABot(userAgent)) return 'Generic Search Bot';
    return null;
}

module.exports = {
    isABot,
    isbot: isABot, // Alias for backward compatibility with isbot library calls
    getBotName
};
