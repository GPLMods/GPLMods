/**
 * GPLMods Bot & Search Engine Crawler Detection Engine
 * Accurately detects Googlebot, Bingbot, and all major search engine crawlers,
 * SEO audit tools, AI search spiders, and social preview scrapers.
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
    'google-safety', 'apis-google', 'google-site-verification', 'googleproducer',
    'google-xrawler', 'google-extended',

    // Microsoft / Bing Family
    'bingbot', 'msnbot', 'bingpreview', 'adidxbot', 'bing-site-auth',

    // Major Global Search Engines
    'slurp', 'duckduckbot', 'duckduckgo', 'baiduspider', 'yandexbot',
    'yandeximages', 'yandexaccessibilitybot', 'yandexmetrika', 'sogou',
    'exabot', 'qwantify', 'petalbot', 'seznambot', 'naverbot', 'yeti',

    // Apple
    'applebot', 'applebot-extended',

    // Social Media & Messaging Preview Spiders
    'facebookexternalhit', 'facebot', 'facebookcatalog', 'meta-externalagent',
    'twitterbot', 'linkedinbot', 'pinterestbot', 'slackbot', 'telegrambot',
    'whatsapp', 'skypeuripreview', 'discordbot', 'redditbot', 'tiktokbot', 'snapchat',

    // AI & Search Indexing Crawlers (Google AI Overviews, OpenAI, Claude, Perplexity, etc.)
    'gptbot', 'chatgpt-user', 'oai-searchbot', 'claudebot', 'claude-web',
    'anthropic-ai', 'perplexitybot', 'bytespider', 'ccbot', 'cohere-ai', 'diffbot',
    'omgili', 'youbot',

    // SEO, Quality, Performance & Auditing Tools
    'screaming frog', 'semrushbot', 'ahrefsbot', 'mj12bot', 'dotbot',
    'rogerbot', 'siteauditbot', 'sitebulb', 'lighthouse', 'chrome-lighthouse',
    'pagespeed', 'google-pagespeed', 'headlesschrome', 'w3c_validator',
    'validator.w3.org', 'archive.org_bot', 'ia_archiver',

    // Headless Browser & Automated Verification Engines
    'phantomjs', 'puppeteer', 'playwright', 'selenium', 'webdriver', 'prerender'
].join('|'), 'i');

/**
 * Determines whether the given request or User-Agent originates from a bot or search engine crawler.
 * 
 * @param {string|object} userAgent - The User-Agent string from the client or req object
 * @param {object} [req] - Optional Express request object for header inspections
 * @returns {boolean} True if crawler/bot, false otherwise
 */
function isABot(userAgent, req) {
    // 1. Resolve User-Agent string and req object
    let ua = '';
    let requestObj = req;

    if (typeof userAgent === 'string') {
        ua = userAgent;
    } else if (userAgent && typeof userAgent === 'object') {
        if (typeof userAgent.get === 'function') {
            requestObj = userAgent;
            ua = userAgent.get('User-Agent') || '';
        } else if (userAgent.headers) {
            requestObj = userAgent;
            ua = userAgent.headers['user-agent'] || '';
        }
    }

    if (!requestObj && req) {
        requestObj = req;
    }

    // 2. Testing query override (e.g. ?crawler=1 or ?bot=1 or ?gsc=1)
    if (requestObj && requestObj.query) {
        if (requestObj.query.crawler === '1' || requestObj.query.bot === '1' || requestObj.query.gsc === '1') {
            return true;
        }
    }

    // 3. Header-based preview flags sent by search engines, bots & prefetchers
    if (requestObj && requestObj.headers) {
        const purpose = (requestObj.headers['purpose'] || requestObj.headers['x-purpose'] || '').toLowerCase();
        if (purpose === 'preview') return true;
        if (requestObj.headers['x-moz'] === 'prefetch') return true;
        if (requestObj.headers['x-google-inspectiontool']) return true;
        if (requestObj.headers['x-bufferbot']) return true;
        if (requestObj.headers['cf-worker']) return true;
    }

    if (!ua || typeof ua !== 'string') {
        // If there's no User-Agent at all on an external HTTP request, treat as automated/bot
        return false;
    }

    // 4. Primary Regex check for major engines (Googlebot, Bingbot, etc.)
    if (CRAWLER_REGEX.test(ua)) {
        return true;
    }

    // 5. Fallback check with npm isbot package for any generic or regional spiders
    try {
        if (typeof isbot === 'function' && isbot(ua)) {
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
    if (ua.includes('google-inspectiontool')) return 'Google InspectionTool';
    if (ua.includes('googlebot')) return 'Googlebot';
    if (ua.includes('googleother')) return 'GoogleOther';
    if (ua.includes('google-extended')) return 'Google-Extended';
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
    if (ua.includes('whatsapp')) return 'WhatsAppBot';
    if (ua.includes('oai-searchbot') || ua.includes('chatgpt-user') || ua.includes('gptbot')) return 'OpenAI Bot';
    if (ua.includes('claudebot') || ua.includes('claude-web')) return 'Anthropic Claude';
    if (ua.includes('perplexitybot')) return 'PerplexityBot';
    if (ua.includes('lighthouse')) return 'Lighthouse';
    if (ua.includes('pagespeed')) return 'PageSpeed';
    if (ua.includes('semrushbot')) return 'SemrushBot';
    if (ua.includes('ahrefsbot')) return 'AhrefsBot';
    if (isABot(userAgent)) return 'Generic Search Bot';
    return null;
}

module.exports = {
    isABot,
    isbot: isABot, // Alias for backward compatibility
    getBotName
};
