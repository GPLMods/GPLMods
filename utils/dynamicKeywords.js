/**
 * GPLMods Dynamic Keyword Harvester & Multi-Engine Suggestion System
 * 
 * Capabilities:
 * 1. Live Mod Harvester: Queries active database mods and synthesizes high-intent search queries
 *    (e.g., "gplmods [name]", "[name] mod apk download", "[name] safe free download").
 * 2. Unspaced Brand Dominance: Hardwires unspaced "gplmods", "gplmods apk", "gplmods site", "gplmods.webredirect.org"
 *    so search engines index and rank the brand without spaces.
 * 3. Multi-Engine Autocomplete API Integration:
 *    - Google Suggest / Autocomplete API (`suggestqueries.google.com`)
 *    - DuckDuckGo Suggest API (`duckduckgo.com/ac`)
 * 4. International Regional Keywords: Synthesizes multilingual search phrases across Spanish,
 *    Portuguese, Russian, Indonesian, French, German, Arabic, Hindi, Japanese, Korean, Vietnamese, Turkish.
 * 5. Google Search Console Query Integration: Ingests real user search queries from Search Console API.
 * 6. Dynamic Page Enrichment: Injects fresh keywords into every public page during SSR.
 */

const axios = require('axios');

// In-Memory Keyword State & Caches
let liveModKeywords = [];
let liveModNames = [];
let googleSuggestKeywords = [];
let ddgSuggestKeywords = [];
let searchConsoleLiveQueries = [];
let lastHarvestTimestamp = 0;
let isHarvesting = false;

// Global Unspaced Brand Variants (Guarantees unspaced queries index #1)
const UNSPACED_BRAND_KEYWORDS = [
    'gplmods',
    'gplmods apk',
    'gplmods mod apk',
    'gplmods download',
    'gplmods free mods',
    'gplmods app',
    'gplmods site',
    'gplmods.webredirect.org',
    'gplmods official',
    'gplmods safe download',
    'gplmods store',
    'gplmods hub',
    'gplmods games',
    'gplmods ipa',
    'gplmods ios',
    'gplmods windows',
    'gplmods android',
    'gplmods wordpress',
    'gplmods virustotal',
    'gplmods 2026',
    'gplmod',
    'gpl-mods',
    'GPLMods',
    'GPL Mods'
];

// Multilingual Global Regional Keywords (Ensures ranking across every country & region)
const GLOBAL_REGIONAL_KEYWORDS = [
    // Spanish (Spain, Mexico, Latin America)
    'gplmods descargar',
    'gplmods descargar gratis',
    'gplmods mod apk',
    'gplmods juegos hackeados',
    'gplmods aplicaciones premium gratis',
    'descargar mods seguros gplmods',

    // Portuguese (Brazil, Portugal)
    'gplmods baixar',
    'gplmods baixar gratis',
    'gplmods mod apk atualizado',
    'gplmods jogos modificados',
    'gplmods apps desbloqueados',
    'baixar apk seguro gplmods',

    // Russian (Russia, Kazakhstan, Belarus, CIS)
    'gplmods скачать',
    'gplmods скачать бесплатно',
    'gplmods взломанные игры',
    'gplmods мод апк',
    'gplmods премиум приложения',
    'безопасные моды gplmods',

    // Indonesian (Indonesia, Southeast Asia)
    'gplmods unduh',
    'gplmods download apk mod',
    'gplmods gratis',
    'gplmods game modifikasi',
    'gplmods aplikasi premium',
    'situs mod aman gplmods',

    // French (France, Canada, Belgium, Africa)
    'gplmods telecharger',
    'gplmods telecharger gratuit',
    'gplmods jeux modifies',
    'gplmods applications premium gratuit',
    'telecharger apk securise gplmods',

    // German (Germany, Austria, Switzerland)
    'gplmods kostenlos herunterladen',
    'gplmods mod apk download',
    'gplmods freigeschaltete apps',
    'sichere mod downloads gplmods',

    // Hindi (India, South Asia)
    'gplmods apk download',
    'gplmods free mod game',
    'gplmods safe download kare',
    'gplmods best app',

    // Arabic (MENA, Middle East)
    'تحميل gplmods',
    'تنزيل gplmods مجانا',
    'تطبيقات مهكرة gplmods',
    'العاب مهكرة gplmods',

    // Japanese (Japan)
    'gplmods ダウンロード',
    'gplmods 無料',
    'gplmods mod apk',
    'gplmods 安全なアプリ',

    // Korean (South Korea)
    'gplmods 다운로드',
    'gplmods 무료',
    'gplmods 모드 apk',
    'gplmods 안전한 다운로드',

    // Turkish (Turkey)
    'gplmods indir',
    'gplmods ucretsiz indir',
    'gplmods hileli apk',
    'gplmods guvenli mod',

    // Vietnamese (Vietnam)
    'gplmods tai ve',
    'gplmods mien phi',
    'gplmods apk mod',
    'gplmods game mod'
];

/**
 * Normalizes keyword string (lowercase, trim, remove excessive spaces)
 */
function cleanKeyword(kw) {
    if (!kw || typeof kw !== 'string') return '';
    return kw.trim().replace(/\s+/g, ' ');
}

/**
 * Harvests autocomplete suggestions from Google Search Suggest API
 * @param {string} query 
 * @returns {Promise<string[]>}
 */
async function fetchGoogleSuggest(query) {
    try {
        const url = `https://suggestqueries.google.com/complete/search?client=firefox&hl=en&q=${encodeURIComponent(query)}`;
        const res = await axios.get(url, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
            },
            timeout: 4500
        });

        if (Array.isArray(res.data) && Array.isArray(res.data[1])) {
            return res.data[1].map(cleanKeyword).filter(Boolean);
        }
        return [];
    } catch (err) {
        return [];
    }
}

/**
 * Harvests autocomplete suggestions from DuckDuckGo Suggest API
 * @param {string} query 
 * @returns {Promise<string[]>}
 */
async function fetchDuckDuckGoSuggest(query) {
    try {
        const url = `https://duckduckgo.com/ac/?q=${encodeURIComponent(query)}&type=list`;
        const res = await axios.get(url, {
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
            },
            timeout: 4500
        });

        if (Array.isArray(res.data) && Array.isArray(res.data[1])) {
            return res.data[1].map(cleanKeyword).filter(Boolean);
        }
        return [];
    } catch (err) {
        return [];
    }
}

/**
 * Generates rich search queries for a live mod document
 */
function generateKeywordsForMod(mod) {
    if (!mod || !mod.name) return [];
    const name = mod.name.trim();
    const lowerName = name.toLowerCase();
    const cat = (mod.category || 'android').toLowerCase();

    const keywords = [
        // Unspaced brand + mod name queries
        `gplmods ${lowerName}`,
        `${lowerName} gplmods`,
        `gplmods ${lowerName} download`,
        `gplmods ${lowerName} mod apk`,
        `gplmods ${lowerName} free`,

        // Core high-volume search queries
        `${lowerName} mod apk`,
        `${lowerName} mod apk download`,
        `${lowerName} mod apk latest version`,
        `${lowerName} premium unlocked`,
        `${lowerName} pro mod apk`,
        `${lowerName} hack apk download`,
        `${lowerName} safe download`,
        `${lowerName} virustotal clean`,
        `${lowerName} free download`
    ];

    if (mod.version) {
        keywords.push(`${lowerName} v${mod.version} mod apk`);
        keywords.push(`${lowerName} ${mod.version} download`);
    }

    if (cat.includes('ios')) {
        keywords.push(`${lowerName} ipa`);
        keywords.push(`${lowerName} ipa download`);
        keywords.push(`${lowerName} ios sideload`);
        keywords.push(`${lowerName} scarlet repo`);
        keywords.push(`${lowerName} esign ipa`);
        keywords.push(`${lowerName} trollstore ipa`);
    } else if (cat === 'windows') {
        keywords.push(`${lowerName} pc download`);
        keywords.push(`${lowerName} windows unlocked`);
        keywords.push(`${lowerName} pc mod`);
    } else if (cat === 'wordpress') {
        keywords.push(`${lowerName} gpl free`);
        keywords.push(`${lowerName} wordpress theme gpl`);
        keywords.push(`${lowerName} wordpress plugin gpl`);
    }

    if (Array.isArray(mod.tags)) {
        mod.tags.forEach(t => {
            if (t && typeof t === 'string') {
                keywords.push(`${lowerName} ${t.toLowerCase()}`);
            }
        });
    }

    return keywords.map(cleanKeyword).filter(Boolean);
}

/**
 * Queries MongoDB for live mods and builds compound keyword matrices
 */
async function harvestLiveModsKeywords(FileModel) {
    if (!FileModel) return [];

    try {
        const liveMods = await FileModel.find({
            status: 'live',
            isLatestVersion: { $ne: false }
        })
            .select('name slug category tags version downloads averageRating')
            .sort({ downloads: -1, averageRating: -1 })
            .limit(120)
            .lean();

        if (!Array.isArray(liveMods) || liveMods.length === 0) {
            return [];
        }

        liveModNames = liveMods.map(m => m.name).filter(Boolean);

        const modKeywordsSet = new Set();
        liveMods.forEach(mod => {
            const kws = generateKeywordsForMod(mod);
            kws.forEach(kw => modKeywordsSet.add(kw));
        });

        liveModKeywords = Array.from(modKeywordsSet);
        return liveModKeywords;
    } catch (err) {
        console.warn('[Dynamic Keywords] Failed to harvest live mods:', err.message);
        return liveModKeywords;
    }
}

/**
 * Harvests Google & DuckDuckGo Suggest API autocomplete queries
 */
async function harvestSearchSuggestKeywords(seedList = []) {
    const seeds = [
        'gplmods',
        'gplmods apk',
        'gpl mods',
        'gplmod',
        'mod apk',
        'mod apk download',
        'happymod alternative safe',
        'ios ipa mod',
        'free premium unlocked apk',
        ...seedList.slice(0, 10)
    ];

    const googleResults = new Set();
    const ddgResults = new Set();

    // Query both search engines concurrently with rate pacing
    for (const seed of seeds) {
        try {
            const [gList, dList] = await Promise.all([
                fetchGoogleSuggest(seed),
                fetchDuckDuckGoSuggest(seed)
            ]);

            gList.forEach(k => googleResults.add(k));
            dList.forEach(k => ddgResults.add(k));
        } catch (_) {}
    }

    googleSuggestKeywords = Array.from(googleResults);
    ddgSuggestKeywords = Array.from(ddgResults);

    return {
        google: googleSuggestKeywords,
        duckduckgo: ddgSuggestKeywords
    };
}

/**
 * Integrates Google Search Console live search queries if configured
 */
async function harvestSearchConsoleQueries(searchConsoleModule, baseUrl) {
    if (!searchConsoleModule || typeof searchConsoleModule.getSearchAnalytics !== 'function') {
        return [];
    }

    try {
        const analytics = await searchConsoleModule.getSearchAnalytics(baseUrl, { rowLimit: 100 });
        if (analytics && Array.isArray(analytics.queries) && analytics.queries.length > 0) {
            searchConsoleLiveQueries = analytics.queries.map(q => q.query).filter(Boolean);
        }
        return searchConsoleLiveQueries;
    } catch (err) {
        return searchConsoleLiveQueries;
    }
}

/**
 * Runs the full keyword harvest workflow:
 * 1. Live mods extraction from database
 * 2. Autocomplete suggestions from Google & DuckDuckGo
 * 3. Search Console live query sync
 * 4. Merging with unspaced brand and global regional keywords
 */
async function runKeywordHarvest(FileModel, searchConsoleModule, baseUrl) {
    if (isHarvesting) return;
    isHarvesting = true;

    try {
        // Step 1: Live mods from database
        await harvestLiveModsKeywords(FileModel);

        // Step 2: Autocomplete APIs using top live mod names as seeds
        const topModNames = liveModNames.slice(0, 8);
        await harvestSearchSuggestKeywords(topModNames);

        // Step 3: Google Search Console real-time queries
        if (searchConsoleModule) {
            await harvestSearchConsoleQueries(searchConsoleModule, baseUrl);
        }

        lastHarvestTimestamp = Date.now();
        console.log(`[Dynamic Keywords] Harvested: ${liveModNames.length} live mods, ${liveModKeywords.length} mod keywords, ${googleSuggestKeywords.length} Google suggest queries, ${ddgSuggestKeywords.length} DDG queries.`);
    } catch (err) {
        console.error('[Dynamic Keywords] Harvest error:', err.message);
    } finally {
        isHarvesting = false;
    }
}

/**
 * Starts periodic automated keyword harvesting (runs every intervalMs)
 */
function startKeywordHarvester(FileModel, searchConsoleModule, baseUrl, intervalMs = 30 * 60 * 1000) {
    // Initial harvest after short delay for server startup
    setTimeout(() => {
        runKeywordHarvest(FileModel, searchConsoleModule, baseUrl);
    }, 5000);

    // Periodic interval
    const timer = setInterval(() => {
        runKeywordHarvest(FileModel, searchConsoleModule, baseUrl);
    }, intervalMs);

    if (timer && timer.unref) {
        timer.unref();
    }

    return timer;
}

/**
 * Dynamically resolves keywords for any public page.
 * Combines:
 * - Unspaced brand keywords ("gplmods", "gplmods apk")
 * - Specific mod / category keywords if present
 * - Top trending live mod keywords
 * - Real-time Google & DDG search suggestions
 * - Global international regional keywords
 * 
 * @param {string} routePath
 * @param {object} locals
 * @returns {string} Comma-separated keyword list
 */
function getDynamicKeywordsForPage(routePath, locals = {}) {
    const keywordSet = new Set();

    // 1. Always prioritize unspaced brand terms
    UNSPACED_BRAND_KEYWORDS.forEach(k => keywordSet.add(k));

    // 2. If entity is a mod, inject its custom keywords first
    if (locals.file || locals.masterFile) {
        const mod = locals.file || locals.masterFile;
        const modKws = generateKeywordsForMod(mod);
        modKws.forEach(k => keywordSet.add(k));
    }

    // 3. Category-specific keywords
    if (routePath.startsWith('/category') || (locals.category && typeof locals.category === 'string')) {
        const cat = (locals.category || '').toLowerCase();
        keywordSet.add(`gplmods ${cat}`);
        keywordSet.add(`${cat} mods gplmods`);
        keywordSet.add(`download ${cat} mods`);
    }

    // 4. Inject top trending live mods from DB (up to 12)
    const sampleModKeywords = liveModKeywords.slice(0, 16);
    sampleModKeywords.forEach(k => keywordSet.add(k));

    // 5. Inject Google Suggest autocomplete queries (up to 8)
    const sampleGoogleKeywords = googleSuggestKeywords.slice(0, 10);
    sampleGoogleKeywords.forEach(k => keywordSet.add(k));

    // 6. Inject Search Console live queries if available
    const sampleGscQueries = searchConsoleLiveQueries.slice(0, 8);
    sampleGscQueries.forEach(k => keywordSet.add(k));

    // 7. Inject global regional keywords for international search engine coverage (up to 12)
    const sampleRegional = GLOBAL_REGIONAL_KEYWORDS.slice(0, 14);
    sampleRegional.forEach(k => keywordSet.add(k));

    return Array.from(keywordSet).slice(0, 45).join(', ');
}

/**
 * Returns current snapshot of all harvested keywords
 */
function getKeywordState() {
    return {
        liveModCount: liveModNames.length,
        liveModKeywordsCount: liveModKeywords.length,
        googleSuggestCount: googleSuggestKeywords.length,
        ddgSuggestCount: ddgSuggestKeywords.length,
        gscQueriesCount: searchConsoleLiveQueries.length,
        lastHarvest: lastHarvestTimestamp ? new Date(lastHarvestTimestamp).toISOString() : null,
        topLiveMods: liveModNames.slice(0, 15),
        sampleKeywords: liveModKeywords.slice(0, 20)
    };
}

module.exports = {
    UNSPACED_BRAND_KEYWORDS,
    GLOBAL_REGIONAL_KEYWORDS,
    fetchGoogleSuggest,
    fetchDuckDuckGoSuggest,
    generateKeywordsForMod,
    harvestLiveModsKeywords,
    harvestSearchSuggestKeywords,
    harvestSearchConsoleQueries,
    runKeywordHarvest,
    startKeywordHarvester,
    getDynamicKeywordsForPage,
    getKeywordState
};
