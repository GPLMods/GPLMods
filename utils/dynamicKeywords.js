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
// Full Form Variants of GPL Mods (General Public License Modify / Modifications / Mods)
const FULL_FORM_GPL_MODS = [
    'General Public License Modify',
    'general public license modify',
    'GENERAL PUBLIC LICENSE MODIFY',
    'GeneralPublicLicenseModify',
    'generalpubliclicensemodify',
    'GENERALPUBLICLICENSEMODIFY',
    'General Public License Modifications',
    'general public license modifications',
    'GENERAL PUBLIC LICENSE MODIFICATIONS',
    'GeneralPublicLicenseModifications',
    'generalpubliclicensemodifications',
    'General Public License Mods',
    'general public license mods',
    'GENERAL PUBLIC LICENSE MODS',
    'GeneralPublicLicenseMods',
    'generalpubliclicensemods',
    'General Public License Mod',
    'general public license mod',
    'GeneralPublicLicenseMod',
    'generalpubliclicensemod',
    'General Public License',
    'general public license',
    'GENERAL PUBLIC LICENSE',
    'GeneralPublicLicense',
    'generalpubliclicense',
    'General Public Licence Modify',
    'general public licence modify',
    'GeneralPublicLicenceModify',
    'general public lisance modify',
    'generalpubliclisancemodify',
    'GPL Mods',
    'gpl mods',
    'GPL MODS',
    'GPLMods',
    'gplmods',
    'GPLMODS',
    'gpl-mods',
    'GPL-Mods'
];

/**
 * Expands any tag into space, no-space, uppercase, lowercase, and title-case variants.
 */
function expandTagVariations(tag) {
    if (!tag || typeof tag !== 'string') return [];
    const trimmed = tag.trim();
    if (!trimmed) return [];

    const variations = new Set();
    variations.add(trimmed);
    variations.add(trimmed.toLowerCase());
    variations.add(trimmed.toUpperCase());
    variations.add(trimmed.replace(/\b\w/g, c => c.toUpperCase()));

    // No space
    const noSpace = trimmed.replace(/\s+/g, '');
    if (noSpace !== trimmed) {
        variations.add(noSpace);
        variations.add(noSpace.toLowerCase());
        variations.add(noSpace.toUpperCase());
    }

    // Spaced if hyphenated or underscored
    if (trimmed.includes('-') || trimmed.includes('_')) {
        const spaced = trimmed.replace(/[-_]+/g, ' ');
        variations.add(spaced);
        variations.add(spaced.toLowerCase());
        variations.add(spaced.toUpperCase());
    }

    // CamelCase spaced
    const camelSpaced = trimmed.replace(/([a-z])([A-Z])/g, '$1 $2');
    if (camelSpaced !== trimmed) {
        variations.add(camelSpaced);
        variations.add(camelSpaced.toLowerCase());
        variations.add(camelSpaced.toUpperCase());
    }

    return Array.from(variations);
}

// Global Unspaced Brand Variants & Full Forms (Guarantees indexing for all permutations)
const UNSPACED_BRAND_KEYWORDS = [
    ...FULL_FORM_GPL_MODS,
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

    const nameVariations = expandTagVariations(name);
    const keywords = [
        // Brand + mod queries with full form
        `gplmods ${lowerName}`,
        `gpl mods ${lowerName}`,
        `General Public License Modify ${name}`,
        `general public license modify ${lowerName}`,
        `${lowerName} gplmods`,
        `${lowerName} gpl mods`,
        `gplmods ${lowerName} download`,
        `gplmods ${lowerName} mod apk`,
        `gplmods ${lowerName} free`,

        // Core search queries
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

    // Add name variations (uppercase, lowercase, unspaced, spaced)
    nameVariations.forEach(v => {
        keywords.push(v);
        keywords.push(`${v} mod`);
        keywords.push(`${v} download`);
    });

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
                const tagVars = expandTagVariations(t);
                tagVars.forEach(tv => {
                    keywords.push(tv);
                    keywords.push(`${lowerName} ${tv.toLowerCase()}`);
                });
            }
        });
    }

    return Array.from(new Set(keywords.map(cleanKeyword).filter(Boolean)));
}

// 7 Days Cache TTL
const KEYWORD_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

function getKeywordCacheModel() {
    try {
        return require('../models/keywordCache');
    } catch (_) {
        return null;
    }
}

/**
 * Loads cached keywords from MongoDB on server startup so no external API calls are made for existing data.
 */
async function loadKeywordsFromDbCache(FileModel = null) {
    try {
        const KeywordCache = getKeywordCacheModel();
        if (!KeywordCache) return false;

        const cachedEntries = await KeywordCache.find({}).lean();
        let loadedGoogle = [];
        let loadedDdg = [];
        let loadedGsc = [];
        const loadedModKws = new Set(liveModKeywords);

        for (const entry of cachedEntries) {
            if (entry.type === 'google_suggest' && Array.isArray(entry.keywords)) {
                entry.keywords.forEach(k => loadedGoogle.push(k));
            } else if (entry.type === 'ddg_suggest' && Array.isArray(entry.keywords)) {
                entry.keywords.forEach(k => loadedDdg.push(k));
            } else if (entry.type === 'search_console' && Array.isArray(entry.keywords)) {
                entry.keywords.forEach(k => loadedGsc.push(k));
            } else if (entry.type === 'mod_keywords' && Array.isArray(entry.keywords)) {
                entry.keywords.forEach(k => loadedModKws.add(k));
            }
        }

        if (loadedGoogle.length > 0) googleSuggestKeywords = Array.from(new Set(loadedGoogle));
        if (loadedDdg.length > 0) ddgSuggestKeywords = Array.from(new Set(loadedDdg));
        if (loadedGsc.length > 0) searchConsoleLiveQueries = Array.from(new Set(loadedGsc));
        if (loadedModKws.size > 0) liveModKeywords = Array.from(loadedModKws);

        if (FileModel) {
            const filesWithKws = await FileModel.find({
                status: 'live',
                dynamicKeywords: { $exists: true, $not: { $size: 0 } }
            }).select('name dynamicKeywords').lean();

            const names = new Set(liveModNames);
            filesWithKws.forEach(f => {
                if (f.name) names.add(f.name);
                if (Array.isArray(f.dynamicKeywords)) {
                    f.dynamicKeywords.forEach(k => loadedModKws.add(k));
                }
            });
            liveModNames = Array.from(names);
            liveModKeywords = Array.from(loadedModKws);
        }

        console.log(`[Dynamic Keywords Cache] Loaded from DB on server startup: ${liveModKeywords.length} mod keywords, ${googleSuggestKeywords.length} Google suggest queries, ${ddgSuggestKeywords.length} DDG queries, ${searchConsoleLiveQueries.length} GSC queries.`);
        return true;
    } catch (err) {
        console.warn('[Dynamic Keywords Cache] Error loading cached keywords on startup:', err.message);
        return false;
    }
}

/**
 * Queries MongoDB for live mods and builds compound keyword matrices with 7-day database caching.
 */
async function harvestLiveModsKeywords(FileModel) {
    if (!FileModel) return [];

    try {
        const KeywordCache = getKeywordCacheModel();
        const now = Date.now();
        const sevenDaysAgo = new Date(now - KEYWORD_CACHE_TTL_MS);

        const liveMods = await FileModel.find({
            status: 'live',
            isLatestVersion: { $ne: false }
        })
            .select('name slug category tags version downloads averageRating dynamicKeywords keywordsLastFetchedAt')
            .sort({ downloads: -1, averageRating: -1 })
            .limit(120)
            .lean();

        if (!Array.isArray(liveMods) || liveMods.length === 0) {
            return [];
        }

        liveModNames = liveMods.map(m => m.name).filter(Boolean);
        const modKeywordsSet = new Set(liveModKeywords);

        for (const mod of liveMods) {
            // Check if keywords already cached in File doc or KeywordCache within last 7 days
            const isFreshInMod = mod.keywordsLastFetchedAt && (now - new Date(mod.keywordsLastFetchedAt).getTime()) < KEYWORD_CACHE_TTL_MS;
            if (isFreshInMod && Array.isArray(mod.dynamicKeywords) && mod.dynamicKeywords.length > 0) {
                // Re-use cached keywords without re-generating
                mod.dynamicKeywords.forEach(kw => modKeywordsSet.add(kw));
                continue;
            }

            // Check KeywordCache collection
            let cachedDoc = null;
            if (KeywordCache) {
                cachedDoc = await KeywordCache.findOne({ modId: mod._id, type: 'mod_keywords', lastFetchedAt: { $gte: sevenDaysAgo } }).lean();
            }

            if (cachedDoc && Array.isArray(cachedDoc.keywords) && cachedDoc.keywords.length > 0) {
                cachedDoc.keywords.forEach(kw => modKeywordsSet.add(kw));
                continue;
            }

            // Generate keywords only for mods missing cache or older than 7 days
            const kws = generateKeywordsForMod(mod);
            kws.forEach(kw => modKeywordsSet.add(kw));

            // Store in database cache with lastFetchedAt timestamp
            if (KeywordCache) {
                await KeywordCache.findOneAndUpdate(
                    { modId: mod._id, type: 'mod_keywords' },
                    {
                        key: `mod_${mod._id}`,
                        modId: mod._id,
                        type: 'mod_keywords',
                        keywords: kws,
                        lastFetchedAt: new Date()
                    },
                    { upsert: true, new: true }
                ).catch(() => {});
            }

            await FileModel.findByIdAndUpdate(mod._id, {
                dynamicKeywords: kws,
                keywordsLastFetchedAt: new Date()
            }).catch(() => {});
        }

        liveModKeywords = Array.from(modKeywordsSet);
        return liveModKeywords;
    } catch (err) {
        console.warn('[Dynamic Keywords] Failed to harvest live mods:', err.message);
        return liveModKeywords;
    }
}

/**
 * Harvests Google & DuckDuckGo Suggest API autocomplete queries with 7-day database caching.
 */
async function harvestSearchSuggestKeywords(seedList = []) {
    const KeywordCache = getKeywordCacheModel();
    const now = Date.now();
    const sevenDaysAgo = new Date(now - KEYWORD_CACHE_TTL_MS);

    // Check if Google and DDG suggestions are already cached in DB within 7 days
    if (KeywordCache) {
        const cachedGoogle = await KeywordCache.findOne({ key: 'google_suggest_global', lastFetchedAt: { $gte: sevenDaysAgo } }).lean();
        const cachedDdg = await KeywordCache.findOne({ key: 'ddg_suggest_global', lastFetchedAt: { $gte: sevenDaysAgo } }).lean();

        let usedCache = false;
        if (cachedGoogle && Array.isArray(cachedGoogle.keywords) && cachedGoogle.keywords.length > 0) {
            googleSuggestKeywords = cachedGoogle.keywords;
            usedCache = true;
        }
        if (cachedDdg && Array.isArray(cachedDdg.keywords) && cachedDdg.keywords.length > 0) {
            ddgSuggestKeywords = cachedDdg.keywords;
            usedCache = true;
        }
        if (usedCache && cachedGoogle && cachedDdg) {
            return { google: googleSuggestKeywords, duckduckgo: ddgSuggestKeywords };
        }
    }

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

    const googleResults = new Set(googleSuggestKeywords);
    const ddgResults = new Set(ddgSuggestKeywords);

    // Query search engines only when cache is expired or missing
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

    // Persist to MongoDB cache with 7-day TTL
    if (KeywordCache) {
        await Promise.all([
            KeywordCache.findOneAndUpdate(
                { key: 'google_suggest_global' },
                {
                    key: 'google_suggest_global',
                    type: 'google_suggest',
                    keywords: googleSuggestKeywords,
                    lastFetchedAt: new Date()
                },
                { upsert: true, new: true }
            ).catch(() => {}),
            KeywordCache.findOneAndUpdate(
                { key: 'ddg_suggest_global' },
                {
                    key: 'ddg_suggest_global',
                    type: 'ddg_suggest',
                    keywords: ddgSuggestKeywords,
                    lastFetchedAt: new Date()
                },
                { upsert: true, new: true }
            ).catch(() => {})
        ]);
    }

    return {
        google: googleSuggestKeywords,
        duckduckgo: ddgSuggestKeywords
    };
}

/**
 * Integrates Google Search Console live search queries with 7-day database caching.
 */
async function harvestSearchConsoleQueries(searchConsoleModule, baseUrl) {
    if (!searchConsoleModule || typeof searchConsoleModule.getSearchAnalytics !== 'function') {
        return searchConsoleLiveQueries;
    }

    const KeywordCache = getKeywordCacheModel();
    const now = Date.now();
    const sevenDaysAgo = new Date(now - KEYWORD_CACHE_TTL_MS);

    // Check DB cache for Search Console queries within 7 days
    if (KeywordCache) {
        const cachedGsc = await KeywordCache.findOne({ key: 'search_console_live_queries', lastFetchedAt: { $gte: sevenDaysAgo } }).lean();
        if (cachedGsc && Array.isArray(cachedGsc.keywords) && cachedGsc.keywords.length > 0) {
            searchConsoleLiveQueries = cachedGsc.keywords;
            return searchConsoleLiveQueries;
        }
    }

    try {
        const analytics = await searchConsoleModule.getSearchAnalytics(baseUrl, { rowLimit: 100 });
        if (analytics && Array.isArray(analytics.queries) && analytics.queries.length > 0) {
            searchConsoleLiveQueries = analytics.queries.map(q => q.query).filter(Boolean);

            if (KeywordCache) {
                await KeywordCache.findOneAndUpdate(
                    { key: 'search_console_live_queries' },
                    {
                        key: 'search_console_live_queries',
                        type: 'search_console',
                        keywords: searchConsoleLiveQueries,
                        lastFetchedAt: new Date()
                    },
                    { upsert: true, new: true }
                ).catch(() => {});
            }
        }
        return searchConsoleLiveQueries;
    } catch (err) {
        return searchConsoleLiveQueries;
    }
}

/**
 * Runs the full keyword harvest workflow:
 * 1. Checks 7-day database cache first
 * 2. Live mods extraction from database (caches per mod for 7 days)
 * 3. Autocomplete suggestions from Google & DuckDuckGo (cached for 7 days)
 * 4. Search Console live query sync (cached for 7 days)
 */
async function runKeywordHarvest(FileModel, searchConsoleModule, baseUrl, forceRefresh = false) {
    if (isHarvesting) return;
    isHarvesting = true;

    try {
        // Step 1: Live mods from database (re-uses 7-day cache)
        await harvestLiveModsKeywords(FileModel);

        // Step 2: Autocomplete APIs using top live mod names as seeds (re-uses 7-day cache)
        const topModNames = liveModNames.slice(0, 8);
        await harvestSearchSuggestKeywords(topModNames);

        // Step 3: Google Search Console real-time queries (re-uses 7-day cache)
        if (searchConsoleModule) {
            await harvestSearchConsoleQueries(searchConsoleModule, baseUrl);
        }

        lastHarvestTimestamp = Date.now();
        console.log(`[Dynamic Keywords] Active keyword pools: ${liveModNames.length} live mods, ${liveModKeywords.length} mod keywords, ${googleSuggestKeywords.length} Google suggest queries, ${ddgSuggestKeywords.length} DDG queries.`);
    } catch (err) {
        console.error('[Dynamic Keywords] Harvest error:', err.message);
    } finally {
        isHarvesting = false;
    }
}

/**
 * Starts periodic automated keyword harvesting:
 * 1. Loads from database cache immediately on startup.
 * 2. Checks/refreshes keywords regularly every 7 days (with a 24-hour cycle checking for stale 7-day items).
 */
function startKeywordHarvester(FileModel, searchConsoleModule, baseUrl, intervalMs = 24 * 60 * 60 * 1000) {
    // Initial fast load from DB cache on server startup (no network lag)
    loadKeywordsFromDbCache(FileModel).then(() => {
        // Run harvest to fill in any items older than 7 days
        setTimeout(() => {
            runKeywordHarvest(FileModel, searchConsoleModule, baseUrl);
        }, 3000);
    });

    // Check periodically (every 24h) to refresh any items that have passed the 7-day TTL
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
    FULL_FORM_GPL_MODS,
    expandTagVariations,
    fetchGoogleSuggest,
    fetchDuckDuckGoSuggest,
    generateKeywordsForMod,
    harvestLiveModsKeywords,
    harvestSearchSuggestKeywords,
    harvestSearchConsoleQueries,
    runKeywordHarvest,
    startKeywordHarvester,
    loadKeywordsFromDbCache,
    getDynamicKeywordsForPage,
    getKeywordState
};
