/**
 * GPLMods High-Performance Caching & Serialization Engine
 * Powered by apicache, cachier & fast-json-stringify
 */

const apicache = require('apicache');
const Cachier = require('cachier');
const fastJson = require('fast-json-stringify');

// ==========================================
// 1. APICACHE ROUTE MIDDLEWARE
// ==========================================

// Configure global apicache defaults
apicache.options({
    statusCodes: {
        include: [200]
    },
    headers: {
        'cache-control': 'public, max-age=300'
    }
});

/**
 * Creates route-level caching middleware that automatically bypasses authenticated users and non-GET requests
 */
function routeCache(duration = '5 minutes') {
    const middleware = apicache.middleware(duration, (req, res) => {
        // Only cache GET requests
        if (req.method !== 'GET') return false;

        // Skip cache for logged-in users to ensure personalization
        if (req.user || req.session?.user || req.session?.passport?.user) return false;

        // Skip cache if explicit no-cache header is provided
        if (req.headers['x-no-cache']) return false;

        // Only cache successful 200 responses
        return res.statusCode === 200;
    });

    return middleware;
}

// ==========================================
// 2. CACHIER KEY-VALUE IN-MEMORY ENGINE
// ==========================================

const memStore = new Cachier.MemStore();
const cachierInstance = new Cachier({ store: memStore });

const cacheDb = {
    /**
     * Retrieves an item from the cache
     */
    get(key) {
        return new Promise((resolve, reject) => {
            cachierInstance.get(key, (err, val) => {
                if (err) return reject(err);
                resolve(val);
            });
        });
    },

    /**
     * Saves an item to the cache
     */
    set(key, value) {
        return new Promise((resolve, reject) => {
            cachierInstance.set(key, value, (err) => {
                if (err) return reject(err);
                resolve(true);
            });
        });
    },

    /**
     * High-speed wrap pattern: returns cached data or calls fetcher, stores result, and returns
     */
    async wrap(key, fetcherFn, maxAgeMs = 300000) {
        try {
            const cached = await this.get(key);
            if (cached !== undefined && cached !== null) {
                return cached;
            }
        } catch (e) {
            // Ignore cache miss errors
        }

        const freshData = await fetcherFn();
        if (freshData !== undefined && freshData !== null) {
            await this.set(key, freshData, maxAgeMs).catch(() => {});
        }
        return freshData;
    }
};

// ==========================================
// 3. FAST-JSON-STRINGIFY HIGH SPEED SERIALIZERS
// ==========================================

const stringifyModSummary = fastJson({
    title: 'ModSummary',
    type: 'object',
    properties: {
        _id: { type: 'string' },
        name: { type: 'string' },
        slug: { type: 'string' },
        category: { type: 'string' },
        version: { type: 'string' },
        downloadsCount: { type: 'integer' },
        averageRating: { type: 'number' },
        smartIconUrl: { type: 'string' },
        isLatestVersion: { type: 'boolean' }
    }
});

const stringifyModList = fastJson({
    title: 'ModListResponse',
    type: 'object',
    properties: {
        success: { type: 'boolean' },
        count: { type: 'integer' },
        mods: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    _id: { type: 'string' },
                    name: { type: 'string' },
                    slug: { type: 'string' },
                    category: { type: 'string' },
                    version: { type: 'string' },
                    downloadsCount: { type: 'integer' },
                    averageRating: { type: 'number' },
                    smartIconUrl: { type: 'string' }
                }
            }
        }
    }
});

const stringifyStats = fastJson({
    title: 'StatsResponse',
    type: 'object',
    properties: {
        success: { type: 'boolean' },
        totalMods: { type: 'integer' },
        totalDownloads: { type: 'integer' },
        totalUsers: { type: 'integer' },
        timestamp: { type: 'string' }
    }
});

module.exports = {
    apicache,
    routeCache,
    cacheDb,
    stringifyModSummary,
    stringifyModList,
    stringifyStats
};
