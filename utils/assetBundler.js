/**
 * GPLMods Dynamic Asset Bundler & Performance Accelerator
 * Powered by CleanCSS, Terser & Esbuild
 * 
 * Features:
 * 1. Runtime CSS/JS Minification (CleanCSS & Esbuild/Terser)
 * 2. Mobile Acceleration Headers (Google Core Web Vitals)
 * 3. Preconnect and DNS-Prefetch Optimization
 * 4. High-Efficiency HTTP Caching Headers
 */

const fs = require('fs');
const path = require('path');
const CleanCSS = require('clean-css');
const terser = require('terser');
let esbuild = null;

try {
    esbuild = require('esbuild');
} catch (e) {
    // Esbuild fallback to terser
}

const cleanCssOptimizer = new CleanCSS({
    level: {
        1: {
            all: true,
            normalizeUrls: false
        },
        2: {
            restructureRules: true,
            mergeSemantically: true
        }
    }
});

/**
 * Minifies CSS code string
 */
function minifyCss(cssContent) {
    if (!cssContent || typeof cssContent !== 'string') return '';
    try {
        const output = cleanCssOptimizer.minify(cssContent);
        return output.styles || cssContent;
    } catch (err) {
        console.warn('[AssetBundler] CSS minification warning:', err.message);
        return cssContent;
    }
}

/**
 * Minifies JavaScript code string
 */
async function minifyJs(jsContent) {
    if (!jsContent || typeof jsContent !== 'string') return '';

    if (esbuild) {
        try {
            const result = await esbuild.transform(jsContent, {
                minify: true,
                target: 'es2018'
            });
            return result.code || jsContent;
        } catch (e) {
            // fallback to terser
        }
    }

    try {
        const minified = await terser.minify(jsContent, {
            compress: true,
            mangle: true
        });
        return minified.code || jsContent;
    } catch (err) {
        console.warn('[AssetBundler] JS minification warning:', err.message);
        return jsContent;
    }
}

// In-memory cache for fast, zero-disk-I/O delivery of minified critical assets
const assetCache = new Map();

function getCachedAsset(filePath, minifierFn, mimeType) {
    try {
        if (!fs.existsSync(filePath)) return null;
        const stats = fs.statSync(filePath);
        const cacheKey = `${filePath}:${stats.mtimeMs}`;
        if (assetCache.has(cacheKey)) {
            return assetCache.get(cacheKey);
        }
        const rawContent = fs.readFileSync(filePath, 'utf8');
        const minified = minifierFn ? minifierFn(rawContent) : rawContent;
        const etag = `W/"${Buffer.byteLength(minified)}-${stats.mtimeMs}"`;
        const cached = { content: minified, etag, mimeType };
        assetCache.set(cacheKey, cached);
        return cached;
    } catch (e) {
        return null;
    }
}

/**
 * Express middleware that adds mobile performance and SEO acceleration headers:
 * - Preconnect to Google Fonts and CDNs
 * - Core Web Vitals caching headers
 * - Client Hints for mobile optimization
 * - Transparent delivery of minified CSS and JS
 */
function assetOptimizationMiddleware() {
    const publicDir = path.join(__dirname, '..', 'public');

    return (req, res, next) => {
        // 1. Mobile Client Hints for responsive asset serving
        res.setHeader('Accept-CH', 'Sec-CH-UA-Mobile, Sec-CH-UA-Platform, Sec-CH-Viewport-Width');

        const reqPath = req.path.toLowerCase();

        // 3. Transparent Minified Asset Delivery
        if (reqPath === '/css/style.css' || reqPath === '/css/style.min.css') {
            const minCssPath = path.join(publicDir, 'css', 'style.min.css');
            const asset = getCachedAsset(minCssPath, null, 'text/css; charset=UTF-8') ||
                          getCachedAsset(path.join(publicDir, 'css', 'style.css'), minifyCss, 'text/css; charset=UTF-8');
            if (asset) {
                res.setHeader('Content-Type', asset.mimeType);
                res.setHeader('ETag', asset.etag);
                res.setHeader('Cache-Control', 'public, max-age=2592000, stale-while-revalidate=86400');
                res.setHeader('Vary', 'Accept-Encoding');
                if (req.headers['if-none-match'] === asset.etag) {
                    return res.status(304).end();
                }
                return res.send(asset.content);
            }
        }

        if (reqPath === '/js/main.js' || reqPath === '/js/main.min.js') {
            const minJsPath = path.join(publicDir, 'js', 'main.min.js');
            const asset = getCachedAsset(minJsPath, null, 'application/javascript; charset=UTF-8');
            if (asset) {
                res.setHeader('Content-Type', asset.mimeType);
                res.setHeader('ETag', asset.etag);
                res.setHeader('Cache-Control', 'public, max-age=2592000, stale-while-revalidate=86400');
                res.setHeader('Vary', 'Accept-Encoding');
                if (req.headers['if-none-match'] === asset.etag) {
                    return res.status(304).end();
                }
                return res.send(asset.content);
            }
        }

        if (reqPath === '/js/notifications.js' || reqPath === '/js/notifications.min.js') {
            const minNotifJs = path.join(publicDir, 'js', 'notifications.min.js');
            const asset = getCachedAsset(minNotifJs, null, 'application/javascript; charset=UTF-8');
            if (asset) {
                res.setHeader('Content-Type', asset.mimeType);
                res.setHeader('ETag', asset.etag);
                res.setHeader('Cache-Control', 'public, max-age=2592000, stale-while-revalidate=86400');
                res.setHeader('Vary', 'Accept-Encoding');
                if (req.headers['if-none-match'] === asset.etag) {
                    return res.status(304).end();
                }
                return res.send(asset.content);
            }
        }

        if (reqPath === '/js/currency-exchange.js' || reqPath === '/js/currency-exchange.min.js') {
            const minCurrJs = path.join(publicDir, 'js', 'currency-exchange.min.js');
            const asset = getCachedAsset(minCurrJs, null, 'application/javascript; charset=UTF-8');
            if (asset) {
                res.setHeader('Content-Type', asset.mimeType);
                res.setHeader('ETag', asset.etag);
                res.setHeader('Cache-Control', 'public, max-age=2592000, stale-while-revalidate=86400');
                res.setHeader('Vary', 'Accept-Encoding');
                if (req.headers['if-none-match'] === asset.etag) {
                    return res.status(304).end();
                }
                return res.send(asset.content);
            }
        }

        if (reqPath === '/css/notifications.css' || reqPath === '/css/notifications.min.css') {
            const minNotifPath = path.join(publicDir, 'css', 'notifications.min.css');
            const asset = getCachedAsset(minNotifPath, null, 'text/css; charset=UTF-8') ||
                          getCachedAsset(path.join(publicDir, 'css', 'notifications.css'), minifyCss, 'text/css; charset=UTF-8');
            if (asset) {
                res.setHeader('Content-Type', asset.mimeType);
                res.setHeader('ETag', asset.etag);
                res.setHeader('Cache-Control', 'public, max-age=2592000, stale-while-revalidate=86400');
                res.setHeader('Vary', 'Accept-Encoding');
                if (req.headers['if-none-match'] === asset.etag) {
                    return res.status(304).end();
                }
                return res.send(asset.content);
            }
        }

        // 4. Static asset caching headers
        if (reqPath.match(/\.(css|js|woff2|woff|ttf|png|jpg|jpeg|gif|svg|ico|webp|json)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=2592000, stale-while-revalidate=86400');
            res.setHeader('Vary', 'Accept-Encoding');
        }

        next();
    };
}

module.exports = {
    minifyCss,
    minifyJs,
    assetOptimizationMiddleware
};
