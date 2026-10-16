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

/**
 * Express middleware that adds mobile performance and SEO acceleration headers:
 * - Preconnect to Google Fonts and CDNs
 * - Core Web Vitals caching headers
 * - Client Hints for mobile optimization
 */
function assetOptimizationMiddleware() {
    return (req, res, next) => {
        // 1. Mobile Client Hints for responsive asset serving
        res.setHeader('Accept-CH', 'Sec-CH-UA-Mobile, Sec-CH-UA-Platform, Sec-CH-Viewport-Width');

        // 2. Preconnect headers for faster Google Fonts and CDN resource discovery
        res.setHeader('Link', [
            '<https://fonts.googleapis.com>; rel=preconnect',
            '<https://fonts.gstatic.com>; rel=preconnect; crossorigin',
            '<https://cdn.jsdelivr.net>; rel=dns-prefetch'
        ].join(', '));

        // 3. Static asset caching headers
        const reqPath = req.path.toLowerCase();
        if (reqPath.match(/\.(css|js|woff2|woff|ttf|png|jpg|jpeg|gif|svg|ico|webp)$/)) {
            // Static assets: cache for 30 days
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
