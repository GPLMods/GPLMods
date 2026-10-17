/**
 * GPLMods Static Asset Optimizer & Bundler
 * Minifies style.css, notifications.css, and main.js using CleanCSS & Terser
 */

const fs = require('fs');
const path = require('path');
const CleanCSS = require('clean-css');
const terser = require('terser');

async function buildAssets() {
    console.log('[AssetBuilder] Starting static asset optimization...');
    const publicDir = path.join(__dirname, '..', 'public');

    // 1. Minify style.css -> style.min.css
    const stylePath = path.join(publicDir, 'css', 'style.css');
    if (fs.existsSync(stylePath)) {
        const raw = fs.readFileSync(stylePath, 'utf8');
        const minified = new CleanCSS({ level: 2 }).minify(raw).styles;
        fs.writeFileSync(path.join(publicDir, 'css', 'style.min.css'), minified);
        console.log(`[AssetBuilder] Minified style.css: ${raw.length} -> ${minified.length} bytes (-${((raw.length - minified.length) / raw.length * 100).toFixed(1)}%)`);
    }

    // 2. Minify notifications.css -> notifications.min.css
    const notifPath = path.join(publicDir, 'css', 'notifications.css');
    if (fs.existsSync(notifPath)) {
        const raw = fs.readFileSync(notifPath, 'utf8');
        const minified = new CleanCSS({ level: 2 }).minify(raw).styles;
        fs.writeFileSync(path.join(publicDir, 'css', 'notifications.min.css'), minified);
        console.log(`[AssetBuilder] Minified notifications.css: ${raw.length} -> ${minified.length} bytes (-${((raw.length - minified.length) / raw.length * 100).toFixed(1)}%)`);
    }

    // 3. Minify main.js -> main.min.js
    const mainJsPath = path.join(publicDir, 'js', 'main.js');
    if (fs.existsSync(mainJsPath)) {
        const raw = fs.readFileSync(mainJsPath, 'utf8');
        const minified = await terser.minify(raw, { compress: true, mangle: true });
        if (minified.code) {
            fs.writeFileSync(path.join(publicDir, 'js', 'main.min.js'), minified.code);
            console.log(`[AssetBuilder] Minified main.js: ${raw.length} -> ${minified.code.length} bytes (-${((raw.length - minified.code.length) / raw.length * 100).toFixed(1)}%)`);
        }
    }

    // 4. Minify notifications.js -> notifications.min.js
    const notifJsPath = path.join(publicDir, 'js', 'notifications.js');
    if (fs.existsSync(notifJsPath)) {
        const raw = fs.readFileSync(notifJsPath, 'utf8');
        const minified = await terser.minify(raw, { compress: true, mangle: true });
        if (minified.code) {
            fs.writeFileSync(path.join(publicDir, 'js', 'notifications.min.js'), minified.code);
            console.log(`[AssetBuilder] Minified notifications.js: ${raw.length} -> ${minified.code.length} bytes (-${((raw.length - minified.code.length) / raw.length * 100).toFixed(1)}%)`);
        }
    }

    // 5. Minify currency-exchange.js -> currency-exchange.min.js
    const currJsPath = path.join(publicDir, 'js', 'currency-exchange.js');
    if (fs.existsSync(currJsPath)) {
        const raw = fs.readFileSync(currJsPath, 'utf8');
        const minified = await terser.minify(raw, { compress: true, mangle: true });
        if (minified.code) {
            fs.writeFileSync(path.join(publicDir, 'js', 'currency-exchange.min.js'), minified.code);
            console.log(`[AssetBuilder] Minified currency-exchange.js: ${raw.length} -> ${minified.code.length} bytes (-${((raw.length - minified.code.length) / raw.length * 100).toFixed(1)}%)`);
        }
    }

    console.log('[AssetBuilder] Static asset optimization completed successfully!');
}

if (require.main === module) {
    buildAssets().catch(err => {
        console.error('[AssetBuilder] Build failed:', err);
        process.exit(1);
    });
}

module.exports = { buildAssets };
