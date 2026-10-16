/**
 * GPLMods Batch Image Optimizer
 * Optimizes existing images in public/images, uploads/, and other site directories
 * Uses imagemin (mozjpeg / pngquant) + sharp + reSmush.it fallback
 * Preserves extensions:
 * - Icons: .png
 * - Screenshots: .jpg
 * - GIFs: .gif
 */

const fs = require('fs');
const path = require('path');
const { optimizeExistingFile } = require('../utils/imageOptimizer');

async function processDirectory(dirPath, syncFtp = false) {
    if (!fs.existsSync(dirPath)) {
        console.log(`Directory does not exist: ${dirPath}`);
        return { totalFiles: 0, totalSaved: 0 };
    }

    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    let totalFiles = 0;
    let totalSaved = 0;

    for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);

        if (entry.isDirectory()) {
            const subResult = await processDirectory(fullPath, syncFtp);
            totalFiles += subResult.totalFiles;
            totalSaved += subResult.totalSaved;
        } else if (entry.isFile()) {
            const ext = path.extname(entry.name).toLowerCase();
            if (['.png', '.jpg', '.jpeg', '.gif'].includes(ext)) {
                try {
                    const relativeKey = path.relative(path.join(__dirname, '..', 'public'), fullPath).replace(/\\/g, '/');
                    const stats = await optimizeExistingFile(fullPath, {
                        syncFtp,
                        ftpKey: relativeKey.startsWith('..') ? null : relativeKey,
                        useResmushFallback: true
                    });

                    if (stats.savedBytes > 0) {
                        totalFiles++;
                        totalSaved += stats.savedBytes;
                    }
                } catch (err) {
                    console.error(`Failed to optimize ${entry.name}:`, err.message);
                }
            }
        }
    }

    return { totalFiles, totalSaved };
}

async function run() {
    console.log("=== GPLMODS BATCH IMAGE OPTIMIZATION ===");
    const targetDirs = [
        path.join(__dirname, '..', 'public', 'images'),
        path.join(__dirname, '..', 'uploads')
    ];

    let grandTotalFiles = 0;
    let grandTotalSaved = 0;

    for (const dir of targetDirs) {
        console.log(`\nScanning directory: ${dir}...`);
        const result = await processDirectory(dir, false);
        grandTotalFiles += result.totalFiles;
        grandTotalSaved += result.totalSaved;
    }

    console.log(`\n========================================`);
    console.log(`Optimization Completed!`);
    console.log(`Total Images Optimized: ${grandTotalFiles}`);
    console.log(`Total Storage Saved: ${(grandTotalSaved / (1024 * 1024)).toFixed(2)} MB`);
    console.log(`========================================\n`);
}

if (require.main === module) {
    run().catch(console.error);
}

module.exports = { processDirectory, run };
