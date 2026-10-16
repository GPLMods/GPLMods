/**
 * GPLMods Advanced Image Optimization Engine
 * 
 * Features:
 * 1. Multer + Sharp Pipeline:
 *    - Real-time compression for newly uploaded images.
 *    - Strict extension preservation:
 *      * Icons -> always .png (optimized PNG palette, max 512x512)
 *      * Screenshots -> always .jpg (mozjpeg compression, quality 80, max 1920x1080)
 *      * GIFs -> always .gif (animated frame preservation)
 * 2. Imagemin + Mozjpeg + Pngquant Pipeline:
 *    - For already uploaded images (batch optimization)
 * 3. reSmush.it API Fallback:
 *    - Free external fallback API if local compression fails or for secondary compression pass
 * 4. InfinityFree FTP Sync:
 *    - Syncs optimized images to FTP mirror for failover
 */

const fs = require('fs');
const path = require('path');
const sharp = require('sharp');
const axios = require('axios');
const FormData = require('form-data');

// Optional imagemin imports (CommonJS safe)
let imagemin = null;
let imageminMozjpeg = null;
let imageminPngquant = null;

try {
    imagemin = require('imagemin');
    imageminMozjpeg = require('imagemin-mozjpeg');
    imageminPngquant = require('imagemin-pngquant');
} catch (e) {
    console.warn('[ImageOptimizer] imagemin native plugins not loaded, falling back to sharp:', e.message);
}

// Lazy-loaded FTP mirror to avoid circular dependencies
let ftpMirror = null;
function getFtpMirror() {
    if (!ftpMirror) {
        try {
            ftpMirror = require('./storage/ftpSync');
        } catch (e) {
            try {
                ftpMirror = require('./ftpSync');
            } catch (err) {
                console.warn('[ImageOptimizer] FTP mirror utility not available:', err.message);
            }
        }
    }
    return ftpMirror;
}

/**
 * Optimizes an image buffer using the reSmush.it REST API as a fallback.
 * 
 * @param {Buffer} buffer - Original image buffer
 * @param {string} originalFilename - Name of the file
 * @param {number} [quality=80] - Desired quality percentage
 * @returns {Promise<Buffer|null>} Optimized buffer or null on failure
 */
async function resmushImageBuffer(buffer, originalFilename = 'image.jpg', quality = 80) {
    if (!buffer || buffer.length === 0) return null;

    try {
        const form = new FormData();
        form.append('files', buffer, {
            filename: originalFilename,
            contentType: 'application/octet-stream'
        });

        const res = await axios.post(`http://api.resmush.it/ws.php?qlty=${quality}`, form, {
            headers: form.getHeaders(),
            timeout: 10000,
            maxContentLength: 50 * 1024 * 1024,
            maxBodyLength: 50 * 1024 * 1024
        });

        if (res.data && res.data.dest) {
            // Fetch the compressed image from reSmush.it CDN
            const downloadRes = await axios.get(res.data.dest, {
                responseType: 'arraybuffer',
                timeout: 10000
            });

            const downloadedBuffer = Buffer.from(downloadRes.data);
            if (downloadedBuffer.length < buffer.length) {
                console.log(`[reSmush.it] Successfully compressed ${originalFilename}: ${buffer.length} -> ${downloadedBuffer.length} bytes (-${Math.round((1 - downloadedBuffer.length / buffer.length) * 100)}%)`);
                return downloadedBuffer;
            }
        }
    } catch (err) {
        console.warn(`[reSmush.it] Fallback request failed for ${originalFilename}:`, err.message);
    }
    return null;
}

/**
 * Real-time optimization for new uploads (Multer + Sharp).
 * 
 * Strict extension preservation:
 * - Icons: .png
 * - Screenshots: .jpg
 * - GIFs: .gif
 * 
 * @param {object} file - Express Multer file object ({ buffer, originalname, mimetype, size })
 * @param {string} [assetType='auto'] - 'icon', 'screenshot', 'gif', or 'auto'
 * @returns {Promise<object>} The modified and optimized Multer file object
 */
async function optimizeUploadedImage(file, assetType = 'auto') {
    if (!file || !file.buffer) return file;

    const ext = path.extname(file.originalname || '').toLowerCase();
    const isGif = ext === '.gif' || file.mimetype === 'image/gif';
    const isPng = ext === '.png' || file.mimetype === 'image/png';
    const isJpg = ext === '.jpg' || ext === '.jpeg' || file.mimetype === 'image/jpeg';

    const originalSize = file.buffer.length;

    try {
        // 1. ICON PROCESSING (Strictly PNG)
        if (assetType === 'icon' || (!isGif && !isJpg && (assetType === 'auto' && file.fieldname === 'softwareIcon'))) {
            let sharpInstance = sharp(file.buffer, { failOnError: false });
            const metadata = await sharpInstance.metadata();

            // Resize down if larger than 512x512 standard icon bounds
            if (metadata.width > 512 || metadata.height > 512) {
                sharpInstance = sharpInstance.resize(512, 512, {
                    fit: 'inside',
                    withoutEnlargement: true
                });
            }

            const optimizedBuffer = await sharpInstance
                .png({
                    compressionLevel: 9,
                    adaptiveFiltering: true,
                    palette: true,
                    quality: 80
                })
                .toBuffer();

            if (optimizedBuffer.length < originalSize) {
                file.buffer = optimizedBuffer;
                file.size = optimizedBuffer.length;
            }

            // Enforce PNG extension and mimetype
            file.mimetype = 'image/png';
            const baseName = path.basename(file.originalname, ext);
            file.originalname = `${baseName}.png`;

            console.log(`[ImageOptimizer] Optimized Icon (${file.originalname}): ${(originalSize / 1024).toFixed(1)}KB -> ${(file.size / 1024).toFixed(1)}KB`);
            return file;
        }

        // 2. GIF PROCESSING (Strictly GIF - preserve animation)
        if (isGif || assetType === 'gif') {
            try {
                const optimizedBuffer = await sharp(file.buffer, { animated: true, failOnError: false })
                    .gif({ effort: 7 })
                    .toBuffer();

                if (optimizedBuffer.length < originalSize) {
                    file.buffer = optimizedBuffer;
                    file.size = optimizedBuffer.length;
                }
            } catch (gifErr) {
                // If animated GIF compression encounters libvips error, keep original buffer
                console.warn(`[ImageOptimizer] Animated GIF pass skipped, keeping original:`, gifErr.message);
            }

            file.mimetype = 'image/gif';
            const baseName = path.basename(file.originalname, ext);
            file.originalname = `${baseName}.gif`;
            return file;
        }

        // 3. SCREENSHOT PROCESSING (Strictly JPG/JPEG)
        if (assetType === 'screenshot' || file.fieldname === 'screenshots' || (!isGif && !isPng)) {
            let sharpInstance = sharp(file.buffer, { failOnError: false });
            const metadata = await sharpInstance.metadata();

            // Resize down if larger than 1920x1080 bounds
            if (metadata.width > 1920 || metadata.height > 1080) {
                sharpInstance = sharpInstance.resize(1920, 1080, {
                    fit: 'inside',
                    withoutEnlargement: true
                });
            }

            const optimizedBuffer = await sharpInstance
                .jpeg({
                    quality: 80,
                    mozjpeg: true,
                    progressive: true
                })
                .toBuffer();

            if (optimizedBuffer.length < originalSize) {
                file.buffer = optimizedBuffer;
                file.size = optimizedBuffer.length;
            }

            file.mimetype = 'image/jpeg';
            const baseName = path.basename(file.originalname, ext);
            file.originalname = `${baseName}.jpg`;

            console.log(`[ImageOptimizer] Optimized Screenshot (${file.originalname}): ${(originalSize / 1024).toFixed(1)}KB -> ${(file.size / 1024).toFixed(1)}KB`);
            return file;
        }

        // 4. GENERAL IMAGE FALLBACK (Avatars, Card Backgrounds, Banners)
        if (isPng) {
            const optimizedBuffer = await sharp(file.buffer, { failOnError: false })
                .png({ compressionLevel: 9, adaptiveFiltering: true, palette: true, quality: 80 })
                .toBuffer();
            if (optimizedBuffer.length < originalSize) {
                file.buffer = optimizedBuffer;
                file.size = optimizedBuffer.length;
            }
            file.mimetype = 'image/png';
        } else {
            const optimizedBuffer = await sharp(file.buffer, { failOnError: false })
                .jpeg({ quality: 80, mozjpeg: true, progressive: true })
                .toBuffer();
            if (optimizedBuffer.length < originalSize) {
                file.buffer = optimizedBuffer;
                file.size = optimizedBuffer.length;
            }
            file.mimetype = 'image/jpeg';
        }

        console.log(`[ImageOptimizer] Optimized Image (${file.originalname}): ${(originalSize / 1024).toFixed(1)}KB -> ${(file.size / 1024).toFixed(1)}KB`);
        return file;
    } catch (err) {
        console.error(`[ImageOptimizer] Error optimizing upload ${file.originalname}:`, err.message);
        return file; // Return unaltered file if optimization fails
    }
}

/**
 * Optimizes an existing image buffer using imagemin (mozjpeg / pngquant) with sharp and reSmush.it fallback.
 * 
 * @param {Buffer} buffer - Existing file buffer
 * @param {string} filename - Filename with extension
 * @param {object} [options={}] - Options
 * @returns {Promise<Buffer>} The optimized buffer
 */
async function optimizeExistingBuffer(buffer, filename, options = {}) {
    if (!buffer || buffer.length === 0) return buffer;

    const ext = path.extname(filename).toLowerCase();
    const originalSize = buffer.length;
    let result = buffer;

    // Pass 1: Try imagemin if plugins are loaded
    if (imagemin && (imageminMozjpeg || imageminPngquant)) {
        try {
            const plugins = [];
            if (ext === '.jpg' || ext === '.jpeg') {
                if (imageminMozjpeg) plugins.push(imageminMozjpeg({ quality: options.quality || 80 }));
            } else if (ext === '.png') {
                if (imageminPngquant) plugins.push(imageminPngquant({ quality: [0.65, 0.80], speed: 4 }));
            }

            if (plugins.length > 0) {
                const imageminBuffer = await imagemin.buffer(buffer, { plugins });
                if (imageminBuffer && imageminBuffer.length < result.length) {
                    result = imageminBuffer;
                }
            }
        } catch (e) {
            // imagemin pass failed, fallback to sharp
        }
    }

    // Pass 2: Try sharp if imagemin did not reduce size
    if (result.length >= originalSize) {
        try {
            if (ext === '.png') {
                const sharpBuffer = await sharp(buffer, { failOnError: false })
                    .png({ compressionLevel: 9, adaptiveFiltering: true, palette: true, quality: 80 })
                    .toBuffer();
                if (sharpBuffer.length < result.length) result = sharpBuffer;
            } else if (ext === '.jpg' || ext === '.jpeg') {
                const sharpBuffer = await sharp(buffer, { failOnError: false })
                    .jpeg({ quality: 80, mozjpeg: true, progressive: true })
                    .toBuffer();
                if (sharpBuffer.length < result.length) result = sharpBuffer;
            } else if (ext === '.gif') {
                try {
                    const sharpBuffer = await sharp(buffer, { animated: true, failOnError: false })
                        .gif({ effort: 7 })
                        .toBuffer();
                    if (sharpBuffer.length < result.length) result = sharpBuffer;
                } catch (e) {}
            }
        } catch (e) {}
    }

    // Pass 3: reSmush.it fallback if still not significantly reduced
    if (options.useResmushFallback && (result.length >= originalSize || (result.length / originalSize) > 0.9)) {
        try {
            const resmushed = await resmushImageBuffer(buffer, filename, options.quality || 80);
            if (resmushed && resmushed.length < result.length) {
                result = resmushed;
            }
        } catch (e) {}
    }

    return result;
}

/**
 * Optimizes an existing file on disk and optionally mirrors it to FTP.
 * 
 * @param {string} filePath - Absolute path to local file
 * @param {object} [options={}] - Options { syncFtp: boolean, ftpKey: string, useResmushFallback: boolean }
 * @returns {Promise<{ originalSize: number, newSize: number, savedBytes: number, percent: number }>}
 */
async function optimizeExistingFile(filePath, options = {}) {
    if (!fs.existsSync(filePath)) {
        throw new Error(`File does not exist: ${filePath}`);
    }

    const originalBuffer = fs.readFileSync(filePath);
    const originalSize = originalBuffer.length;
    const filename = path.basename(filePath);

    const optimizedBuffer = await optimizeExistingBuffer(originalBuffer, filename, {
        useResmushFallback: options.useResmushFallback !== false,
        quality: options.quality || 80
    });

    const newSize = optimizedBuffer.length;
    const savedBytes = Math.max(0, originalSize - newSize);
    const percent = originalSize > 0 ? Math.round((savedBytes / originalSize) * 100) : 0;

    if (savedBytes > 0) {
        fs.writeFileSync(filePath, optimizedBuffer);
        console.log(`[ImageOptimizer] Optimized ${filename}: ${(originalSize / 1024).toFixed(1)}KB -> ${(newSize / 1024).toFixed(1)}KB (-${percent}%)`);

        // Sync to FTP if requested and ftpKey is supplied
        if (options.syncFtp && options.ftpKey) {
            const mirror = getFtpMirror();
            if (mirror && typeof mirror.mirrorToFTP === 'function') {
                mirror.mirrorToFTP(optimizedBuffer, options.ftpKey).catch(e => {
                    console.error(`[ImageOptimizer] Background FTP sync failed for ${options.ftpKey}:`, e.message);
                });
            }
        }
    }

    return { originalSize, newSize, savedBytes, percent };
}

module.exports = {
    optimizeUploadedImage,
    optimizeExistingBuffer,
    optimizeExistingFile,
    resmushImageBuffer
};
