/**
 * GPLMods Backblaze B2 Image Optimizer & InfinityFree FTP Sync Engine
 * 
 * Capabilities:
 * 1. Iterates over all image assets stored in Backblaze B2 bucket
 * 2. Compresses images using Sharp + Imagemin (MozJPEG / PNGQuant) + reSmush.it API fallback
 * 3. Strictly preserves file extensions:
 *    - Icons -> .png
 *    - Screenshots -> .jpg
 *    - GIFs -> .gif
 * 4. Re-uploads reduced image buffers back to B2
 * 5. Syncs / mirrors the compressed images to InfinityFree FTP
 */

if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config();
}

const { S3Client, ListObjectsV2Command, GetObjectCommand, PutObjectCommand } = require('@aws-sdk/client-s3');
const { optimizeExistingBuffer } = require('../utils/imageOptimizer');
const { mirrorToFTP, shouldMirrorToFTP } = require('../utils/storage/ftpSync');
const path = require('path');

const s3Client = new S3Client({
    endpoint: `https://${process.env.B2_ENDPOINT}`,
    region: process.env.B2_REGION,
    credentials: {
        accessKeyId: process.env.B2_ACCESS_KEY_ID,
        secretAccessKey: process.env.B2_SECRET_ACCESS_KEY
    }
});

const IMAGE_EXTENSIONS = new Set(['.png', '.jpg', '.jpeg', '.gif', '.webp']);

function isImageKey(key) {
    if (!key) return false;
    const ext = path.extname(key).toLowerCase();
    if (IMAGE_EXTENSIONS.has(ext)) return true;
    return key.includes('screenshot') || key.includes('icon') || key.includes('avatar');
}

function resolveContentType(key) {
    const ext = path.extname(key).toLowerCase();
    switch (ext) {
        case '.png': return 'image/png';
        case '.jpg':
        case '.jpeg': return 'image/jpeg';
        case '.gif': return 'image/gif';
        case '.webp': return 'image/webp';
        default: return 'application/octet-stream';
    }
}

async function streamToBuffer(stream) {
    const chunks = [];
    for await (const chunk of stream) {
        chunks.push(chunk instanceof Buffer ? chunk : Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
}

/**
 * Optimizes B2 images in batches and syncs them to FTP
 * 
 * @param {object} options
 * @param {number} [options.limit=100] Max number of files to process
 * @param {string} [options.prefix=''] Filter key prefix
 * @param {boolean} [options.dryRun=false] If true, does not write changes to B2 or FTP
 * @param {boolean} [options.syncFtp=true] Whether to mirror to InfinityFree FTP
 */
async function runB2Optimization(options = {}) {
    const bucket = process.env.B2_BUCKET_NAME;
    if (!bucket) {
        throw new Error("B2_BUCKET_NAME is not configured in environment.");
    }

    const limit = options.limit || 50;
    const prefix = options.prefix || '';
    const dryRun = options.dryRun || false;
    const syncFtp = options.syncFtp !== false;

    console.log(`\n======================================================`);
    console.log(`Starting B2 Image Optimization & FTP Sync Engine`);
    console.log(`Bucket: ${bucket} | Prefix: "${prefix}" | Limit: ${limit} | DryRun: ${dryRun}`);
    console.log(`======================================================\n`);

    let continuationToken = null;
    let processedCount = 0;
    let optimizedCount = 0;
    let ftpSyncedCount = 0;
    let totalSavedBytes = 0;

    do {
        const listParams = {
            Bucket: bucket,
            MaxKeys: Math.min(100, limit - processedCount)
        };
        if (prefix) listParams.Prefix = prefix;
        if (continuationToken) listParams.ContinuationToken = continuationToken;

        const listRes = await s3Client.send(new ListObjectsV2Command(listParams));
        const objects = listRes.Contents || [];

        for (const obj of objects) {
            if (processedCount >= limit) break;

            const key = obj.Key;
            if (!isImageKey(key)) continue;

            processedCount++;
            const originalSize = obj.Size || 0;

            try {
                // 1. Download original buffer from B2
                const getRes = await s3Client.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
                const originalBuffer = await streamToBuffer(getRes.Body);

                // 2. Compress via Sharp / Imagemin / reSmush.it with strict extension retention
                const filename = path.basename(key);
                const optimizedBuffer = await optimizeExistingBuffer(originalBuffer, filename, {
                    useResmushFallback: true,
                    quality: 80
                });

                const newSize = optimizedBuffer.length;
                const saved = Math.max(0, originalSize - newSize);
                const percent = originalSize > 0 ? Math.round((saved / originalSize) * 100) : 0;

                if (saved > 0 && percent >= 3) {
                    optimizedCount++;
                    totalSavedBytes += saved;
                    console.log(`[B2 Optimizer] ${key}: ${(originalSize / 1024).toFixed(1)}KB -> ${(newSize / 1024).toFixed(1)}KB (-${percent}%)`);

                    if (!dryRun) {
                        // 3. Re-upload optimized buffer to B2
                        await s3Client.send(new PutObjectCommand({
                            Bucket: bucket,
                            Key: key,
                            Body: optimizedBuffer,
                            ContentType: resolveContentType(key)
                        }));

                        // 4. Mirror to InfinityFree FTP
                        if (syncFtp && shouldMirrorToFTP(key)) {
                            try {
                                await mirrorToFTP(optimizedBuffer, key);
                                ftpSyncedCount++;
                                console.log(`  -> Synced to InfinityFree FTP: ${key}`);
                            } catch (ftpErr) {
                                console.warn(`  -> FTP sync error for ${key}:`, ftpErr.message);
                            }
                        }
                    }
                } else {
                    console.log(`[B2 Optimizer] Already optimized: ${key} (${(originalSize / 1024).toFixed(1)}KB)`);
                    // Ensure mirrored to FTP even if already optimized
                    if (!dryRun && syncFtp && shouldMirrorToFTP(key)) {
                        try {
                            await mirrorToFTP(originalBuffer, key);
                            ftpSyncedCount++;
                        } catch (e) {}
                    }
                }
            } catch (fileErr) {
                console.error(`[B2 Optimizer] Error processing ${key}:`, fileErr.message);
            }
        }

        continuationToken = listRes.NextContinuationToken;
    } while (continuationToken && processedCount < limit);

    console.log(`\n======================================================`);
    console.log(`B2 Optimization & Sync Completed!`);
    console.log(`Images Examined: ${processedCount}`);
    console.log(`Images Re-compressed: ${optimizedCount}`);
    console.log(`Images Mirrored to FTP: ${ftpSyncedCount}`);
    console.log(`Total Storage Saved: ${(totalSavedBytes / (1024 * 1024)).toFixed(2)} MB`);
    console.log(`======================================================\n`);

    return {
        processedCount,
        optimizedCount,
        ftpSyncedCount,
        totalSavedBytes
    };
}

if (require.main === module) {
    const args = process.argv.slice(2);
    const limit = args.includes('--limit') ? parseInt(args[args.indexOf('--limit') + 1], 10) : 100;
    const prefix = args.includes('--prefix') ? args[args.indexOf('--prefix') + 1] : '';
    const dryRun = args.includes('--dry-run');

    runB2Optimization({ limit, prefix, dryRun })
        .catch(err => {
            console.error("B2 optimization failed:", err);
            process.exit(1);
        });
}

module.exports = { runB2Optimization };
