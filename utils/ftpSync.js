const ftp = require("basic-ftp");
const fs = require("fs");
const path = require("path");

const IMAGE_FOLDERS = new Set(['avatars', 'icons', 'screenshots']);

function normalizeB2Key(b2Key) {
    if (!b2Key || typeof b2Key !== 'string') return null;
    return b2Key.replace(/^\/+/, '').replace(/\\/g, '/');
}

function shouldMirrorToFTP(b2Key) {
    const normalized = normalizeB2Key(b2Key);
    if (!normalized) return false;
    return IMAGE_FOLDERS.has(normalized.split('/')[0].toLowerCase());
}

/**
 * Uploads a file buffer to the InfinityFree FTP server as a backup mirror.
 * @param {Buffer|String} fileData - The file buffer or path to the temp file.
 * @param {String} b2Key - The exact filename/path we used for B2 (e.g., 'icons/123.png').
 */
async function mirrorToFTP(fileData, b2Key) {
    if (!shouldMirrorToFTP(b2Key)) return;

    const client = new ftp.Client();
    // client.ftp.verbose = true; // Uncomment for debugging FTP connection issues

    try {
        await client.access({
            host: process.env.FTP_HOST,
            user: process.env.FTP_USER,
            password: process.env.FTP_PASS,
            secure: false // InfinityFree free tier usually does not support FTPS
        });

        const normalizedKey = normalizeB2Key(b2Key);
        const parts = normalizedKey.split('/');
        const fileName = parts.pop();
        const remoteDir = parts.join('/');

        // Navigate to the base website directory (usually 'htdocs' on InfinityFree)
        const basePath = process.env.FTP_BASE_PATH || '/htdocs';
        await client.cd(basePath);

        // Ensure the subfolder exists on the FTP server
        if (remoteDir) {
            await client.ensureDir(remoteDir);
        }

        // Upload the file
        const remotePath = remoteDir ? `${remoteDir}/${fileName}` : fileName;
        if (Buffer.isBuffer(fileData)) {
            const { Readable } = require('stream');
            const stream = Readable.from(fileData);
            await client.uploadFrom(stream, remotePath);
        } else if (typeof fileData === 'string' && fs.existsSync(fileData)) {
            await client.uploadFrom(fileData, remotePath);
        }

        console.log(`[FTP Mirror] Successfully backed up ${normalizedKey} to InfinityFree.`);

    } catch (err) {
        console.error(`[FTP Mirror] Failed to upload ${b2Key}:`, err);
    } finally {
        client.close();
    }
}

/**
 * Deletes a file from the InfinityFree FTP server.
 * @param {String} b2Key - The exact filename/path (e.g., 'icons/123.png').
 */
async function deleteFromFTP(b2Key) {
    if (!shouldMirrorToFTP(b2Key) || !b2Key || b2Key === 'external-link') return;

    const client = new ftp.Client();
    try {
        await client.access({
            host: process.env.FTP_HOST,
            user: process.env.FTP_USER,
            password: process.env.FTP_PASS,
            secure: false
        });

        const normalizedKey = normalizeB2Key(b2Key);
        const fullPath = `${process.env.FTP_BASE_PATH || '/htdocs'}/${normalizedKey}`;
        
        await client.remove(fullPath);
        console.log(`[FTP Mirror] Successfully deleted ${normalizedKey} from InfinityFree.`);

    } catch (err) {
        if (err.code !== 550) {
            console.error(`[FTP Mirror] Failed to delete ${b2Key}:`, err.message);
        }
    } finally {
        client.close();
    }
}

module.exports = { mirrorToFTP, deleteFromFTP, shouldMirrorToFTP };