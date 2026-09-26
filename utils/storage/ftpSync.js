const ftp = require("basic-ftp");
const fs = require("fs");
const path = require("path");

const IMAGE_FOLDERS = new Set(['users', 'clubs', 'avatars', 'card-avatars', 'card-backgrounds', 'icons', 'screenshots', 'docs', 'forums', 'requests', 'support', 'distributors', 'dmca', 'ios-certs', 'announcements']);

function normalizeB2Key(b2Key) {
    if (!b2Key || typeof b2Key !== 'string') return null;
    return b2Key.replace(/^\/+/, '').replace(/\\/g, '/');
}

function shouldMirrorToFTP(b2Key) {
    const normalized = normalizeB2Key(b2Key);
    if (!normalized) return false;
    const parts = normalized.split('/');
    const topLevel = parts[0].toLowerCase();
    const ext = path.extname(normalized).toLowerCase();
    const isImage = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico'].includes(ext);

    // 1. Users hierarchy: users/staff/... and users/members/...
    if (topLevel === 'users') {
        return isImage;
    }

    // 2. Mod archives stay in B2; only app icons, screenshots, and reviews metadata are mirrored.
    if (topLevel === 'mods') {
        const fileName = parts[parts.length - 1].toLowerCase();
        if (fileName.startsWith('app-icon') || fileName.startsWith('file-screenshot') || parts.includes('screenshot') || parts.includes('screenshots') || parts.includes('icons')) {
            return isImage;
        }
        if (parts.includes('reviews') && ext === '.json') {
            return true;
        }
        return false;
    }

    // 3. Clubs hierarchy
    if (topLevel === 'clubs') {
        return isImage;
    }

    if (IMAGE_FOLDERS.has(topLevel)) return true;
    
    return isImage;
}

async function mirrorToFTP(fileData, b2Key) {
    if (!shouldMirrorToFTP(b2Key)) return;

    const client = new ftp.Client();

    try {
        await client.access({
            host: process.env.FTP_HOST,
            user: process.env.FTP_USER,
            password: process.env.FTP_PASS,
            secure: false
        });

        const normalizedKey = normalizeB2Key(b2Key);
        const parts = normalizedKey.split('/');
        const fileName = parts.pop();
        const remoteDir = parts.join('/');

        const basePath = process.env.FTP_BASE_PATH || '/htdocs';
        await client.cd(basePath);

        if (remoteDir) {
            await client.ensureDir(remoteDir);
        }

        if (Buffer.isBuffer(fileData)) {
            const { Readable } = require('stream');
            const stream = Readable.from(fileData);
            await client.uploadFrom(stream, fileName);
        } else if (typeof fileData === 'string' && fs.existsSync(fileData)) {
            await client.uploadFrom(fileData, fileName);
        }

        console.log(`[FTP Mirror] Successfully backed up ${normalizedKey} to InfinityFree.`);

    } catch (err) {
        console.error(`[FTP Mirror] Failed to upload ${b2Key}:`, err);
    } finally {
        client.close();
    }
}

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
