/**
 * ============================================================================
 * MOD & FILE STORAGE UTILITY
 * Manages dedicated on-disk and metadata folder hierarchy for mods.
 * Mirrors the club storage architecture:
 *   uploads/mods/<platform>/<SafeModName>/
 *     ├── reviews/
 *     │     └── reviews.json
 *     ├── main-file-by-<user>@<email>/
 *     │     ├── screenshot/
 *     │     └── old-version/
 *     └── <variantId>-by-<user>@<email>/
 *           ├── screenshot/
 *           └── old-version/
 * ============================================================================
 */

const fs = require('fs');
const path = require('path');
const { slugify, getPlatformStoragePath, getModStorageKey } = require('./storagePaths');

const MODS_BASE_DIR = path.join(__dirname, '..', 'uploads', 'mods');
const PUBLIC_MODS_DIR = path.join(__dirname, '..', 'public', 'uploads', 'mods');

/**
 * Sanitizes a directory name for safe filesystem usage.
 */
function sanitizeFolderName(name) {
    if (!name || typeof name !== 'string') return 'mod-' + Date.now();
    let clean = name.replace(/[<>:"/\\|?*]/g, '').trim();
    if (!clean) clean = 'mod-' + Date.now();
    return slugify(clean);
}

/**
 * Ensures all required directories exist for a mod on disk.
 */
function ensureModDirectories(category, modName, uploader = {}, isVariant = false, variantId = null) {
    const platPath = getPlatformStoragePath(category);
    const modSlug = sanitizeFolderName(modName);
    const modStoragePath = path.join(MODS_BASE_DIR, platPath.replace(/^mods\//, ''), modSlug);
    const publicStoragePath = path.join(PUBLIC_MODS_DIR, platPath.replace(/^mods\//, ''), modSlug);

    const username = slugify(uploader?.username || uploader || 'community');
    const email = (uploader?.email || 'user@gplmods.com').toLowerCase().trim();

    const uploaderSubfolder = isVariant && variantId
        ? `${slugify(String(variantId))}-by-${username}@${email}`
        : `main-file-by-${username}@${email}`;

    const subdirs = {
        base: modStoragePath,
        reviews: path.join(modStoragePath, 'reviews'),
        uploaderDir: path.join(modStoragePath, uploaderSubfolder),
        screenshot: path.join(modStoragePath, uploaderSubfolder, 'screenshot'),
        oldVersion: path.join(modStoragePath, uploaderSubfolder, 'old-version')
    };

    Object.values(subdirs).forEach(dir => {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    });

    if (!fs.existsSync(publicStoragePath)) {
        fs.mkdirSync(publicStoragePath, { recursive: true });
    }

    return {
        modSlug,
        storagePath: modStoragePath,
        publicStoragePath,
        uploaderSubfolder,
        subdirs
    };
}

/**
 * Writes or updates the mod-info.json metadata file on disk.
 */
function saveModMetadata(fileDoc) {
    try {
        if (!fileDoc || !fileDoc.name) return;
        const { storagePath } = ensureModDirectories(
            fileDoc.category,
            fileDoc.name,
            { username: fileDoc.uploader },
            Boolean(fileDoc.isVariant),
            fileDoc._id
        );
        const infoFile = path.join(storagePath, 'mod-info.json');
        const data = {
            id: String(fileDoc._id || fileDoc.id),
            name: fileDoc.name,
            slug: fileDoc.slug,
            version: fileDoc.version,
            category: fileDoc.category,
            uploader: fileDoc.uploader,
            developer: fileDoc.developer || 'N/A',
            rating: fileDoc.averageRating || 0,
            downloads: fileDoc.downloads || 0,
            iconKey: fileDoc.iconKey || '',
            screenshotKeys: fileDoc.screenshotKeys || [],
            isVariant: Boolean(fileDoc.isVariant),
            masterFile: fileDoc.masterFile || null,
            variants: fileDoc.variants || [],
            olderVersions: fileDoc.olderVersions || [],
            updatedAt: new Date().toISOString()
        };
        fs.writeFileSync(infoFile, JSON.stringify(data, null, 2), 'utf8');
    } catch (e) {
        console.error(`[FileStorage] Error saving metadata for ${fileDoc?.name}:`, e.message);
    }
}

/**
 * Saves reviews archive dump to the mod's dedicated reviews folder.
 */
async function saveModReviewsArchive(fileDocOrId, reviews = null) {
    try {
        let fileDoc = fileDocOrId;
        if (typeof fileDocOrId === 'string' || fileDocOrId instanceof require('mongoose').Types.ObjectId) {
            const File = require('../models/core/file');
            fileDoc = await File.findById(fileDocOrId);
        }
        if (!fileDoc) return;

        if (!reviews) {
            const Review = require('../models/core/review');
            reviews = await Review.find({ file: fileDoc._id }).sort({ createdAt: -1 }).lean();
        }

        const { subdirs } = ensureModDirectories(
            fileDoc.category,
            fileDoc.name,
            { username: fileDoc.uploader },
            Boolean(fileDoc.isVariant),
            fileDoc._id
        );

        const filePath = path.join(subdirs.reviews, 'reviews.json');
        fs.writeFileSync(filePath, JSON.stringify(reviews || [], null, 2), 'utf8');
        return { success: true, filePath };
    } catch (e) {
        console.error(`[FileStorage] Error saving reviews archive:`, e.message);
        return { success: false, error: e.message };
    }
}

module.exports = {
    MODS_BASE_DIR,
    PUBLIC_MODS_DIR,
    ensureModDirectories,
    saveModMetadata,
    saveModReviewsArchive
};
