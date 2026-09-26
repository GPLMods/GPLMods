const path = require('path');

function slugify(text) {
    if (!text || typeof text !== 'string') return '';
    return text
        .toString()
        .toLowerCase()
        .trim()
        .replace(/\s+/g, '-')           // Replace spaces with -
        .replace(/[^\w\-]+/g, '')       // Remove all non-word chars
        .replace(/\-\-+/g, '-')         // Replace multiple - with single -
        .replace(/^-+/, '')             // Trim - from start of text
        .replace(/-+$/, '');            // Trim - from end of text
}

function sanitizeFilename(filename) {
    if (!filename || typeof filename !== 'string') return 'file';
    const withDashes = filename.replace(/\s+/g, '-');
    return withDashes.replace(/[^a-zA-Z0-9.\-_@]/g, '');
}

/**
 * Resolves the base storage path for a user according to the database improvement plan:
 * - staff:
 *   - users/staff/owner/<email>/
 *   - users/staff/admin/<email>/
 *   - users/staff/support/<email>/
 * - members:
 *   - users/members/free/<email>/
 *   - users/members/premium/GPLLite/<email>/
 *   - users/members/premium/GPLPlus/<email>/
 *
 * @param {Object} user - User document or user object with email, role, and membership
 * @returns {string} - e.g. "users/staff/owner/bhatnagar@gmail.com"
 */
function getUserStorageBasePath(user) {
    if (!user) return 'users/members/free/unknown';
    const email = (user.email || 'user').toLowerCase().trim();
    const role = (user.role || 'member').toLowerCase();

    if (['owner', 'admin', 'support'].includes(role)) {
        return `users/staff/${role}/${email}`;
    }

    // Members, distributors, etc.
    const rawMembership = (user.membership || 'free');
    if (rawMembership === 'plus' || rawMembership === 'GPLPlus') {
        return `users/members/premium/GPLPlus/${email}`;
    } else if (rawMembership === 'lite' || rawMembership === 'GPLLite' || rawMembership === 'premium') {
        return `users/members/premium/GPLLite/${email}`;
    }
    return `users/members/free/${email}`;
}

/**
 * Generates the standardized storage key for user assets:
 * - Profile avatar: users/<role_or_tier_path>/<email>/profile/user-profile-avatar.<ext>
 * - ID Card avatar: users/<role_or_tier_path>/<email>/id-card/user-id-card-avatar.<ext>
 * - ID Card background: users/<role_or_tier_path>/<email>/id-card/user-id-card-background.<ext>
 *
 * @param {Object} user - User object
 * @param {'avatar'|'card-avatar'|'card-bg'} assetType - Type of asset being uploaded
 * @param {string} [originalFilename] - Original filename or extension
 * @returns {string} - Standardized B2 and FTP key
 */
function getUserAssetKey(user, assetType, originalFilename = '') {
    const basePath = getUserStorageBasePath(user);
    const ext = path.extname(originalFilename || '').toLowerCase() || '.png';

    switch (assetType) {
        case 'avatar':
        case 'profile':
        case 'profile-avatar':
            return `${basePath}/profile/user-profile-avatar${ext}`;
        case 'card-avatar':
            return `${basePath}/id-card/user-id-card-avatar${ext}`;
        case 'card-bg':
        case 'card-background':
            return `${basePath}/id-card/user-id-card-background${ext}`;
        default:
            return `${basePath}/${assetType}${ext}`;
    }
}

/**
 * Resolves platform storage path:
 * - android: mods/android
 * - ios:
 *   - jailed (IPA): mods/ios/jailed
 *   - jailbroken (DEB): mods/ios/jailbroken
 * - windows: mods/windows
 * - wordpress: mods/wordpress
 *
 * @param {string} category - Category / platform identifier
 * @returns {string} - Platform path
 */
function getPlatformStoragePath(category) {
    const raw = (category || '').toLowerCase().trim();
    if (raw === 'ios-jailed' || raw === 'ios/jailed' || raw === 'jailed') {
        return 'mods/ios/jailed';
    }
    if (raw === 'ios-jailbroken' || raw === 'ios/jailbroken' || raw === 'jailbroken') {
        return 'mods/ios/jailbroken';
    }
    if (raw === 'android') {
        return 'mods/android';
    }
    if (raw === 'windows') {
        return 'mods/windows';
    }
    if (raw === 'wordpress') {
        return 'mods/wordpress';
    }
    return `mods/${slugify(raw || 'general')}`;
}

/**
 * Resolves the standardized mod storage key:
 * - Root: mods/<platform>/<mod-name>/
 *   - App Icon: mods/<platform>/<mod-name>/app-icon.<ext>
 *   - Reviews: mods/<platform>/<mod-name>/reviews/<filename>
 *   - Main File folder: mods/<platform>/<mod-name>/main-file-by-<user>@<email>/
 *     - Main file: mods/<platform>/<mod-name>/main-file-by-<user>@<email>/<filename>
 *     - Screenshots: mods/<platform>/<mod-name>/main-file-by-<user>@<email>/screenshot/file-screenshot-<1..4>.<ext>
 *     - Old versions: mods/<platform>/<mod-name>/main-file-by-<user>@<email>/old-version/<vOldVersion-filename>
 *   - Variant folder: mods/<platform>/<mod-name>/<variantId>-by-<user>@<email>/
 *     - Variant file: mods/<platform>/<mod-name>/<variantId>-by-<user>@<email>/<filename>
 *     - Screenshots: mods/<platform>/<mod-name>/<variantId>-by-<user>@<email>/screenshot/file-screenshot-<1..4>.<ext>
 *     - Old versions: mods/<platform>/<mod-name>/<variantId>-by-<user>@<email>/old-version/<vOldVersion-filename>
 *
 * @param {Object} opts
 * @param {string} opts.category - Platform category
 * @param {string} opts.modName - Mod / App name
 * @param {Object|string} opts.uploader - Uploader user object or username
 * @param {string} [opts.uploaderEmail] - Uploader email
 * @param {boolean} [opts.isVariant] - Whether this is a variant
 * @param {string} [opts.variantId] - Unique variant identifier
 * @param {'icon'|'file'|'screenshot'|'old-version'|'reviews'} opts.assetType - Asset type
 * @param {number} [opts.screenshotIndex] - 1, 2, 3, 4
 * @param {string} [opts.originalFilename] - Original filename
 * @param {string} [opts.version] - Mod version string
 * @returns {string} - Standardized B2 and FTP key
 */
function getModStorageKey(opts = {}) {
    const platPath = getPlatformStoragePath(opts.category || opts.platform);
    const modSlug = slugify(opts.modName || 'mod');
    
    // Resolve uploader username and email
    let username = 'community';
    let email = 'user@gplmods.com';
    if (opts.uploader && typeof opts.uploader === 'object') {
        username = slugify(opts.uploader.username || 'user');
        email = (opts.uploader.email || opts.uploaderEmail || 'user@gplmods.com').toLowerCase().trim();
    } else if (typeof opts.uploader === 'string') {
        username = slugify(opts.uploader);
        if (opts.uploaderEmail) email = opts.uploaderEmail.toLowerCase().trim();
    }

    const uploaderSubfolder = (opts.isVariant && opts.variantId)
        ? `${slugify(String(opts.variantId))}-by-${username}@${email}`
        : `main-file-by-${username}@${email}`;

    const ext = path.extname(opts.originalFilename || '').toLowerCase();
    const cleanFilename = sanitizeFilename(opts.originalFilename || `${modSlug}${ext}`);

    switch (opts.assetType) {
        case 'icon':
            return `${platPath}/${modSlug}/app-icon${ext || '.png'}`;
        case 'file':
            return `${platPath}/${modSlug}/${uploaderSubfolder}/${cleanFilename}`;
        case 'screenshot': {
            const idx = opts.screenshotIndex || 1;
            return `${platPath}/${modSlug}/${uploaderSubfolder}/screenshot/file-screenshot-${idx}${ext || '.png'}`;
        }
        case 'old-version': {
            const verPrefix = opts.version ? `v${opts.version.replace(/[^a-zA-Z0-9.-]/g, '')}-` : '';
            return `${platPath}/${modSlug}/${uploaderSubfolder}/old-version/${verPrefix}${cleanFilename}`;
        }
        case 'reviews':
        case 'review': {
            const revFile = opts.originalFilename ? sanitizeFilename(opts.originalFilename) : 'reviews.json';
            return `${platPath}/${modSlug}/reviews/${revFile}`;
        }
        default:
            return `${platPath}/${modSlug}/${uploaderSubfolder}/${cleanFilename}`;
    }
}

module.exports = {
    slugify,
    sanitizeFilename,
    getUserStorageBasePath,
    getUserAssetKey,
    getPlatformStoragePath,
    getModStorageKey
};
