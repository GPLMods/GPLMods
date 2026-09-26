/**
 * ============================================================================
 * CLUB STORAGE UTILITY
 * Manages dedicated on-disk folder hierarchy for clubs and communities.
 * Creates organized folders:
 *   uploads/clubs/<SafeClubName>/
 *     ├── chat/
 *     ├── roles/
 *     ├── users/
 *     ├── gif/
 *     ├── icons/
 *     └── banners/
 * ============================================================================
 */

const fs = require('fs');
const path = require('path');

// Base directory for club storage
const CLUBS_BASE_DIR = path.join(__dirname, '..', 'uploads', 'clubs');
const PUBLIC_CLUBS_DIR = path.join(__dirname, '..', 'public', 'uploads', 'clubs');

/**
 * Sanitizes a club name for safe usage as a directory name on all OS platforms.
 * Strips characters invalid in Windows and UNIX file paths: < > : " / \ | ? *
 * @param {string} clubName
 * @returns {string}
 */
function sanitizeClubFolderName(clubName) {
    if (!clubName || typeof clubName !== 'string') return 'unnamed-club';
    let clean = clubName.replace(/[<>:"/\\|?*]/g, '').trim();
    if (!clean) clean = 'club-' + Date.now();
    return clean;
}

/**
 * Ensures all required subdirectories exist for a club.
 * @param {string} clubName
 * @returns {{ folderName: string, storagePath: string, subdirs: Object }}
 */
function ensureClubDirectories(clubName) {
    const folderName = sanitizeClubFolderName(clubName);
    const storagePath = path.join(CLUBS_BASE_DIR, folderName);
    const publicStoragePath = path.join(PUBLIC_CLUBS_DIR, folderName);

    const subdirs = {
        chat: path.join(storagePath, 'chat'),
        roles: path.join(storagePath, 'roles'),
        users: path.join(storagePath, 'users'),
        gif: path.join(storagePath, 'gif'),
        icons: path.join(storagePath, 'icons'),
        banners: path.join(storagePath, 'banners')
    };

    // Ensure main storage directories
    Object.values(subdirs).forEach(dir => {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
    });

    // Also ensure public mirror for web-accessible icons, banners, and gifs
    ['icons', 'banners', 'gif'].forEach(folder => {
        const publicSubdir = path.join(publicStoragePath, folder);
        if (!fs.existsSync(publicSubdir)) {
            fs.mkdirSync(publicSubdir, { recursive: true });
        }
    });

    return {
        folderName,
        storagePath,
        publicStoragePath,
        subdirs
    };
}

/**
 * Writes or updates the club-info.json metadata file on disk.
 * @param {Object} club
 */
function saveClubMetadata(club) {
    try {
        if (!club || !club.name) return;
        const { storagePath } = ensureClubDirectories(club.name);
        const infoFile = path.join(storagePath, 'club-info.json');
        const data = {
            id: String(club._id || club.id),
            name: club.name,
            slug: club.slug,
            description: club.description || '',
            tags: club.tags || [],
            isDefault: Boolean(club.isDefault),
            isPrivate: Boolean(club.isPrivate),
            primaryLanguage: club.primaryLanguage || 'English',
            country: club.country || 'GLOBAL',
            aboutAdmin: club.aboutAdmin || '',
            rules: club.rules || [],
            memberCount: club.memberCount || 1,
            updatedAt: new Date().toISOString()
        };
        fs.writeFileSync(infoFile, JSON.stringify(data, null, 2), 'utf8');
    } catch (e) {
        console.error(`[ClubStorage] Error saving metadata for ${club?.name}:`, e.message);
    }
}

/**
 * Saves chat message archive dump to disk.
 * @param {string} clubName
 * @param {string} channelName
 * @param {Array} messages
 */
function saveClubChatArchive(clubName, channelName, messages) {
    try {
        const { subdirs } = ensureClubDirectories(clubName);
        const safeChannelName = (channelName || 'general').replace(/[^a-zA-Z0-9_-]/g, '_');
        const filePath = path.join(subdirs.chat, `${safeChannelName}.json`);
        fs.writeFileSync(filePath, JSON.stringify(messages || [], null, 2), 'utf8');
        return { success: true, filePath };
    } catch (e) {
        console.error(`[ClubStorage] Error saving chat archive for ${clubName}:`, e.message);
        return { success: false, error: e.message };
    }
}

/**
 * Saves roles dump to disk.
 * @param {string} clubName
 * @param {Array} roles
 */
function saveClubRolesArchive(clubName, roles) {
    try {
        const { subdirs } = ensureClubDirectories(clubName);
        const filePath = path.join(subdirs.roles, 'roles.json');
        fs.writeFileSync(filePath, JSON.stringify(roles || [], null, 2), 'utf8');
        return { success: true, filePath };
    } catch (e) {
        console.error(`[ClubStorage] Error saving roles archive for ${clubName}:`, e.message);
        return { success: false, error: e.message };
    }
}

/**
 * Saves member roster dump to disk.
 * @param {string} clubName
 * @param {Array} members
 */
function saveClubMembersArchive(clubName, members) {
    try {
        const { subdirs } = ensureClubDirectories(clubName);
        const filePath = path.join(subdirs.users, 'members.json');
        fs.writeFileSync(filePath, JSON.stringify(members || [], null, 2), 'utf8');
        return { success: true, filePath };
    } catch (e) {
        console.error(`[ClubStorage] Error saving members archive for ${clubName}:`, e.message);
        return { success: false, error: e.message };
    }
}

module.exports = {
    CLUBS_BASE_DIR,
    PUBLIC_CLUBS_DIR,
    sanitizeClubFolderName,
    ensureClubDirectories,
    saveClubMetadata,
    saveClubChatArchive,
    saveClubRolesArchive,
    saveClubMembersArchive
};
