/**
 * ============================================================================
 * CLUB SEED & RESERVED NAMES UTILITY
 * Manages the permanent default system club ("GPL Community") and protects
 * reserved names from being created by normal community members.
 * ============================================================================
 */

const Club = require('../models/community/club');
const ClubChannel = require('../models/community/clubChannel');
const ClubRole = require('../models/community/clubRole');
const ClubMember = require('../models/community/clubMember');
const ClubMessage = require('../models/community/clubMessage');
const User = require('../models/user');
const { ensureClubDirectories, saveClubMetadata } = require('./clubStorage');

const RESERVED_CLUB_NAMES = [
    'gpl community',
    'gplmods',
    'gplmods official',
    'gpl mods',
    'gpl mods official',
    'official gplmods',
    'gpl official',
    'gpl staff',
    'gpl team',
    'gpl admin',
    'gpl support'
];

/**
 * Checks if a requested club name conflicts with reserved official names.
 * @param {string} name - Requested club name.
 * @returns {boolean}
 */
function isClubNameReserved(name) {
    if (!name || typeof name !== 'string') return true;
    const clean = name.toLowerCase().replace(/[^a-z0-9 ]/g, '').replace(/\s+/g, ' ').trim();
    return RESERVED_CLUB_NAMES.some(reserved => clean === reserved || clean.includes(reserved));
}

/**
 * Ensures the default "GPL Community" club exists with all standard channels and roles.
 * All users belong to this club and cannot leave it.
 */
async function ensureDefaultClub() {
    try {
        let defaultClub = await Club.findOne({ isDefault: true });

        if (!defaultClub) {
            defaultClub = await Club.findOne({ name: 'GPL Community' });
        }

        // Find site owner or admin to assign as creator
        let creatorUser = await User.findOne({ role: 'owner' });
        if (!creatorUser) {
            creatorUser = await User.findOne({ role: 'admin' });
        }
        if (!creatorUser) {
            creatorUser = await User.findOne({});
        }

        const creatorId = creatorUser ? creatorUser._id : null;

        if (!defaultClub && creatorId) {
            console.log('[Clubs] Auto-provisioning default club "GPL Community"...');

            const { folderName, storagePath } = ensureClubDirectories('GPL Community');

            defaultClub = await Club.create({
                name: 'GPL Community',
                slug: 'gpl-community',
                description: 'The official GPLMods community hub for all members, developers, and mod creators. Get platform updates, discover safe mods, and chat with fellow modders.',
                tags: ['Official', 'Mods', 'Community', 'Android', 'iOS', 'Windows', 'WordPress', 'Safe', 'Gaming', 'Support'],
                iconUrl: '/images/team-logo.png',
                bannerUrl: '/images/default-banner.jpg',
                creator: creatorId,
                isDefault: true,
                isPrivate: false,
                joinApprovalRequired: false,
                primaryLanguage: 'English',
                country: 'GLOBAL',
                aboutAdmin: 'Official GPLMods administration team. We build and maintain 100% safe, working mods and community spaces.',
                rules: [
                    'Respect all community members, staff, and mod creators.',
                    'Only official GPLMods site links are allowed in chats.',
                    'No piracy of paid community work, scamming, or harmful payloads.',
                    'Keep conversations constructive and in the relevant channels.',
                    'Follow site terms of service and community safety guidelines.'
                ],
                storageFolderName: folderName,
                storagePath: storagePath,
                isVerified: true
            });

            saveClubMetadata(defaultClub);

            // Create default roles
            const ownerRole = await ClubRole.create({
                club: defaultClub._id,
                name: 'Club Creator',
                color: '#FFD700',
                badgeIcon: '👑',
                position: 100,
                permissions: {
                    canManageClub: true,
                    canManageChannels: true,
                    canManageRoles: true,
                    canKickMembers: true,
                    canSendMessages: true,
                    canPostPolls: true,
                    canAuditPrivate: true
                }
            });

            const staffRole = await ClubRole.create({
                club: defaultClub._id,
                name: 'Site Staff',
                color: '#5865F2',
                badgeIcon: '🛡️',
                position: 90,
                permissions: {
                    canManageClub: true,
                    canManageChannels: true,
                    canManageRoles: true,
                    canKickMembers: true,
                    canSendMessages: true,
                    canPostPolls: true,
                    canAuditPrivate: true
                }
            });

            const distributorRole = await ClubRole.create({
                club: defaultClub._id,
                name: 'Distributor',
                color: '#BA68C8',
                badgeIcon: '📦',
                position: 50,
                permissions: {
                    canManageClub: false,
                    canManageChannels: false,
                    canManageRoles: false,
                    canKickMembers: false,
                    canSendMessages: true,
                    canPostPolls: true,
                    canAuditPrivate: false
                }
            });

            const memberRole = await ClubRole.create({
                club: defaultClub._id,
                name: 'Member',
                color: '#99AAB5',
                badgeIcon: '🔰',
                position: 10,
                isDefault: true,
                permissions: {
                    canManageClub: false,
                    canManageChannels: false,
                    canManageRoles: false,
                    canKickMembers: false,
                    canSendMessages: true,
                    canPostPolls: true,
                    canAuditPrivate: false
                }
            });

            // Create standard channels
            const rulesChannel = await ClubChannel.create({
                club: defaultClub._id,
                name: 'rules',
                topic: 'Official community rules and guidelines. Please read before participating.',
                type: 'rules',
                isReadOnly: true,
                position: 1
            });

            const announcementsChannel = await ClubChannel.create({
                club: defaultClub._id,
                name: 'announcements',
                topic: 'Official GPLMods site announcements, guide updates, and warnings.',
                type: 'announcements',
                isReadOnly: true,
                position: 2
            });

            const uploadsChannel = await ClubChannel.create({
                club: defaultClub._id,
                name: 'new-uploads',
                topic: 'Automated feed of newly uploaded mods on GPLMods.',
                type: 'new-uploads',
                isReadOnly: true,
                position: 3
            });

            const updatesChannel = await ClubChannel.create({
                club: defaultClub._id,
                name: 'new-updates',
                topic: 'Automated feed of mod updates, patches, and new versions.',
                type: 'new-updates',
                isReadOnly: true,
                position: 4
            });

            const generalChannel = await ClubChannel.create({
                club: defaultClub._id,
                name: 'general',
                topic: 'General discussion for all GPLMods community members.',
                type: 'text',
                isReadOnly: false,
                position: 5
            });

            const pollsChannel = await ClubChannel.create({
                club: defaultClub._id,
                name: 'polls',
                topic: 'Community feedback polls and feature voting.',
                type: 'polls',
                isReadOnly: false,
                position: 6
            });

            defaultClub.channelCount = 6;
            await defaultClub.save();

            // Add creator as member
            await ClubMember.create({
                club: defaultClub._id,
                user: creatorId,
                roles: [ownerRole._id],
                isCreator: true,
                status: 'active'
            });

            // Post welcome seed messages
            await ClubMessage.create({
                club: defaultClub._id,
                channel: rulesChannel._id,
                sender: creatorId,
                content: `📜 **Welcome to the GPL Community Rules Channel!**\n\n1. Be respectful to all members and developers.\n2. External links to third-party websites are strictly blocked. Only official GPLMods site links may be posted.\n3. Follow platform security policies.\n4. Enjoy modding safely!`,
                isSystemMessage: true
            });

            await ClubMessage.create({
                club: defaultClub._id,
                channel: announcementsChannel._id,
                sender: creatorId,
                content: `📢 **Welcome to GPLMods Official Announcements!**\n\nStay tuned here for major site updates, new category launches, safety guides, and platform maintenance alerts.`,
                isSystemMessage: true
            });

            await ClubMessage.create({
                club: defaultClub._id,
                channel: generalChannel._id,
                sender: creatorId,
                content: `👋 Welcome to the official **#general** channel of GPLMods! Introduce yourself and share what mods you're playing.`,
                isSystemMessage: true
            });

            console.log('[Clubs] Default club "GPL Community" successfully provisioned!');
        }

        return defaultClub;
    } catch (error) {
        console.error('[Clubs] Error ensuring default club:', error);
        return null;
    }
}

/**
 * Ensures a user is enrolled in the default "GPL Community" club.
 * @param {string|Object} userOrId
 */
async function ensureUserInDefaultClub(userOrId) {
    try {
        if (!userOrId) return;
        const userId = userOrId._id || userOrId;
        const defaultClub = await Club.findOne({ isDefault: true });
        if (!defaultClub) return;

        const existing = await ClubMember.findOne({
            club: defaultClub._id,
            user: userId
        });

        if (!existing) {
            const memberRole = await ClubRole.findOne({ club: defaultClub._id, isDefault: true });
            await ClubMember.create({
                club: defaultClub._id,
                user: userId,
                roles: memberRole ? [memberRole._id] : [],
                status: 'active'
            });
            await Club.findByIdAndUpdate(defaultClub._id, { $inc: { memberCount: 1 } });
        }
    } catch (e) {
        console.error('[Clubs] Error enrolling user in default club:', e.message);
    }
}

module.exports = {
    RESERVED_CLUB_NAMES,
    isClubNameReserved,
    ensureDefaultClub,
    ensureUserInDefaultClub
};
