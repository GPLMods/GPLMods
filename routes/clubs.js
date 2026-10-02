/**
 * ============================================================================
 * CLUBS & COMMUNITIES ROUTER
 * Handles Discord-like club directory, channels, real-time messaging, roles,
 * polls, join requests, distributor mod tracking, and link security.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const multer = require('multer');

// Models
const Club = require('../models/community/club');
const ClubChannel = require('../models/community/clubChannel');
const ClubRole = require('../models/community/clubRole');
const ClubMember = require('../models/community/clubMember');
const ClubMessage = require('../models/community/clubMessage');
const ClubJoinRequest = require('../models/community/clubJoinRequest');
const ClubInvite = require('../models/community/clubInvite');
const User = require('../models/user');
const UserNotification = require('../models/userNotification');

// Utilities
const { ensureClubDirectories, saveClubMetadata, saveClubChatArchive, saveClubRolesArchive, saveClubMembersArchive } = require('../utils/clubStorage');
const { isClubNameReserved, ensureDefaultClub, ensureUserInDefaultClub } = require('../utils/clubSeed');
const { validateMessageLinks } = require('../utils/linkSanitizer');

// Multer Storage for Club Icon & Banner
const clubMediaStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        const tempDir = path.join(__dirname, '..', 'public', 'uploads', 'clubs', '_temp');
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        cb(null, tempDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, 'club-' + uniqueSuffix + ext);
    }
});

const uploadClubMedia = multer({
    storage: clubMediaStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: function (req, file, cb) {
        const allowedTypes = /jpeg|jpg|png|webp|gif/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);
        if (extname && mimetype) {
            return cb(null, true);
        }
        cb(new Error('Only JPG, PNG, WEBP, and GIF images are allowed.'));
    }
});

// Middleware: Require Login
function ensureAuth(req, res, next) {
    if (req.isAuthenticated && req.isAuthenticated()) {
        return next();
    }
    return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
}

// Helper: Slugify text
function slugify(text) {
    if (!text) return '';
    return text.toString().toLowerCase()
        .replace(/\s+/g, '-')
        .replace(/[^\w\-]+/g, '')
        .replace(/\-\-+/g, '-')
        .replace(/^-+/, '')
        .replace(/-+$/, '');
}

// Helper: Resolve club by slug or id
async function resolveClub(slugOrId) {
    if (!slugOrId) return null;
    let club = null;
    if (slugOrId.match(/^[0-9a-fA-F]{24}$/)) {
        club = await Club.findById(slugOrId).populate('creator', 'username profileImageKey role signedAvatarUrl');
    }
    if (!club) {
        club = await Club.findOne({ slug: slugOrId.toLowerCase() }).populate('creator', 'username profileImageKey role signedAvatarUrl');
    }
    if (club) {
        club.bannerUrl = club.bannerUrl || '/images/default-banner.jpg';
    }
    return club;
}

// ============================================================================
// 1. CLUBS DIRECTORY & DISCOVERY (INDEX)
// ============================================================================
router.get('/', async (req, res) => {
    try {
        await ensureDefaultClub();
        if (req.user) {
            await ensureUserInDefaultClub(req.user._id);
        }

        const { q, tag, lang, country, access, sort } = req.query;
        let queryFilter = {};

        // Keyword Search
        if (q && q.trim()) {
            const regex = new RegExp(q.trim(), 'i');
            queryFilter.$or = [
                { name: regex },
                { description: regex },
                { tags: regex }
            ];
            // If query is an ObjectId
            if (q.trim().match(/^[0-9a-fA-F]{24}$/)) {
                queryFilter.$or.push({ _id: q.trim() });
            }
        }

        // Tag Filter
        if (tag && tag.trim()) {
            queryFilter.tags = { $in: [new RegExp(`^${tag.trim()}$`, 'i')] };
        }

        // Language Filter
        if (lang && lang !== 'all') {
            queryFilter.primaryLanguage = lang;
        }

        // Country/Region Filter
        if (country && country !== 'all') {
            queryFilter.country = country;
        }

        // Access Filter
        if (access === 'public') {
            queryFilter.isPrivate = false;
        } else if (access === 'private') {
            queryFilter.isPrivate = true;
        }

        // Sorting
        let sortOption = { isDefault: -1, memberCount: -1, createdAt: -1 };
        if (sort === 'newest') sortOption = { isDefault: -1, createdAt: -1 };
        if (sort === 'members') sortOption = { isDefault: -1, memberCount: -1 };
        if (sort === 'name') sortOption = { name: 1 };

        const clubs = await Club.find(queryFilter)
            .sort(sortOption)
            .populate('creator', 'username profileImageKey role signedAvatarUrl')
            .lean();

        // Get user's joined club IDs if logged in
        let joinedClubIds = [];
        if (req.user) {
            const memberships = await ClubMember.find({ user: req.user._id, status: 'active' }).select('club').lean();
            joinedClubIds = memberships.map(m => String(m.club));
        }

        // Popular tags for filter bar
        const popularTags = ['Official', 'Mods', 'Android', 'iOS', 'Windows', 'WordPress', 'Gaming', 'Support', 'Tweaks', 'Dev'];

        clubs.forEach(c => {
            c.bannerUrl = c.bannerUrl || '/images/default-banner.jpg';
        });

        let userCreatedCount = 0;
        let userClubCap = 3;
        let isHigherTierUser = false;
        if (req.user) {
            userCreatedCount = await Club.countDocuments({ creator: req.user._id });
            const capInfo = getClubCreationCap(req.user);
            userClubCap = capInfo.cap;
            isHigherTierUser = capInfo.isHigherTier;
        }

        res.render('pages/clubs/index', {
            pageTitle: 'Clubs & Communities',
            pageDescription: 'Discover and join creator clubs, distributor communities, and modding channels on GPLMods.',
            clubs,
            totalClubs: clubs.length,
            joinedClubIds,
            popularTags,
            userCreatedCount,
            userClubCap,
            isHigherTierUser,
            filters: {
                q: q || '',
                tag: tag || '',
                lang: lang || 'all',
                country: country || 'all',
                access: access || 'all',
                sort: sort || 'members'
            }
        });
    } catch (err) {
        console.error('[Clubs] Index error:', err);
        res.status(500).render('pages/error', { errorCode: '500', errorTitle: 'Server Error', errorMessage: 'Failed to load clubs. Please try again later.' });
    }
});

// Helper to determine club creation cap: 3 for Free, 5 for GPLLite, GPLPlus, Owner, Distributor, Admin, Support
function getClubCreationCap(user) {
    if (!user) return { cap: 0, isHigherTier: false };
    const higherTierMemberships = ['GPLLite', 'GPLPlus', 'lite', 'plus', 'premium'];
    const staffRoles = ['owner', 'distributor', 'admin', 'support'];
    const isHigherTier = higherTierMemberships.includes(user.membership) || staffRoles.includes(user.role);
    return {
        cap: isHigherTier ? 5 : 3,
        isHigherTier
    };
}

// ============================================================================
// 2. CREATE A NEW CLUB
// ============================================================================
router.get('/create', ensureAuth, async (req, res) => {
    try {
        const userCreatedCount = await Club.countDocuments({ creator: req.user._id });
        const { cap: maxClubsAllowed, isHigherTier } = getClubCreationCap(req.user);
        const limitReached = userCreatedCount >= maxClubsAllowed;

        res.render('pages/clubs/create', {
            pageTitle: 'Create a Club',
            error: limitReached ? `You have reached your limit of ${maxClubsAllowed} clubs (${isHigherTier ? 'GPLLite, GPLPlus, and Staff members can create up to 5 clubs' : 'Free users can create up to 3 clubs. Upgrade to GPLLite or GPLPlus to create up to 5 clubs'}).` : null,
            formData: {},
            userCreatedCount,
            maxClubsAllowed,
            isHigherTier,
            limitReached
        });
    } catch (err) {
        console.error("Error loading club create page:", err);
        res.redirect('/clubs');
    }
});

router.post('/create', ensureAuth, uploadClubMedia.fields([
    { name: 'icon', maxCount: 1 },
    { name: 'banner', maxCount: 1 }
]), async (req, res) => {
    try {
        const { name, description, tags, primaryLanguage, country, aboutAdmin, rules, isPrivate, joinApprovalRequired } = req.body;

        const formData = { name, description, tags, primaryLanguage, country, aboutAdmin, rules, isPrivate };

        // Check user's created club count (3 max for free, 5 max for GPLLite, GPLPlus, Owner, Distributor, Admin, Support)
        const userCreatedCount = await Club.countDocuments({ creator: req.user._id });
        const { cap: maxClubsAllowed, isHigherTier } = getClubCreationCap(req.user);
        const limitReached = userCreatedCount >= maxClubsAllowed;

        if (limitReached) {
            return res.render('pages/clubs/create', {
                pageTitle: 'Create a Club',
                error: `You have reached your limit of ${maxClubsAllowed} clubs (${isHigherTier ? 'GPLLite, GPLPlus, and Staff members can create up to 5 clubs max' : 'Free users can create up to 3 clubs max. Upgrade to GPLLite or GPLPlus to create up to 5 clubs'}).`,
                formData,
                userCreatedCount,
                maxClubsAllowed,
                isHigherTier,
                limitReached: true
            });
        }

        // 1. Validate Club Name
        if (!name || name.trim().length < 3) {
            return res.render('pages/clubs/create', {
                pageTitle: 'Create a Club',
                error: 'Club name must be at least 3 characters long.',
                formData,
                userCreatedCount,
                maxClubsAllowed,
                isHigherTier,
                limitReached: false
            });
        }

        if (name.trim().length > 60) {
            return res.render('pages/clubs/create', {
                pageTitle: 'Create a Club',
                error: 'Club name cannot exceed 60 characters.',
                formData,
                userCreatedCount,
                maxClubsAllowed,
                isHigherTier,
                limitReached: false
            });
        }

        // 2. Reserved Name Check
        if (isClubNameReserved(name.trim())) {
            return res.render('pages/clubs/create', {
                pageTitle: 'Create a Club',
                error: 'This club name is reserved for official GPLMods communities. Please choose another name.',
                formData,
                userCreatedCount,
                maxClubsAllowed,
                isHigherTier,
                limitReached: false
            });
        }

        // 3. Name Uniqueness Check
        const existingClub = await Club.findOne({ name: new RegExp(`^${name.trim()}$`, 'i') });
        if (existingClub) {
            return res.render('pages/clubs/create', {
                pageTitle: 'Create a Club',
                error: 'A club with this name already exists. Please choose a unique name.',
                formData,
                userCreatedCount,
                maxClubsAllowed,
                isHigherTier,
                limitReached: false
            });
        }

        const clubSlug = slugify(name.trim());
        const slugExists = await Club.findOne({ slug: clubSlug });
        const finalSlug = slugExists ? `${clubSlug}-${Date.now().toString().slice(-4)}` : clubSlug;

        // 4. Parse Tags (Max 10)
        let parsedTags = [];
        if (tags && typeof tags === 'string') {
            parsedTags = tags.split(',')
                .map(t => t.trim())
                .filter(t => t.length > 0)
                .slice(0, 10);
        }

        // 5. Parse Rules
        let parsedRules = [];
        if (rules && typeof rules === 'string') {
            parsedRules = rules.split('\n')
                .map(r => r.trim())
                .filter(r => r.length > 0);
        }
        if (parsedRules.length === 0) {
            parsedRules = [
                'Be respectful to all members and staff.',
                'Only official GPLMods site links are allowed.',
                'No spam, scamming, or abusive language.',
                'Follow community guidelines.'
            ];
        }

        // 6. Setup Directory on Disk
        const { folderName, storagePath, publicStoragePath } = ensureClubDirectories(name.trim());

        // Handle uploaded icon & banner
        let iconUrl = '/images/default-avatar.png';
        let bannerUrl = '/images/default-banner.jpg';

        if (req.files && req.files.icon && req.files.icon[0]) {
            const uploadedIcon = req.files.icon[0];
            const destPath = path.join(publicStoragePath, 'icons', path.basename(uploadedIcon.path));
            fs.renameSync(uploadedIcon.path, destPath);
            iconUrl = `/uploads/clubs/${folderName}/icons/${path.basename(destPath)}`;
        }

        if (req.files && req.files.banner && req.files.banner[0]) {
            const uploadedBanner = req.files.banner[0];
            const destPath = path.join(publicStoragePath, 'banners', path.basename(uploadedBanner.path));
            fs.renameSync(uploadedBanner.path, destPath);
            bannerUrl = `/uploads/clubs/${folderName}/banners/${path.basename(destPath)}`;
        }

        // 7. Create Club Document
        const newClub = await Club.create({
            name: name.trim(),
            slug: finalSlug,
            description: description ? description.trim() : '',
            tags: parsedTags,
            iconUrl,
            bannerUrl,
            creator: req.user._id,
            isDefault: false,
            isPrivate: isPrivate === 'on' || isPrivate === 'true',
            joinApprovalRequired: joinApprovalRequired === 'on' || joinApprovalRequired === 'true',
            primaryLanguage: primaryLanguage || 'English',
            country: country || 'GLOBAL',
            aboutAdmin: aboutAdmin ? aboutAdmin.trim() : '',
            rules: parsedRules,
            storageFolderName: folderName,
            storagePath: storagePath,
            trackedCreators: [req.user._id], // Creator is tracked by default for updates
            memberCount: 1,
            channelCount: 6,
            isVerified: ['owner', 'admin', 'distributor', 'support'].includes(req.user.role)
        });

        // 8. Create Default Roles for this Club
        const ownerRole = await ClubRole.create({
            club: newClub._id,
            name: 'Club Creator',
            color: '#FFD700',
            badgeIcon: '🎨',
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

        const modRole = await ClubRole.create({
            club: newClub._id,
            name: 'Moderator',
            color: '#5865F2',
            badgeIcon: '🛡️',
            position: 50,
            permissions: {
                canManageClub: false,
                canManageChannels: true,
                canManageRoles: false,
                canKickMembers: true,
                canSendMessages: true,
                canPostPolls: true,
                canAuditPrivate: false
            }
        });

        const memberRole = await ClubRole.create({
            club: newClub._id,
            name: 'everyone',
            color: '#99AAB5',
            badgeIcon: '🌐',
            position: 1,
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

        // 9. Create Standard Channels
        const rulesChan = await ClubChannel.create({
            club: newClub._id,
            name: 'rules',
            topic: 'Community rules and guidelines.',
            type: 'rules',
            isReadOnly: true,
            position: 1
        });

        const announcementsChan = await ClubChannel.create({
            club: newClub._id,
            name: 'announcements',
            topic: 'Official club announcements and updates.',
            type: 'announcements',
            isReadOnly: true,
            position: 2
        });

        const uploadsChan = await ClubChannel.create({
            club: newClub._id,
            name: 'new-uploads',
            topic: 'Automated feed of new mods uploaded by tracked creators.',
            type: 'new-uploads',
            isReadOnly: true,
            position: 3
        });

        const updatesChan = await ClubChannel.create({
            club: newClub._id,
            name: 'new-updates',
            topic: 'Automated feed of updates and new versions for tracked mods.',
            type: 'new-updates',
            isReadOnly: true,
            position: 4
        });

        const generalChan = await ClubChannel.create({
            club: newClub._id,
            name: 'general',
            topic: 'General chat and discussion.',
            type: 'text',
            isReadOnly: false,
            position: 5
        });

        const pollsChan = await ClubChannel.create({
            club: newClub._id,
            name: 'polls',
            topic: 'Community votes and surveys.',
            type: 'polls',
            isReadOnly: false,
            position: 6
        });

        // 10. Enroll Creator
        await ClubMember.create({
            club: newClub._id,
            user: req.user._id,
            roles: [ownerRole._id],
            isCreator: true,
            status: 'active'
        });

        // Save disk metadata
        saveClubMetadata(newClub);

        // Initial welcome message in rules
        await ClubMessage.create({
            club: newClub._id,
            channel: rulesChan._id,
            sender: req.user._id,
            content: `📜 **Welcome to ${newClub.name}!**\n\nPlease read and respect our community rules:\n${parsedRules.map((r, i) => `${i + 1}. ${r}`).join('\n')}`,
            isSystemMessage: true
        });

        return res.redirect(`/clubs/${newClub.slug}`);
    } catch (err) {
        console.error('[Clubs] Club creation error:', err);
        const userCreatedCount = await Club.countDocuments({ creator: req.user._id }).catch(() => 0);
        const { cap: maxClubsAllowed, isHigherTier } = getClubCreationCap(req.user);
        return res.render('pages/clubs/create', {
            pageTitle: 'Create a Club',
            error: 'An unexpected error occurred while creating your club. Please try again.',
            formData: req.body || {},
            userCreatedCount,
            maxClubsAllowed,
            isHigherTier,
            limitReached: false
        });
    }
});

// ============================================================================
// 3. PRE-JOIN PREVIEW (INFORMATION AT A GLANCE)
// ============================================================================
router.get('/:slugOrId/preview', async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) {
            return res.status(404).render('pages/error', { errorCode: '404', errorTitle: 'Club Not Found', errorMessage: 'The club you are looking for does not exist.' });
        }

        let isMember = false;
        let isPending = false;

        if (req.user) {
            const membership = await ClubMember.findOne({ club: club._id, user: req.user._id });
            if (membership && membership.status === 'active') {
                isMember = true;
            } else if (membership && membership.status === 'pending_approval') {
                isPending = true;
            }
            if (!isPending) {
                const pendingReq = await ClubJoinRequest.findOne({ club: club._id, user: req.user._id, status: 'pending' });
                if (pendingReq) isPending = true;
            }
        }

        res.render('pages/clubs/preview', {
            pageTitle: `${club.name} - Preview`,
            club,
            isMember,
            isPending,
            isStaff: req.user && ['owner', 'admin'].includes(req.user.role)
        });
    } catch (err) {
        console.error('[Clubs] Preview error:', err);
        res.status(500).render('pages/error', { errorCode: '500', errorTitle: 'Server Error', errorMessage: 'Failed to load club preview.' });
    }
});

// ============================================================================
// 4. DISCORD-LIKE MAIN CLUB INTERFACE
// ============================================================================
router.get('/:slugOrId', async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) {
            return res.status(404).render('pages/error', { errorCode: '404', errorTitle: 'Club Not Found', errorMessage: 'The club you are looking for does not exist.' });
        }
        if (!club.bannerUrl || club.isDefault || club.slug === 'gpl-community') {
            club.bannerUrl = club.bannerUrl || '/images/default-banner.jpg';
        }

        // Check if user visited via a unique invite code (?invite=CODE)
        let inviteCodeUsed = req.query.invite ? String(req.query.invite).trim().toUpperCase() : null;
        let validInvite = null;
        if (inviteCodeUsed) {
            validInvite = await ClubInvite.findOne({ club: club._id, code: inviteCodeUsed }).populate('inviter', 'username');
        }

        // If user is guest
        if (!req.user) {
            if (inviteCodeUsed) {
                return res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
            }
            return res.redirect(`/clubs/${club.slug}/preview`);
        }

        // Check if user is staff (Owner or Admin)
        const isStaff = ['owner', 'admin'].includes(req.user.role);

        // Check membership
        let membership = await ClubMember.findOne({ club: club._id, user: req.user._id });

        // If default club ("GPL Community"), auto-enroll user immediately
        if (!membership && club.isDefault) {
            await ensureUserInDefaultClub(req.user._id);
            membership = await ClubMember.findOne({ club: club._id, user: req.user._id });
        }

        // Ensure default role exists
        let defaultRole = await ClubRole.findOne({ club: club._id, isDefault: true });
        if (defaultRole && defaultRole.name === 'Member') {
            defaultRole.name = 'everyone';
            defaultRole.badgeIcon = '🌐';
            defaultRole.position = 1;
            await defaultRole.save();
        } else if (!defaultRole) {
            defaultRole = await ClubRole.create({
                club: club._id,
                name: 'everyone',
                color: '#99AAB5',
                badgeIcon: '🌐',
                position: 1,
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
        }

        // Process Joining via Unique Invite Code if not already active member
        let justJoinedViaInvite = false;
        if (validInvite && (!membership || membership.status !== 'active')) {
            if (!membership) {
                membership = await ClubMember.create({
                    club: club._id,
                    user: req.user._id,
                    roles: defaultRole ? [defaultRole._id] : [],
                    status: 'active',
                    invitedBy: validInvite.inviter ? validInvite.inviter._id : null
                });
                await Club.findByIdAndUpdate(club._id, { $inc: { memberCount: 1 } });
            } else {
                membership.status = 'active';
                if (validInvite.inviter) membership.invitedBy = validInvite.inviter._id;
                await membership.save();
                await Club.findByIdAndUpdate(club._id, { $inc: { memberCount: 1 } });
            }
            justJoinedViaInvite = true;

            // Increment invite uses
            validInvite.uses = (validInvite.uses || 0) + 1;
            await validInvite.save();

            // Increment inviter's total invite count
            if (validInvite.inviter) {
                const inviterMember = await ClubMember.findOneAndUpdate(
                    { club: club._id, user: validInvite.inviter._id },
                    { $inc: { inviteCount: 1 } },
                    { new: true }
                );
                const newInviteCount = inviterMember ? (inviterMember.inviteCount || 1) : 1;

                // Post announcement welcome message to club
                const welcomeChan = await ClubChannel.findOne({ club: club._id, name: { $in: ['general', 'announcements'] } }) || await ClubChannel.findOne({ club: club._id });
                if (welcomeChan) {
                    const welcomeMsg = await ClubMessage.create({
                        club: club._id,
                        channel: welcomeChan._id,
                        sender: validInvite.inviter._id,
                        content: `🎉 **@${req.user.username}** joined the club via **@${validInvite.inviter.username}**'s invite link! (@${validInvite.inviter.username} now has **${newInviteCount}** invites 🏆)`,
                        isSystemMessage: true
                    });
                    const io = req.app.get('io');
                    if (io) {
                        io.to(`club_${club._id}_chan_${welcomeChan._id}`).emit('club_new_message', {
                            _id: welcomeMsg._id,
                            channel: welcomeChan._id,
                            club: club._id,
                            content: welcomeMsg.content,
                            isSystemMessage: true,
                            createdAt: welcomeMsg.createdAt,
                            sender: {
                                username: 'GPL Community',
                                signedAvatarUrl: '/images/team-logo.png',
                                role: 'admin',
                                badges: []
                            }
                        });
                    }
                }

                // In-App Notification to Inviter
                await UserNotification.create({
                    user: validInvite.inviter._id,
                    title: 'New Club Invite Accepted! 🏆',
                    message: `${req.user.username} accepted your invitation and joined "${club.name}"! You now have ${newInviteCount} total invites.`,
                    type: 'success',
                    link: `/clubs/${club.slug}`
                });
            }
        }

        // If user is not member and not site staff
        if (!membership && !isStaff) {
            if (club.isPrivate) {
                return res.redirect(`/clubs/${club.slug}/preview`);
            } else {
                // Auto-join public club upon direct visit if logged in
                membership = await ClubMember.create({
                    club: club._id,
                    user: req.user._id,
                    roles: defaultRole ? [defaultRole._id] : [],
                    status: 'active'
                });
                await Club.findByIdAndUpdate(club._id, { $inc: { memberCount: 1 } });
            }
        }

        // Fetch all channels for this club sorted by position, deduplicate in DB if duplicates exist
        const rawChannels = await ClubChannel.find({ club: club._id }).sort({ position: 1, createdAt: 1 });
        const seenChanMap = new Map();
        const allChannels = [];
        const duplicateChanIdsToDelete = [];

        for (const chan of rawChannels) {
            const normName = String(chan.name || '').toLowerCase().trim();
            if (!seenChanMap.has(normName)) {
                seenChanMap.set(normName, chan);
                allChannels.push(chan.toObject ? chan.toObject() : chan);
            } else {
                const keeperChan = seenChanMap.get(normName);
                await ClubMessage.updateMany({ channel: chan._id }, { $set: { channel: keeperChan._id } });
                duplicateChanIdsToDelete.push(chan._id);
            }
        }

        if (duplicateChanIdsToDelete.length > 0) {
            await ClubChannel.deleteMany({ _id: { $in: duplicateChanIdsToDelete } });
            await Club.findByIdAndUpdate(club._id, { channelCount: allChannels.length });
        }

        // Filter visible channels based on Role-Specific channel permissions
        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id) || (req.user && (req.user.role === 'owner' || (club.isDefault && req.user.role === 'admin')));
        const userClubRoles = membership ? (membership.roles || []) : [];
        const userClubRoleIds = userClubRoles.map(r => String(r._id || r));
        const hasManageClubPerm = isStaff || isClubCreator || userClubRoles.some(r => r && r.permissions && r.permissions.canManageClub);

        const channels = allChannels.filter(chan => {
            const mode = chan.accessMode || (chan.isPrivate ? 'role_private' : 'open');
            if (mode === 'open' || mode === 'public_view') {
                return true;
            }
            if (mode === 'role_private') {
                if (isStaff || isClubCreator) return true;
                if (!chan.allowedRoles || chan.allowedRoles.length === 0) return false;
                return chan.allowedRoles.some(r => userClubRoleIds.includes(String(r._id || r)));
            }
            return true;
        });

        // Determine active channel (from query `?channel=...` or defaults to `#general` or first visible)
        let activeChannel = null;
        if (req.query.channel) {
            activeChannel = channels.find(c => String(c._id) === req.query.channel || c.name === req.query.channel);
        }
        if (!activeChannel) {
            activeChannel = channels.find(c => c.name === 'general') || channels[0] || null;
        }

        // Calculate if user can chat in the active channel
        let canUserChatInActiveChannel = false;
        if (activeChannel) {
            if (isStaff || isClubCreator) {
                canUserChatInActiveChannel = true;
            } else if (activeChannel.isReadOnly) {
                canUserChatInActiveChannel = false;
            } else {
                const mode = activeChannel.accessMode || (activeChannel.isPrivate ? 'role_private' : 'open');
                if (mode === 'open') {
                    canUserChatInActiveChannel = true;
                } else if (mode === 'public_view' || mode === 'role_private') {
                    // Only allowed roles can chat
                    canUserChatInActiveChannel = Boolean(activeChannel.allowedRoles && activeChannel.allowedRoles.some(r => userClubRoleIds.includes(String(r._id || r))));
                } else {
                    canUserChatInActiveChannel = true;
                }
            }
        }

        // Fetch recent messages for active channel
        let messages = [];
        const getSmartImg = req.app.get('getSmartImageUrl');
        if (activeChannel) {
            messages = await ClubMessage.find({ channel: activeChannel._id })
                .sort({ createdAt: -1 })
                .limit(75)
                .populate({
                    path: 'sender',
                    select: 'username profileImageKey role signedAvatarUrl cardAvatarUrl avatar avatarUrl membership isPremium badges'
                })
                .lean();

            for (const msg of messages) {
                if (msg.sender) {
                    const isGPLMods = msg.sender.username === 'GPLMods';
                    const defaultLogo = isGPLMods ? '/images/team-logo.png' : '/images/default-avatar.png';
                    if (msg.sender.signedAvatarUrl && msg.sender.signedAvatarUrl !== '/images/default-avatar.png') {
                        // Keep signed avatar
                    } else if (msg.sender.cardAvatarUrl && msg.sender.cardAvatarUrl !== '/images/default-avatar.png') {
                        msg.sender.signedAvatarUrl = msg.sender.cardAvatarUrl;
                    } else if (msg.sender.avatarUrl && msg.sender.avatarUrl !== '/images/default-avatar.png') {
                        msg.sender.signedAvatarUrl = msg.sender.avatarUrl;
                    } else if (msg.sender.avatar && msg.sender.avatar !== '/images/default-avatar.png') {
                        msg.sender.signedAvatarUrl = msg.sender.avatar;
                    } else if (msg.sender.profileImageKey && getSmartImg) {
                        try {
                            const url = await getSmartImg(msg.sender.profileImageKey);
                            if (url && url !== '/images/default-avatar.png') {
                                msg.sender.signedAvatarUrl = url;
                            }
                        } catch(e) {}
                    }
                    if (!msg.sender.signedAvatarUrl) {
                        msg.sender.signedAvatarUrl = defaultLogo;
                    }
                }
            }
            messages.reverse(); // Chronological order
        }

        // Fetch roles for this club
        const roles = await ClubRole.find({ club: club._id }).sort({ position: -1 }).lean();

        // Fetch members of this club (with populated user info)
        const members = await ClubMember.find({ club: club._id, status: 'active' })
            .populate({
                path: 'user',
                select: 'username profileImageKey role signedAvatarUrl cardAvatarUrl avatar avatarUrl membership isPremium badges'
            })
            .populate('roles')
            .lean();

        for (const m of members) {
            if (m.user) {
                const isGPLMods = m.user.username === 'GPLMods';
                const defaultLogo = isGPLMods ? '/images/team-logo.png' : '/images/default-avatar.png';
                if (m.user.signedAvatarUrl && m.user.signedAvatarUrl !== '/images/default-avatar.png') {
                    // Keep signed avatar
                } else if (m.user.cardAvatarUrl && m.user.cardAvatarUrl !== '/images/default-avatar.png') {
                    m.user.signedAvatarUrl = m.user.cardAvatarUrl;
                } else if (m.user.avatarUrl && m.user.avatarUrl !== '/images/default-avatar.png') {
                    m.user.signedAvatarUrl = m.user.avatarUrl;
                } else if (m.user.avatar && m.user.avatar !== '/images/default-avatar.png') {
                    m.user.signedAvatarUrl = m.user.avatar;
                } else if (m.user.profileImageKey && getSmartImg) {
                    try {
                        const url = await getSmartImg(m.user.profileImageKey);
                        if (url && url !== '/images/default-avatar.png') {
                            m.user.signedAvatarUrl = url;
                        }
                    } catch(e) {}
                }
                if (!m.user.signedAvatarUrl) {
                    m.user.signedAvatarUrl = defaultLogo;
                }
            }
        }

        // Fetch user's joined clubs for the leftmost vertical rail
        const userMemberships = await ClubMember.find({ user: req.user._id, status: 'active' })
            .populate('club')
            .lean();
        const joinedClubs = userMemberships.map(m => m.club).filter(Boolean);

        // Fetch or create logged-in user's unique invite code
        let myInvite = await ClubInvite.findOne({ club: club._id, inviter: req.user._id });
        if (!myInvite) {
            const code = crypto.randomBytes(4).toString('hex').toUpperCase();
            myInvite = await ClubInvite.create({
                club: club._id,
                inviter: req.user._id,
                code: code
            });
        }
        const myInviteCount = membership ? (membership.inviteCount || 0) : 0;

        // Check pending join requests count (for badge in settings)
        let pendingRequestsCount = 0;
        if (hasManageClubPerm) {
            pendingRequestsCount = await ClubJoinRequest.countDocuments({ club: club._id, status: 'pending' });
        }

        res.render('pages/clubs/view', {
            pageTitle: `${club.name} | GPLMods Clubs`,
            club,
            channels,
            activeChannel,
            canUserChatInActiveChannel,
            myInviteCode: myInvite ? myInvite.code : '',
            myInviteCount,
            userClubRoleIds,
            messages,
            roles,
            members,
            joinedClubs,
            membership,
            isStaff,
            isClubCreator,
            hasManageClubPerm,
            pendingRequestsCount,
            vanishedModeDefault: req.session.vanishedMode === true
        });
    } catch (err) {
        console.error('[Clubs] View club error:', err);
        res.status(500).render('pages/error', { errorCode: '500', errorTitle: 'Server Error', errorMessage: 'Failed to load club interface.' });
    }
});

// ============================================================================
// 5. JOIN / LEAVE CLUB & UNIQUE INVITES
// ============================================================================
router.post('/:slugOrId/join', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const inviteCode = (req.body.invite || req.query.invite || '').trim().toUpperCase();
        let validInvite = null;
        if (inviteCode) {
            validInvite = await ClubInvite.findOne({ club: club._id, code: inviteCode }).populate('inviter', 'username');
        }

        const existing = await ClubMember.findOne({ club: club._id, user: req.user._id });
        if (existing && existing.status === 'active') {
            return res.redirect(`/clubs/${club.slug}`);
        }

        if (club.isPrivate && !club.isDefault && !validInvite) {
            return res.redirect(`/clubs/${club.slug}/preview?req=1`);
        }

        const defaultRole = await ClubRole.findOne({ club: club._id, isDefault: true });

        if (existing) {
            existing.status = 'active';
            if (validInvite && validInvite.inviter) existing.invitedBy = validInvite.inviter._id;
            await existing.save();
        } else {
            await ClubMember.create({
                club: club._id,
                user: req.user._id,
                roles: defaultRole ? [defaultRole._id] : [],
                status: 'active',
                invitedBy: validInvite && validInvite.inviter ? validInvite.inviter._id : null
            });
            await Club.findByIdAndUpdate(club._id, { $inc: { memberCount: 1 } });
        }

        if (validInvite && validInvite.inviter) {
            validInvite.uses = (validInvite.uses || 0) + 1;
            await validInvite.save();

            const inviterMember = await ClubMember.findOneAndUpdate(
                { club: club._id, user: validInvite.inviter._id },
                { $inc: { inviteCount: 1 } },
                { new: true }
            );
            const newInviteCount = inviterMember ? (inviterMember.inviteCount || 1) : 1;

            const welcomeChan = await ClubChannel.findOne({ club: club._id, name: { $in: ['general', 'announcements'] } }) || await ClubChannel.findOne({ club: club._id });
            if (welcomeChan) {
                const welcomeMsg = await ClubMessage.create({
                    club: club._id,
                    channel: welcomeChan._id,
                    sender: validInvite.inviter._id,
                    content: `🎉 **@${req.user.username}** joined the club via **@${validInvite.inviter.username}**'s invite link! (@${validInvite.inviter.username} now has **${newInviteCount}** invites 🏆)`,
                    isSystemMessage: true
                });
                const io = req.app.get('io');
                if (io) {
                    io.to(`club_${club._id}_chan_${welcomeChan._id}`).emit('club_new_message', {
                        _id: welcomeMsg._id,
                        channel: welcomeChan._id,
                        club: club._id,
                        content: welcomeMsg.content,
                        isSystemMessage: true,
                        createdAt: welcomeMsg.createdAt,
                        sender: {
                            username: 'GPL Community',
                            signedAvatarUrl: '/images/team-logo.png',
                            role: 'admin',
                            badges: []
                        }
                    });
                }
            }

            await UserNotification.create({
                user: validInvite.inviter._id,
                title: 'New Club Invite Accepted! 🏆',
                message: `${req.user.username} joined "${club.name}" using your invite link! You now have ${newInviteCount} total invites.`,
                type: 'success',
                link: `/clubs/${club.slug}`
            });
        }

        saveClubMetadata(club);
        return res.redirect(`/clubs/${club.slug}`);
    } catch (err) {
        console.error('[Clubs] Join error:', err);
        return res.status(500).redirect('/clubs');
    }
});

// Get or Generate Unique Member Invite Link & Stats
router.get('/:slugOrId/my-invite', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        let invite = await ClubInvite.findOne({ club: club._id, inviter: req.user._id });
        if (!invite) {
            const code = crypto.randomBytes(4).toString('hex').toUpperCase();
            invite = await ClubInvite.create({
                club: club._id,
                inviter: req.user._id,
                code: code
            });
        }

        const member = await ClubMember.findOne({ club: club._id, user: req.user._id });
        const totalInvites = member ? (member.inviteCount || 0) : 0;
        const host = req.get('host');
        const protocol = req.protocol;
        const inviteUrl = `${protocol}://${host}/clubs/${club.slug}?invite=${invite.code}`;

        return res.json({
            success: true,
            code: invite.code,
            inviteUrl: inviteUrl,
            uses: invite.uses || 0,
            totalInvites: totalInvites
        });
    } catch (err) {
        console.error('[Clubs] My invite error:', err);
        return res.status(500).json({ error: 'Failed to retrieve invite link.' });
    }
});

router.post('/:slugOrId/leave', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        if (club.isDefault) {
            return res.status(400).send('You cannot leave the default GPL Community club.');
        }

        if (String(club.creator._id || club.creator) === String(req.user._id)) {
            return res.status(400).send('Club creators cannot leave their own club.');
        }

        const deleted = await ClubMember.findOneAndDelete({ club: club._id, user: req.user._id });
        if (deleted) {
            await Club.findByIdAndUpdate(club._id, { $inc: { memberCount: -1 } });
            saveClubMetadata(club);
        }

        return res.redirect('/clubs');
    } catch (err) {
        console.error('[Clubs] Leave error:', err);
        return res.status(500).redirect('/clubs');
    }
});

// ============================================================================
// 6. PRIVATE CLUB JOIN REQUESTS & APPROVALS
// ============================================================================
router.post('/:slugOrId/request-join', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const message = req.body.message ? req.body.message.trim() : '';

        const existingReq = await ClubJoinRequest.findOne({ club: club._id, user: req.user._id });
        if (existingReq) {
            existingReq.status = 'pending';
            existingReq.message = message;
            existingReq.createdAt = new Date();
            await existingReq.save();
        } else {
            await ClubJoinRequest.create({
                club: club._id,
                user: req.user._id,
                message: message
            });
        }

        await UserNotification.create({
            user: club.creator._id || club.creator,
            title: `New Join Request: ${club.name}`,
            message: `${req.user.username} has requested to join your private club "${club.name}".`,
            type: 'info'
        });

        return res.redirect(`/clubs/${club.slug}/preview?requested=true`);
    } catch (err) {
        console.error('[Clubs] Request join error:', err);
        return res.status(500).redirect('/clubs');
    }
});

router.post('/:slugOrId/requests/:requestId/approve', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id);
        const isStaff = ['owner', 'admin'].includes(req.user.role);

        if (!isClubCreator && !isStaff) {
            return res.status(403).json({ error: 'Unauthorized to approve join requests.' });
        }

        const joinReq = await ClubJoinRequest.findById(req.params.requestId);
        if (!joinReq) return res.status(404).json({ error: 'Request not found.' });

        joinReq.status = 'approved';
        joinReq.reviewedBy = req.user._id;
        joinReq.reviewedAt = new Date();
        await joinReq.save();

        const defaultRole = await ClubRole.findOne({ club: club._id, isDefault: true });
        const existingMember = await ClubMember.findOne({ club: club._id, user: joinReq.user });

        if (existingMember) {
            existingMember.status = 'active';
            await existingMember.save();
        } else {
            await ClubMember.create({
                club: club._id,
                user: joinReq.user,
                roles: defaultRole ? [defaultRole._id] : [],
                status: 'active'
            });
            await Club.findByIdAndUpdate(club._id, { $inc: { memberCount: 1 } });
        }

        await UserNotification.create({
            user: joinReq.user,
            title: `Join Request Approved!`,
            message: `Congratulations! Your request to join "${club.name}" was approved. You can now chat in the community channels.`,
            type: 'success'
        });

        saveClubMetadata(club);

        if (req.xhr || req.headers.accept?.includes('json')) {
            return res.json({ success: true });
        }
        return res.redirect(`/clubs/${club.slug}`);
    } catch (err) {
        console.error('[Clubs] Approve request error:', err);
        return res.status(500).json({ error: 'Failed to approve request.' });
    }
});

router.post('/:slugOrId/requests/:requestId/reject', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id);
        const isStaff = ['owner', 'admin'].includes(req.user.role);

        if (!isClubCreator && !isStaff) {
            return res.status(403).json({ error: 'Unauthorized.' });
        }

        const joinReq = await ClubJoinRequest.findById(req.params.requestId);
        if (!joinReq) return res.status(404).json({ error: 'Request not found.' });

        joinReq.status = 'rejected';
        joinReq.reviewedBy = req.user._id;
        joinReq.reviewedAt = new Date();
        await joinReq.save();

        if (req.xhr || req.headers.accept?.includes('json')) {
            return res.json({ success: true });
        }
        return res.redirect(`/clubs/${club.slug}`);
    } catch (err) {
        console.error('[Clubs] Reject request error:', err);
        return res.status(500).json({ error: 'Failed to reject request.' });
    }
});

// ============================================================================
// 7. CHANNELS & ROLES MANAGEMENT
// ============================================================================
router.post('/:slugOrId/channels', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id);
        const isStaff = ['owner', 'admin'].includes(req.user.role);

        if (!isClubCreator && !isStaff) {
            return res.status(403).json({ error: 'Unauthorized to create channels.' });
        }

        const { name, topic, type, accessMode, isPrivate, allowedRoles, isReadOnly } = req.body;
        if (!name || name.trim().length < 2) {
            return res.status(400).json({ error: 'Channel name is required.' });
        }

        const cleanName = slugify(name.trim());
        const existingChan = await ClubChannel.findOne({ club: club._id, name: cleanName });
        if (existingChan) {
            return res.redirect(`/clubs/${club.slug}?channel=${existingChan._id}`);
        }

        const totalChannels = await ClubChannel.countDocuments({ club: club._id });

        const finalAccessMode = ['open', 'public_view', 'role_private'].includes(accessMode)
            ? accessMode
            : ((isPrivate === 'on' || isPrivate === 'true' || isPrivate === true) ? 'role_private' : 'open');
        const finalIsPrivate = (finalAccessMode === 'role_private');

        let parsedAllowedRoles = [];
        if (allowedRoles) {
            parsedAllowedRoles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
        }

        const newChannel = await ClubChannel.create({
            club: club._id,
            name: cleanName,
            topic: topic ? topic.trim() : '',
            type: ['text', 'polls', 'announcements'].includes(type) ? type : 'text',
            accessMode: finalAccessMode,
            isPrivate: finalIsPrivate,
            allowedRoles: parsedAllowedRoles,
            isReadOnly: isReadOnly === 'on' || isReadOnly === 'true' || isReadOnly === true,
            position: totalChannels + 1
        });

        await Club.findByIdAndUpdate(club._id, { $inc: { channelCount: 1 } });

        const io = req.app.get('io');
        if (io) {
            io.to(`club_${club._id}`).emit('club_channel_created', newChannel);
        }

        if (req.xhr || req.headers.accept?.includes('json')) {
            return res.json({ success: true, channel: newChannel });
        }
        return res.redirect(`/clubs/${club.slug}?channel=${newChannel._id}`);
    } catch (err) {
        console.error('[Clubs] Channel creation error:', err);
        return res.status(500).json({ error: 'Failed to create channel.' });
    }
});

// Edit Channel Information & Access
router.post('/:slugOrId/channels/:channelId/edit', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id) || (club.isDefault && req.user.role === 'admin');
        const isStaff = ['owner', 'admin'].includes(req.user.role);

        if (!isClubCreator && !isStaff) {
            return res.status(403).json({ error: 'Unauthorized to edit channel.' });
        }

        const channel = await ClubChannel.findById(req.params.channelId);
        if (!channel) return res.status(404).json({ error: 'Channel not found.' });

        const { name, topic, type, accessMode, isPrivate, isReadOnly, allowedRoles, allowedRolesCleared } = req.body;

        if (name && name.trim()) {
            channel.name = slugify(name.trim());
        }
        if (typeof topic === 'string') {
            channel.topic = topic.trim();
        }
        if (type && ['text', 'polls', 'announcements'].includes(type) && !['rules', 'new-uploads', 'new-updates'].includes(channel.type)) {
            channel.type = type;
        }

        if (accessMode && ['open', 'public_view', 'role_private'].includes(accessMode)) {
            channel.accessMode = accessMode;
            channel.isPrivate = (accessMode === 'role_private');
        } else if (typeof isPrivate !== 'undefined') {
            channel.isPrivate = isPrivate === true || isPrivate === 'true' || isPrivate === 'on';
            if (channel.isPrivate) channel.accessMode = 'role_private';
        }

        if (typeof isReadOnly !== 'undefined') {
            channel.isReadOnly = isReadOnly === true || isReadOnly === 'true' || isReadOnly === 'on';
        }

        if (allowedRoles) {
            channel.allowedRoles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];
        } else if (allowedRolesCleared === 'true' || allowedRolesCleared === true) {
            channel.allowedRoles = [];
        }

        await channel.save();

        const io = req.app.get('io');
        if (io) {
            io.to(`club_${club._id}`).emit('club_channel_updated', channel);
        }

        if (req.xhr || req.headers.accept?.includes('json')) {
            return res.json({ success: true, channel });
        }
        return res.redirect(`/clubs/${club.slug}?channel=${channel._id}`);
    } catch (err) {
        console.error('[Clubs] Channel edit error:', err);
        return res.status(500).json({ error: 'Failed to edit channel.' });
    }
});

// Delete Channel
router.post('/:slugOrId/channels/:channelId/delete', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id) || (club.isDefault && req.user.role === 'admin');
        const isStaff = ['owner', 'admin'].includes(req.user.role);

        if (!isClubCreator && !isStaff) {
            return res.status(403).json({ error: 'Unauthorized to delete channel.' });
        }

        const channel = await ClubChannel.findById(req.params.channelId);
        if (!channel) return res.status(404).json({ error: 'Channel not found.' });

        if (['rules', 'announcements', 'new-uploads', 'new-updates'].includes(channel.type)) {
            return res.status(400).json({ error: 'Default system channels cannot be deleted.' });
        }

        await ClubMessage.deleteMany({ channel: channel._id });
        await ClubChannel.findByIdAndDelete(channel._id);
        await Club.findByIdAndUpdate(club._id, { $inc: { channelCount: -1 } });

        const io = req.app.get('io');
        if (io) {
            io.to(`club_${club._id}`).emit('club_channel_deleted', { channelId: channel._id });
        }

        const fallback = await ClubChannel.findOne({ club: club._id }).sort({ position: 1 });

        if (req.xhr || req.headers.accept?.includes('json')) {
            return res.json({ success: true, fallbackUrl: `/clubs/${club.slug}${fallback ? '?channel=' + fallback._id : ''}` });
        }
        return res.redirect(`/clubs/${club.slug}${fallback ? '?channel=' + fallback._id : ''}`);
    } catch (err) {
        console.error('[Clubs] Channel deletion error:', err);
        return res.status(500).json({ error: 'Failed to delete channel.' });
    }
});

// Create New Role
router.post('/:slugOrId/roles', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id) || (club.isDefault && req.user.role === 'admin');
        const isStaff = ['owner', 'admin'].includes(req.user.role);

        if (!isClubCreator && !isStaff) {
            return res.status(403).json({ error: 'Unauthorized to create roles.' });
        }

        const { name, color, badgeIcon, canManageChannels, canKickMembers, canPostPolls, canManageClub } = req.body;
        if (!name || name.trim().length < 2) {
            return res.status(400).json({ error: 'Role name is required (at least 2 characters).' });
        }

        const newRole = await ClubRole.create({
            club: club._id,
            name: name.trim(),
            color: color || '#5865F2',
            badgeIcon: badgeIcon || '🛡️',
            position: 20,
            permissions: {
                canManageClub: canManageClub === 'on' || canManageClub === 'true' || canManageClub === true,
                canManageChannels: canManageChannels === 'on' || canManageChannels === 'true' || canManageChannels === true,
                canManageRoles: false,
                canKickMembers: canKickMembers === 'on' || canKickMembers === 'true' || canKickMembers === true,
                canSendMessages: true,
                canPostPolls: canPostPolls === 'on' || canPostPolls === 'true' || canPostPolls === true,
                canAuditPrivate: false
            }
        });

        const allRoles = await ClubRole.find({ club: club._id }).lean();
        saveClubRolesArchive(club.name, allRoles);

        if (req.xhr || req.headers.accept?.includes('json')) {
            return res.json({ success: true, role: newRole });
        }
        return res.redirect(`/clubs/${club.slug}`);
    } catch (err) {
        console.error('[Clubs] Role creation error:', err);
        return res.status(500).json({ error: 'Failed to create role.' });
    }
});

// Edit Role
router.post('/:slugOrId/roles/:roleId/edit', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id) || (club.isDefault && req.user.role === 'admin');
        const isStaff = ['owner', 'admin'].includes(req.user.role);

        if (!isClubCreator && !isStaff) {
            return res.status(403).json({ error: 'Unauthorized to edit roles.' });
        }

        const role = await ClubRole.findOne({ _id: req.params.roleId, club: club._id });
        if (!role) return res.status(404).json({ error: 'Role not found.' });

        const { name, color, badgeIcon, canManageChannels, canKickMembers, canPostPolls, canManageClub } = req.body;
        if (name && name.trim()) role.name = name.trim();
        if (color && color.trim()) role.color = color.trim();
        if (badgeIcon && badgeIcon.trim()) role.badgeIcon = badgeIcon.trim();

        if (!role.permissions) role.permissions = {};
        if (typeof canManageChannels !== 'undefined') {
            role.permissions.canManageChannels = canManageChannels === true || canManageChannels === 'true' || canManageChannels === 'on';
        }
        if (typeof canKickMembers !== 'undefined') {
            role.permissions.canKickMembers = canKickMembers === true || canKickMembers === 'true' || canKickMembers === 'on';
        }
        if (typeof canPostPolls !== 'undefined') {
            role.permissions.canPostPolls = canPostPolls === true || canPostPolls === 'true' || canPostPolls === 'on';
        }
        if (typeof canManageClub !== 'undefined') {
            role.permissions.canManageClub = canManageClub === true || canManageClub === 'true' || canManageClub === 'on';
        }

        await role.save();
        const allRoles = await ClubRole.find({ club: club._id }).lean();
        saveClubRolesArchive(club.name, allRoles);

        return res.json({ success: true, role });
    } catch (err) {
        console.error('[Clubs] Role edit error:', err);
        return res.status(500).json({ error: 'Failed to edit role.' });
    }
});

// Delete Role
router.post('/:slugOrId/roles/:roleId/delete', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id) || (club.isDefault && req.user.role === 'admin');
        const isStaff = ['owner', 'admin'].includes(req.user.role);

        if (!isClubCreator && !isStaff) {
            return res.status(403).json({ error: 'Unauthorized to delete roles.' });
        }

        const role = await ClubRole.findOne({ _id: req.params.roleId, club: club._id });
        if (!role) return res.status(404).json({ error: 'Role not found.' });

        if (role.isDefault || role.name === 'everyone') {
            return res.status(400).json({ error: 'The default @everyone role cannot be deleted.' });
        }

        // Remove from members
        await ClubMember.updateMany({ club: club._id, roles: role._id }, { $pull: { roles: role._id } });
        // Remove from channels
        await ClubChannel.updateMany({ club: club._id, allowedRoles: role._id }, { $pull: { allowedRoles: role._id } });
        await ClubRole.findByIdAndDelete(role._id);

        const allRoles = await ClubRole.find({ club: club._id }).lean();
        saveClubRolesArchive(club.name, allRoles);

        return res.json({ success: true, deletedRoleId: req.params.roleId });
    } catch (err) {
        console.error('[Clubs] Role delete error:', err);
        return res.status(500).json({ error: 'Failed to delete role.' });
    }
});

// Role Assignment to Members (Add / Remove) - Enforces 10 Role Max
router.post('/:slugOrId/roles/assign', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id) || (club.isDefault && req.user.role === 'admin');
        const isStaff = ['owner', 'admin'].includes(req.user.role);

        if (!isClubCreator && !isStaff) {
            return res.status(403).json({ error: 'Unauthorized to manage member roles.' });
        }

        const { memberId, roleId, action } = req.body;
        if (!memberId || !roleId) {
            return res.status(400).json({ error: 'Member ID and Role ID are required.' });
        }

        const member = await ClubMember.findById(memberId);
        if (!member) return res.status(404).json({ error: 'Member not found.' });

        if (action === 'remove') {
            member.roles = (member.roles || []).filter(r => String(r) !== String(roleId));
        } else {
            if (!member.roles) member.roles = [];
            if (!member.roles.some(r => String(r) === String(roleId))) {
                // Strict Max 10 Roles Validation
                if (member.roles.length >= 10) {
                    return res.status(400).json({ error: 'A member can have a maximum of 10 roles.' });
                }
                member.roles.push(roleId);
            }
        }

        await member.save();
        await member.populate('roles');

        return res.json({ success: true, member });
    } catch (err) {
        console.error('[Clubs] Role assignment error:', err);
        return res.status(500).json({ error: err.message || 'Failed to update member role.' });
    }
});

// Bulk Member Roles Update (Enforces 10 Role Max)
router.post('/:slugOrId/members/:memberId/roles', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id) || (club.isDefault && req.user.role === 'admin');
        const isStaff = ['owner', 'admin'].includes(req.user.role);

        if (!isClubCreator && !isStaff) {
            return res.status(403).json({ error: 'Unauthorized to manage member roles.' });
        }

        const member = await ClubMember.findById(req.params.memberId);
        if (!member) return res.status(404).json({ error: 'Member not found.' });

        let { roleIds } = req.body;
        if (!Array.isArray(roleIds)) roleIds = roleIds ? [roleIds] : [];

        // Strict Max 10 Roles Validation
        if (roleIds.length > 10) {
            return res.status(400).json({ error: 'A member can have a maximum of 10 roles.' });
        }

        member.roles = roleIds;
        await member.save();
        await member.populate('roles');

        return res.json({ success: true, member });
    } catch (err) {
        console.error('[Clubs] Bulk member roles error:', err);
        return res.status(500).json({ error: err.message || 'Failed to update member roles.' });
    }
});

// ============================================================================
// CLUB TRACKED CREATORS (UPLOAD & UPDATE PREFERENCES)
// ============================================================================
router.get('/:slugOrId/tracked-creators', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const populatedClub = await Club.findById(club._id).populate({
            path: 'trackedCreatorsConfig.creator',
            select: 'username profileImageKey role signedAvatarUrl cardAvatarUrl avatar'
        }).populate('trackedCreators', 'username profileImageKey role signedAvatarUrl cardAvatarUrl avatar');

        const config = populatedClub.trackedCreatorsConfig || [];
        return res.json({ success: true, trackedCreators: config });
    } catch (err) {
        console.error('[Clubs] Get tracked creators error:', err);
        return res.status(500).json({ error: 'Failed to fetch tracked creators.' });
    }
});

router.post('/:slugOrId/tracked-creators/add', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id) || (club.isDefault && req.user.role === 'admin');
        const isStaff = ['owner', 'admin'].includes(req.user.role);
        if (!isClubCreator && !isStaff) return res.status(403).json({ error: 'Unauthorized.' });

        const { username, trackType } = req.body;
        if (!username || !username.trim()) return res.status(400).json({ error: 'Username is required.' });

        const targetUser = await User.findOne({ username: username.trim() });
        if (!targetUser) return res.status(404).json({ error: `User "${username}" was not found.` });

        const validTrackType = ['uploads', 'updates', 'both'].includes(trackType) ? trackType : 'both';

        const clubDoc = await Club.findById(club._id);
        if (!clubDoc.trackedCreatorsConfig) clubDoc.trackedCreatorsConfig = [];

        const existingIndex = clubDoc.trackedCreatorsConfig.findIndex(tc => String(tc.creator) === String(targetUser._id));
        if (existingIndex > -1) {
            clubDoc.trackedCreatorsConfig[existingIndex].trackType = validTrackType;
        } else {
            clubDoc.trackedCreatorsConfig.push({
                creator: targetUser._id,
                trackType: validTrackType
            });
        }

        if (!clubDoc.trackedCreators) clubDoc.trackedCreators = [];
        if (!clubDoc.trackedCreators.some(id => String(id) === String(targetUser._id))) {
            clubDoc.trackedCreators.push(targetUser._id);
        }

        await clubDoc.save();
        return res.json({ success: true, message: `Now tracking ${targetUser.username} (${validTrackType})` });
    } catch (err) {
        console.error('[Clubs] Add tracked creator error:', err);
        return res.status(500).json({ error: 'Failed to add tracked creator.' });
    }
});

router.post('/:slugOrId/tracked-creators/update', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id) || (club.isDefault && req.user.role === 'admin');
        const isStaff = ['owner', 'admin'].includes(req.user.role);
        if (!isClubCreator && !isStaff) return res.status(403).json({ error: 'Unauthorized.' });

        const { creatorId, trackType } = req.body;
        if (!creatorId) return res.status(400).json({ error: 'Creator ID is required.' });

        const validTrackType = ['uploads', 'updates', 'both'].includes(trackType) ? trackType : 'both';
        const clubDoc = await Club.findById(club._id);

        const item = clubDoc.trackedCreatorsConfig.find(tc => String(tc.creator) === String(creatorId));
        if (item) {
            item.trackType = validTrackType;
            await clubDoc.save();
        }
        return res.json({ success: true, trackType: validTrackType });
    } catch (err) {
        console.error('[Clubs] Update tracked creator error:', err);
        return res.status(500).json({ error: 'Failed to update tracking preference.' });
    }
});

router.post('/:slugOrId/tracked-creators/remove', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id) || (club.isDefault && req.user.role === 'admin');
        const isStaff = ['owner', 'admin'].includes(req.user.role);
        if (!isClubCreator && !isStaff) return res.status(403).json({ error: 'Unauthorized.' });

        const { creatorId } = req.body;
        if (!creatorId) return res.status(400).json({ error: 'Creator ID is required.' });

        const clubDoc = await Club.findById(club._id);
        clubDoc.trackedCreatorsConfig = (clubDoc.trackedCreatorsConfig || []).filter(tc => String(tc.creator) !== String(creatorId));
        clubDoc.trackedCreators = (clubDoc.trackedCreators || []).filter(id => String(id) !== String(creatorId));
        await clubDoc.save();

        return res.json({ success: true, message: 'Creator removed from club tracking.' });
    } catch (err) {
        console.error('[Clubs] Remove tracked creator error:', err);
        return res.status(500).json({ error: 'Failed to remove tracked creator.' });
    }
});

// ============================================================================
// 8. CHANNEL MESSAGES, POLLS & REACTIONS REST API
// ============================================================================
router.get('/:slugOrId/channels/:channelId/messages', ensureAuth, async (req, res) => {
    try {
        const getSmartImg = req.app.get('getSmartImageUrl');
        const messages = await ClubMessage.find({ channel: req.params.channelId })
            .sort({ createdAt: -1 })
            .limit(50)
            .populate('sender', 'username profileImageKey role signedAvatarUrl cardAvatarUrl avatar avatarUrl membership isPremium badges')
            .lean();

        for (const msg of messages) {
            if (msg.sender) {
                const isGPLMods = msg.sender.username === 'GPLMods';
                const defaultLogo = isGPLMods ? '/images/team-logo.png' : '/images/default-avatar.png';
                if (msg.sender.signedAvatarUrl && msg.sender.signedAvatarUrl !== '/images/default-avatar.png') {
                    // Keep existing signed url
                } else if (msg.sender.cardAvatarUrl && msg.sender.cardAvatarUrl !== '/images/default-avatar.png') {
                    msg.sender.signedAvatarUrl = msg.sender.cardAvatarUrl;
                } else if (msg.sender.avatarUrl && msg.sender.avatarUrl !== '/images/default-avatar.png') {
                    msg.sender.signedAvatarUrl = msg.sender.avatarUrl;
                } else if (msg.sender.avatar && msg.sender.avatar !== '/images/default-avatar.png') {
                    msg.sender.signedAvatarUrl = msg.sender.avatar;
                } else if (msg.sender.profileImageKey && getSmartImg) {
                    try {
                        const url = await getSmartImg(msg.sender.profileImageKey);
                        if (url && url !== '/images/default-avatar.png') {
                            msg.sender.signedAvatarUrl = url;
                        }
                    } catch(e) {}
                }
                if (!msg.sender.signedAvatarUrl) {
                    msg.sender.signedAvatarUrl = defaultLogo;
                }
            }
        }

        messages.reverse();
        return res.json({ success: true, messages });
    } catch (err) {
        console.error('[Clubs] Fetch messages error:', err);
        return res.status(500).json({ error: 'Failed to load messages.' });
    }
});

// Edit Message REST Endpoint
router.put('/:slugOrId/messages/:messageId', ensureAuth, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content || !content.trim()) return res.status(400).json({ error: 'Message content cannot be empty.' });

        const message = await ClubMessage.findById(req.params.messageId);
        if (!message || message.isDeleted) return res.status(404).json({ error: 'Message not found.' });

        const club = await resolveClub(req.params.slugOrId);
        const isSender = String(message.sender) === String(req.user._id);
        const isStaff = ['owner', 'admin'].includes(req.user.role);
        const isCreator = club && (String(club.creator._id || club.creator) === String(req.user._id) || (club.isDefault && req.user.role === 'admin'));

        if (!isSender && !isStaff && !isCreator) {
            return res.status(403).json({ error: 'Unauthorized to edit this message.' });
        }

        let safeText = content.trim();
        try { safeText = global.profanityFilter.clean(safeText); } catch(e) {}

        message.content = safeText;
        message.isEdited = true;
        message.editedAt = new Date();
        await message.save();

        const io = req.app.get('io');
        if (io) {
            io.to(`club_${message.club}_chan_${message.channel}`).emit('club_message_edited', {
                messageId: message._id,
                content: safeText,
                isEdited: true,
                editedAt: message.editedAt
            });
        }

        return res.json({ success: true, message });
    } catch (err) {
        console.error('[Clubs] Edit message REST error:', err);
        return res.status(500).json({ error: 'Failed to edit message.' });
    }
});

// Delete Message REST Endpoint
router.delete('/:slugOrId/messages/:messageId', ensureAuth, async (req, res) => {
    try {
        const message = await ClubMessage.findById(req.params.messageId);
        if (!message) return res.status(404).json({ error: 'Message not found.' });

        const club = await resolveClub(req.params.slugOrId);
        const isSender = String(message.sender) === String(req.user._id);
        const isStaff = ['owner', 'admin'].includes(req.user.role);
        const isCreator = club && (String(club.creator._id || club.creator) === String(req.user._id) || (club.isDefault && req.user.role === 'admin'));

        if (!isSender && !isStaff && !isCreator) {
            return res.status(403).json({ error: 'Unauthorized to delete this message.' });
        }

        message.content = '[This message was deleted]';
        message.isDeleted = true;
        message.deletedAt = new Date();
        await message.save();

        const io = req.app.get('io');
        if (io) {
            io.to(`club_${message.club}_chan_${message.channel}`).emit('club_message_deleted', {
                messageId: message._id
            });
        }

        return res.json({ success: true });
    } catch (err) {
        console.error('[Clubs] Delete message REST error:', err);
        return res.status(500).json({ error: 'Failed to delete message.' });
    }
});

// Edit Poll / Announcement Poll REST Endpoint (Site Owner / Creator can edit question or close poll)
router.post('/:slugOrId/polls/:messageId/edit', ensureAuth, async (req, res) => {
    try {
        const { question, closed } = req.body;
        const message = await ClubMessage.findById(req.params.messageId);
        if (!message || !message.poll) return res.status(404).json({ error: 'Poll not found.' });

        const club = await resolveClub(req.params.slugOrId);
        const isSender = String(message.sender) === String(req.user._id);
        const isStaff = ['owner', 'admin'].includes(req.user.role);
        const isCreator = club && (String(club.creator._id || club.creator) === String(req.user._id) || (club.isDefault && req.user.role === 'admin'));

        if (!isSender && !isStaff && !isCreator) {
            return res.status(403).json({ error: 'Unauthorized to edit this poll.' });
        }

        if (question && question.trim()) {
            message.poll.question = question.trim();
        }
        if (typeof closed !== 'undefined') {
            message.poll.closed = Boolean(closed);
        }

        await message.save();

        const io = req.app.get('io');
        if (io) {
            io.to(`club_${message.club}_chan_${message.channel}`).emit('club_poll_updated', {
                messageId: message._id,
                poll: message.poll
            });
        }

        return res.json({ success: true, poll: message.poll });
    } catch (err) {
        console.error('[Clubs] Edit poll error:', err);
        return res.status(500).json({ error: 'Failed to update poll.' });
    }
});

// Post Poll Endpoint
router.post('/:slugOrId/channels/:channelId/poll', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const channel = await ClubChannel.findById(req.params.channelId);
        if (!channel) return res.status(404).json({ error: 'Channel not found' });

        const { question, options } = req.body;
        if (!question || !question.trim()) {
            return res.status(400).json({ error: 'Poll question is required.' });
        }

        let parsedOptions = [];
        if (Array.isArray(options)) {
            parsedOptions = options.map(opt => ({ text: String(opt).trim(), votes: [] })).filter(o => o.text.length > 0);
        } else if (typeof options === 'string') {
            parsedOptions = options.split('\n').map(o => ({ text: o.trim(), votes: [] })).filter(o => o.text.length > 0);
        }

        if (parsedOptions.length < 2) {
            return res.status(400).json({ error: 'A poll must have at least 2 options.' });
        }

        const pollMessage = await ClubMessage.create({
            club: club._id,
            channel: channel._id,
            sender: req.user._id,
            content: `📊 **POLL:** ${question.trim()}`,
            poll: {
                question: question.trim(),
                options: parsedOptions,
                closed: false
            }
        });

        // Broadcast via Socket.IO if available
        const io = req.app.get('io');
        if (io) {
            io.to(`club_${club._id}_chan_${channel._id}`).emit('club_poll_created', {
                messageId: pollMessage._id,
                channelId: channel._id,
                poll: pollMessage.poll,
                sender: {
                    _id: req.user._id,
                    username: req.user.username,
                    signedAvatarUrl: req.user.signedAvatarUrl
                },
                createdAt: pollMessage.createdAt
            });
        }

        if (req.xhr || req.headers.accept?.includes('json')) {
            return res.json({ success: true, pollMessage });
        }
        return res.redirect(`/clubs/${club.slug}?channel=${channel._id}`);
    } catch (err) {
        console.error('[Clubs] Create poll error:', err);
        return res.status(500).json({ error: 'Failed to create poll.' });
    }
});

// Vote in Poll
router.post('/:slugOrId/polls/:messageId/vote', ensureAuth, async (req, res) => {
    try {
        const { optionIndex } = req.body;
        const message = await ClubMessage.findById(req.params.messageId);
        if (!message || !message.poll) return res.status(404).json({ error: 'Poll not found.' });

        if (message.poll.closed) {
            return res.status(400).json({ error: 'This poll is closed.' });
        }

        const userId = req.user._id;

        // Remove user's previous vote across all options
        message.poll.options.forEach(opt => {
            opt.votes = opt.votes.filter(v => String(v) !== String(userId));
        });

        // Add vote to chosen option
        const targetOption = message.poll.options[parseInt(optionIndex, 10)];
        if (targetOption) {
            targetOption.votes.push(userId);
        }

        await message.save();

        const io = req.app.get('io');
        if (io) {
            io.to(`club_${message.club}_chan_${message.channel}`).emit('club_poll_updated', {
                messageId: message._id,
                poll: message.poll
            });
        }

        return res.json({ success: true, poll: message.poll });
    } catch (err) {
        console.error('[Clubs] Poll vote error:', err);
        return res.status(500).json({ error: 'Failed to record vote.' });
    }
});

// Reaction Toggle Endpoint
router.post('/:slugOrId/messages/:messageId/react', ensureAuth, async (req, res) => {
    try {
        const { emoji } = req.body;
        if (!emoji) return res.status(400).json({ error: 'Emoji is required.' });

        const message = await ClubMessage.findById(req.params.messageId);
        if (!message) return res.status(404).json({ error: 'Message not found.' });

        const userId = req.user._id;
        let reactionObj = message.reactions.find(r => r.emoji === emoji);

        if (!reactionObj) {
            reactionObj = { emoji, users: [userId] };
            message.reactions.push(reactionObj);
        } else {
            const userIndex = reactionObj.users.findIndex(u => String(u) === String(userId));
            if (userIndex > -1) {
                // Remove reaction (toggle off)
                reactionObj.users.splice(userIndex, 1);
                if (reactionObj.users.length === 0) {
                    message.reactions = message.reactions.filter(r => r.emoji !== emoji);
                }
            } else {
                // Add reaction
                reactionObj.users.push(userId);
            }
        }

        await message.save();

        const io = req.app.get('io');
        if (io) {
            io.to(`club_${message.club}_chan_${message.channel}`).emit('club_reaction_updated', {
                messageId: message._id,
                reactions: message.reactions
            });
        }

        return res.json({ success: true, reactions: message.reactions });
    } catch (err) {
        console.error('[Clubs] Reaction error:', err);
        return res.status(500).json({ error: 'Failed to toggle reaction.' });
    }
});

// ==========================================
// CLUB MANAGEMENT (EDIT / DELETE)
// ==========================================

// Edit Club Settings
router.post('/:slugOrId/edit', ensureAuth, uploadClubMedia.fields([{ name: 'icon', maxCount: 1 }, { name: 'banner', maxCount: 1 }]), async (req, res) => {
    try {
        const club = await Club.findOne({
            $or: [{ slug: req.params.slugOrId }, { _id: req.params.slugOrId.match(/^[0-9a-fA-F]{24}$/) ? req.params.slugOrId : null }]
        });
        if (!club) return res.status(404).json({ error: 'Club not found.' });

        const isOwner = String(club.creator) === String(req.user._id) || req.user.role === 'owner';
        if (!isOwner) return res.status(403).json({ error: 'Permission denied. Only the club owner can edit the club.' });

        if (req.body.name && req.body.name.trim() !== club.name) {
            if (club.isDefault) {
                return res.status(403).json({ error: 'Cannot rename the official community.' });
            }
            const reserved = isClubNameReserved(req.body.name);
            if (reserved) return res.status(400).json({ error: 'This club name is reserved.' });
            
            const existing = await Club.findOne({ name: { $regex: new RegExp(`^${req.body.name.trim()}$`, 'i') } });
            if (existing && String(existing._id) !== String(club._id)) {
                return res.status(400).json({ error: 'A club with this name already exists.' });
            }
            
            club.name = req.body.name.trim();
        }

        if (req.body.description !== undefined) {
            club.description = req.body.description.trim();
        }

        if (req.body.isPrivate !== undefined) {
            if (club.isDefault) {
                return res.status(403).json({ error: 'Cannot change visibility of the official community.' });
            }
            club.isPrivate = (req.body.isPrivate === 'true' || req.body.isPrivate === true);
        }

        // Handle file uploads
        if (req.files && req.files.icon && req.files.icon[0]) {
            const finalIconPath = `/uploads/clubs/${req.files.icon[0].filename}`;
            fs.renameSync(req.files.icon[0].path, path.join(__dirname, '..', 'public', finalIconPath));
            club.iconUrl = finalIconPath;
        }
        if (req.files && req.files.banner && req.files.banner[0]) {
            const finalBannerPath = `/uploads/clubs/${req.files.banner[0].filename}`;
            fs.renameSync(req.files.banner[0].path, path.join(__dirname, '..', 'public', finalBannerPath));
            club.bannerUrl = finalBannerPath;
        }

        await club.save();
        return res.json({ success: true, club, redirectUrl: `/clubs/${club.slug}` });
    } catch (err) {
        console.error('[Clubs] Edit club error:', err);
        return res.status(500).json({ error: 'Failed to update club settings.' });
    }
});

// Delete Club
router.post('/:slugOrId/delete', ensureAuth, async (req, res) => {
    try {
        const club = await Club.findOne({
            $or: [{ slug: req.params.slugOrId }, { _id: req.params.slugOrId.match(/^[0-9a-fA-F]{24}$/) ? req.params.slugOrId : null }]
        });
        if (!club) return res.status(404).json({ error: 'Club not found.' });

        if (club.isDefault) return res.status(403).json({ error: 'The official GPLMods community cannot be deleted.' });

        const isOwner = String(club.creator) === String(req.user._id) || req.user.role === 'owner';
        if (!isOwner) return res.status(403).json({ error: 'Permission denied. Only the club owner can delete the club.' });

        // Delete associated channels, messages, members
        await ClubChannel.deleteMany({ club: club._id });
        await ClubMessage.deleteMany({ club: club._id });
        await ClubMember.deleteMany({ club: club._id });
        await ClubRole.deleteMany({ club: club._id });
        await ClubJoinRequest.deleteMany({ club: club._id });
        await ClubInvite.deleteMany({ club: club._id });
        
        await club.deleteOne();
        
        return res.json({ success: true, redirectUrl: '/clubs' });
    } catch (err) {
        console.error('[Clubs] Delete club error:', err);
        return res.status(500).json({ error: 'Failed to delete club.' });
    }
});

module.exports = router;
