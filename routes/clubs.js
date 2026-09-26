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
const multer = require('multer');

// Models
const Club = require('../models/community/club');
const ClubChannel = require('../models/community/clubChannel');
const ClubRole = require('../models/community/clubRole');
const ClubMember = require('../models/community/clubMember');
const ClubMessage = require('../models/community/clubMessage');
const ClubJoinRequest = require('../models/community/clubJoinRequest');
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

        res.render('pages/clubs/index', {
            pageTitle: 'Clubs & Communities',
            pageDescription: 'Discover and join creator clubs, distributor communities, and modding channels on GPLMods.',
            clubs,
            totalClubs: clubs.length,
            joinedClubIds,
            popularTags,
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
        res.status(500).render('pages/500');
    }
});

// ============================================================================
// 2. CREATE A NEW CLUB
// ============================================================================
router.get('/create', ensureAuth, async (req, res) => {
    res.render('pages/clubs/create', {
        pageTitle: 'Create a Club',
        error: null,
        formData: {}
    });
});

router.post('/create', ensureAuth, uploadClubMedia.fields([
    { name: 'icon', maxCount: 1 },
    { name: 'banner', maxCount: 1 }
]), async (req, res) => {
    try {
        const { name, description, tags, primaryLanguage, country, aboutAdmin, rules, isPrivate, joinApprovalRequired } = req.body;

        const formData = { name, description, tags, primaryLanguage, country, aboutAdmin, rules, isPrivate };

        // 1. Validate Club Name
        if (!name || name.trim().length < 3) {
            return res.render('pages/clubs/create', {
                pageTitle: 'Create a Club',
                error: 'Club name must be at least 3 characters long.',
                formData
            });
        }

        if (name.trim().length > 60) {
            return res.render('pages/clubs/create', {
                pageTitle: 'Create a Club',
                error: 'Club name cannot exceed 60 characters.',
                formData
            });
        }

        // 2. Reserved Name Check
        if (isClubNameReserved(name.trim())) {
            return res.render('pages/clubs/create', {
                pageTitle: 'Create a Club',
                error: 'This club name is reserved for official GPLMods communities. Please choose another name.',
                formData
            });
        }

        // 3. Name Uniqueness Check
        const existingClub = await Club.findOne({ name: new RegExp(`^${name.trim()}$`, 'i') });
        if (existingClub) {
            return res.render('pages/clubs/create', {
                pageTitle: 'Create a Club',
                error: 'A club with this name already exists. Please choose a unique name.',
                formData
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
            channelCount: 6
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
        return res.render('pages/clubs/create', {
            pageTitle: 'Create a Club',
            error: 'An unexpected error occurred while creating your club. Please try again.',
            formData: req.body || {}
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
            return res.status(404).render('pages/404');
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
        res.status(500).render('pages/500');
    }
});

// ============================================================================
// 4. DISCORD-LIKE MAIN CLUB INTERFACE
// ============================================================================
router.get('/:slugOrId', async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) {
            return res.status(404).render('pages/404');
        }

        // If user is guest
        if (!req.user) {
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

        // If user is not member and not site staff
        if (!membership && !isStaff) {
            if (club.isPrivate) {
                return res.redirect(`/clubs/${club.slug}/preview`);
            } else {
                // Auto-join public club upon direct visit if logged in
                const defaultRole = await ClubRole.findOne({ club: club._id, isDefault: true });
                membership = await ClubMember.create({
                    club: club._id,
                    user: req.user._id,
                    roles: defaultRole ? [defaultRole._id] : [],
                    status: 'active'
                });
                await Club.findByIdAndUpdate(club._id, { $inc: { memberCount: 1 } });
            }
        }

        // Fetch all channels for this club sorted by position
        const channels = await ClubChannel.find({ club: club._id }).sort({ position: 1 }).lean();

        // Determine active channel (from query `?channel=...` or defaults to `#general` or first available)
        let activeChannel = null;
        if (req.query.channel) {
            activeChannel = channels.find(c => String(c._id) === req.query.channel || c.name === req.query.channel);
        }
        if (!activeChannel) {
            activeChannel = channels.find(c => c.name === 'general') || channels[0];
        }

        // Fetch recent messages for active channel
        let messages = [];
        if (activeChannel) {
            messages = await ClubMessage.find({ channel: activeChannel._id })
                .sort({ createdAt: -1 })
                .limit(75)
                .populate({
                    path: 'sender',
                    select: 'username profileImageKey role signedAvatarUrl membership isPremium badges'
                })
                .lean();
            messages.reverse(); // Chronological order
        }

        // Fetch roles for this club
        const roles = await ClubRole.find({ club: club._id }).sort({ position: -1 }).lean();

        // Fetch members of this club (with populated user info)
        const members = await ClubMember.find({ club: club._id, status: 'active' })
            .populate({
                path: 'user',
                select: 'username profileImageKey role signedAvatarUrl membership isPremium badges'
            })
            .populate('roles')
            .lean();

        // Fetch user's joined clubs for the leftmost vertical rail
        const userMemberships = await ClubMember.find({ user: req.user._id, status: 'active' })
            .populate('club')
            .lean();
        const joinedClubs = userMemberships.map(m => m.club).filter(Boolean);

        // Check if user has management permissions in this club
        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id);
        const userClubRoles = membership ? (membership.roles || []) : [];
        const hasManageClubPerm = isStaff || isClubCreator || userClubRoles.some(r => r && r.permissions && r.permissions.canManageClub);

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
        res.status(500).render('pages/500');
    }
});

// ============================================================================
// 5. JOIN / LEAVE CLUB
// ============================================================================
router.post('/:slugOrId/join', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const existing = await ClubMember.findOne({ club: club._id, user: req.user._id });
        if (existing && existing.status === 'active') {
            return res.redirect(`/clubs/${club.slug}`);
        }

        if (club.isPrivate && !club.isDefault) {
            return res.redirect(`/clubs/${club.slug}/preview?req=1`);
        }

        const defaultRole = await ClubRole.findOne({ club: club._id, isDefault: true });

        if (existing) {
            existing.status = 'active';
            await existing.save();
        } else {
            await ClubMember.create({
                club: club._id,
                user: req.user._id,
                roles: defaultRole ? [defaultRole._id] : [],
                status: 'active'
            });
            await Club.findByIdAndUpdate(club._id, { $inc: { memberCount: 1 } });
        }

        saveClubMetadata(club);
        return res.redirect(`/clubs/${club.slug}`);
    } catch (err) {
        console.error('[Clubs] Join error:', err);
        return res.status(500).redirect('/clubs');
    }
});

router.post('/:slugOrId/leave', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        // Default club cannot be left
        if (club.isDefault) {
            return res.status(400).send('You cannot leave the default GPL Community club.');
        }

        // Club creator cannot leave without transferring ownership
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

        // Notify club creator
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

        // Enroll member
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

        // Notify user in notification hub
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

        const { name, topic, type, isPrivate } = req.body;
        if (!name || name.trim().length < 2) {
            return res.status(400).json({ error: 'Channel name is required.' });
        }

        const cleanName = slugify(name.trim());
        const totalChannels = await ClubChannel.countDocuments({ club: club._id });

        const newChannel = await ClubChannel.create({
            club: club._id,
            name: cleanName,
            topic: topic ? topic.trim() : '',
            type: ['text', 'polls'].includes(type) ? type : 'text',
            isPrivate: isPrivate === 'on' || isPrivate === 'true',
            position: totalChannels + 1
        });

        await Club.findByIdAndUpdate(club._id, { $inc: { channelCount: 1 } });

        return res.redirect(`/clubs/${club.slug}?channel=${newChannel._id}`);
    } catch (err) {
        console.error('[Clubs] Channel creation error:', err);
        return res.status(500).json({ error: 'Failed to create channel.' });
    }
});

router.post('/:slugOrId/roles', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id);
        const isStaff = ['owner', 'admin'].includes(req.user.role);

        if (!isClubCreator && !isStaff) {
            return res.status(403).json({ error: 'Unauthorized to create roles.' });
        }

        const { name, color, badgeIcon, canManageChannels, canKickMembers, canPostPolls } = req.body;
        if (!name || name.trim().length < 2) {
            return res.status(400).json({ error: 'Role name is required.' });
        }

        const newRole = await ClubRole.create({
            club: club._id,
            name: name.trim(),
            color: color || '#5865F2',
            badgeIcon: badgeIcon || '🛡️',
            position: 20,
            permissions: {
                canManageClub: false,
                canManageChannels: canManageChannels === 'on' || canManageChannels === 'true',
                canManageRoles: false,
                canKickMembers: canKickMembers === 'on' || canKickMembers === 'true',
                canSendMessages: true,
                canPostPolls: canPostPolls === 'on' || canPostPolls === 'true',
                canAuditPrivate: false
            }
        });

        const allRoles = await ClubRole.find({ club: club._id }).lean();
        saveClubRolesArchive(club.name, allRoles);

        return res.redirect(`/clubs/${club.slug}`);
    } catch (err) {
        console.error('[Clubs] Role creation error:', err);
        return res.status(500).json({ error: 'Failed to create role.' });
    }
});

// Assign Tracked Creator Profiles to Track Mod Uploads & Updates
router.post('/:slugOrId/tracked-creators', ensureAuth, async (req, res) => {
    try {
        const club = await resolveClub(req.params.slugOrId);
        if (!club) return res.status(404).json({ error: 'Club not found' });

        const isClubCreator = String(club.creator._id || club.creator) === String(req.user._id);
        const isStaff = ['owner', 'admin'].includes(req.user.role);

        if (!isClubCreator && !isStaff) {
            return res.status(403).json({ error: 'Unauthorized.' });
        }

        const { username } = req.body;
        if (!username || !username.trim()) {
            return res.status(400).json({ error: 'Username required.' });
        }

        const targetUser = await User.findOne({ username: username.trim() });
        if (!targetUser) {
            return res.status(404).json({ error: `User "${username}" was not found.` });
        }

        await Club.findByIdAndUpdate(club._id, {
            $addToSet: { trackedCreators: targetUser._id }
        });

        return res.redirect(`/clubs/${club.slug}`);
    } catch (err) {
        console.error('[Clubs] Tracked creator error:', err);
        return res.status(500).json({ error: 'Failed to add tracked creator.' });
    }
});

// ============================================================================
// 8. CHANNEL MESSAGES, POLLS & REACTIONS REST API
// ============================================================================
router.get('/:slugOrId/channels/:channelId/messages', ensureAuth, async (req, res) => {
    try {
        const messages = await ClubMessage.find({ channel: req.params.channelId })
            .sort({ createdAt: -1 })
            .limit(50)
            .populate('sender', 'username profileImageKey role signedAvatarUrl membership isPremium badges')
            .lean();
        messages.reverse();
        return res.json({ success: true, messages });
    } catch (err) {
        console.error('[Clubs] Fetch messages error:', err);
        return res.status(500).json({ error: 'Failed to load messages.' });
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

module.exports = router;
