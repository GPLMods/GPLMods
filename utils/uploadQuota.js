/**
 * ============================================================================
 * GPLMODS UPLOAD QUOTA & TIER ENGINE
 * Dual quota management:
 * 1. Live replenishment (+1 slot immediately when mod goes live/approved)
 * 2. Rolling 7-day weekly reset for pending/unreviewed uploads
 * 3. File size caps per membership tier
 * ============================================================================
 */

const File = require('../models/core/file');

const TIER_CONFIGS = {
    free: {
        tier: 'free',
        label: 'Registered Member',
        totalSlots: 3,
        maxFileSizeMb: 300,
        maxFileSizeBytes: 300 * 1024 * 1024,
        supportAdDownloads: true
    },
    lite: {
        tier: 'lite',
        label: 'GPL Lite',
        totalSlots: 5,
        maxFileSizeMb: 600,
        maxFileSizeBytes: 600 * 1024 * 1024,
        supportAdDownloads: false
    },
    plus: {
        tier: 'plus',
        label: 'GPL Plus',
        totalSlots: 10,
        maxFileSizeMb: 2048,
        maxFileSizeBytes: 2048 * 1024 * 1024,
        supportAdDownloads: false
    },
    distributor: {
        tier: 'distributor',
        label: 'Distributor Partner',
        totalSlots: 50,
        maxFileSizeMb: 2048,
        maxFileSizeBytes: 2048 * 1024 * 1024,
        supportAdDownloads: false
    }
};

/**
 * Get tier quota configuration for a given user
 */
function getTierQuotaConfig(user) {
    if (!user) return TIER_CONFIGS.free;

    if (user.role === 'distributor' || user.role === 'admin' || user.role === 'owner') {
        return TIER_CONFIGS.distributor;
    }

    if (user.membership === 'plus' || user.membership === 'premium') {
        return TIER_CONFIGS.plus;
    }

    if (user.membership === 'lite') {
        return TIER_CONFIGS.lite;
    }

    return TIER_CONFIGS.free;
}

/**
 * Calculate user's current live and weekly upload quota
 * Only new mod uploads consume slots (updates do not consume slots).
 * Approved mods (status: 'live') do not hold slots hostage (+1 refunded immediately).
 * Pending unreviewed mods release their slot after 7 days (rolling weekly reset).
 */
async function getUserUploadQuota(user) {
    const config = getTierQuotaConfig(user);
    if (!user) {
        return {
            ...config,
            usedSlots: 0,
            remainingSlots: 0,
            canUpload: false,
            earliestReset: null,
            pendingFiles: []
        };
    }

    // Admins and owners have unlimited/max flexibility
    if (user.role === 'admin' || user.role === 'owner') {
        return {
            ...config,
            usedSlots: 0,
            remainingSlots: config.totalSlots,
            canUpload: true,
            earliestReset: null,
            pendingFiles: []
        };
    }

    // Rolling 7-day window
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    // Active pending files that consume slots:
    // - uploaded by user
    // - not an update / not a child version
    // - status is still pending / processing / draft (not yet live, not rejected)
    // - submitted within the rolling 7-day window
    const activePendingFiles = await File.find({
        uploader: user.username,
        isUpdate: { $ne: true },
        parentFile: null,
        status: { $in: ['pending', 'processing', 'draft'] },
        createdAt: { $gte: sevenDaysAgo }
    }).select('_id name createdAt status originalFilename').lean();

    const usedSlots = activePendingFiles.length;
    const remainingSlots = Math.max(0, config.totalSlots - usedSlots);
    const canUpload = remainingSlots > 0;

    let earliestReset = null;
    if (activePendingFiles.length > 0) {
        const oldest = activePendingFiles.reduce((prev, curr) => 
            new Date(prev.createdAt) < new Date(curr.createdAt) ? prev : curr
        );
        earliestReset = new Date(new Date(oldest.createdAt).getTime() + 7 * 24 * 60 * 60 * 1000);
    }

    return {
        ...config,
        usedSlots,
        remainingSlots,
        canUpload,
        earliestReset,
        pendingFiles: activePendingFiles
    };
}

/**
 * Validate file size against the user's tier maximum
 */
function validateUploadFileSize(user, fileSizeBytes) {
    const config = getTierQuotaConfig(user);
    const isAdminOrDist = user && (user.role === 'admin' || user.role === 'owner' || user.role === 'distributor');

    if (!isAdminOrDist && fileSizeBytes > config.maxFileSizeBytes) {
        return {
            valid: false,
            maxFileSizeMb: config.maxFileSizeMb,
            tier: config.tier,
            error: `File size exceeds your ${config.maxFileSizeMb}MB limit for the ${config.label} tier.`
        };
    }

    return {
        valid: true,
        maxFileSizeMb: config.maxFileSizeMb,
        tier: config.tier
    };
}

module.exports = {
    TIER_CONFIGS,
    getTierQuotaConfig,
    getUserUploadQuota,
    validateUploadFileSize
};
