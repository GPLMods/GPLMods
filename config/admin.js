// config/admin.js
const bcrypt = require('bcryptjs');
const axios = require('axios');
const { S3Client, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { componentLoader, Components } = require('../components/loader');

// Import all models (via categorized barrel / root entry points)
const User = require('../models/user');
const File = require('../models/file');
const Review = require('../models/review');
const Report = require('../models/report');
const Dmca = require('../models/dmca');
const Announcement = require('../models/announcement');
const UnbanRequest = require('../models/unbanRequest');
const Request = require('../models/request');
const DistributorApplication = require('../models/distributorApplication');
const UserNotification = require('../models/userNotification');
const SupportTicket = require('../models/supportTicket');
const AutomatedCampaign = require('../models/automatedCampaign');
const SiteState = require('../models/siteState'); 
const Subscriber = require('../models/subscriber');
const NewsletterCampaign = require('../models/newsletterCampaign');
const DocCategory = require('../models/docCategory');
const DocPage = require('../models/docPage');
const License = require('../models/content/license');
const Issue = require('../models/issue');
const Reply = require('../models/reply');
const PointHistory = require('../models/pointHistory');
const ApiLimit = require('../models/system/apiLimit');
const TranslationCache = require('../models/translationCache');
const IosDns = require('../models/iosDns');
const IosCert = require('../models/iosCert');
const VpnCache = require('../models/vpnCache');
const SourceCode = require('../models/sourceCode');
const StaticPage = require('../models/staticPage');
const AIKnowledge = require('../models/aiKnowledge');

function extractVTId(input) {
    if (!input) return "";
    let cleanInput = input.trim();
    if (cleanInput.startsWith('http://') || cleanInput.startsWith('https://')) {
        try {
            const urlObj = new URL(cleanInput);
            const pathParts = urlObj.pathname.split('/').filter(p => p !== '');
            const fileIndex = pathParts.indexOf('file');
            const analysisIndex = pathParts.indexOf('file-analysis');
            if (fileIndex !== -1 && pathParts.length > fileIndex + 1) return pathParts[fileIndex + 1];
            else if (analysisIndex !== -1 && pathParts.length > analysisIndex + 1) return pathParts[analysisIndex + 1];
            const hashMatch = cleanInput.match(/[a-fA-F0-9]{64}/);
            if (hashMatch) return hashMatch[0];
        } catch (e) { console.error("Invalid VT URL:", e); }
    }
    return cleanInput;
}

const s3ClientAdmin = new S3Client({
    endpoint: `https://${process.env.B2_ENDPOINT}`,
    region: process.env.B2_REGION,
    credentials: {
        accessKeyId: process.env.B2_ACCESS_KEY_ID,
        secretAccessKey: process.env.B2_SECRET_ACCESS_KEY,
    }
});

const triggerCloudflareRebuild = async () => {
    try {
        const webhookUrl = 'https://api.cloudflare.com/client/v4/pages/webhooks/deploy_hooks/YOUR_SECRET_UUID';
        await axios.post(webhookUrl);
        console.log("Cloudflare rebuild triggered successfully.");
    } catch (e) {
        console.error("Failed to trigger Cloudflare rebuild:", e.message);
    }
};

const deleteFromB2Admin = async (fileKey) => {
    if (!fileKey || fileKey === 'external-link') return;
    try {
        await s3ClientAdmin.send(new DeleteObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: fileKey }));
        console.log(`AdminJS deleted ${fileKey} from B2.`);
        
        const { deleteFromFTP } = require('../utils/ftpSync');
        deleteFromFTP(fileKey).catch(e => console.error("Admin FTP delete failed", e));
        
    } catch (error) {
        console.error(`AdminJS failed to delete ${fileKey}:`, error.message);
    }
};

async function createAdminRouter() {
    const AdminJSModule = await import('adminjs');
    const AdminJS = AdminJSModule.default || AdminJSModule;
    const ValidationError = AdminJS.ValidationError || AdminJSModule.ValidationError;
    
    const AdminJSExpress = await import('@adminjs/express');
    const AdminJSMongoose = await import('@adminjs/mongoose');
    const { dark, light } = await import('@adminjs/themes');

    AdminJS.registerAdapter({
        Database: AdminJSMongoose.Database,
        Resource: AdminJSMongoose.Resource,
    });

    const gplModsTheme = {
        ...dark,
        id: 'dark', 
        name: 'GPL Mods Premium',
        overrides: {
            ...dark.overrides, 
            typography: {
                ...dark.overrides?.typography,
                fontFamilies: {
                    primary: "'Poppins', sans-serif"
                }
            },
            colors: {
                ...dark.overrides?.colors, 
                primary100: '#FFD700', primary80: '#e5c200', primary60: '#ccad00', primary40: '#b29700', primary20: '#332b00',  
                bg: '#0a0a0a', container: '#1a1a1a', white: '#1a1a1a', text: '#ffffff', grey100: '#ffffff',    
                grey80: '#c0c0c0', grey60: '#a0a0a0', grey40: '#444444', grey20: '#2a2a2a', border: '#333333',     
                errorLight: '#ffadad', error: '#e53935', errorDark: '#b71c1c', successLight: '#b0ffb0', success: '#43a047',    
                successDark: '#1b5e20', infoLight: '#90caf9', info: '#2196F3', infoDark: '#0d47a1',
            }
        }
    };

    const isProduction = true; 

    // --- Structured AdminJS Navigation Groups ---
    const usersNav = { name: 'Users & Access', icon: 'Users' };
    const modsNav = { name: 'Mods & Repositories', icon: 'Package' };
    const communityNav = { name: 'Community & Forum', icon: 'MessageSquare' };
    const docsNav = { name: 'Documentation & Content', icon: 'BookOpen' };
    const moderationNav = { name: 'Publishers & Moderation', icon: 'Shield' };
    const systemNav = { name: 'System & Analytics', icon: 'Settings' };

    const adminJsOptions = {
        rootPath: '/admin',
        componentLoader: componentLoader, 
        
        branding: {
            companyName: 'GPL Mods',
            logo: '/images/logo.png',
            withMadeWithLove: false,
        },
        defaultTheme: 'dark', 
        availableThemes: [gplModsTheme, light], 
        
        env: { NODE_ENV: isProduction ? 'production' : 'development' },
        assets: {
            styles: isProduction ? ['/.adminjs/bundle.css', '/css/admin-custom.css'] : ['/css/admin-custom.css'],
            scripts: isProduction ? ['/.adminjs/bundle.js', '/js/image-fallback.js', '/js/admin-badges.js'] : ['/js/admin-badges.js', '/js/image-fallback.js'],
        },
        dashboard: { 
            component: Components.Dashboard,
            handler: async (request, response, context) => {
                const startOfMonth = new Date();
                startOfMonth.setDate(1);
                startOfMonth.setHours(0, 0, 0, 0);

                const totalUsers = await User.countDocuments();
                const newUsersThisMonth = await User.countDocuments({ createdAt: { $gte: startOfMonth } });

                const totalMods = await File.countDocuments();
                const newModsThisMonth = await File.countDocuments({ createdAt: { $gte: startOfMonth } });

                const downloadAgg = await File.aggregate([{ $group: { _id: null, total: { $sum: "$downloads" } } }]);
                const totalDownloads = downloadAgg.length > 0 ? downloadAgg[0].total : 0;

                const viewsAgg = await File.aggregate([{ $group: { _id: null, total: { $sum: "$views" } } }]);
                const totalViews = viewsAgg.length > 0 ? viewsAgg[0].total : 0;

                // Action-required counts
                const pendingReports = await Report.countDocuments({ status: 'pending' });
                const pendingApprovals = await File.countDocuments({ status: 'pending' });
                const openTickets = await SupportTicket.countDocuments({ status: 'open' });

                const platformAgg = await File.aggregate([
                    { $group: { _id: "$category", value: { $sum: 1 } } }
                ]);
                const modsByPlatform = platformAgg.map(p => ({
                    name: p._id ? p._id.toUpperCase() : 'UNKNOWN',
                    value: p.value
                }));

                const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
                const recentUploadsAgg = await File.aggregate([
                    { $match: { createdAt: { $gte: sevenDaysAgo } } },
                    { $group: { 
                        _id: { $dateToString: { format: "%m/%d", date: "$createdAt" } }, 
                        uploads: { $sum: 1 } 
                    }},
                    { $sort: { _id: 1 } }
                ]);
                const uploadChartData = recentUploadsAgg.map(item => ({
                    name: item._id, 
                    Uploads: item.uploads
                }));

                // 30-day user growth for line chart
                const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
                const userGrowthAgg = await User.aggregate([
                    { $match: { createdAt: { $gte: thirtyDaysAgo } } },
                    { $group: {
                        _id: { $dateToString: { format: "%m/%d", date: "$createdAt" } },
                        count: { $sum: 1 }
                    }},
                    { $sort: { _id: 1 } }
                ]);
                const userGrowthData = userGrowthAgg.map(item => ({
                    date: item._id,
                    users: item.count
                }));

                // Recent activity
                const recentUsers = await User.find({})
                    .sort({ createdAt: -1 })
                    .limit(5)
                    .select('username createdAt role')
                    .lean();
                const recentMods = await File.find({})
                    .sort({ createdAt: -1 })
                    .limit(5)
                    .select('name category status createdAt')
                    .lean();

                return {
                    stats: { totalUsers, newUsersThisMonth, totalMods, newModsThisMonth, totalDownloads, totalViews },
                    actionRequired: { pendingReports, pendingApprovals, openTickets },
                    modsByPlatform,
                    uploadChartData,
                    userGrowthData,
                    recentUsers: recentUsers.map(u => ({ username: u.username, date: u.createdAt, role: u.role })),
                    recentMods: recentMods.map(m => ({ name: m.name, category: m.category, status: m.status, date: m.createdAt }))
                };
            }
        },
        
        branding: {
            companyName: 'GPL Mods',
            logo: '/images/logo.png', 
            softwareBrothers: false,
            withMadeWithLove: false, 
        },

        resources: [
            // ---------------------------------
            // USERS & ACCESS
            // ---------------------------------
            {
                resource: User,
                options: {
                    navigation: usersNav,
                    listProperties: ['profileImageKey', '_id', 'username', 'cardId', 'dateOfBirth', 'forumPoints', 'email', 'role', 'membership', 'isVerifiedAccount', 'isBanned', 'lastSeen'],
                    showProperties: ['_id', 'username', 'email', 'cardId', 'role', 'membership', 'membershipExpiresAt', 'subscriptionId', 'membershipPlan', 'isVerified', 'isBanned', 'banReason', 'createdAt', 'lastSeen', 'bio', 'isVerifiedAccount', 'verifiedBadgeText', 'profileLottieBadges', 'country', 'socialLinks.telegram', 'socialLinks.discord', 'socialLinks.website', 'socialLinks.youtube'],
                    editProperties: ['username', 'dateOfBirth', 'forumPoints', 'email', 'role', 'membership', 'membershipExpiresAt', 'subscriptionId', 'membershipPlan', 'isVerified', 'isBanned', 'banReason', 'bio', 'isVerifiedAccount', 'verifiedBadgeText', 'profileLottieBadges', 'country', 'newPassword', 'socialLinks.telegram', 'socialLinks.discord', 'socialLinks.website', 'socialLinks.youtube'],
                    properties: {
                        password: { isVisible: false },
                        newPassword: { type: 'password', label: 'New Password (leave blank to keep unchanged)' },
                        profileLottieBadges: { description: 'Custom profile Lottie badges (max 3). Specify animation (e.g. verified.json, card.json, crown.json), title, description, and color.' },
                        bio: { type: 'textarea', description: 'User profile biography' },
                        banReason: { type: 'textarea', description: 'Reason for banning the user' },
                        cardId: { isVisible: { edit: false, filter: true, list: true, show: true } },
                        role: {
                            isVisible: {
                                list: true,
                                show: true,
                                filter: true,
                                edit: (context) => context?.currentAdmin?.role === 'owner',
                                new: (context) => context?.currentAdmin?.role === 'owner'
                            },
                            description: 'Security: Only the Owner can modify user roles.'
                        },
                        membership: {
                            isVisible: {
                                list: true,
                                show: true,
                                filter: true,
                                edit: (context) => context?.currentAdmin?.role === 'owner',
                                new: (context) => context?.currentAdmin?.role === 'owner'
                            },
                            description: 'Security: Only the Owner can modify user membership or subscription status.'
                        },
                        membershipExpiresAt: {
                            isVisible: {
                                list: true,
                                show: true,
                                filter: true,
                                edit: (context) => context?.currentAdmin?.role === 'owner',
                                new: (context) => context?.currentAdmin?.role === 'owner'
                            }
                        },
                        subscriptionId: {
                            isVisible: {
                                list: true,
                                show: true,
                                filter: true,
                                edit: (context) => context?.currentAdmin?.role === 'owner',
                                new: (context) => context?.currentAdmin?.role === 'owner'
                            }
                        },
                        membershipPlan: {
                            isVisible: {
                                list: true,
                                show: true,
                                filter: true,
                                edit: (context) => context?.currentAdmin?.role === 'owner',
                                new: (context) => context?.currentAdmin?.role === 'owner'
                            }
                        },
                        'socialLinks.telegram': { description: 'e.g., https://t.me/yourname' },
                        'socialLinks.discord': { description: 'e.g., https://discord.gg/...' },
                        'socialLinks.website': { description: 'e.g., https://yourwebsite.com' },
                        'socialLinks.youtube': { description: 'e.g., https://youtube.com/...' },
                        profileImageKey: {
                            components: { list: Components.AvatarCell, show: Components.AvatarCell },
                            isVisible: { edit: false, filter: false, list: true, show: true } 
                        }
                    },
                    actions: {
                        new: { 
                            isAccessible: true,
                            before: async (request, context) => {
                                const currentAdmin = context?.currentAdmin;
                                const isOwner = currentAdmin && String(currentAdmin.role).toLowerCase() === 'owner';
                                if (!isOwner) {
                                    if (request.payload.role && request.payload.role !== 'member') {
                                        throw new ValidationError({
                                            role: { message: 'Only the site owner can assign elevated roles to users.' }
                                        });
                                    }
                                    if (request.payload.membership && request.payload.membership !== 'free') {
                                        throw new ValidationError({
                                            membership: { message: 'Only the site owner can configure paid user subscriptions.' }
                                        });
                                    }
                                    request.payload.role = 'member';
                                    request.payload.membership = 'free';
                                    delete request.payload.subscriptionId;
                                    delete request.payload.membershipExpiresAt;
                                    delete request.payload.membershipPlan;
                                }
                                return request;
                            }
                        },
                        edit: { 
                            isAccessible: true,
                            before: async (request, context) => {
                                const { newPassword, ...payload } = request.payload;
                                if (newPassword && newPassword.length > 0) {
                                    payload.password = await bcrypt.hash(newPassword, 10);
                                }
                                if (payload.isBanned === true || payload.isBanned === 'true') {
                                    payload.cardId = null;
                                    payload.cardLoginToken = null;
                                }

                                const currentAdmin = context?.currentAdmin;
                                const isOwner = currentAdmin && String(currentAdmin.role).toLowerCase() === 'owner';

                                if (!isOwner) {
                                    const restrictedFields = ['role', 'membership', 'membershipExpiresAt', 'subscriptionId', 'membershipPlan'];
                                    
                                    // Check if non-owner is attempting to alter restricted fields
                                    if (context.record && context.record.params) {
                                        for (const field of restrictedFields) {
                                            if (payload[field] !== undefined && String(payload[field]) !== String(context.record.params[field] || '')) {
                                                const fieldLabel = field === 'role' ? 'user roles' : 'user subscriptions';
                                                throw new ValidationError({
                                                    [field]: { message: `Only the site owner can change ${fieldLabel}.` }
                                                });
                                            }
                                        }
                                    }

                                    // Strictly strip/restore original values from record
                                    restrictedFields.forEach(field => {
                                        if (context.record && context.record.params && context.record.params[field] !== undefined) {
                                            payload[field] = context.record.params[field];
                                        } else {
                                            delete payload[field];
                                        }
                                    });
                                }

                                request.payload = payload;
                                return request;
                            }
                        },
                        delete: { isAccessible: true }
                    }
                }
            },
            {
                resource: PointHistory,
                options: {
                    navigation: usersNav,
                    listProperties: ['user', 'amount', 'reason', 'createdAt'],
                    showProperties: ['user', 'amount', 'reason', 'customMessage', 'createdAt'],
                    editProperties: ['user', 'amount', 'reason', 'customMessage'],
                    properties: {
                        customMessage: { type: 'richtext', description: 'Optional message to the user explaining why they got/lost these points.' },
                        amount: { description: 'Use positive numbers to add points (e.g., 50) and negative to deduct (e.g., -10).' }
                    },
                    actions: {
                        new: {
                            after: async (response, request, context) => {
                                if (request.method === 'post' && response.record && !Object.keys(response.record.errors || {}).length) {
                                    const amount = Number(response.record.params.amount);
                                    const userId = response.record.params.user;
                                    await User.findByIdAndUpdate(userId, { $inc: { forumPoints: amount } });
                                }
                                return response;
                            }
                        },
                        edit: { isAccessible: false },
                        delete: { isAccessible: false } 
                    }
                }
            },
            {
                resource: UserNotification,
                options: {
                    navigation: usersNav,
                    listProperties: ['user', 'title', 'type', 'isRead', 'createdAt'],
                    showProperties: ['user', 'title', 'message', 'type', 'isRead', 'createdAt'],
                    editProperties: ['user', 'title', 'message', 'type'], 
                    properties: { message: { type: 'textarea' } }
                }
            },

            // ---------------------------------
            // MODS & REPOSITORIES
            // ---------------------------------
            {
                resource: File,
                options: {
                    navigation: modsNav,
                    listProperties: ['iconKey', 'name', 'ageRating', 'fileSize', 'version', 'isVariant', 'status', 'showInRepo', 'category'],
                    editProperties: [
                        'name', 'version', 'ageRating', 'developer', 'uploader', 'modDescription', 'modFeatures', 'officialDescription', 'importantNote',
                        'whatsNew', 'category', 'status', 'rejectionReason', 'certification', 'isLatestVersion', 'iosPackageId',
                        'showInSitemap', 'virusTotalId', 'virusTotalAnalysisId', 'architectures', 'minOsVersion', 
                        'iconKey', 'screenshotKeys', 'videoUrl',  'manualFileScanUrl', 'manualSiteScanUrl', 'isEditorsChoice', 'editorsChoiceDescription',
                        'fileKey', 'fileSize', 'originalFilename', 'externalDownloadUrl', 'alternativeLinks', 'customAdLink',
                        'isMultiPart', 'downloadParts', 'installationInstructions', 'directDownloadUrl',
                        'isVariant', 'showInRepo', 'masterFile', 'license'
                    ],
                    showProperties: [
                        'iconKey', 'name', 'version', 'ageRating', 'developer', 'uploader', 'status', 'rejectionReason',
                        'certification', 'category', 'downloads', 'averageRating', 'showInSitemap', 'isEditorsChoice', 'editorsChoiceDescription',
                        'externalDownloadUrl', 'fileKey', 'fileSize', 'originalFilename', 'customAdLink',  'manualFileScanUrl', 'manualSiteScanUrl',
                        'virusTotalId', 'virusTotalAnalysisId', 'screenshotKeys', 'videoUrl', 'createdAt', 'updatedAt', 'architectures', 'minOsVersion',  
                        'isMultiPart', 'downloadParts', 'installationInstructions', 'alternativeLinks', 'directDownloadUrl', 'iosPackageId',
                        'isVariant', 'showInRepo', 'masterFile', 'license'
                    ],
                    properties: {
                        modDescription: { type: 'richtext' },
                        officialDescription: { type: 'richtext' },
                        modFeatures: { type: 'richtext' }, 
                        whatsNew: { type: 'richtext' },
                        importantNote: { type: 'richtext' }, 
                        installationInstructions: { type: 'textarea', description: 'Step-by-step instructions for installing this mod.' },
                        showInRepo: { description: 'Uncheck this to hide this mod from F-Droid, Sileo, AltStore, repo etc.' },
                        iosPackageId: { description: 'Optional: For iOS Jailbroken (DEB) tweaks ONLY.' },
                        isEditorsChoice: { description: 'Check this to feature this mod in the Editor\'s Choice banner.' },
                        editorsChoiceDescription: { type: 'textarea', description: '(Optional) A short, catchy description.' },
                        externalDownloadUrl: { description: 'Paste direct download link from Google Drive, Dropbox, Mega, etc.' },
                        alternativeLinks: { isArray: true, description: 'Add alternative download mirrors.' },
                        virusTotalId: { description: 'Paste the FULL VirusTotal URL (https://...) OR just the SHA-256 Hash.' },
                        fileKey: { description: 'The Backblaze B2 file path' },
                        customAdLink: { description: 'MANUAL OVERRIDE: Paste a direct Linkvertise/Ad link here.' },
                        directDownloadUrl: { description: 'Optional: Paste a true direct link (like Dropbox with ?dl=1).' },
                        license: { description: 'Optional software license for this mod.' },
                        screenshotKeys: { isArray: true, description: 'Paste direct image URLs (https://...).' },
                        rejectionReason: {
                            type: 'textarea',
                            description: 'Provide a reason if rejecting this mod.',
                            isVisible: { edit: (record) => record.params.status === 'rejected', list: false, filter: false, show: true }
                        },
                        iconKey: { 
                            description: 'Paste a direct image URL (https://...) OR a Backblaze B2 key.',
                            components: { list: Components.ImagePreview, show: Components.ImagePreview }
                        },
                        isMultiPart: { description: 'Check this box if the file is split into multiple download links.' },
                        downloadParts: { isArray: true, description: 'Add the individual links here.' },
                        'downloadParts.partVirusTotalId': { description: 'Paste the FULL VirusTotal URL OR SHA-256 Hash.' },
                        'downloadParts.partVirusTotalScanDate': { isVisible: { edit: false, show: true, list: false } },
                        'downloadParts.partVirusTotalPositiveCount': { isVisible: { edit: false, show: true, list: false } },
                        'downloadParts.partVirusTotalTotalScans': { isVisible: { edit: false, show: true, list: false } },
                        isVariant: {
                            components: { list: Components.VariantBadge },
                            isDisabled: true 
                        },
                        masterFile: {
                            description: 'If this is a Variant, this is the ID of the original Master App it belongs to.',
                            isDisabled: true 
                        }
                    },
                    actions: {
                        new: { 
                            isAccessible: true,
                            before: async (request) => {
                                if (request.payload.virusTotalId) request.payload.virusTotalId = extractVTId(request.payload.virusTotalId);
                                Object.keys(request.payload).forEach(key => {
                                    if (key.startsWith('downloadParts.') && key.endsWith('.partVirusTotalId')) {
                                        request.payload[key] = extractVTId(request.payload[key]);
                                    }
                                });
                                return request;
                            }
                        },
                        edit: { 
                            isAccessible: true,
                            before: async (request) => {
                                if (request.payload.virusTotalId) request.payload.virusTotalId = extractVTId(request.payload.virusTotalId);
                                Object.keys(request.payload).forEach(key => {
                                    if (key.startsWith('downloadParts.') && key.endsWith('.partVirusTotalId')) {
                                        request.payload[key] = extractVTId(request.payload[key]);
                                    }
                                });
                                return request;
                            }
                        },
                        delete: { 
                            isAccessible: true,
                            before: async (request, context) => {
                                const recordId = request.params.recordId;
                                const fileToDelete = await File.findById(recordId).populate('olderVersions');
                                if (fileToDelete) {
                                    await deleteFromB2Admin(fileToDelete.fileKey);
                                    await deleteFromB2Admin(fileToDelete.iconKey);
                                    if (fileToDelete.screenshotKeys) {
                                        for (const key of fileToDelete.screenshotKeys) await deleteFromB2Admin(key);
                                    }
                                    if (fileToDelete.olderVersions) {
                                        for (const oldV of fileToDelete.olderVersions) {
                                            await deleteFromB2Admin(oldV.fileKey);
                                            await File.findByIdAndDelete(oldV._id);
                                        }
                                    }
                                    await Review.deleteMany({ file: recordId });
                                    await Report.updateMany({ file: recordId }, { status: 'resolved' });
                                }
                                return request;
                            }
                        },
                        viewOnSite: {
                            actionType: 'record', icon: 'ExternalLink', component: Components.ActionRedirect,
                            handler: async (request, response, context) => {
                                const updatedRecord = context.record.toJSON(context.currentAdmin);
                                updatedRecord.params.redirectUrl = `/mods/${context.record.params._id}`;
                                return { record: updatedRecord, notice: { message: 'Opening mod page...', type: 'success' } };
                            }
                        },
                        testDownload: {
                            actionType: 'record', icon: 'Download', component: Components.ActionRedirect,
                            handler: async (request, response, context) => {
                                const updatedRecord = context.record.toJSON(context.currentAdmin);
                                updatedRecord.params.redirectUrl = `/download-file/${context.record.params._id}`;
                                return { record: updatedRecord, notice: { message: 'Initiating test download...', type: 'success' } };
                            }
                        },
                        viewVirusTotal: {
                            actionType: 'record', icon: 'Shield', component: Components.ActionRedirect,
                            handler: async (request, response, context) => {
                                const vtHash = context.record.params.virusTotalId || "";
                                const vtAnalysis = context.record.params.virusTotalAnalysisId || "";
                                let vtUrl = `https://www.virustotal.com/`;
                                if (vtHash.length === 64) vtUrl = `https://www.virustotal.com/gui/file/${vtHash}`;
                                else if (vtAnalysis) vtUrl = `https://www.virustotal.com/gui/file-analysis/${vtAnalysis}`;
                                else if (vtHash) vtUrl = `https://www.virustotal.com/gui/file-analysis/${vtHash}`;
                                
                                const updatedRecord = context.record.toJSON(context.currentAdmin);
                                updatedRecord.params.redirectUrl = vtUrl;
                                return { record: updatedRecord, notice: { message: 'Opening VirusTotal report...', type: 'success' } };
                            }
                        },
                        manageVotes: {
                            actionType: 'record',
                            icon: 'ThumbsUp',
                            component: Components.ManageVotes, 
                            handler: async (request, response, context) => {
                                const file = context.record;
                                if (request.method === 'post') {
                                    const { actionType, newWorkingCount, newNotWorkingCount } = request.payload;

                                    try {
                                        if (actionType === 'reset') {
                                            await File.findByIdAndUpdate(file.params._id, {
                                                workingVoteCount: 0,
                                                notWorkingVoteCount: 0,
                                                votedWorkingBy: [],
                                                votedNotWorkingBy: []
                                            });
                                            return {
                                                record: file.toJSON(context.currentAdmin),
                                                notice: { message: 'All votes have been successfully reset to 0.', type: 'success' },
                                                redirectUrl: context.h.resourceActionUrl({ resourceId: 'File', actionName: 'list' })
                                            };
                                        } 
                                        else if (actionType === 'override') {
                                            await File.findByIdAndUpdate(file.params._id, {
                                                workingVoteCount: parseInt(newWorkingCount, 10) || 0,
                                                notWorkingVoteCount: parseInt(newNotWorkingCount, 10) || 0,
                                                votedWorkingBy: [],
                                                votedNotWorkingBy: []
                                            });
                                            return {
                                                record: file.toJSON(context.currentAdmin),
                                                notice: { message: 'Vote counts have been manually overridden.', type: 'success' },
                                                redirectUrl: context.h.resourceActionUrl({ resourceId: 'File', actionName: 'list' })
                                            };
                                        }
                                    } catch (error) {
                                        return {
                                            record: file.toJSON(context.currentAdmin),
                                            notice: { message: `Error updating votes: ${error.message}`, type: 'error' }
                                        };
                                    }
                                }
                                return { record: file.toJSON(context.currentAdmin) };
                            }
                        }
                    }
                }
            },
            {
                resource: SourceCode,
                options: {
                    navigation: modsNav,
                    listProperties: ['title', 'githubRepo', 'isPrivate', 'status'],
                    editProperties: ['title', 'slug', 'githubOwner', 'githubRepo', 'isPrivate', 'description', 'allowedRoles', 'allowedUsers', 'status'],
                    showProperties: ['title', 'slug', 'githubOwner', 'githubRepo', 'isPrivate', 'description', 'allowedRoles', 'allowedUsers', 'status'],
                    properties: {
                        description: { type: 'textarea' },
                        allowedRoles: { isArray: true },
                        allowedUsers: {
                            isArray: true,
                            description: 'Select specific users who are allowed to download this source code.'
                        }
                    }
                }
            },
            {
                resource: Review,
                options: {
                    navigation: modsNav,
                    listProperties: ['username', 'rating', 'comment', 'file', 'createdAt'],
                    showProperties: ['username', 'rating', 'comment', 'file', 'user', 'createdAt', 'updatedAt'],
                    editProperties: ['rating', 'comment'],
                    properties: {
                        comment: { type: 'textarea' }
                    },
                    actions: { edit: { isAccessible: true }, delete: { isAccessible: true } },
                },
            },
            {
                resource: IosCert,
                options: {
                    navigation: modsNav,
                    listProperties: ['name', 'status', 'updatedAt'],
                    actions: {
                        new: {
                            after: async (response, request, context) => {
                                if (request.method === 'post') await triggerCloudflareRebuild();
                                return response;
                            }
                        },
                        edit: {
                            after: async (response, request, context) => {
                                if (request.method === 'post') await triggerCloudflareRebuild();
                                return response;
                            }
                        },
                        delete: {
                            after: async (response, request, context) => {
                                if (request.method === 'post') await triggerCloudflareRebuild();
                                return response;
                            }
                        }
                    }
                }
            },
            {
                resource: IosDns,
                options: {
                    navigation: modsNav,
                    listProperties: ['name', 'configUrl', 'isRecommended', 'updatedAt']
                }
            },

            // ---------------------------------
            // COMMUNITY & FORUM
            // ---------------------------------
            {
                resource: Issue,
                options: {
                    navigation: communityNav,
                    listProperties: ['title', 'category', 'status', 'author', 'createdAt'],
                    showProperties: ['title', 'slug', 'category', 'status', 'views', 'author', 'content', 'createdAt'],
                    editProperties: ['title', 'slug', 'category', 'status', 'content'],
                    properties: { content: { type: 'richtext' } }
                }
            },
            {
                resource: Reply,
                options: {
                    navigation: communityNav,
                    listProperties: ['issue', 'author', 'isSolution', 'isAdminReply', 'createdAt'],
                    editProperties: ['content', 'isSolution', 'isAdminReply'],
                    properties: { content: { type: 'richtext' } }
                }
            },
            {
                resource: Request,
                options: {
                    navigation: communityNav,
                    listProperties: ['appName', 'requestType', 'platform', 'username', 'status', 'createdAt'],
                    showProperties: [
                        'requestType', 'appName', 'platform', 'requestedVersion', 
                        'officialLink', 'existingModLink', 'modFeaturesRequested', 
                        'additionalNotes', 'username', 'status', 'adminNotes', 'createdAt'
                    ],
                    editProperties: ['status', 'adminNotes'], 
                    properties: {
                        modFeaturesRequested: { type: 'textarea' },
                        additionalNotes: { type: 'textarea' },
                        adminNotes: { type: 'textarea' }
                    }
                }
            },
            {
                resource: SupportTicket,
                options: {
                    navigation: communityNav,
                    listProperties: ['subject', 'category', 'username', 'status', 'createdAt'],
                    showProperties: ['status', 'category', 'subject', 'message', 'username', 'email', 'adminNotes', 'createdAt', 'updatedAt'],
                    editProperties: ['status', 'adminNotes'], 
                    properties: { message: { type: 'textarea' }, adminNotes: { type: 'textarea' } }
                }
            },
            {
                resource: UnbanRequest,
                options: {
                    navigation: communityNav,
                    listProperties: ['username', 'email', 'status', 'createdAt'],
                    showProperties: ['user', 'username', 'email', 'appealMessage', 'status', 'createdAt', 'updatedAt'],
                    editProperties: ['status', 'appealMessage'],
                    properties: {
                        appealMessage: { type: 'textarea' }
                    }
                }
            },

            // ---------------------------------
            // DOCUMENTATION & CONTENT
            // ---------------------------------
            {
                resource: DocCategory,
                options: {
                    navigation: docsNav,
                    listProperties: ['name', 'order', 'createdAt'],
                    editProperties: ['name', 'order']
                }
            },
            {
                resource: DocPage,
                options: {
                    navigation: docsNav,
                    listProperties: ['title', 'category', 'order', 'slug'],
                    editProperties: ['title', 'category', 'order', 'featuredImageKey', 'content'], 
                    showProperties: ['title', 'category', 'order', 'slug', 'featuredImageKey', 'content', 'createdAt'],
                    properties: {
                        content: { type: 'richtext' },
                        featuredImageKey: { description: 'Optional: Paste a direct image URL (https://...) or B2 Key for the cover image.' },
                        category: { isSortable: true }
                    },
                    actions: {
                        new: {
                            before: async (request) => {
                                if (request.payload.title) {
                                    request.payload.slug = request.payload.title.toString().toLowerCase().replace(/\s+/g, '-').replace(/[^\w\-]+/g, '').replace(/\-\-+/g, '-').replace(/^-+/, '').replace(/-+$/, '');
                                }
                                return request;
                            }
                        },
                        edit: {
                            before: async (request) => {
                                if (request.payload.title) {
                                    request.payload.slug = request.payload.title.toString().toLowerCase().replace(/\s+/g, '-').replace(/[^\w\-]+/g, '').replace(/\-\-+/g, '-').replace(/^-+/, '').replace(/-+$/, '');
                                }
                                return request;
                            }
                        }
                    }
                }
            },
            {
                resource: Announcement,
                options: {
                    navigation: docsNav,
                    listProperties: ['title', 'author', 'createdAt'],
                    editProperties: ['title', 'author', 'content'],
                    properties: { content: { type: 'richtext' } },
                },
            },
            {
                resource: License,
                options: {
                    navigation: docsNav,
                    id: 'License',
                    name: 'Licenses',
                    listProperties: ['name', 'slug', 'shortDescription', 'createdAt'],
                    showProperties: ['name', 'slug', 'shortDescription', 'content', 'createdAt', 'updatedAt'],
                    editProperties: ['name', 'slug', 'shortDescription', 'content'],
                    properties: { content: { type: 'textarea' }, shortDescription: { type: 'textarea' } }
                }
            },
            {
                resource: StaticPage,
                options: {
                    navigation: docsNav,
                    listProperties: ['slug', 'title', 'isPublished', 'updatedAt'],
                    showProperties: ['slug', 'title', 'content', 'isPublished', 'createdAt', 'updatedAt'],
                    editProperties: ['slug', 'title', 'content', 'isPublished'],
                    properties: {
                        slug: { description: 'Public path segment, for example faq or privacy-policy.' },
                        content: { type: 'richtext', description: 'HTML content shown on the public page. Only trusted administrators should edit this field.' }
                    }
                }
            },

            // ---------------------------------
            // PUBLISHERS & MODERATION
            // ---------------------------------
            {
                resource: DistributorApplication,
                options: {
                    navigation: moderationNav,
                    listProperties: ['organizationName', 'username', 'primaryDistributionPlatform', 'status', 'createdAt'],
                    showProperties: [
                        'status', 'organizationName', 'username', 'email', 
                        'primaryDistributionPlatform', 'platformUrl', 'monetizationMethod',
                        'adminContactName', 'adminSocialLink', 
                        'socialTelegram', 'socialDiscord', 'socialWebsite', 'socialYoutube',
                        'adminNotes', 'createdAt'
                    ],
                    editProperties: ['status', 'adminNotes'],
                    properties: { adminNotes: { type: 'textarea' } }
                }
            },
            {
                resource: Report,
                options: {
                    navigation: moderationNav,
                    listProperties: ['reportedFileName', 'reportingUsername', 'reason', 'status', 'createdAt'],
                    showProperties: ['file', 'reportedFileName', 'reportingUser', 'reportingUsername', 'reason', 'additionalComments', 'status', 'createdAt', 'updatedAt'],
                    editProperties: ['status', 'reason', 'additionalComments'],
                    properties: {
                        additionalComments: { type: 'textarea' }
                    }
                },
            },
            {
                resource: Dmca,
                options: {
                    navigation: moderationNav,
                    listProperties: ['fullName', 'infringingUrl', 'status', 'createdAt'],
                    editProperties: ['status'],
                }
            },

            // ---------------------------------
            // SYSTEM & ANALYTICS
            // ---------------------------------
            {
                resource: SiteState,
                options: {
                    navigation: systemNav,
                    actions: {
                        new: { isAccessible: async () => { const count = await SiteState.countDocuments(); return count === 0; } },
                        delete: { isAccessible: false } 
                    },
                    listProperties: ['status', 'targetAudience', 'enableGeminiChatbot', 'enableLinkvertise', 'enableAutomationEngine', 'updatedAt'],
                    showProperties: [
                        'status', 'targetAudience', 'targetUsername', 'enableGeminiChatbot', 'geminiHiddenPages',
                        'enableAutomationEngine', 'maintenanceTitle', 'maintenanceMessage', 'unavailableTitle',
                        'unavailableMessage', 'enableLinkvertise', 'linkvertiseId', 'adNetworkBaseUrl',
                        'socialLinks.youtube', 'socialLinks.discord', 'socialLinks.github', 'socialLinks.twitter',
                        'socialLinks.linkedin', 'socialLinks.reddit', 'socialLinks.instagram', 'socialLinks.facebook',
                        'socialLinks.threads', 'socialLinks.gravatar', 'updatedAt'
                    ],
                    editProperties: [
                        'status', 'targetAudience', 'targetUsername', 'enableGeminiChatbot', 'geminiHiddenPages',
                        'enableAutomationEngine', 'maintenanceTitle', 'maintenanceMessage', 
                        'unavailableTitle', 'unavailableMessage', 'enableLinkvertise', 'linkvertiseId', 'adNetworkBaseUrl',
                        'socialLinks.youtube', 'socialLinks.discord', 'socialLinks.github', 'socialLinks.twitter',
                        'socialLinks.linkedin', 'socialLinks.reddit', 'socialLinks.instagram', 'socialLinks.facebook',
                        'socialLinks.threads', 'socialLinks.gravatar'
                    ],
                    properties: {
                        enableGeminiChatbot: { description: 'Master toggle to show or hide the Google Gemini Support Chatbot on the website.' },
                        geminiHiddenPages: { description: 'Pages or URL slug patterns where Gemini Chatbot should be hidden (e.g. /admin, /upload, /mods/:id, /status).' },
                        maintenanceMessage: { type: 'richtext' },
                        unavailableMessage: { type: 'richtext' },
                        targetUsername: { description: 'Only required if Target Audience is "specific-user".' },
                        adNetworkBaseUrl: { description: 'Use {{ID}} for your Account ID and {{URL}} for the Base64 encoded target link.' },
                        'socialLinks.youtube': { description: 'Footer and About page YouTube URL.' },
                        'socialLinks.discord': { description: 'Footer and About page Discord URL.' },
                        'socialLinks.github': { description: 'Footer and About page GitHub URL.' },
                        'socialLinks.twitter': { description: 'Footer and About page X/Twitter URL.' },
                        'socialLinks.linkedin': { description: 'Footer and About page LinkedIn URL.' },
                        'socialLinks.reddit': { description: 'Footer and About page Reddit URL.' },
                        'socialLinks.instagram': { description: 'Footer and About page Instagram URL.' },
                        'socialLinks.facebook': { description: 'Footer and About page Facebook URL.' },
                        'socialLinks.threads': { description: 'Footer and About page Threads URL.' },
                        'socialLinks.gravatar': { description: 'Footer and About page Gravatar URL.' }
                    }
                }
            },
            {
                resource: Subscriber,
                options: {
                    navigation: systemNav,
                    listProperties: ['email', 'isSubscribed', 'source', 'createdAt'],
                }
            },
            {
                resource: NewsletterCampaign,
                options: {
                    navigation: systemNav,
                    listProperties: ['subject', 'audience', 'template', 'status', 'sentCount', 'createdAt'],
                    showProperties: ['subject', 'template', 'audience', 'content', 'callToActionText', 'callToActionUrl', 'status', 'sentCount', 'createdAt'],
                    editProperties: ['subject', 'template', 'audience', 'content', 'callToActionText', 'callToActionUrl', 'status'],
                    properties: {
                        content: { type: 'richtext', description: 'The main body of the email. HTML is supported.' },
                        audience: { description: 'WARNING: Selecting anything other than "test-admin-only" will send emails when status is changed to "sending".' }
                    },
                    actions: {
                        edit: {
                            after: async (response, request, context) => {
                                if (request.method === 'post' && request.payload.status === 'sending' && context.record.params.status === 'draft') {
                                    const { processNewsletterCampaign } = require('../utils/mailer');
                                    processNewsletterCampaign(context.record.params._id);
                                    response.notice = { message: 'Campaign queued for sending.', type: 'success' };
                                }
                                return response;
                            }
                        }
                    }
                }
            },
            {
                resource: AutomatedCampaign,
                options: {
                    navigation: systemNav,
                    listProperties: ['title', 'targetGroup', 'scheduledDate', 'status'],
                    properties: { notificationMessage: { type: 'textarea' } }
                }
            },
            {
                resource: ApiLimit,
                options: {
                    navigation: systemNav,
                    listProperties: ['service', 'metric', 'period', 'limit', 'unit', 'used', 'enabled', 'autoDisabled', 'windowEnd'],
                    editProperties: ['service', 'metric', 'period', 'limit', 'unit', 'resetDay', 'rolling', 'trackingOnly', 'enabled', 'autoDisableOnError', 'autoDisabled'],
                    showProperties: ['service', 'metric', 'period', 'limit', 'unit', 'resetDay', 'rolling', 'trackingOnly', 'used', 'enabled', 'autoDisableOnError', 'autoDisabled', 'disabledReason', 'windowStart', 'windowEnd', 'lastErrorAt', 'updatedAt'],
                    properties: {
                        service: { description: 'Lowercase provider key, for example deepl.' },
                        metric: { description: 'The measured resource, for example requests, emails, or bandwidth.' },
                        period: { description: 'Usage window. Current windows reset automatically in UTC.' },
                        unit: { description: 'Unit displayed for this limit.' },
                        resetDay: { description: 'Monthly reset day, from 1 to 28. Used by providers with a non-first-day billing cycle.' },
                        rolling: { description: 'Informational flag for provider windows that roll continuously.' },
                        trackingOnly: { description: 'Plan-only limit. It is recorded for administration but does not block application requests.' },
                        limit: { description: 'Maximum units for the current window, such as characters.' },
                        enabled: { description: 'Manual master switch for this provider.' },
                        autoDisableOnError: { description: 'Lock requests until the window resets after a provider error.' },
                        used: { isVisible: { list: true, show: true, edit: false, filter: true } },
                        autoDisabled: { description: 'Set false to clear an automatic lock after resolving the provider issue.' },
                        disabledReason: { isVisible: { list: false, show: true, edit: false, filter: false } },
                        windowStart: { isVisible: { list: false, show: true, edit: false, filter: false } },
                        windowEnd: { isVisible: { list: true, show: true, edit: false, filter: true } },
                        lastErrorAt: { isVisible: { list: false, show: true, edit: false, filter: false } }
                    }
                }
            },
            {
                resource: VpnCache,
                options: {
                    navigation: systemNav,
                    listProperties: ['ip', 'isVpn', 'visitCount', 'firstSeenAt', 'lastVisitedAt', 'updatedAt'],
                    editProperties: [],
                    showProperties: [
                        'ip', 'isVpn', 'visitCount', 'firstSeenAt', 'lastVisitedAt', 'createdAt', 'updatedAt',
                        'security.vpn', 'security.proxy', 'security.tor', 'security.relay',
                        'location.city', 'location.region', 'location.country', 'location.continent',
                        'location.region_code', 'location.country_code', 'location.continent_code',
                        'location.latitude', 'location.longitude', 'location.time_zone', 'location.is_in_european_union',
                        'network.network', 'network.autonomous_system_number', 'network.autonomous_system_organization',
                        'rawResponse'
                    ],
                    actions: {
                        new: { isAccessible: false },
                        edit: { isAccessible: false },
                        delete: { isAccessible: false }
                    }
                }
            },
            {
                resource: TranslationCache,
                options: {
                    navigation: systemNav,
                    listProperties: ['originalText', 'targetLanguage', 'translatedText'],
                    showProperties: ['originalText', 'targetLanguage', 'translatedText'],
                    properties: {
                        originalText: { type: 'textarea' },
                        translatedText: { type: 'textarea' }
                    },
                    actions: {
                        new: { isAccessible: false }
                    }
                }
            },
            {
                resource: AIKnowledge,
                options: {
                    navigation: systemNav,
                    listProperties: ['topic', 'keywords', 'isActive', 'updatedAt'],
                    showProperties: ['topic', 'keywords', 'response', 'isActive', 'createdAt', 'updatedAt'],
                    editProperties: ['topic', 'keywords', 'response', 'isActive'],
                    properties: {
                        keywords: { type: 'textarea', description: 'Comma-separated keywords or search triggers.' },
                        response: { type: 'richtext', description: 'Rich-text formatted response provided by the AI assistant.' }
                    }
                }
            }
        ] 
    };
    const adminJs = new AdminJS(adminJsOptions);
    const adminRouter = AdminJSExpress.buildRouter(adminJs);
    
    return adminRouter;
}

module.exports = createAdminRouter;