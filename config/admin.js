// config/admin.js
const bcrypt = require('bcryptjs');
const axios = require('axios');

// 1. IMPORT THE SINGLETON LOADER
// --- ✅ FIX 1: ADD THIS LINE TO IMPORT THE AWS SDK ---
const { S3Client, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const { componentLoader, Components } = require('../components/loader');

// Import all your models
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
const DocCategory = require('../models/docCategory'); // <--- ADD THIS
const DocPage = require('../models/docPage');  // <--- ADD THIS
const Issue = require('../models/issue');     // <--- ADD THIS
const Reply = require('../models/reply');     // <--- ADD THIS
const PointHistory = require('../models/pointHistory');
const TranslationQuota = require('../models/translationQuota');
const IosDns = require('../models/iosDns');
const IosCert = require('../models/iosCert');
    

// --- Helper Function ---
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
// --- NEW: B2 Delete Helper for AdminJS ---
const s3ClientAdmin = new S3Client({
    endpoint: `https://${process.env.B2_ENDPOINT}`,
    region: process.env.B2_REGION,
    credentials: {
        accessKeyId: process.env.B2_ACCESS_KEY_ID,
        secretAccessKey: process.env.B2_SECRET_ACCESS_KEY,
    }
});

// Helper to trigger Cloudflare rebuild
const triggerCloudflareRebuild = async () => {
    try {
        // REPLACE WITH YOUR CLOUDFLARE DEPLOY HOOK URL
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
        
        // ✅ TRIGGER BACKUP DELETE HERE
        // Note: You will need to import deleteFromFTP at the top of admin.js!
        const { deleteFromFTP } = require('../utils/ftpSync');
        deleteFromFTP(fileKey).catch(e => console.error("Admin FTP delete failed", e));
        
    } catch (error) {
        console.error(`AdminJS failed to delete ${fileKey}:`, error.message);
    }
};
// 2. EXPORT AN ASYNC FACTORY FUNCTION
// We must use dynamic imports because AdminJS v7 is ESM only.
async function createAdminRouter() {
    
    // Import ESM modules dynamically
    const AdminJSModule = await import('adminjs');
    const AdminJS = AdminJSModule.default || AdminJSModule;
    
    const AdminJSExpress = await import('@adminjs/express');
    const AdminJSMongoose = await import('@adminjs/mongoose');
    const { dark, light } = await import('@adminjs/themes');

    // Register Adapter
    AdminJS.registerAdapter({
        Database: AdminJSMongoose.Database,
        Resource: AdminJSMongoose.Resource,
    });

    // Define Theme
    const gplModsTheme = {
        ...dark,
        id: 'dark', 
        name: 'GPL Mods Premium',
        overrides: {
            ...dark.overrides, 
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

    // ✅ FIX 1: We define isProduction properly here. 
    // Setting it to 'true' forces AdminJS into production mode.
    const isProduction = true; 
    // --- Define Shared Folders ---
    const marketingNav = { name: 'Marketing', icon: 'Mail' };
    const docsNav = { name: 'Documentation', icon: 'Book' };

    // Configure AdminJS
    const adminJsOptions = {
        rootPath: '/admin',
        componentLoader: componentLoader, 
        
        defaultTheme: 'dark', 
        availableThemes:[gplModsTheme, light], 
        
        // ✅ FIX 2: Properly pass the env variables into AdminJS
        env: { NODE_ENV: isProduction ? 'production' : 'development' },
        assets: {
            styles: isProduction ? ['/.adminjs/bundle.css'] : [],
            scripts: isProduction ? ['/.adminjs/bundle.js', '/js/image-fallback.js'] : [],
        },
        dashboard: { 
            component: Components.Dashboard,
            // --- NEW: REAL-TIME DATA HANDLER ---
            handler: async (request, response, context) => {
                // Get the first day of the current month
                const startOfMonth = new Date();
                startOfMonth.setDate(1);
                startOfMonth.setHours(0, 0, 0, 0);

                // 1. User Stats
                const totalUsers = await User.countDocuments();
                const newUsersThisMonth = await User.countDocuments({ createdAt: { $gte: startOfMonth } });

                // 2. Mod Stats
                const totalMods = await File.countDocuments();
                const newModsThisMonth = await File.countDocuments({ createdAt: { $gte: startOfMonth } });

                // 3. Download Stats
                const downloadAgg = await File.aggregate([{ $group: { _id: null, total: { $sum: "$downloads" } } }]);
                const totalDownloads = downloadAgg.length > 0 ? downloadAgg[0].total : 0;

                // 4. CHART DATA: Mods by Platform (Pie Chart)
                const platformAgg = await File.aggregate([
                    { $group: { _id: "$category", value: { $sum: 1 } } }
                ]);
                const modsByPlatform = platformAgg.map(p => ({
                    name: p._id ? p._id.toUpperCase() : 'UNKNOWN',
                    value: p.value
                }));

                // 5. CHART DATA: Uploads Last 7 Days (Line Chart)
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

                // Return all this data to the React frontend
                return {
                    stats: { totalUsers, newUsersThisMonth, totalMods, newModsThisMonth, totalDownloads },
                    modsByPlatform,
                    uploadChartData
                };
            }
        },
        
        branding: {
            companyName: 'GPL Mods',
            logo: '/images/logo.png', 
            softwareBrothers: false,
            withMadeWithLove: false, 
        },

                resources:[
            // ---------------------------------
            // USER MANAGEMENT
            // ---------------------------------
            {
                resource: User,
                options: {
                    navigation: { icon: 'User' }, // ✅ Valid Carbon Icon
                    listProperties:['profileImageKey', '_id', 'username', 'dateOfBirth', 'forumPoints', 'email', 'role', 'isVerifiedAccount', 'isBanned', 'lastSeen'],
                    showProperties:['_id', 'username', 'email', 'role', 'isVerified', 'isBanned', 'banReason', 'createdAt', 'lastSeen', 'bio', 'isVerifiedAccount', 'verifiedBadgeText', 'country', 'socialLinks.telegram', 'socialLinks.discord', 'socialLinks.website', 'socialLinks.youtube'],
                    editProperties:['username', 'dateOfBirth', 'forumPoints', 'email', 'role', 'isVerified', 'isBanned', 'banReason', 'bio', 'isVerifiedAccount', 'verifiedBadgeText', 'country', 'newPassword', 'socialLinks.telegram', 'socialLinks.discord', 'socialLinks.website', 'socialLinks.youtube'],
                    properties: {
                        password: { isVisible: false },
                        newPassword: { type: 'password', label: 'New Password (leave blank to keep unchanged)' },
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
                        new: { isAccessible: true },
                        edit: { 
                            isAccessible: true,
                            before: async (request) => {
                                const { newPassword, ...payload } = request.payload;
                                if (newPassword && newPassword.length > 0) {
                                    payload.password = await bcrypt.hash(newPassword, 10);
                                }
                                request.payload = payload;
                                return request;
                            }
                        },
                        delete: { isAccessible: true }
                    }
                }
            },
        // ---------------------------------
        // GAMIFICATION & POINT HISTORY
        // ---------------------------------
        {
            resource: PointHistory,
            options: {
                listProperties: ['user', 'amount', 'reason', 'createdAt'],
                showProperties: ['user', 'amount', 'reason', 'customMessage', 'createdAt'],
                editProperties: ['user', 'amount', 'reason', 'customMessage'],
                properties: {
                    customMessage: { type: 'richtext', description: 'Optional message to the user explaining why they got/lost these points.' },
                    amount: { description: 'Use positive numbers to add points (e.g., 50) and negative to deduct (e.g., -10).' }
                },
                actions: {
                    new: {
                        // When an admin creates a manual point record, physically update the user's total balance
                        after: async (response, request, context) => {
                            if (request.method === 'post' && response.record && !Object.keys(response.record.errors || {}).length) {
                                const amount = Number(response.record.params.amount);
                                const userId = response.record.params.user;
                                // Find the user and apply the math
                                const User = require('../models/user');
                                await User.findByIdAndUpdate(userId, { $inc: { forumPoints: amount } });
                            }
                            return response;
                        }
                    },
                    edit: { isAccessible: false }, // Prevent editing history to maintain ledger integrity
                    delete: { isAccessible: false } 
                }
            }
        },
            
            // ---------------------------------
            // FILE (MOD) MANAGEMENT
            // ---------------------------------
            {
                resource: File,
                options: {
                    navigation: { icon: 'File' }, // ✅ Valid Carbon Icon
                    listProperties:['iconKey', 'name', 'ageRating', 'fileSize', 'version', 'isVariant', 'status', 'showInRepo', 'category'],
                    editProperties:[
                        'name', 'version', 'ageRating', 'developer', 'uploader', 'modDescription', 'modFeatures', 'officialDescription', 'importantNote',
                        'whatsNew', 'category', 'status', 'rejectionReason', 'certification', 'isLatestVersion', 'iosPackageId',
                        'showInSitemap', 'virusTotalId', 'virusTotalAnalysisId', 'architectures', 'minOsVersion', 
                        'iconKey', 'screenshotKeys', 'videoUrl',  'manualFileScanUrl', 'manualSiteScanUrl', 'isEditorsChoice', 'editorsChoiceDescription',
                        'fileKey', 'fileSize', 'originalFilename', 'externalDownloadUrl', 'alternativeLinks', 'customAdLink',
                        'isMultiPart', 'downloadParts', 'installationInstructions','directDownloadUrl',
                        'isVariant', 'showInRepo', 'masterFile'
                    ],
                    showProperties:[
                        'iconKey', 'name', 'version', 'ageRating', 'developer', 'uploader', 'status', 'rejectionReason',
                        'certification', 'category', 'downloads', 'averageRating', 'showInSitemap', 'isEditorsChoice', 'editorsChoiceDescription',
                        'externalDownloadUrl', 'fileKey', 'fileSize', 'originalFilename', 'customAdLink',  'manualFileScanUrl', 'manualSiteScanUrl',
                        'virusTotalId', 'virusTotalAnalysisId', 'screenshotKeys', 'videoUrl', 'createdAt', 'updatedAt', 'architectures', 'minOsVersion',  
                        'isMultiPart', 'downloadParts', 'installationInstructions', 'alternativeLinks', 'directDownloadUrl', 'iosPackageId',
                        'isVariant', 'showInRepo', 'masterFile'
                    ],
                    properties: {
                        modDescription: { type: 'richtext' },
                        officialDescription: { type: 'richtext' },
                        modFeatures: { type: 'richtext' }, 
                        whatsNew: { type: 'richtext' },
                        importantNote: { type: 'richtext' }, 
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
                        screenshotKeys: { isArray: true, description: 'Paste direct image URLs (https://...).' },
                        rejectionReason: {
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
                    // ======== NEW: ADMIN VOTE MANAGEMENT ========
                    manageVotes: {
                        actionType: 'record',
                        icon: 'ThumbsUp',
                        // We use a custom component for the UI of this action
                        component: Components.ManageVotes, 
                        handler: async (request, response, context) => {
                            const file = context.record;
                            
                            // If the request method is POST, it means the admin submitted the form
                            if (request.method === 'post') {
                                const { actionType, newWorkingCount, newNotWorkingCount } = request.payload;

                                try {
                                    if (actionType === 'reset') {
                                        // Reset everything to 0
                                        await File.findByIdAndUpdate(file.params._id, {
                                            workingVoteCount: 0,
                                            notWorkingVoteCount: 0,
                                            votedWorkingBy: [],
                                            votedNotWorkingBy:[]
                                        });
                                        return {
                                            record: file.toJSON(context.currentAdmin),
                                            notice: { message: 'All votes have been successfully reset to 0.', type: 'success' },
                                            redirectUrl: context.h.resourceActionUrl({ resourceId: 'File', actionName: 'list' })
                                        };
                                    } 
                                    else if (actionType === 'override') {
                                        // Manually set the counts (Warning: this doesn't populate the user arrays, 
                                        // it just forces the numbers. It's best used after a reset).
                                        await File.findByIdAndUpdate(file.params._id, {
                                            workingVoteCount: parseInt(newWorkingCount, 10) || 0,
                                            notWorkingVoteCount: parseInt(newNotWorkingCount, 10) || 0,
                                            votedWorkingBy:[], // Clear arrays to prevent sync issues when manually overriding numbers
                                            votedNotWorkingBy:[]
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
                            
                            // If GET request, just render the component
                            return {
                                record: file.toJSON(context.currentAdmin)
                            };
                        }
                    }
                    // ============================================

                } // End of actions object
            } // End of options object
            }, // End of File resource
            // ---------------------------------
            // COMMUNITY FORUM
            // ---------------------------------
            {
                resource: Issue,
                options: {
                    listProperties: ['title', 'category', 'status', 'author', 'createdAt'],
                    showProperties: ['title', 'slug', 'category', 'status', 'views', 'author', 'content', 'createdAt'],
                    editProperties: ['title', 'slug', 'category', 'status', 'content'],
                    properties: {
                        content: { type: 'richtext' } // AdminJS will render a rich text editor for this
                    }
                }
            },
            {
                resource: Reply,
                options: {
                    listProperties: ['issue', 'author', 'isSolution', 'isAdminReply', 'createdAt'],
                    editProperties: ['content', 'isSolution', 'isAdminReply'],
                    properties: {
                        content: { type: 'richtext' }
                    }
                }
            },

            // ---------------------------------
            // GLOBAL SITE CONTROLS
            // ---------------------------------
            {
                resource: SiteState,
                options: {
                    navigation: { icon: 'Server' }, // ✅ Valid Carbon Icon
                    actions: {
                        new: { isAccessible: async () => { const count = await SiteState.countDocuments(); return count === 0; } },
                        delete: { isAccessible: false } 
                    },
                    listProperties:['status', 'targetAudience', 'enableLinkvertise', 'enableAutomationEngine', 'updatedAt'],
                    editProperties:[
                        'status', 'targetAudience', 'targetUsername', 'enableAutomationEngine',
                        'maintenanceTitle', 'maintenanceMessage', 
                        'unavailableTitle', 'unavailableMessage', 'enableLinkvertise', 'linkvertiseId', 'adNetworkBaseUrl',
                    ],
                    properties: {
                        maintenanceMessage: { type: 'richtext' },
                        unavailableMessage: { type: 'richtext' },
                        targetUsername: { description: 'Only required if Target Audience is "specific-user".' },
                        adNetworkBaseUrl: { description: 'Use {{ID}} for your Account ID and {{URL}} for the Base64 encoded target link.' }
                    }
                }
            },
        {
            resource: TranslationQuota,
            options: {
                listProperties: ['monthYear', 'characterCount', 'updatedAt'],
                actions: {
                    new: { isAccessible: false }, // System handles creation
                    delete: { isAccessible: false }
                }
            }
        },

            // ---------------------------------
            // NEWSLETTER & MARKETING
            // ---------------------------------
            {
                resource: Subscriber,
                options: {
                    navigation: marketingNav, // ✅ Groups into "Marketing" folder with Email icon
                    listProperties: ['email', 'isSubscribed', 'source', 'createdAt'],
                }
            },
            {
                resource: NewsletterCampaign,
                options: {
                    navigation: marketingNav, // ✅ Groups into "Marketing" folder with Email icon
                    listProperties:['subject', 'audience', 'template', 'status', 'sentCount', 'createdAt'],
                    showProperties:['subject', 'template', 'audience', 'content', 'callToActionText', 'callToActionUrl', 'status', 'sentCount', 'createdAt'],
                    editProperties:['subject', 'template', 'audience', 'content', 'callToActionText', 'callToActionUrl', 'status'],
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

            // ---------------------------------
            // DOCUMENTATION (CUSTOM WIKI)
            // ---------------------------------
            {
                resource: DocCategory,
                options: {
                    navigation: docsNav, // ✅ Groups into "Documentation" folder with Catalog icon
                    listProperties: ['name', 'order', 'createdAt'],
                    editProperties:['name', 'order']
                }
            },
            {
                resource: DocPage,
                options: {
                    navigation: docsNav, // ✅ Groups into "Documentation" folder with Catalog icon
                    listProperties:['title', 'category', 'order', 'slug'],
                    editProperties:['title', 'category', 'order', 'featuredImageKey', 'content'], 
                    showProperties:['title', 'category', 'order', 'slug', 'featuredImageKey', 'content', 'createdAt'],
                    properties: {
                        content: { type: 'richtext' },
                        featuredImageKey: {description: 'Optional: Paste a direct image URL (https://...) or B2 Key for the cover image.'},
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

            // ---------------------------------
            // DIRECT USER NOTIFICATIONS
            // ---------------------------------
            {
                resource: UserNotification,
                options: {
                    navigation: { icon: 'Bell' }, // ✅ Valid Carbon Icon
                    listProperties:['user', 'title', 'type', 'isRead', 'createdAt'],
                    showProperties:['user', 'title', 'message', 'type', 'isRead', 'createdAt'],
                    editProperties:['user', 'title', 'message', 'type'], 
                    properties: { message: { type: 'textarea' } }
                }
            },

            // ---------------------------------
            // SUPPORT TICKETS
            // ---------------------------------
            {
                resource: SupportTicket,
                options: {
                    navigation: { icon: 'Info' }, // ✅ Valid Carbon Icon
                    listProperties: ['subject', 'category', 'username', 'status', 'createdAt'],
                    showProperties:['status', 'category', 'subject', 'message', 'username', 'email', 'adminNotes', 'createdAt', 'updatedAt'],
                    editProperties: ['status', 'adminNotes'], 
                    properties: { message: { type: 'textarea' }, adminNotes: { type: 'textarea' } }
                }
            },

            // ---------------------------------
            // AUTOMATED CAMPAIGNS
            // ---------------------------------
            {
                resource: AutomatedCampaign,
                options: {
                    navigation: { icon: 'Settings' }, // ✅ Valid Carbon Icon
                    listProperties:['title', 'targetGroup', 'scheduledDate', 'status'],
                    properties: { notificationMessage: { type: 'textarea' } }
                }
            },

            // ---------------------------------
            // PARTNERSHIP APPLICATIONS
            // ---------------------------------
            {
                resource: DistributorApplication,
                options: {
                    navigation: { icon: 'Users' }, // ✅ Valid Carbon Icon
                    listProperties:['organizationName', 'username', 'primaryDistributionPlatform', 'status', 'createdAt'],
                    showProperties:[
                        'status', 'organizationName', 'username', 'email', 
                        'primaryDistributionPlatform', 'platformUrl', 'monetizationMethod',
                        'adminContactName', 'adminSocialLink', 
                        'socialTelegram', 'socialDiscord', 'socialWebsite', 'socialYoutube',
                        'adminNotes', 'createdAt'
                    ],
                    editProperties:['status', 'adminNotes'],
                    properties: { adminNotes: { type: 'textarea' } }
                }
            },

            // ---------------------------------
            // USER REQUESTS
            // ---------------------------------
            {
                resource: Request,
                options: {
                    navigation: { icon: 'UserPlus' }, // ✅ Valid Carbon Icon
                    listProperties:['appName', 'requestType', 'platform', 'username', 'status', 'createdAt'],
                    showProperties:[
                        'requestType', 'appName', 'platform', 'requestedVersion', 
                        'officialLink', 'existingModLink', 'modFeaturesRequested', 
                        'additionalNotes', 'username', 'status', 'adminNotes', 'createdAt'
                    ],
                    editProperties:['status', 'adminNotes'], 
                    properties: {
                        modFeaturesRequested: { type: 'textarea' },
                        additionalNotes: { type: 'textarea' },
                        adminNotes: { type: 'textarea' }
                    }
                }
            },

            // ---------------------------------
            // MODERATION RESOURCES
            // ---------------------------------
            {
                resource: Review,
                options: {
                    navigation: { icon: 'Star' }, // ✅ Valid Carbon Icon
                    listProperties:['username', 'rating', 'comment', 'file', 'createdAt'],
                    actions: { edit: { isAccessible: true }, delete: { isAccessible: true } },
                },
            },
            {
                resource: Report,
                options: {
                    navigation: { icon: 'ShieldOff' }, // ✅ Valid Carbon Icon
                    listProperties:['reportedFileName', 'reportingUsername', 'reason', 'status', 'createdAt'],
                    editProperties: ['status'],
                },
            },
            {
                resource: Dmca,
                options: {
                    navigation: { icon: 'Slash' }, // ✅ Valid Carbon Icon
                    listProperties:['fullName', 'infringingUrl', 'status', 'createdAt'],
                    editProperties: ['status'],
                }
            },
            {
                resource: UnbanRequest,
                options: {
                    navigation: { icon: 'UserX' }, // ✅ Valid Carbon Icon
                    listProperties: ['username', 'email', 'status', 'createdAt'],
                    editProperties:['status'],
                }
            },

          {
            resource: IosCert,
            options: {
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

            // ---------------------------------
            // SITE CONTENT RESOURCE
            // ---------------------------------
            {
                resource: Announcement,
                options: {
                    navigation: { icon: 'MessageSquare' }, // ✅ Valid Carbon Icon
                    listProperties: ['title', 'author', 'createdAt'],
                    editProperties: ['title', 'author', 'content'],
                    properties: { content: { type: 'richtext' } },
                },
            }
        ] 
    };
    const adminJs = new AdminJS(adminJsOptions);
    
    // In v7+, buildRouter expects the AdminJS instance. 
    // We don't need to pass a pre-configured router if we aren't using custom auth middleware *inside* AdminJS.
    // Since you use ensureAuthenticated from Express, this standard buildRouter is perfect.
    const adminRouter = AdminJSExpress.buildRouter(adminJs);
    
    return adminRouter;
}

module.exports = createAdminRouter;