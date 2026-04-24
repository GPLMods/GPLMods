// config/admin.js
const bcrypt = require('bcryptjs');

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
const DocPage = require('../models/docPage');         // <--- ADD THIS

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

const deleteFromB2Admin = async (fileKey) => {
    if (!fileKey || fileKey === 'external-link') return;
    try {
        await s3ClientAdmin.send(new DeleteObjectCommand({ Bucket: process.env.B2_BUCKET_NAME, Key: fileKey }));
        console.log(`AdminJS deleted ${fileKey} from B2.`);
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

    // Configure AdminJS
    const adminJsOptions = {
        rootPath: '/admin',
        componentLoader: componentLoader, 
        
        defaultTheme: 'dark', 
        availableThemes:[gplModsTheme, light], 
        
        // ✅ FIX 2: Properly pass the env variables into AdminJS
        env: { NODE_ENV: isProduction ? 'production' : 'development' },
        assets: {
            styles: isProduction ? ['/.adminjs/bundle.css'] :[],
            scripts: isProduction ? ['/.adminjs/bundle.js'] :[]
        },
        // --- DASHBOARD CONFIGURATION (DATA FOR CHARTS) ---
        dashboard: { 
            component: Components.Dashboard,
            handler: async () => {
                // --- 1. Define Timeframes ---
                const now = new Date();
                const startOfThisMonth = new Date(now.getFullYear(), now.getMonth(), 1);
                
                // Optional: Compare to last month for growth percentages
                const startOfLastMonth = new Date(now.getFullYear(), now.getMonth() - 1, 1);
                const endOfLastMonth = new Date(now.getFullYear(), now.getMonth(), 0, 23, 59, 59);

                // --- 2. Calculate All-Time Totals ---
                const totalUsers = await User.countDocuments();
                const totalMods = await File.countDocuments({ isLatestVersion: true, status: 'live' });
                
                // Total Downloads (All-Time)
                const totalDownloadsData = await File.aggregate([{ $group: { _id: null, total: { $sum: "$downloads" } } }]);
                const totalDownloads = totalDownloadsData.length > 0 ? totalDownloadsData[0].total : 0;

                // --- 3. Calculate "This Month" Metrics ---
                const newUsersThisMonth = await User.countDocuments({ createdAt: { $gte: startOfThisMonth } });
                const newModsThisMonth = await File.countDocuments({ 
                    createdAt: { $gte: startOfThisMonth }, 
                    isLatestVersion: true, 
                    status: 'live' 
                });

                // To get "New Downloads This Month", we need a separate tracking collection, 
                // but since we only store a single 'downloads' integer right now, we can approximate 
                // by tracking new file uploads vs total files, or just show total downloads for now.
                // A true "downloads this month" requires a separate DownloadHistory model.
                // For now, we will show "New Users" and "New Mods".

                // --- 4. Data for Pie Chart (Platform Distribution) ---
                const modsByPlatform = await File.aggregate([
                    { $match: { isLatestVersion: true, status: 'live' } },
                    { $group: { _id: "$category", count: { $sum: 1 } } }
                ]);

                // --- 5. Data for Line Chart (Last 30 Days of Uploads) ---
                // We expand this from 7 days to 30 days for a better view
                const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
                const uploadsByDay = await File.aggregate([
                    { $match: { createdAt: { $gte: thirtyDaysAgo }, isLatestVersion: true } },
                    { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }, count: { $sum: 1 } } },
                    { $sort: { _id: 1 } }
                ]);

                return {
                    stats: { 
                        totalUsers, 
                        newUsersThisMonth,
                        totalMods, 
                        newModsThisMonth,
                        totalDownloads 
                    },
                    modsByPlatform: modsByPlatform.map(p => ({ name: p._id || 'unknown', value: p.count })),
                    chartData: uploadsByDay
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
                  // USER MANAGEMENT
            {
                resource: User,
                options: {
                    navigation: { icon: 'Users' }, 
                    listProperties: ['profileImageKey', '_id', 'username', 'email', 'role', 'isBanned', 'lastSeen'],
                    showProperties:['profileImageKey', '_id', 'profileImageKey', 'username', 'email', 'role', 'isVerified', 'isBanned', 'banReason', 'createdAt', 'lastSeen', 'bio', 'socialLinks'],
                    editProperties:['username', 'email', 'role', 'isVerified', 'isBanned', 'banReason', 'bio', 'newPassword', 'socialLinks.telegram', 'socialLinks.discord', 'socialLinks.website', 'socialLinks.youtube'],
                    properties: {
                        password: { isVisible: false },
                        newPassword: { type: 'password', label: 'New Password (leave blank to keep unchanged)' },
                        'socialLinks.telegram': { description: 'e.g., https://t.me/yourname' },
                        'socialLinks.discord': { description: 'e.g., https://discord.gg/...' },
                        'socialLinks.website': { description: 'e.g., https://yourwebsite.com' },
                        'socialLinks.youtube': { description: 'e.g., https://youtube.com/...' },
                        // ✅ FIX: Use ImagePreview for avatars
                        profileImageKey: {
                            components: {
                                list: Components.ImagePreview,
                                show: Components.ImagePreview,
                            },
                            // Ensure it's hidden on the edit form if you don't want them editing the raw key manually
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
            
            // FILE (MOD) MANAGEMENT
            {
                 resource: File,
                options: {
                    navigation: { icon: 'FileCode' },
                    // ✅ NEW: Added 'isVariant' to the list view
                    listProperties: ['iconKey', 'name', 'fileSize', 'version', 'isVariant', 'status', 'category'],
                    editProperties: [
                        'name', 'version', 'developer', 'uploader', 'modDescription', 'modFeatures', 'officialDescription', 'importantNote',
                        'whatsNew', 'category', 'status', 'rejectionReason', 'certification', 'isLatestVersion',
                        'showInSitemap', 'virusTotalId', 'virusTotalAnalysisId', 
                        'iconKey', 'screenshotKeys', 'videoUrl',
                        'fileKey', 'fileSize', 'originalFilename', 'externalDownloadUrl', 
                        'isMultiPart', 'downloadParts', 'installationInstructions',
                        // ✅ NEW: Added Variant fields to edit view
                        'isVariant', 'masterFile'
                    ],
                    showProperties: [
                        'iconKey', 'name', 'version', 'developer', 'uploader', 'status', 'rejectionReason',
                        'certification', 'category', 'downloads', 'averageRating', 'showInSitemap', 
                        'externalDownloadUrl', 'fileKey', 'fileSize', 'originalFilename',
                        'virusTotalId', 'virusTotalAnalysisId', 'screenshotKeys', 'videoUrl', 'createdAt', 'updatedAt', 
                        'isMultiPart', 'downloadParts', 'installationInstructions',
                        // ✅ NEW: Added Variant fields to show view
                        'isVariant', 'masterFile'
                    ],
                    properties: {
                        modDescription: { type: 'richtext' },
                        officialDescription: { type: 'richtext' },
                        modFeatures: { type: 'richtext' }, 
                        whatsNew: { type: 'richtext' },
                        importantNote: { type: 'richtext' }, // Ensure the new field is here too
                        externalDownloadUrl: { description: 'Paste direct download link from Google Drive, Dropbox, Mega, etc.' },
                        virusTotalId: { description: 'Paste the FULL VirusTotal URL (https://...) OR just the SHA-256 Hash.' },
                        fileKey: { description: 'The Backblaze B2 file path' },
                        screenshotKeys: { isArray: true, description: 'Paste direct image URLs (https://...).' },
                        rejectionReason: {
                            isVisible: {
                               edit: (record) => record.params.status === 'rejected',
                               list: false, filter: false, show: true
                            }
                        },
                        iconKey: { 
                            description: 'Paste a direct image URL (https://...) OR a Backblaze B2 key.',
                            // ✅ FIX: Use ImagePreview for mod icons
                            components: {
                                list: Components.ImagePreview,
                                show: Components.ImagePreview,
                            }
                        },
                                                isMultiPart: {
                            description: 'Check this box if the file is split into multiple download links.'
                        },
                        downloadParts: {
                            isArray: true,
                            description: 'Add the individual links here (e.g., Part 1, Part 2).'
                        },
                        // Tell AdminJS about the new nested field
                        'downloadParts.partVirusTotalId': {
                            description: 'Paste the FULL VirusTotal URL (https://...) OR just the SHA-256 Hash for THIS SPECIFIC PART.'
                        },
                        // Hide the raw stats from the edit form to keep it clean
                        'downloadParts.partVirusTotalScanDate': { isVisible: { edit: false, show: true, list: false } },
                        'downloadParts.partVirusTotalPositiveCount': { isVisible: { edit: false, show: true, list: false } },
                        'downloadParts.partVirusTotalTotalScans': { isVisible: { edit: false, show: true, list: false } },
                        
                        // ======== NEW: VARIANT LOGIC FOR ADMINJS ========
                        isVariant: {
                            // Make it a visually distinct pill/badge in the list view
                            components: {
                                // ✅ FIX: Use the pre-loaded component from the singleton!
                                list: Components.VariantBadge, 
                            },
                            // Prevent admins from accidentally un-checking it and breaking the DB structure
                            isDisabled: true 
                        },
                        masterFile: {
                            description: 'If this is a Variant, this is the ID of the original Master App it belongs to.',
                            isDisabled: true // Prevent admins from re-assigning a variant to a different master file
                        }
                        // ================================================
                    },
                    actions: {
                        new: { 
                            isAccessible: true,
                            before: async (request) => {
                                // 1. Clean the main VT ID
                                if (request.payload.virusTotalId) {
                                    request.payload.virusTotalId = extractVTId(request.payload.virusTotalId);
                                }
                                
                                // 2. Clean ALL the multi-part VT IDs
                                // AdminJS sends arrays as flat objects: {'downloadParts.0.partVirusTotalId': '...', 'downloadParts.1...': '...'}
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
                                // (Copy the exact same logic from 'new.before' here)
                                if (request.payload.virusTotalId) {
                                    request.payload.virusTotalId = extractVTId(request.payload.virusTotalId);
                                }
                                Object.keys(request.payload).forEach(key => {
                                    if (key.startsWith('downloadParts.') && key.endsWith('.partVirusTotalId')) {
                                        request.payload[key] = extractVTId(request.payload[key]);
                                    }
                                });
                                return request;
                            }
                        },
                                                // --- UPDATED: Admin Delete Mod Action (Deletes from Cloud too) ---
                        delete: { 
                            isAccessible: true,
                            before: async (request, context) => {
                                // 1. We must fetch the record BEFORE it gets deleted to get the keys
                                const recordId = request.params.recordId;
                                const fileToDelete = await File.findById(recordId).populate('olderVersions');
                                
                                if (fileToDelete) {
                                    // 2. Delete main files from B2
                                    await deleteFromB2Admin(fileToDelete.fileKey);
                                    await deleteFromB2Admin(fileToDelete.iconKey);
                                    if (fileToDelete.screenshotKeys) {
                                        for (const key of fileToDelete.screenshotKeys) {
                                            await deleteFromB2Admin(key);
                                        }
                                    }
                                    
                                    // 3. Delete older versions from B2 and DB
                                    if (fileToDelete.olderVersions) {
                                        for (const oldV of fileToDelete.olderVersions) {
                                            await deleteFromB2Admin(oldV.fileKey);
                                            await File.findByIdAndDelete(oldV._id);
                                        }
                                    }
                                    
                                    // 4. Clean up related Reviews and Reports
                                    await Review.deleteMany({ file: recordId });
                                    await Report.updateMany({ file: recordId }, { status: 'resolved' });
                                }
                                
                                // 5. Return the request so AdminJS can proceed with deleting the main DB record
                                return request;
                            }
                        },
                        
                        // ✅ FIX: Update Custom Actions to use the Redirect Component
                        viewOnSite: {
                            actionType: 'record',
                            icon: 'View',
                            component: Components.ActionRedirect, // <--- ADD THIS
                            handler: async (request, response, context) => {
                                // We pass the redirect URL inside the record params so the component can read it
                                const updatedRecord = context.record.toJSON(context.currentAdmin);
                                updatedRecord.params.redirectUrl = `/mods/${context.record.params._id}`;
                                return {
                                    record: updatedRecord,
                                    notice: { message: 'Opening mod page...', type: 'success' }
                                };
                            }
                        },
                        testDownload: {
                            actionType: 'record',
                            icon: 'Download',
                            component: Components.ActionRedirect, // <--- ADD THIS
                            handler: async (request, response, context) => {
                                const updatedRecord = context.record.toJSON(context.currentAdmin);
                                updatedRecord.params.redirectUrl = `/download-file/${context.record.params._id}`;
                                return {
                                    record: updatedRecord,
                                    notice: { message: 'Initiating test download...', type: 'success' }
                                };
                            }
                        },
                        viewVirusTotal: {
                            actionType: 'record',
                            icon: 'Shield',
                            component: Components.ActionRedirect, // <--- ADD THIS
                            handler: async (request, response, context) => {
                                const vtHash = context.record.params.virusTotalId || "";
                                const vtAnalysis = context.record.params.virusTotalAnalysisId || "";
                                let vtUrl = `https://www.virustotal.com/`;
                                if (vtHash.length === 64) vtUrl = `https://www.virustotal.com/gui/file/${vtHash}`;
                                else if (vtAnalysis) vtUrl = `https://www.virustotal.com/gui/file-analysis/${vtAnalysis}`;
                                else if (vtHash) vtUrl = `https://www.virustotal.com/gui/file-analysis/${vtHash}`;
                                
                                const updatedRecord = context.record.toJSON(context.currentAdmin);
                                updatedRecord.params.redirectUrl = vtUrl;
                                
                                return {
                                    record: updatedRecord,
                                    notice: { message: 'Opening VirusTotal report...', type: 'success' }
                                 };
                            }
                        }
                    } 
                } 
            }, 
            // GLOBAL SITE CONTROLS
            {
                resource: SiteState,
                options: {
                    navigation: { icon: 'Settings' },
                    actions: {
                        new: {
                            isAccessible: async () => {
                                const count = await SiteState.countDocuments();
                                return count === 0;
                            }
                        },
                        delete: { isAccessible: false } 
                    },
                    listProperties: ['status', 'targetAudience', 'updatedAt'],
                    editProperties: [
                        'status', 'targetAudience', 'targetUsername', 
                        'maintenanceTitle', 'maintenanceMessage', 
                        'unavailableTitle', 'unavailableMessage'
                    ],
                    properties: {
                        maintenanceMessage: { type: 'textarea' },
                        unavailableMessage: { type: 'textarea' },
                        targetUsername: { description: 'Only required if Target Audience is "specific-user".' }
                    }
                }
            },
                    // ---------------------------------
        // NEWSLETTER & MARKETING
        // ---------------------------------
        {
            resource: Subscriber,
            options: {
                listProperties: ['email', 'isSubscribed', 'source', 'createdAt'],
                // Admins shouldn't really edit subscribers manually, maybe just delete or toggle status
            }
        },
        {
            resource: NewsletterCampaign,
            options: {
                listProperties: ['subject', 'audience', 'template', 'status', 'sentCount', 'createdAt'],
                showProperties: ['subject', 'template', 'audience', 'content', 'callToActionText', 'callToActionUrl', 'status', 'sentCount', 'createdAt'],
                editProperties: ['subject', 'template', 'audience', 'content', 'callToActionText', 'callToActionUrl', 'status'],
                properties: {
                    content: { type: 'richtext', description: 'The main body of the email. HTML is supported.' },
                    audience: { description: 'WARNING: Selecting anything other than "test-admin-only" will send emails when status is changed to "sending".' }
                },
                actions: {
                    // We need a custom hook to actually SEND the emails when the admin changes status to 'sending'
                    edit: {
                        after: async (response, request, context) => {
                            // Check if the admin just updated the status to 'sending'
                            if (request.method === 'post' && request.payload.status === 'sending' && context.record.params.status === 'draft') {
                                
                                // --- TRIGGER THE EMAIL SENDING PROCESS ---
                                // We call a background utility function so AdminJS doesn't hang
                                // waiting for 10,000 emails to send.
                                const { processNewsletterCampaign } = require('../utils/mailer');
                                processNewsletterCampaign(context.record.params._id);
                                
                                // Update the response notice
                                response.notice = {
                                    message: 'Campaign has been queued for sending. It will process in the background.',
                                    type: 'success',
                                };
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
                    navigation: { name: 'Documentation', icon: 'Book' },
                    listProperties: ['name', 'order', 'createdAt'],
                    editProperties:['name', 'order']
                }
            },
            {
                resource: DocPage,
                options: {
                    navigation: { name: 'Documentation', icon: 'Document' },
                    listProperties:['title', 'category', 'order', 'slug'],
                    // Exclude slug from edit so it's generated automatically
                    editProperties:['title', 'category', 'order', 'content'], 
                    showProperties:['title', 'category', 'order', 'slug', 'content', 'createdAt'],
                    properties: {
                        content: { 
                            type: 'richtext' // Essential for writing the docs
                        },
                        category: {
                            // AdminJS will automatically create a dropdown for the reference field
                            isSortable: true
                        }
                    },
                    actions: {
                        new: {
                            // ✅ FIX: Auto-generate the slug before saving a new page
                            before: async (request) => {
                                if (request.payload.title) {
                                    // Use a simple slugify regex
                                    let baseSlug = request.payload.title.toString().toLowerCase()
                                        .replace(/\s+/g, '-')
                                        .replace(/[^\w\-]+/g, '')
                                        .replace(/\-\-+/g, '-')
                                        .replace(/^-+/, '')
                                        .replace(/-+$/, '');
                                    
                                    request.payload.slug = baseSlug;
                                }
                                return request;
                            }
                        },
                                                edit: {
                            // ✅ FIX: Auto-update the slug if the title changes
                            before: async (request) => {
                                if (request.payload.title) {
                                    let baseSlug = request.payload.title.toString().toLowerCase()
                                        .replace(/\s+/g, '-')
                                        .replace(/[^\w\-]+/g, '')
                                        .replace(/\-\-+/g, '-')
                                        .replace(/^-+/, '')
                                        .replace(/-+$/, '');
                                    
                                    request.payload.slug = baseSlug;
                                }
                                return request;
                    }
                }
            }
        }
        },
            // DIRECT USER NOTIFICATIONS
            {
                resource: UserNotification,
                options: {
                    navigation: { icon: 'Bell' },
                    listProperties: ['user', 'title', 'type', 'isRead', 'createdAt'],
                    showProperties: ['user', 'title', 'message', 'type', 'isRead', 'createdAt'],
                    editProperties: ['user', 'title', 'message', 'type'], 
                    properties: { message: { type: 'textarea' } }
                }
            },
            // SUPPORT TICKETS
            {
                resource: SupportTicket,
                options: {
                    navigation: { icon: 'Ticket' },
                    listProperties: ['subject', 'category', 'username', 'status', 'createdAt'],
                    showProperties: ['status', 'category', 'subject', 'message', 'username', 'email', 'adminNotes', 'createdAt', 'updatedAt'],
                    editProperties: ['status', 'adminNotes'], 
                    properties: { message: { type: 'textarea' }, adminNotes: { type: 'textarea' } }
                }
            },
            // AUTOMATED CAMPAIGNS
            {
                resource: AutomatedCampaign,
                options: {
                    navigation: { icon: 'Robot' },
                    listProperties: ['title', 'targetGroup', 'scheduledDate', 'status'],
                    properties: { notificationMessage: { type: 'textarea' } }
                }
            },
            // PARTNERSHIP APPLICATIONS
            {
                resource: DistributorApplication,
                options: {
                    navigation: { icon: 'Handshake' },
                    listProperties: ['organizationName', 'username', 'primaryDistributionPlatform', 'status', 'createdAt'],
                    showProperties:[
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
            // USER REQUESTS
            {
                resource: Request,
                options: {
                    navigation: { icon: 'Target' }, 
                    listProperties:['appName', 'requestType', 'platform', 'username', 'status', 'createdAt'],
                    showProperties:[
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
            // MODERATION RESOURCES
            {
                resource: Review,
                options: {
                    navigation: { icon: 'Star' },
                    listProperties:['username', 'rating', 'comment', 'file', 'createdAt'],
                    actions: { edit: { isAccessible: true }, delete: { isAccessible: true } },
                },
            },
            {
                resource: Report,
                options: {
                    navigation: { icon: 'Flag' },
                    listProperties:['reportedFileName', 'reportingUsername', 'reason', 'status', 'createdAt'],
                    editProperties: ['status'],
                },
            },
            {
                resource: Dmca,
                options: {
                    navigation: { icon: 'ShieldWarning' },
                    listProperties:['fullName', 'infringingUrl', 'status', 'createdAt'],
                    editProperties: ['status'],
                }
            },
            {
                resource: UnbanRequest,
                options: {
                    navigation: { icon: 'Unlock' },
                    listProperties: ['username', 'email', 'status', 'createdAt'],
                    editProperties:['status'],
                }
            },
            // SITE CONTENT RESOURCE
            {
                resource: Announcement,
                options: {
                    navigation: { icon: 'Megaphone' },
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