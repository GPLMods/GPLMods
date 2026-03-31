const bcrypt = require('bcryptjs');

// ==========================================
// 1. IMPORT ALL MONGOOSE MODELS
// ==========================================
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

// ==========================================
// 2. HELPER FUNCTIONS
// ==========================================

/**
 * Extracts the raw ID/Hash from a full VirusTotal URL.
 */
function extractVTId(input) {
    if (!input) return "";
    let cleanInput = input.trim();
    
    // If it's a full URL, try to extract the ID/Hash
    if (cleanInput.startsWith('http://') || cleanInput.startsWith('https://')) {
        try {
            const urlObj = new URL(cleanInput);
            const pathParts = urlObj.pathname.split('/').filter(p => p !== '');
            
            // VT URLs usually look like: /gui/file/<HASH> or /gui/file-analysis/<ID>
            if (pathParts.length >= 2) {
                // The ID is almost always the last part of the path
                return pathParts[pathParts.length - 1]; 
            }
        } catch (e) {
            console.error("Invalid VT URL provided to AdminJS:", e);
        }
    }
    // If it's not a URL, or extraction failed, return what they typed
    return cleanInput;
}

/**
 * Constructs a fully qualified public URL for a Backblaze B2 key.
 * This assumes your bucket is public and uses the S3-compatible API.
 */
function getPublicB2Url(key) {
    if (!key) return '';
    // If it's already a full URL (like an external link or Google avatar), return it
    if (key.startsWith('http://') || key.startsWith('https://')) return key;
    
    // Clean up the endpoint string (remove https:// if present)
    let endpoint = process.env.B2_ENDPOINT || 's3.us-west-004.backblazeb2.com';
    endpoint = endpoint.replace('https://', '').replace('http://', '');
    
    const bucket = process.env.B2_BUCKET_NAME || 'gpl-cloud';
    
    // Standard public S3/B2 URL format: https://bucketname.endpoint/key
    return `https://${bucket}.${endpoint}/${key}`;
}

// ==========================================
// 3. MAIN ROUTER GENERATOR
// ==========================================
async function createAdminRouter() {
    
    // --- DYNAMICALLY IMPORT ESM PACKAGES ---
    const AdminJSModule = await import('adminjs');
    const AdminJS = AdminJSModule.default || AdminJSModule;
    const { ComponentLoader } = AdminJSModule; 

    const AdminJSExpress = await import('@adminjs/express');
    const AdminJSMongoose = await import('@adminjs/mongoose');
    const { dark, light } = await import('@adminjs/themes');

    // --- REGISTER MONGOOSE ADAPTER ---
    AdminJS.registerAdapter({
        Database: AdminJSMongoose.Database,
        Resource: AdminJSMongoose.Resource,
    });

    // --- SETUP CUSTOM REACT COMPONENTS ---
    const componentLoader = new ComponentLoader();
    const Components = {
        Dashboard: componentLoader.add('Dashboard', '../components/dashboard.jsx'),
        SidebarBranding: componentLoader.override('SidebarBranding', '../components/SidebarBranding.jsx')
    };

    // --- DEFINE CUSTOM THEME (GPL Mods Premium) ---
    const gplModsTheme = {
        ...dark,
        id: 'dark', // CRITICAL: Keep ID 'dark' so AdminJS finds the base CSS/JS bundle
        name: 'GPL Mods Premium',
        overrides: {
            ...dark.overrides, 
            colors: {
                ...dark.overrides?.colors, 
                primary100: '#FFD700', // Gold
                primary80: '#e5c200',  
                primary60: '#ccad00',  
                primary40: '#b29700',  
                primary20: '#332b00',  
                bg: '#0a0a0a',         // Black
                container: '#1a1a1a',  // Dark Gray
                white: '#1a1a1a',      
                text: '#ffffff',       // White
                grey100: '#ffffff',    
                grey80: '#c0c0c0',     // Silver
                grey60: '#a0a0a0',     
                grey40: '#444444',     
                grey20: '#2a2a2a',     
                border: '#333333',     
                errorLight: '#ffadad',
                error: '#e53935',      // Red
                errorDark: '#b71c1c',
                successLight: '#b0ffb0',
                success: '#43a047',    // Green
                successDark: '#1b5e20',
                infoLight: '#90caf9',
                info: '#2196F3',       // Blue
                infoDark: '#0d47a1',
            }
        }
    };

    // ==========================================
    // 4. DEFINE ADMINJS OPTIONS & RESOURCES
    // ==========================================
    const adminJsOptions = {
        rootPath: '/admin',
        componentLoader, 
        defaultTheme: 'dark', // Force our modified dark theme
        availableThemes: [gplModsTheme, light], 
        env: process.env.NODE_ENV || 'development', // Crucial for skipping bundler on Render
        
        // --- DASHBOARD CONFIGURATION ---
        dashboard: { 
            component: Components.Dashboard,
            // Handler to fetch data for the custom React dashboard charts
            handler: async (request, response, context) => {
                const totalUsers = await User.countDocuments();
                const totalMods = await File.countDocuments({ isLatestVersion: true });
                const totalDownloadsData = await File.aggregate([{ $group: { _id: null, total: { $sum: "$downloads" } } }]);
                const totalDownloads = totalDownloadsData.length > 0 ? totalDownloadsData[0].total : 0;
                
                const modsByPlatform = await File.aggregate([
                    { $match: { isLatestVersion: true } },
                    { $group: { _id: "$category", count: { $sum: 1 } } }
                ]);

                // Aggregate uploads per day for the last 7 days
                const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
                const uploadsByDay = await File.aggregate([
                    { $match: { createdAt: { $gte: sevenDaysAgo } } },
                    { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }, count: { $sum: 1 } } },
                    { $sort: { _id: 1 } }
                ]);

                return {
                    stats: { totalUsers, totalMods, totalDownloads },
                    modsByPlatform: modsByPlatform.map(p => ({ name: p._id, value: p.count })),
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

        // --- RESOURCE CONFIGURATIONS ---
        resources: [
            // ---------------------------------
            // USER MANAGEMENT
            // ---------------------------------
            {
                resource: User,
                options: {
                    navigation: { icon: 'Users' }, 
                    listProperties: ['profileImageKey', 'username', 'email', 'role', 'isBanned', 'lastSeen'],
                    showProperties:['_id', 'profileImageKey', 'username', 'email', 'role', 'isVerified', 'isBanned', 'banReason', 'createdAt', 'lastSeen', 'bio'],
                    editProperties:['username', 'email', 'role', 'isVerified', 'isBanned', 'banReason', 'bio', 'newPassword'],
                    properties: {
                        password: { isVisible: false },
                        newPassword: { type: 'password', label: 'New Password (leave blank to keep unchanged)' },
                        // We use a custom object here so we can render raw HTML in the 'after' hook
                        profileImageKey: {
                            components: {
                                list: AdminJSModule.ComponentLoader.defaultComponents.Text,
                                show: AdminJSModule.ComponentLoader.defaultComponents.Text
                            },
                            custom: { isHtml: true } 
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
                        delete: { isAccessible: true },
                        
                        // --- HOOKS TO RENDER HTML IMAGES IN LIST/SHOW VIEWS ---
                        list: {
                            after: async (response) => {
                                if (response.records) {
                                    response.records.forEach(record => {
                                        const key = record.params.profileImageKey;
                                        if (key) {
                                            const url = getPublicB2Url(key);
                                            record.params.profileImageKey = `<img src="${url}" style="width: 40px; height: 40px; border-radius: 50%; object-fit: cover; border: 1px solid #FFD700;" alt="Avatar" />`;
                                        } else {
                                            record.params.profileImageKey = `<div style="width: 40px; height: 40px; border-radius: 50%; background: #333; display: flex; align-items: center; justify-content: center; color: #888; font-size: 10px;">N/A</div>`;
                                        }
                                    });
                                }
                                return response;
                            }
                        },
                        show: {
                            after: async (response) => {
                                if (response.record && response.record.params.profileImageKey) {
                                    const url = getPublicB2Url(response.record.params.profileImageKey);
                                    response.record.params.profileImageKey = `<img src="${url}" style="width: 150px; height: 150px; border-radius: 50%; object-fit: cover; border: 3px solid #FFD700;" alt="Avatar" />`;
                                }
                                return response;
                            }
                        }
                    }
                }
            },
            
            // ---------------------------------
            // FILE (MOD) MANAGEMENT
            // ---------------------------------
            {
                resource: File,
                options: {
                    navigation: { icon: 'FileCode' },
                    listProperties:['iconKey', 'name', 'fileSize', 'version', 'isMultiPart', 'status', 'category'],
                    editProperties:[
                        'name', 'version', 'developer', 'uploader', 'modDescription', 'modFeatures', 'officialDescription',
                        'whatsNew', 'category', 'status', 'rejectionReason', 'certification', 'isLatestVersion',
                        'showInSitemap', 'virusTotalId', 'virusTotalAnalysisId', 'iconKey', 'screenshotKeys',
                        'fileKey', 'fileSize', 'originalFilename', 'externalDownloadUrl', 
                        'isMultiPart', 'downloadParts', 'installationInstructions' 
                    ],
                    showProperties:[
                        'iconKey', 'name', 'version', 'developer', 'uploader', 'status', 'rejectionReason',
                        'certification', 'category', 'downloads', 'averageRating', 'showInSitemap', 
                        'externalDownloadUrl', 'fileKey', 'fileSize', 'originalFilename',
                        'virusTotalId', 'virusTotalAnalysisId', 'screenshotKeys', 'createdAt', 'updatedAt', 
                        'isMultiPart', 'downloadParts', 'installationInstructions'
                    ],
                    properties: {
                        modDescription: { type: 'richtext' },
                        officialDescription: { type: 'richtext' },
                        modFeatures: { type: 'textarea' }, 
                        whatsNew: { type: 'textarea' },
                        externalDownloadUrl: { description: 'Paste direct download link from Google Drive, Dropbox, Mega, etc.' },
                        virusTotalId: { description: 'Paste the FULL VirusTotal URL (https://...) OR just the SHA-256 Hash.' },
                        fileKey: { description: 'The Backblaze B2 file path' },
                        iconKey: { 
                            description: 'Paste a direct image URL (https://...) OR a Backblaze B2 key.',
                            custom: { isHtml: true } // Crucial for HTML rendering
                        },
                        screenshotKeys: { isArray: true, description: 'Paste direct image URLs (https://...).' },
                        rejectionReason: {
                            isVisible: {
                               edit: (record) => record.params.status === 'rejected',
                               list: false, filter: false, show: true
                            }
                        },
                        isMultiPart: { description: 'Check this box if the file is split into multiple download links.' },
                        downloadParts: { isArray: true, description: 'Add the individual links here.' },
                        installationInstructions: { type: 'richtext', description: 'Instructions for extracting.' }
                    },
                    actions: {
                        new: { 
                            isAccessible: true,
                            before: async (request) => {
                                // Smart VT Link Extraction
                                if (request.payload.virusTotalId) {
                                    request.payload.virusTotalId = extractVTId(request.payload.virusTotalId);
                                }
                                return request;
                            }
                        },
                        edit: { 
                            isAccessible: true,
                            before: async (request) => {
                                // Smart VT Link Extraction
                                if (request.payload.virusTotalId) {
                                    request.payload.virusTotalId = extractVTId(request.payload.virusTotalId);
                                }
                                return request;
                            }
                        },
                        delete: { isAccessible: true },
                        
                        // --- HOOKS TO RENDER HTML IMAGES IN LIST/SHOW VIEWS ---
                        list: {
                            after: async (response) => {
                                if (response.records) {
                                    response.records.forEach(record => {
                                        const key = record.params.iconKey || record.params.iconUrl;
                                        if (key) {
                                            const url = getPublicB2Url(key);
                                            record.params.iconKey = `<img src="${url}" style="width: 50px; height: 50px; border-radius: 8px; object-fit: contain; background: #1a1a1a; padding: 2px; border: 1px solid #333;" alt="Icon" />`;
                                        } else {
                                            record.params.iconKey = `<div style="width: 50px; height: 50px; border-radius: 8px; background: #333; display: flex; align-items: center; justify-content: center; color: #888; font-size: 10px;">N/A</div>`;
                                        }
                                    });
                                }
                                return response;
                            }
                        },
                        show: {
                            after: async (response) => {
                                if (response.record && (response.record.params.iconKey || response.record.params.iconUrl)) {
                                    const url = getPublicB2Url(response.record.params.iconKey || response.record.params.iconUrl);
                                    response.record.params.iconKey = `<img src="${url}" style="max-width: 200px; max-height: 200px; border-radius: 12px; object-fit: contain; background: #1a1a1a; padding: 10px; border: 1px solid #333;" alt="Icon" />`;
                                }
                                return response;
                            }
                        },

                        // --- CUSTOM ACTIONS ---
                        viewOnSite: {
                            actionType: 'record',
                            icon: 'View',
                            handler: async (request, response, context) => {
                                return {
                                    record: context.record.toJSON(context.currentAdmin),
                                    notice: { message: 'Opening mod page...', type: 'success' },
                                    redirectUrl: `/mods/${context.record.params._id}`
                                };
                            }
                        },
                        testDownload: {
                            actionType: 'record',
                            icon: 'Download',
                            handler: async (request, response, context) => {
                                return {
                                    record: context.record.toJSON(context.currentAdmin),
                                    notice: { message: 'Initiating test download...', type: 'success' },
                                    redirectUrl: `/download-file/${context.record.params._id}`
                                };
                            }
                        },
                        viewVirusTotal: {
                            actionType: 'record',
                            icon: 'Shield',
                            handler: async (request, response, context) => {
                                const vtHash = context.record.params.virusTotalId || "";
                                const vtAnalysis = context.record.params.virusTotalAnalysisId || "";
                                let vtUrl = `https://www.virustotal.com/`;
                                if (vtHash.length === 64) {
                                    vtUrl = `https://www.virustotal.com/gui/file/${vtHash}`;
                                } else if (vtAnalysis) {
                                    vtUrl = `https://www.virustotal.com/gui/file-analysis/${vtAnalysis}`;
                                } else if (vtHash) {
                                    vtUrl = `https://www.virustotal.com/gui/file-analysis/${vtHash}`;
                                }
                                return {
                                    record: context.record.toJSON(context.currentAdmin),
                                    notice: { message: 'Opening VirusTotal report...', type: 'success' },
                                    redirectUrl: vtUrl
                                 };
                            }
                        }
                    } 
                } 
            }, 

            // ---------------------------------
            // GLOBAL SITE CONTROLS
            // ---------------------------------
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
            // DIRECT USER NOTIFICATIONS
            // ---------------------------------
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

            // ---------------------------------
            // SUPPORT TICKETS
            // ---------------------------------
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

            // ---------------------------------
            // AUTOMATED CAMPAIGNS
            // ---------------------------------
            {
                resource: AutomatedCampaign,
                options: {
                    navigation: { icon: 'Robot' },
                    listProperties: ['title', 'targetGroup', 'scheduledDate', 'status'],
                    properties: { notificationMessage: { type: 'textarea' } }
                }
            },

            // ---------------------------------
            // PARTNERSHIP APPLICATIONS
            // ---------------------------------
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

            // ---------------------------------
            // USER REQUESTS (MODS/UPDATES)
            // ---------------------------------
            {
                resource: Request,
                options: {
                    navigation: { icon: 'Target' }, // Better icon for requests
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

            // ---------------------------------
            // MODERATION RESOURCES
            // ---------------------------------
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

            // ---------------------------------
            // SITE CONTENT RESOURCE
            // ---------------------------------
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
    const adminRouter = AdminJSExpress.buildRouter(adminJs);
    return adminRouter;
}

module.exports = createAdminRouter;