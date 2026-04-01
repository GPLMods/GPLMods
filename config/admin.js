const bcrypt = require('bcryptjs');

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

function extractVTId(input) {
    if (!input) return "";
    let cleanInput = input.trim();
    if (cleanInput.startsWith('http://') || cleanInput.startsWith('https://')) {
        try {
            const urlObj = new URL(cleanInput);
            const pathParts = urlObj.pathname.split('/').filter(p => p !== '');
            if (pathParts.length >= 2) return pathParts[pathParts.length - 1]; 
        } catch (e) {}
    }
    return cleanInput;
}

async function createAdminRouter() {
    const AdminJSModule = await import('adminjs');
    const AdminJS = AdminJSModule.default || AdminJSModule;
    const { ComponentLoader } = AdminJSModule; 

    const AdminJSExpress = await import('@adminjs/express');
    const AdminJSMongoose = await import('@adminjs/mongoose');
    const { dark, light } = await import('@adminjs/themes');

    AdminJS.registerAdapter({
        Database: AdminJSMongoose.Database,
        Resource: AdminJSMongoose.Resource,
    });

    const componentLoader = new ComponentLoader();
    
    // --- LOAD ALL CUSTOM COMPONENTS HERE ---
    const Components = {
        Dashboard: componentLoader.add('Dashboard', '../components/dashboard.jsx'),
        SidebarBranding: componentLoader.override('SidebarBranding', '../components/SidebarBranding.jsx'),
        ImagePreview: componentLoader.add('ImagePreview', '../components/ImagePreview.jsx'),
        ActionRedirect: componentLoader.add('ActionRedirect', '../components/ActionRedirect.jsx') // <-- ADDED
    };

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

    const adminJsOptions = {
        rootPath: '/admin',
        componentLoader, 
        defaultTheme: 'dark', 
        availableThemes: [gplModsTheme, light], 
        env: {
            NODE_ENV: process.env.NODE_ENV || 'development'
        }, 
        
        // --- DASHBOARD CONFIGURATION (DATA FOR CHARTS) ---
        dashboard: { 
            component: Components.Dashboard,
            handler: async () => {
                const totalUsers = await User.countDocuments();
                const totalMods = await File.countDocuments({ isLatestVersion: true });
                const totalDownloadsData = await File.aggregate([{ $group: { _id: null, total: { $sum: "$downloads" } } }]);
                const totalDownloads = totalDownloadsData.length > 0 ? totalDownloadsData[0].total : 0;
                
                // Data for Pie Chart
                const modsByPlatform = await File.aggregate([
                    { $match: { isLatestVersion: true } },
                    { $group: { _id: "$category", count: { $sum: 1 } } }
                ]);

                // Data for Line Chart (Last 7 Days)
                const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
                const uploadsByDay = await File.aggregate([
                    { $match: { createdAt: { $gte: sevenDaysAgo } } },
                    { $group: { _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } }, count: { $sum: 1 } } },
                    { $sort: { _id: 1 } }
                ]);

                return {
                    stats: { totalUsers, totalMods, totalDownloads },
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
                    listProperties: ['profileImageKey', 'username', 'email', 'role', 'isBanned', 'lastSeen'],
                    showProperties:['_id', 'profileImageKey', 'username', 'email', 'role', 'isVerified', 'isBanned', 'banReason', 'createdAt', 'lastSeen', 'bio'],
                    editProperties:['username', 'email', 'role', 'isVerified', 'isBanned', 'banReason', 'bio', 'newPassword'],
                    properties: {
                        password: { isVisible: false },
                        newPassword: { type: 'password', label: 'New Password (leave blank to keep unchanged)' },
                        // ✅ FIX: Use ImagePreview for avatars, but only on list/show
                        profileImageKey: {
                            components: {
                                list: Components.ImagePreview,
                                show: Components.ImagePreview,
                            },
                            // Ensure it's hidden on the edit form if you don't want them editing the raw key
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
                    listProperties:['iconKey', 'name', 'fileSize', 'version', 'isMultiPart', 'status', 'category'],
                    editProperties:[
                        'name', 'version', 'developer', 'uploader', 'modDescription', 'modFeatures', 'officialDescription',
                        'whatsNew', 'category', 'status', 'rejectionReason', 'certification', 'isLatestVersion',
                        'showInSitemap', 'virusTotalId', 'virusTotalAnalysisId', 
                        'iconKey', // Ensure this is in editProperties so it can be edited
                        'screenshotKeys',
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
                        screenshotKeys: { isArray: true, description: 'Paste direct image URLs (https://...).' },
                        rejectionReason: {
                            isVisible: {
                               edit: (record) => record.params.status === 'rejected',
                               list: false, filter: false, show: true
                            }
                        },
                       iconKey: { 
                            description: 'Paste a direct image URL (https://...) OR a Backblaze B2 key.',
                            // ✅ FIX: Use ImagePreview, but allow standard text input on Edit
                            components: {
                                list: Components.ImagePreview,
                                show: Components.ImagePreview,
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
                                if (request.payload.virusTotalId) request.payload.virusTotalId = extractVTId(request.payload.virusTotalId);
                                return request;
                            }
                        },
                        edit: { 
                            isAccessible: true,
                            before: async (request) => {
                                if (request.payload.virusTotalId) request.payload.virusTotalId = extractVTId(request.payload.virusTotalId);
                                return request;
                            }
                        },
                        delete: { isAccessible: true },
                        
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
    const adminRouter = AdminJSExpress.buildRouter(adminJs);
    return adminRouter;
}

module.exports = createAdminRouter;