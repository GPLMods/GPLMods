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
    
    const Components = {
        Dashboard: componentLoader.add('Dashboard', '../components/dashboard.jsx'),
        SidebarBranding: componentLoader.override('SidebarBranding', '../components/SidebarBranding.jsx')
    };

    const gplModsTheme = {
        ...dark, 
        id: 'gplModsTheme',
        name: 'GPL Mods Premium',
        overrides: {
            ...dark.overrides, 
            colors: {
                ...dark.overrides?.colors, 
                primary100: '#FFD700',
                primary80: '#e5c200',  
                primary60: '#ccad00',  
                primary40: '#b29700',  
                primary20: '#332b00',  
                bg: '#0a0a0a',         
                container: '#1a1a1a',  
                white: '#1a1a1a',      
                text: '#ffffff',       
                grey100: '#ffffff',    
                grey80: '#c0c0c0',     
                grey60: '#a0a0a0',     
                grey40: '#444444',     
                grey20: '#2a2a2a',     
                border: '#333333',     
                errorLight: '#ffadad',
                error: '#e53935',      
                errorDark: '#b71c1c',
                successLight: '#b0ffb0',
                success: '#43a047',    
                successDark: '#1b5e20',
                infoLight: '#90caf9',
                info: '#2196F3',       
                infoDark: '#0d47a1',
            }
        }
    };

    const adminJsOptions = {
        rootPath: '/admin',
        componentLoader, 
        defaultTheme: 'gplModsTheme', 
        availableThemes: [gplModsTheme, dark, light], 
        dashboard: { component: Components.Dashboard },
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
                    listProperties: ['username', 'email', 'role', 'isBanned', 'lastSeen'],
                    showProperties:['_id', 'username', 'email', 'role', 'isVerified', 'isBanned', 'banReason', 'createdAt', 'lastSeen', 'bio'],
                    editProperties:['username', 'email', 'role', 'isVerified', 'isBanned', 'banReason', 'bio', 'newPassword'],
                    properties: {
                        password: { isVisible: false },
                        newPassword: { type: 'password', label: 'New Password (leave blank to keep unchanged)' },
                    },
                    actions: {
                        new: { isAccessible: true },
                        edit: { isAccessible: true },
                        delete: { isAccessible: true }
                    }
                }
            },
// ---------------------------------
        // GLOBAL SITE CONTROLS
        // ---------------------------------
        {
            resource: SiteState,
            options: {
                // Ensure only ONE record can ever exist
                actions: {
                    new: {
                        isAccessible: async () => {
                            const count = await SiteState.countDocuments();
                            return count === 0; // Only allow "New" if no record exists
                        }
                    },
                    delete: { isAccessible: false } // Never allow deletion of the master state
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
                    targetUsername: {
                        description: 'Only required if Target Audience is "specific-user". Enter their exact username.'
                    }
                }
            },
// ---------------------------------
        // DIRECT USER NOTIFICATIONS
        // ---------------------------------
        {
            resource: UserNotification,
            options: {
                listProperties: ['user', 'title', 'type', 'isRead', 'createdAt'],
                showProperties: ['user', 'title', 'message', 'type', 'isRead', 'createdAt'],
                editProperties: ['user', 'title', 'message', 'type'], // Don't let admin edit 'isRead'
                properties: {
                    message: { type: 'textarea' }
                }
            }
        },
// ---------------------------------
        // SUPPORT TICKETS
        // ---------------------------------
        {
            resource: SupportTicket,
            options: {
                listProperties: ['subject', 'category', 'username', 'status', 'createdAt'],
                showProperties: [
                    'status', 'category', 'subject', 'message', 
                    'username', 'email', 'adminNotes', 'createdAt', 'updatedAt'
                ],
                editProperties: ['status', 'adminNotes'], // Admins only edit status and notes
                properties: {
                    message: { type: 'textarea' },
                    adminNotes: { type: 'textarea' }
                }
            }
        },
{
            resource: AutomatedCampaign,
            options: {
                listProperties: ['title', 'targetGroup', 'scheduledDate', 'status'],
                properties: {
                    notificationMessage: { type: 'textarea' }
                }
            }
        },
            // FILE (MOD) MANAGEMENT
            {
                resource: File,
                options: {
                    listProperties:['name', 'fileSize', 'version', 'isMultiPart', 'status', 'category','isMultiPart', 'downloadParts', 'installationInstructions'],
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
                        'virusTotalId', 'virusTotalAnalysisId', 'screenshotKeys', 'createdAt', 'updatedAt', 'isMultiPart', 'downloadParts', 'installationInstructions'
                    ],
                    properties: {
                        modDescription: { type: 'richtext' },
                        officialDescription: { type: 'richtext' },
                        modFeatures: { type: 'textarea' }, 
                        whatsNew: { type: 'textarea' },
                        externalDownloadUrl: { description: 'Paste direct download link from Google Drive, Dropbox, Mega, etc.' },
                        fileKey: { description: 'The Backblaze B2 file path' },
                        iconKey: { description: 'Paste a direct image URL (https://...) OR a Backblaze B2 key.' },
                        screenshotKeys: { isArray: true, description: 'Paste direct image URLs (https://...).' },
                        rejectionReason: {
                            isVisible: {
                               edit: (record) => record.params.status === 'rejected',
                               list: false, filter: false, show: true
                            }
                        }, // <--- FIX 1: Added missing brace and comma here
                        isMultiPart: {
                            description: 'Check this box if the file is split into multiple download links.'
                        },
                        downloadParts: {
                            isArray: true,
                            description: 'Add the individual links here (e.g., Part 1, Part 2). Only used if "Is Multi Part" is checked.'
                        },
                        installationInstructions: {
                            type: 'richtext',
                            description: 'Instructions for extracting and installing the multi-part file.'
                        }
                    }, 
                    // <--- FIX 2: Actions are now safely inside the 'options' object
                    actions: {
                        new: { isAccessible: true },
                        edit: { isAccessible: true },
                        delete: { isAccessible: true },
                        viewOnSite: {
                            actionType: 'record',
                            icon: 'View',
                            handler: async (request, response, context) => {
                                return {
                                    record: context.record.toJSON(context.currentAdmin),
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
                                    redirectUrl: vtUrl
                                 };
                            }
                        }
                    } 
                } // closes options
            }, // closes File resource
            // <--- FIX 3: Removed the extra dangling '},' that was here
            // PARTNERSHIP APPLICATIONS
            {
                resource: DistributorApplication,
                options: {
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
                    listProperties:['username', 'rating', 'comment', 'file', 'createdAt'],
                    actions: { edit: { isAccessible: true }, delete: { isAccessible: true } },
                },
            },
            {
                resource: Report,
                options: {
                    listProperties:['reportedFileName', 'reportingUsername', 'reason', 'status', 'createdAt'],
                    editProperties: ['status'],
                },
            },
            {
                resource: Dmca,
                options: {
                    listProperties: ['fullName', 'infringingUrl', 'status', 'createdAt'],
                    editProperties: ['status'],
                }
            },
            {
                resource: UnbanRequest,
                options: {
                    listProperties: ['username', 'email', 'status', 'createdAt'],
                    editProperties:['status'],
                }
            },
            // SITE CONTENT RESOURCE
            {
                resource: Announcement,
                options: {
                    listProperties: ['title', 'author', 'createdAt'],
                    editProperties: ['title', 'author', 'content'],
                    properties: { content: { type: 'richtext' } },
                },
            }
        ] // <--- THIS BRACKET WAS MISSING IN YOUR OLD CODE
    };

    const adminJs = new AdminJS(adminJsOptions);
    const adminRouter = AdminJSExpress.buildRouter(adminJs);
    return adminRouter;
}

module.exports = createAdminRouter;