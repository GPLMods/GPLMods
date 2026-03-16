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

async function createAdminRouter() {
    // --- 1. DYNAMICALLY IMPORT ALL ESM PACKAGES ---
    const AdminJSModule = await import('adminjs');
    const AdminJS = AdminJSModule.default || AdminJSModule;
    const { ComponentLoader } = AdminJSModule; 

    const AdminJSExpress = await import('@adminjs/express');
    const AdminJSMongoose = await import('@adminjs/mongoose');
    const { dark, light } = await import('@adminjs/themes');

    // --- 2. REGISTER THE MONGOOSE ADAPTER ---
    AdminJS.registerAdapter({
        Database: AdminJSMongoose.Database,
        Resource: AdminJSMongoose.Resource,
    });

    // --- 3. SETUP COMPONENT LOADER ---
    const componentLoader = new ComponentLoader();
    
    const Components = {
        // 1. We ADD our custom dashboard page
        Dashboard: componentLoader.add('Dashboard', '../components/dashboard.jsx'),
        
        // 2. We OVERRIDE the default AdminJS components using the names from the repo you found!
        SidebarBranding: componentLoader.override('SidebarBranding', '../components/SidebarBranding.jsx')
        
        // Example: If you wanted to override the "No Records" screen later, you would do:
        // NoRecords: componentLoader.override('NoRecords', '../components/MyCustomNoRecords.jsx')
    };

      // ==========================================
    // 4. THE ULTIMATE GPL MODS THEME (OFFICIAL METHOD)
    // ==========================================
    
    const gplModsTheme = {
        // 1. SPREAD THE DARK THEME: This is the crucial official step.
        // It securely copies the 'bundlePath' and 'stylePath' from the dark theme 
        // so AdminJS knows exactly where to load the CSS and JS from.
        ...dark, 
        
        id: 'gplModsTheme',
        name: 'GPL Mods Premium',
        overrides: {
            ...dark.overrides, // 2. Inherit existing dark mode structural overrides
            colors: {
                ...dark.overrides?.colors, // 3. Inherit existing dark mode colors

                // --- THE GOLD ACCENTS ---
                primary100: '#FFD700', // GPL Gold (Buttons, Active links, Checkboxes)
                primary80: '#e5c200',  // Hover states for Gold buttons
                primary60: '#ccad00',  
                primary40: '#b29700',  
                primary20: '#332b00',  // Very dark gold/brown for subtle highlighted backgrounds

                // --- THE BACKGROUNDS ---
                bg: '#0a0a0a',         // GPL Black (The main page background behind everything)
                container: '#1a1a1a',  // GPL Dark Gray (Makes the cards and sidebar dark)
                white: '#1a1a1a',      // Fallback for containers/inputs

                // --- TEXT & BORDERS (SILVER & WHITE) ---
                text: '#ffffff',       // Standard body text (White)
                grey100: '#ffffff',    // Main Headings (White)
                grey80: '#c0c0c0',     // GPL Silver (Subtitles, Table Headers, secondary text)
                grey60: '#a0a0a0',     // Darker silver for muted text
                grey40: '#444444',     // Dark borders for inputs
                grey20: '#2a2a2a',     // Subtle background for Table Row hovers
                border: '#333333',     // Main divider lines

                // --- STATUS COLORS ---
                errorLight: '#ffadad',
                error: '#e53935',      // Red for delete buttons/errors
                errorDark: '#b71c1c',
                successLight: '#b0ffb0',
                success: '#43a047',    // Green for success/live status
                successDark: '#1b5e20',
                infoLight: '#90caf9',
                info: '#2196F3',       // Blue for info
                infoDark: '#0d47a1',
            }
        }
    };

    // ==========================================
    // 5. DEFINE ADMINJS OPTIONS
    // ==========================================
    const adminJsOptions = {
        rootPath: '/admin',
        componentLoader, 
        
        // Use our new custom theme ID
        defaultTheme: 'gplModsTheme', 
        
        // Pass our custom theme into the available themes array
        availableThemes: [gplModsTheme, dark, light], 
        
        dashboard: {
            component: Components.Dashboard 
        },
        branding: {
            companyName: 'GPL Mods',
            logo: '/images/logo.png', // Ensure this matches your logo path
            softwareBrothers: false,
            withMadeWithLove: false, 
        },
        resources:[
            // USER MANAGEMENT
            {
            resource: User,
            options: {
                // ✅ ADD 'isBanned' and 'banReason' to these arrays
                listProperties: ['username', 'email', 'role', 'isBanned', 'lastSeen'],
                showProperties:['_id', 'username', 'email', 'role', 'isVerified', 'isBanned', 'banReason', 'createdAt', 'lastSeen', 'bio'],
                editProperties:['username', 'email', 'role', 'isVerified', 'isBanned', 'banReason', 'bio', 'newPassword'],
                    properties: {
                        password: { isVisible: false },
                        newPassword: {
                            type: 'password',
                            label: 'New Password (leave blank to keep unchanged)',
                        },
                    },
                    actions: {
                    new: { isAccessible: true },
                    edit: { isAccessible: true },
                    delete: { isAccessible: true },
                    
                    // --- NEW: ADMIN TESTING ACTIONS ---
                    
                    viewOnSite: {
                        actionType: 'record',
                        icon: 'View',
                        handler: async (request, response, context) => {
                            return {
                                record: context.record.toJSON(context.currentAdmin),
                                // Redirects the admin to the frontend mod page
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
                                // Triggers the download route
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
                            
                            let vtUrl = `https://www.virustotal.com/`; // Fallback
                            
                            if (vtHash.length === 64) {
                                vtUrl = `https://www.virustotal.com/gui/file/${vtHash}`;
                            } else if (vtAnalysis) {
                                vtUrl = `https://www.virustotal.com/gui/file-analysis/${vtAnalysis}`;
                            } else if (vtHash) {
                                vtUrl = `https://www.virustotal.com/gui/file-analysis/${vtHash}`;
                            }
                            
                            return {
                                record: context.record.toJSON(context.currentAdmin),
                                // Opens the VirusTotal report
                                redirectUrl: vtUrl
                            };
                        }
                    }
                },
            // FILE (MOD) MANAGEMENT
            {
                resource: File,
                options: {
                    listProperties:['name', 'fileSize', 'version', 'developer', 'uploader', 'status', 'createdAt', 'showInSitemap', 'category'],
                    editProperties:[
                        'name', 'version', 'developer', 'uploader', 'modDescription', 'modFeatures', 'officialDescription',
                        'whatsNew', 'category', 'status', 'rejectionReason', 'certification', 'isLatestVersion',
                        'showInSitemap', 'virusTotalId', 'virusTotalAnalysisId', 'iconKey', 'screenshotKeys',
                        'externalDownloadUrl', 'fileKey', 'fileSize', 'originalFilename' 
                    ],
                    showProperties:[
                        'iconKey', 'name', 'version', 'developer', 'uploader', 'status', 'rejectionReason',
                        'certification', 'category', 'downloads', 'averageRating', 'showInSitemap', 
                        'externalDownloadUrl', 'fileKey', 'fileSize', 'originalFilename',
                        'virusTotalId', 'virusTotalAnalysisId', 'screenshotKeys', 'createdAt', 'updatedAt'
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
                        }
                    },
                    actions: {
                        new: { isAccessible: true },
                        edit: { isAccessible: true },
                        delete: { isAccessible: true }
                    }
                },
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
                listProperties:['fullName', 'infringingUrl', 'status', 'createdAt'],
                editProperties: ['status'],
            },
        },
        // --- ADD UNBAN REQUESTS HERE ---
        {
            resource: UnbanRequest,
            options: {
                listProperties: ['username', 'email', 'status', 'createdAt'],
                editProperties:['status'],
            },
        },
// ---------------------------------
        // USER REQUESTS (MODS/UPDATES)
        // ---------------------------------
        {
            resource: Request,
            options: {
                listProperties:['appName', 'requestType', 'platform', 'username', 'status', 'createdAt'],
                showProperties:[
                    'requestType', 'appName', 'platform', 'requestedVersion', 
                    'officialLink', 'existingModLink', 'modFeaturesRequested', 
                    'additionalNotes', 'username', 'status', 'adminNotes', 'createdAt'
                ],
                editProperties: ['status', 'adminNotes'], // Admins only edit status and notes
                properties: {
                    modFeaturesRequested: { type: 'textarea' },
                    additionalNotes: { type: 'textarea' },
                    adminNotes: { type: 'textarea' }
                }
            }
        },
            // SITE CONTENT RESOURCE
            {
                resource: Announcement,
                options: {
                    listProperties:['title', 'author', 'createdAt'],
                    editProperties: ['title', 'author', 'content'],
                    properties: { content: { type: 'richtext' } },
                },
            },
        ]
    };

    // --- 6. INITIALIZE ADMINJS ---
    const adminJs = new AdminJS(adminJsOptions);
    
    // --- 7. BUILD THE ROUTER ---
    const buildRouter = AdminJSExpress.buildRouter || AdminJSExpress.default.buildRouter;
    
    return buildRouter(adminJs);
}

module.exports = createAdminRouter;