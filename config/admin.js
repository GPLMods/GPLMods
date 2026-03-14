const bcrypt = require('bcryptjs');

// Import all your models
const User = require('../models/user');
const File = require('../models/file');
const Review = require('../models/review');
const Report = require('../models/report');
const Dmca = require('../models/dmca');
const Announcement = require('../models/announcement');

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
        Dashboard: componentLoader.add('Dashboard', '../components/dashboard.jsx')
    };

      // ==========================================
     // 4. THE ULTIMATE GPL MODS THEME
    // ==========================================
    const gplModsTheme = {
        id: 'gplModsTheme',
        name: 'GPL Mods Premium',
        overrides: {
            colors: {
                // By spreading the 'dark' theme colors first, we ensure all un-specified 
                // elements (like dropdowns and inputs) automatically get a dark background!
                ...dark.overrides?.colors, 

                // --- THE GOLD ACCENTS ---
                primary100: '#FFD700', // GPL Gold
                primary80: '#e5c200',  
                primary60: '#ccad00',  
                primary40: '#b29700',  
                primary20: '#332b00',  

                // --- THE BACKGROUNDS ---
                bg: '#0a0a0a',         // GPL Black (Main background)
                container: '#1a1a1a',  // GPL Dark Gray (Cards, Tables, Sidebar background)
                white: '#1a1a1a',      // Fallback for container elements

                // --- TEXT & BORDERS ---
                text: '#ffffff',       // GPL White
                grey100: '#ffffff',    // Headings
                grey80: '#c0c0c0',     // GPL Silver (Subtitles, Table Headers)
                grey60: '#a0a0a0',     
                grey40: '#444444',     // Dark borders for inputs
                grey20: '#2a2a2a',     // Subtle background for Table Row hovers
                border: '#333333',     // Main divider lines

                // --- STATUS COLORS ---
                errorLight: '#ffadad',
                error: '#e53935',      // GPL Red
                errorDark: '#b71c1c',
                successLight: '#b0ffb0',
                success: '#43a047',    // GPL Green
                successDark: '#1b5e20',
                infoLight: '#90caf9',
                info: '#2196F3',       // GPL Blue
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
        defaultTheme: 'gplModsTheme', 
        availableThemes:[gplModsTheme, dark, light], 
        dashboard: {
            component: Components.Dashboard 
        },
        branding: {
            companyName: 'GPL Mods',
            logo: '/images/logo.png',
            softwareBrothers: false,
            withMadeWithLove: false, 
        },
        resources:[
            // USER MANAGEMENT
            {
                resource: User,
                options: {
                    listProperties:['username', 'email', 'role', 'isVerified', 'lastSeen'],
                    showProperties:['_id', 'username', 'email', 'role', 'isVerified', 'createdAt', 'lastSeen', 'bio'],
                    editProperties:['username', 'email', 'role', 'isVerified', 'bio', 'newPassword'],
                    properties: {
                        password: { isVisible: false },
                        newPassword: {
                            type: 'password',
                            label: 'New Password (leave blank to keep unchanged)',
                        },
                    },
                    actions: {
                        edit: {
                            before: async (request) => {
                                const { newPassword, ...payload } = request.payload;
                                if (newPassword && newPassword.length > 0) {
                                    payload.password = await bcrypt.hash(newPassword, 10);
                                }
                                request.payload = payload;
                                return request;
                            },
                        },
                    },
                },
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