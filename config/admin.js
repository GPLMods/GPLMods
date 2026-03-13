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
    // 4. CUSTOM GPL MODS THEME
    // ==========================================
    // We take the official 'dark' theme and inject your website's exact colors!
    const gplModsTheme = {
        ...dark,
        id: 'gplModsTheme',
        name: 'GPL Mods Dark',
        colors: {
            ...dark.colors,
            primary100: '#FFD700', // GPL Gold (Buttons, Highlights)
            primary80: '#e5c200',  // Darker Gold for hover effects
            primary60: '#ccad00',
            primary40: '#b29700',
            primary20: '#4d4100',
            bg: '#0a0a0a',        // GPL Black (Main Background)
            surface: '#1a1a1a',   // GPL Dark Gray (Cards, Sidebar)
            filterBg: '#111111',  // Slightly darker gray for filters
            hoverBg: '#2a2a2a',   // Table row hover
            text: '#ffffff',      // GPL White Text
            grey100: '#c0c0c0',   // GPL Silver Text
            border: '#333333',    // Dark borders
        }
    };

    // ==========================================
    // 5. DEFINE ADMINJS OPTIONS
    // ==========================================
    const adminJsOptions = {
        rootPath: '/admin',
        componentLoader, 
        defaultTheme: 'gplModsTheme', // Set your custom theme as default!
        availableThemes: [gplModsTheme, light], // You can toggle between yours and light mode
        dashboard: {
            component: Components.Dashboard 
        },
        branding: {
            companyName: 'GPL Mods',
            logo: '/images/logo.png',
            softwareBrothers: false,
            withMadeWithLove: false, // Hides the bottom AdminJS watermark
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
                        // --- CRASH FIX: Explicitly define arrays to bypass Mongoose parser bug ---
                        whitelist: { type: 'reference', isArray: true, isVisible: false },
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
                    listProperties:['name', 'uploader', 'status', 'showInSitemap', 'category'],
                    editProperties:[
                        'name', 'version', 'developer', 'modDescription', 'modFeatures', 'officialDescription',
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
                        rejectionReason: {
                            isVisible: {
                               edit: (record) => record.params.status === 'rejected',
                               list: false, filter: false, show: true
                            }
                        },
                        // --- CRASH FIX: Explicitly define arrays to bypass Mongoose parser bug ---
                        screenshotKeys: { type: 'string', isArray: true, description: 'Paste direct image URLs.' },
                        platforms: { type: 'string', isArray: true },
                        tags: { type: 'string', isArray: true },
                        olderVersions: { type: 'reference', isArray: true, isVisible: false },
                        votedOnStatusBy: { type: 'reference', isArray: true, isVisible: false },
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
                    properties: {
                        // --- CRASH FIX: Explicitly define arrays to bypass Mongoose parser bug ---
                        votedBy: { type: 'reference', isArray: true, isVisible: false }
                    },
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