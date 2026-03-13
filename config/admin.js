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
    // This perfectly bypasses all Node 20/22 strict ES Module errors!
    const AdminJSModule = await import('adminjs');
    const AdminJS = AdminJSModule.default || AdminJSModule;

    const AdminJSExpress = await import('@adminjs/express');
    const AdminJSMongoose = await import('@adminjs/mongoose');
    const { dark, light } = await import('@adminjs/themes');

    // --- 2. REGISTER THE MONGOOSE ADAPTER ---
    AdminJS.registerAdapter({
        Database: AdminJSMongoose.Database,
        Resource: AdminJSMongoose.Resource,
    });

    // --- 3. DEFINE ADMINJS OPTIONS ---
    const adminJsOptions = {
        rootPath: '/admin',
        defaultTheme: dark.id,
        availableThemes: [dark, light],
        dashboard: {
            component: AdminJS.bundle('../components/dashboard.jsx')
        },
        branding: {
            companyName: 'GPL Mods',
            logo: '/images/logo.png',
            softwareBrothers: false,
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
                    listProperties: ['reportedFileName', 'reportingUsername', 'reason', 'status', 'createdAt'],
                    editProperties: ['status'],
                },
            },
            {
                resource: Dmca,
                options: {
                    listProperties: ['fullName', 'infringingUrl', 'status', 'createdAt'],
                    editProperties: ['status'],
                },
            },
            // SITE CONTENT RESOURCE
            {
                resource: Announcement,
                options: {
                    listProperties: ['title', 'author', 'createdAt'],
                    editProperties: ['title', 'author', 'content'],
                    properties: { content: { type: 'richtext' } },
                },
            },
        ]
    };

    // --- 4. INITIALIZE ADMINJS ---
    const adminJs = new AdminJS(adminJsOptions);
    
    // --- 5. BUILD THE ROUTER ---
    const buildRouter = AdminJSExpress.buildRouter || AdminJSExpress.default.buildRouter;
    
    return buildRouter(adminJs);
}

module.exports = createAdminRouter;