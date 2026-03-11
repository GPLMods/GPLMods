const AdminJS = require('adminjs');
const AdminJSMongoose = require('@adminjs/mongoose');
const bcrypt = require('bcryptjs');

// Import all your models
const User = require('../models/user');
const File = require('../models/file');
const Review = require('../models/review');
const Report = require('../models/report');
const Dmca = require('../models/dmca');
const Announcement = require('../models/announcement'); // Don't forget this one

AdminJS.registerAdapter({
    Database: AdminJSMongoose.Database,
    Resource: AdminJSMongoose.Resource,
});

const adminJsOptions = {
    rootPath: '/admin',
// --- 1. LINK THE CUSTOM DASHBOARD ---
    dashboard: {
        component: AdminJS.bundle('../components/dashboard.jsx')
    },
    // Define the order of resources in the sidebar
    resources: [
        // ---------------------------------
        // USER MANAGEMENT RESOURCE
        // ---------------------------------
        {
            resource: User,
            options: {
                // Control which fields are visible in which view
                listProperties: ['username', 'email', 'role', 'isVerified', 'lastSeen'],
                showProperties: ['_id', 'username', 'email', 'role', 'isVerified', 'createdAt', 'lastSeen', 'bio'],
                editProperties: ['username', 'email', 'role', 'isVerified', 'bio', 'newPassword'],
                
                properties: {
                    // Make the stored password hash completely invisible
                    password: { isVisible: false },
                    
                    // Create a "virtual" field just for changing the password in the edit form
                    newPassword: {
                        type: 'password',
                        label: 'New Password (leave blank to keep unchanged)',
                    },
                },
                actions: {
                    // The 'before' hook runs before an action saves data
                    edit: {
                        before: async (request) => {
                            const { newPassword, ...payload } = request.payload;

                            // Only hash and update the password if a new one was provided
                            if (newPassword && newPassword.length > 0) {
                                payload.password = await bcrypt.hash(newPassword, 10);
                            }
                            
                            // Return the modified payload to be saved
                            request.payload = payload;
                            return request;
                        },
                    },
                    // We can add a custom "ban" action later if needed
                },
            },
        },
        // ---------------------------------
        // FILE (MOD) MANAGEMENT RESOURCE
        // ---------------------------------
        {
            resource: File,
            options: {
                listProperties:['name', 'fileSize', 'version', 'developer', 'uploader', 'status', 'certification', 'downloads', 'averageRating', 'showInSitemap', 'category', 'createdAt', 'updatedAt'],
                editProperties:[
                    'name', 'version', 'uploader', 'developer', 'modDescription', 'modFeatures', 'officialDescription',
                    'whatsNew', 'category', 'status', 'rejectionReason', 'certification', 'isLatestVersion',
                    'showInSitemap',
                    'virusTotalId', 'virusTotalAnalysisId',
                    'iconKey', 'screenshotKeys',
                    // --- NEW FIELDS ADDED HERE ---
                    'externalDownloadUrl', 'fileKey', 'fileSize', 'originalFilename' 
                ],
                showProperties:[
                    'iconKey', 'name', 'version', 'developer', 'uploader', 'status', 'rejectionReason',
                    'certification', 'category', 'downloads', 'averageRating', 'showInSitemap', 
                    'externalDownloadUrl', 'fileKey', 'fileSize', 'originalFilename', // Added here too
                    'virusTotalId', 'virusTotalAnalysisId', 'screenshotKeys', 'createdAt', 'updatedAt'
                ],
                properties: {
                    modDescription: { type: 'richtext' },
                    officialDescription: { type: 'richtext' },
                    modFeatures: { type: 'textarea' }, 
                    whatsNew: { type: 'textarea' },
                    externalDownloadUrl: {
                        description: 'Paste direct download link from Google Drive, Dropbox, Mega, etc. (Leave fileKey blank if using this)'
                    },
                    fileKey: {
                        description: 'The Backblaze B2 file path (Leave blank if using an external cloud link)'
                    },
                    iconKey: {
                        description: 'Paste a direct image URL (https://...) OR a Backblaze B2 key.'
                    },
                    screenshotKeys: {
                        isArray: true, 
                        description: 'Paste direct image URLs (https://...). Click "Add new item" for multiple.'
                    },
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
                    delete: { isAccessible: true } // Ensures Deletion is enabled
                }
            },
        },
        // ---------------------------------
        // MODERATION RESOURCES
        // ---------------------------------
        {
            resource: Review,
            options: {
                listProperties: ['username', 'rating', 'comment', 'file', 'createdAt'],
                // Admins should be able to edit or delete bad reviews
                actions: {
                    edit: { isAccessible: true },
                    delete: { isAccessible: true },
                },
            },
        },
        {
            resource: Report,
            options: {
                listProperties: ['reportedFileName', 'reportingUsername', 'reason', 'status', 'createdAt'],
                // Admins can edit the status directly
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
        // ---------------------------------
        // SITE CONTENT RESOURCE
        // ---------------------------------
        {
            resource: Announcement,
            options: {
                listProperties: ['title', 'author', 'createdAt'],
                editProperties: ['title', 'author', 'content'],
                properties: {
                    content: { type: 'richtext' }, // Use rich text for announcements
                },
            },
        },
    ],
    branding: {
        companyName: 'GPL Mods Admin Panel',
         logo: '/images/logo.png',
        softwareBrothers: false,
        // --- CUSTOM GPL MODS THEME ---
        theme: {
            colors: {
                // Primary Color (GPL Gold)
                primary100: '#FFD700', 
                primary80: '#e5c200', // Slightly darker gold for hovers
                primary60: '#ccad00',
                primary40: '#b29700',
                primary20: '#4d4100', // Very dark gold/brown for subtle backgrounds
                
                // Backgrounds (GPL Black & Dark Gray)
                bg: '#0a0a0a',        // Main background (Black)
                surface: '#1a1a1a',   // Card/Box background (Dark Gray)
                filterBg: '#111111',  // Filter sidebar background
                hoverBg: '#2a2a2a',   // Hover state for table rows
                
                // Text & Borders (GPL White & Silver)
                text: '#ffffff',      // Main text (White)
                border: '#333333',    // Subtle borders
                grey100: '#c0c0c0',   // Secondary text (GPL Silver)
                grey80: '#999999',
                grey60: '#666666',
                grey40: '#333333',
                grey20: '#1a1a1a',    // Darkest grey
                
                // Status Colors (From your CSS)
                error: '#e53935',     // Red
                success: '#43a047',   // Green
                info: '#2196F3',      // Blue
                
                // Absolute colors
                white: '#ffffff',
                black: '#000000',
            }
        },
    },
};

// --- NEW: Wrap the router creation in an async function ---
async function createAdminRouter() {
    // This is the magic trick: Dynamically importing an ES Module inside a CommonJS file!
    const AdminJSExpress = await import('@adminjs/express');
    
    const adminJs = new AdminJS(adminJsOptions);
    
    // Depending on how it imports, we grab the buildRouter function
    const buildRouter = AdminJSExpress.buildRouter || AdminJSExpress.default.buildRouter;
    
    return buildRouter(adminJs);
}

module.exports = createAdminRouter;