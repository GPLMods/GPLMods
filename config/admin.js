const AdminJS = require('adminjs');
const AdminJSExpress = require('@adminjs/express');
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
                listProperties:['name', 'uploader', 'status', 'showInSitemap', 'category'],
                // Add showInSitemap to editProperties and showProperties
                editProperties:[
                    'name', 'version', 'developer', 'modDescription', 'modFeatures', 'officialDescription',
                    'whatsNew', 'category', 'status', 'rejectionReason', 'certification', 'isLatestVersion',
                    'showInSitemap', // <--- ADDED HERE
                    'virusTotalId', 'virusTotalAnalysisId',
                    'iconKey', 'screenshotKeys' 
                ],
                showProperties:[
                   'iconKey', 'name', 'version', 'developer', 'uploader', 'status', 'rejectionReason',
                    'certification', 'category', 'downloads', 'averageRating', 'showInSitemap', // <--- ADDED HERE
                    'virusTotalId', 'virusTotalAnalysisId', 'iconKey', 'screenshotKeys', 'createdAt', 'updatedAt'
                ],
properties: {
    modDescription: { type: 'richtext' },
    officialDescription: { type: 'richtext' },
    modFeatures: { type: 'textarea' }, // Use textarea so your line-breaks stay intact for the checkmark list
    whatsNew: { type: 'textarea' },
                    iconKey: {
                        description: 'Paste a direct image URL (https://...) OR a Backblaze B2 key.'
                    },
                    screenshotKeys: {
                        isArray: true, // This creates an "Add New Item" button for multiple screenshots
                        description: 'Paste direct image URLs (https://...). Click "Add new item" for multiple.'
                    },
                    rejectionReason: {
                        isVisible: {
                           edit: (record) => record.params.status === 'rejected',
                           list: false, filter: false, show: true
                        }
                    }
                },
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
        companyName: 'GPL Mods Aamin Panel',
        softwareBrothers: false,
    },
};

const adminJs = new AdminJS(adminJsOptions);
const adminRouter = AdminJSExpress.buildRouter(adminJs);

module.exports = adminRouter;