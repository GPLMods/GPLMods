const AdminJS = require('adminjs');
const AdminJSExpress = require('@adminjs/express');
const AdminJSMongoose = require('@adminjs/mongoose');
const bcrypt = require('bcryptjs');

// Import your Mongoose models
const User = require('../models/user');
const File = require('../models/file');
const Review = require('../models/review');
const Report = require('../models/report');

// Register the Mongoose adapter
AdminJS.registerAdapter({
    Database: AdminJSMongoose.Database,
    Resource: AdminJSMongoose.Resource,
});

// Create the main AdminJS configuration object
const adminJsOptions = {
    // Set the path for the admin panel
    rootPath: '/admin',

    // Define which database models to show in the admin panel
    resources: [
        {
            resource: User,
            options: {
                // We can customize how the User model is displayed
                properties: {
                    // Make the password field invisible in lists and show-views
                    password: { isVisible: false },
                    // Instead, create a "virtual" field for changing the password
                    encryptedPassword: {
                        isVisible: { list: false, filter: false, show: false, edit: true, new: true },
                        type: 'password',
                        label: 'Password'
                    },
                },
                actions: {
                    new: {
                        // Before creating a new user, hash their password
                        before: async (request) => {
                            if (request.payload.encryptedPassword) {
                                request.payload.password = await bcrypt.hash(request.payload.encryptedPassword, 10);
                            }
                            return request;
                        },
                    },
                    edit: {
                        // Before updating a user, hash the password if it's been changed
                        before: async (request) => {
                            if (request.payload.encryptedPassword) {
                                request.payload.password = await bcrypt.hash(request.payload.encryptedPassword, 10);
                            }
                            return request;
                        },
                    },
                },
            },
        },
        // Configure other models
        {
            resource: File,
            options: {
                // --- ADDED OPTIONS ---
                editProperties: ['name', 'version', 'modDescription', 'category', 'platforms', 'certification', 'externalUrl', 'fileSize'],
                listProperties: ['name', 'version', 'uploader', 'certification', 'isExternalLink'],
                properties: {
                    // A "virtual" property that doesn't exist in the DB, just for the form.
                    externalUrl: {
                        type: 'string',
                        // This property will only show up on the form for creating a new file
                        isVisible: { list: false, show: true, edit: true, filter: false },
                    }
                },
                actions: {
                    new: {
                        // The 'before' hook runs before the new record is saved.
                        before: async (request) => {
                            const { externalUrl, ...payload } = request.payload;

                            if (externalUrl) {
                                // --- Logic for EXTERNAL LINK ---
                                payload.isExternalLink = true;
                                payload.fileUrl = externalUrl; // The external URL becomes the fileUrl

                                // We will skip B2 upload and VT file scan for external links
                                // A URL scan could be added here later for more security
                            }

                            request.payload = payload;
                            return request;
                        },
                        // The 'after' hook runs if the regular upload happens.
                        after: async (response, request, context) => {
                            // This block only runs for direct file uploads, not external links
                            // It's a better place for your B2/VT logic
                            // This part requires a more advanced refactor not covered here for simplicity
                            return response;
                        }
                    }
                },
                sort: { direction: 'desc', sortBy: 'createdAt' }
            }
        },
        {
            resource: Review,
            options: { sort: { direction: 'desc', sortBy: 'createdAt' } }
        },
        {
            resource: Report,
            options: { sort: { direction: 'desc', sortBy: 'createdAt' } }
        },
    ],

    // Branding configuration
    branding: {
        companyName: 'GPL Mods Dashboard',
        softwareBrothers: false, // Hides the "Made by AdminJS" footer
    },
};

// Create a new AdminJS instance with our options
const adminJs = new AdminJS(adminJsOptions);

// Build the un-protected router
// We will add our own protection middleware in server.js
const adminRouter = AdminJSExpress.buildRouter(adminJs);

// Export the router to be used in server.js
module.exports = adminRouter;