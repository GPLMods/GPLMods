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
            options: { sort: { direction: 'desc', sortBy: 'createdAt' } }
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