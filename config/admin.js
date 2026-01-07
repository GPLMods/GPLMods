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

/**
 * AdminJS Configuration
 * @param {object} currentUser - The currently logged-in user (from req.session)
 */
const adminJsOptions = (currentUser) => ({
    // ---- Dashboard ----
    dashboard: {
        handler: async () => {
            // You can add logic here to show stats on the dashboard
            return { message: `Welcome, ${currentUser.username}! This is your GPL Mods dashboard.` };
        },
        component: AdminJS.bundle('./admin-dashboard-component') // For custom React components
    },
    // ---- Resources (Your Database Models) ----
    resources: [
        // User Management
        {
            resource: User,
            options: {
                properties: {
                    // Make the password field visible only for editing/creation
                    password: {
                        isVisible: { list: false, filter: false, show: false, edit: true, new: true },
                    },
                },
                actions: {
                    new: {
                        // Before creating a new user, hash their password
                        before: async (request) => {
                            if (request.payload.password) {
                                request.payload.password = await bcrypt.hash(request.payload.password, 10);
                            }
                            return request;
                        },
                    },
                    edit: {
                        // Before updating a user, hash their password if it's been changed
                        before: async (request) => {
                            if (request.payload.password && request.payload.password.length) {
                                request.payload.password = await bcrypt.hash(request.payload.password, 10);
                            } else {
                                // If password is not changed, remove it from payload to avoid saving an empty one
                                delete request.payload.password;
                            }
                            return request;
                        },
                    },
                },
            },
        },
        // File, Review, and Report Management
        { resource: File, options: { /* Add custom options if needed */ } },
        { resource: Review, options: { /* e.g., listProperties: ['username', 'rating', 'comment'] */ } },
        { resource: Report, options: { /* e.g., sort: { direction: 'desc', sortBy: 'createdAt' } */ } },
    ],
    // ---- Branding ----
    branding: {
        companyName: 'GPL Mods',
        logo: false, // You can add a URL to your logo here
        softwareBrothers: false // Hides the "Made by AdminJS" footer
    },
});

/**
 * Creates and configures the AdminJS router.
 * @param {object} app - The Express app instance.
 */
const setupAdmin = (app) => {
    // --- AUTHENTICATION & ROUTER SETUP ---
    // IMPORTANT: This router must be protected so only admins can access it.
    // We create a separate router that is only used if the user is an admin.
    const adminRouter = AdminJSExpress.buildAuthenticatedRouter(
        null, // We pass null here because we're handling auth logic ourselves
        {
            authenticate: async (email, password) => {
                // This is a dummy function, real authentication happens in the middleware.
                return null;
            },
            cookieName: process.env.SESSION_COOKIE_NAME || 'connect.sid',
            cookiePassword: process.env.SESSION_SECRET || 'a-fallback-secret-key',
        },
        null,
        {
            // Inject the adminJsOptions with the current user
            resave: false,
            saveUninitialized: false,
            secret: process.env.SESSION_SECRET || 'a-fallback-secret-key',
        }
    );

    // This middleware dynamically builds and attaches the AdminJS router
    // ONLY for authenticated admins.
    app.use('/admin', (req, res, next) => {
        if (req.isAuthenticated() && req.user.role === 'admin') {
            // If user is an authenticated admin, dynamically create their admin panel instance
            const adminJs = new AdminJS(adminJsOptions(req.user));
            // This re-wires the router to use the new AdminJS instance
            adminRouter.get('/', (req, res) => res.redirect('/admin/dashboard'));
            adminRouter._router = AdminJSExpress.buildRouter(adminJs, adminRouter._router)._router;
            
            // And now serve it
            return adminRouter(req, res, next);
        }
        // If they are not an admin, they can't access this route
        return res.status(403).send("Forbidden: You must be an admin to access this page.");
    });
};

module.exports = setupAdmin;