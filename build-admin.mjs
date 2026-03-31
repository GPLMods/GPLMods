import AdminJSModule from 'adminjs';
import * as AdminJSMongoose from '@adminjs/mongoose';

const AdminJS = AdminJSModule.default || AdminJSModule;
const { ComponentLoader } = AdminJSModule;

// Register the Mongoose adapter
AdminJS.registerAdapter({
    Database: AdminJSMongoose.Database,
    Resource: AdminJSMongoose.Resource,
});

const componentLoader = new ComponentLoader();

// Tell it which files need to be bundled
const Components = {
    Dashboard: componentLoader.add('Dashboard', './components/dashboard.jsx'),
    SidebarBranding: componentLoader.override('SidebarBranding', './components/SidebarBranding.jsx')
};

const adminJsOptions = {
    rootPath: '/admin',
    componentLoader, 
    dashboard: { component: Components.Dashboard },
};

console.log("Starting AdminJS pre-build...");

try {
    const adminJs = new AdminJS(adminJsOptions);
    
    // This triggers the heavy Webpack build process
    await adminJs.initialize();
    
    console.log("AdminJS pre-build complete! Bundle saved to .adminjs folder.");
    process.exit(0); // Exit successfully
} catch (e) {
    console.error("Build failed:", e);
    process.exit(1); // Exit with error
}