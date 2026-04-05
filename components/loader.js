// components/loader.js
const { ComponentLoader } = require('adminjs'); // Using require() since it's used by the main server
const path = require('path');

// 1. Create the SINGLE instance
const componentLoader = new ComponentLoader();

// 2. Add all components to this single instance
const Components = {
    Dashboard: componentLoader.add('Dashboard', path.resolve(__dirname, './dashboard.jsx')),
    SidebarBranding: componentLoader.override('SidebarBranding', path.resolve(__dirname, './SidebarBranding.jsx')),
    ImagePreview: componentLoader.add('ImagePreview', path.resolve(__dirname, './ImagePreview.jsx')),
    ActionRedirect: componentLoader.add('ActionRedirect', path.resolve(__dirname, './ActionRedirect.jsx')),
    VariantBadge: componentLoader.add('VariantBadge', path.resolve(__dirname, './VariantBadge.jsx'))
};

// 3. Export BOTH the loader instance AND the component references
module.exports = { componentLoader, Components };