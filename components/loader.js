const { ComponentLoader } = require('adminjs');
const path = require('path');

const componentLoader = new ComponentLoader();

const Components = {
    Dashboard: componentLoader.add('Dashboard', path.resolve(__dirname, './dashboard.jsx')),
    SidebarBranding: componentLoader.override('SidebarBranding', path.resolve(__dirname, './SidebarBranding.jsx')),
    ActionRedirect: componentLoader.add('ActionRedirect', path.resolve(__dirname, './ActionRedirect.jsx')),
    VariantBadge: componentLoader.add('VariantBadge', path.resolve(__dirname, './VariantBadge.jsx')),
    
    // ✅ FIX 1: Removed the extra './components/' from the path
    AvatarCell: componentLoader.add('AvatarCell', path.resolve(__dirname, './AvatarCell.jsx')),
    
    // ✅ FIX 2: Completed the cut-off ImagePreview line
    ImagePreview: componentLoader.add('ImagePreview', path.resolve(__dirname, './ImagePreview.jsx'))
};

module.exports = { componentLoader, Components };