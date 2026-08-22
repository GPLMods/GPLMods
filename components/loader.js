const { ComponentLoader } = require('adminjs');
const path = require('path');

const componentLoader = new ComponentLoader();

const Components = {
    Dashboard: componentLoader.add('Dashboard', path.resolve(__dirname, './dashboard/CustomDashboard.jsx')),
    SidebarBranding: componentLoader.override('SidebarBranding', path.resolve(__dirname, './dashboard/SidebarBranding.jsx')),
    ActionRedirect: componentLoader.add('ActionRedirect', path.resolve(__dirname, './actions/ActionRedirect.jsx')),
    VariantBadge: componentLoader.add('VariantBadge', path.resolve(__dirname, './cells/VariantBadge.jsx')),
    AvatarCell: componentLoader.add('AvatarCell', path.resolve(__dirname, './cells/AvatarCell.jsx')),
    ImagePreview: componentLoader.add('ImagePreview', path.resolve(__dirname, './cells/ImagePreview.jsx')),
    ManageVotes: componentLoader.add('ManageVotes', path.resolve(__dirname, './actions/ManageVotes.jsx'))
};

module.exports = { componentLoader, Components };