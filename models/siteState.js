const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const SiteStateSchema = new Schema({
    // We use a fixed ID so we can always easily find the one active state document
    singletonId: {
        type: String,
        default: 'master-state',
        unique: true
    },
    
    // The overarching state of the website
    status: {
        type: String,
        enum: ['online', 'maintenance', 'unavailable'],
        default: 'online'
    },
    
    // Who does this status apply to? (e.g., If 'maintenance', who sees the maintenance page?)
    targetAudience: {
        type: String,
        enum: ['all-users', 'guests-only', 'members-only', 'specific-user'],
        default: 'all-users'
    },
    
    // If 'specific-user' is selected above, provide their username here
    targetUsername: {
        type: String,
        trim: true
    },

    // Custom text to display on the Maintenance Page
    maintenanceTitle: { type: String, default: 'Under Maintenance' },
    maintenanceMessage: { type: String, default: 'GPL Mods is currently down for scheduled maintenance. We will be back online shortly. Thank you for your patience!' },

    // Custom text to display on the Unavailable Page
    unavailableTitle: { type: String, default: 'Service Temporarily Unavailable' },
    unavailableMessage: { type: String, default: 'This specific service or page is currently unavailable. Please check back later.' }

}, { timestamps: true });

module.exports = mongoose.model('SiteState', SiteStateSchema);