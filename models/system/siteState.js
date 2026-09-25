const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const SiteStateSchema = new Schema({
    singletonId: {
        type: String,
        default: 'master-state',
        unique: true
    },
    status: {
        type: String,
        enum: ['online', 'maintenance', 'unavailable', 'coming-soon'],
        default: 'online'
    },
    targetAudience: {
        type: String,
        enum: ['all-users', 'guests-only', 'members-only', 'specific-user'],
        default: 'all-users'
    },
    targetUsername: {
        type: String,
        trim: true
    },
    maintenanceTitle: { type: String, default: 'Under Maintenance' },
    maintenanceMessage: { type: String, default: 'GPL Mods is currently down for scheduled maintenance. We will be back online shortly. Thank you for your patience!' },
    unavailableTitle: { type: String, default: 'Service Temporarily Unavailable' },
    unavailableMessage: { type: String, default: 'This specific service or page is currently unavailable. Please check back later.' },
    // --- DYNAMIC COMING SOON CONFIGURATION ---
    comingSoonTitle: { type: String, default: 'Something Awesome is Coming Soon' },
    comingSoonMessage: { type: String, default: "We're working hard to bring you a new and exciting feature. Stay tuned for the big reveal!" },
    comingSoonCustomText: { type: String, default: 'Feature is currently under development. Stay tuned for official announcements!' },
    comingSoonEnableTimer: { type: Boolean, default: true },
    comingSoonLaunchDate: { type: Date, default: () => new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) },
    comingSoonAllowedRoles: [{ type: String, trim: true }],
    comingSoonAllowedUsers: [{ type: String, trim: true }],
    comingSoonAutoPublishOnTimerEnd: { type: Boolean, default: true },
    enableAutomationEngine: {
        type: Boolean,
        default: false
    },
    enableLinkvertise: {
        type: Boolean,
        default: true
    },
    linkvertiseId: {
        type: String,
        default: '5373913'
    },
    adNetworkBaseUrl: {
        type: String,
        default: 'https://link-to.net/{{ID}}/dynamic?r={{URL}}'
    },
    socialLinks: {
        youtube: { type: String, default: 'https://youtube.com/@gplmods', trim: true },
        discord: { type: String, default: 'https://discord.gg/d7FEDp4vm', trim: true },
        github: { type: String, default: 'https://github.com/GPLMods-Team', trim: true },
        twitter: { type: String, default: 'https://x.com/GPLMods', trim: true },
        linkedin: { type: String, default: 'https://in.linkedin.com/in/gpl-mods-05a22a403', trim: true },
        reddit: { type: String, default: 'https://www.reddit.com/user/GPLMods', trim: true },
        instagram: { type: String, default: 'https://www.instagram.com/gplmods', trim: true },
        facebook: { type: String, default: 'https://www.facebook.com/profile.php?id=61572148715492', trim: true },
        threads: { type: String, default: 'https://threads.net/gplmods', trim: true },
        gravatar: { type: String, default: 'https://gravatar.com/theoristcandid03a1c47c5b', trim: true }
    },
    weeklyPlaylist: [{
        title: { type: String },
        src: { type: String }
    }],
    enableGeminiChatbot: {
        type: Boolean,
        default: true
    },
    geminiHiddenPages: [{
        type: String,
        trim: true
    }],
    debuggerHourlyKey: {
        type: String,
        default: null
    },
    debuggerHourlyKeyExpiresAt: {
        type: Date,
        default: null
    },
    debuggerMasterKey: {
        type: String,
        default: 'T1BBZG1pbkAyMDI2'
    },
    enableDevtoolProtection: {
        type: Boolean,
        default: true
    },
}, { timestamps: true });

module.exports = mongoose.model('SiteState', SiteStateSchema);
