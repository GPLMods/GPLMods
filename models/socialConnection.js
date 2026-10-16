const mongoose = require('mongoose');

const socialConnectionSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    platform: {
        type: String,
        enum: ['discord', 'telegram', 'reddit'],
        required: true
    },
    socialId: {
        type: String,
        required: true,
        trim: true,
        index: true
    },
    socialUsername: {
        type: String,
        default: ''
    },
    authCode: {
        type: String,
        default: null,
        index: true
    },
    authCodeExpiresAt: {
        type: Date,
        default: null
    },
    dailySearchCount: {
        type: Number,
        default: 0
    },
    dailySupportCount: {
        type: Number,
        default: 0
    },
    lastResetDate: {
        type: String,
        default: () => new Date().toISOString().split('T')[0]
    },
    connectedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Ensure a user can only connect one account per platform
socialConnectionSchema.index({ user: 1, platform: 1 }, { unique: true });
socialConnectionSchema.index({ platform: 1, socialId: 1 }, { unique: true, sparse: true });

module.exports = mongoose.model('SocialConnection', socialConnectionSchema);
