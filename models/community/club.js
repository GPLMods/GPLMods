const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ClubSchema = new Schema({
    name: {
        type: String,
        required: true,
        trim: true,
        unique: true,
        maxlength: 80
    },
    slug: {
        type: String,
        required: true,
        trim: true,
        unique: true,
        lowercase: true,
        index: true
    },
    description: {
        type: String,
        default: '',
        maxlength: 1000
    },
    tags: {
        type: [String],
        default: [],
        validate: [v => v.length <= 10, 'A club can have a maximum of 10 tags.']
    },
    iconUrl: {
        type: String,
        default: '/images/default-avatar.png'
    },
    bannerUrl: {
        type: String,
        default: '/images/default-banner.jpg'
    },
    creator: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    isDefault: {
        type: Boolean,
        default: false,
        index: true
    },
    isPrivate: {
        type: Boolean,
        default: false,
        index: true
    },
    joinApprovalRequired: {
        type: Boolean,
        default: false
    },
    primaryLanguage: {
        type: String,
        default: 'English',
        trim: true
    },
    country: {
        type: String,
        default: 'GLOBAL',
        trim: true
    },
    aboutAdmin: {
        type: String,
        default: '',
        maxlength: 1500
    },
    rules: {
        type: [String],
        default: [
            'Be respectful to all members and staff.',
            'No spamming, flooding, or offensive content.',
            'Only GPLMods official links are allowed.',
            'Follow community safety and moderation guidelines.'
        ]
    },
    storageFolderName: {
        type: String,
        required: true
    },
    storagePath: {
        type: String,
        required: true
    },
    trackedCreators: [{
        type: Schema.Types.ObjectId,
        ref: 'User'
    }],
    memberCount: {
        type: Number,
        default: 1
    },
    channelCount: {
        type: Number,
        default: 0
    },
    isVerified: {
        type: Boolean,
        default: false
    },
    settings: {
        allowMemberInvites: { type: Boolean, default: true },
        allowMemberPolls: { type: Boolean, default: true },
        autoTranslateEnabled: { type: Boolean, default: true }
    }
}, {
    timestamps: true
});

ClubSchema.index({ name: 'text', description: 'text', tags: 'text' });

module.exports = mongoose.model('Club', ClubSchema);
