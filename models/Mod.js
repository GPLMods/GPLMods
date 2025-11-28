// models/Mod.js

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ModSchema = new Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    slug: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    description: {
        type: String,
        required: true
    },
    appDescription: {
        type: String,
        required: true
    },
    platform: {
        type: String,
        required: true,
        enum: ['android', 'ios-jailed', 'ios-jailbroken', 'windows', 'wordpress']
    },
    category: {
        type: String,
        required: true
    },
    version: {
        type: String,
        required: true
    },
    fileType: {
        type: String,
        required: true
    },
    modType: {
        type: String,
        required: true
    },
    modFilePath: {
        type: String,
        required: true
    },
    iconPath: {
        type: String,
        required: true
    },
    screenshotPaths: [{
        type: String
    }],
    isFeatured: {
        type: Boolean,
        default: false
    },
    status: {
        type: String,
        enum: ['pending', 'live', 'rejected'],
        default: 'pending'
    },
    uploader: {
        type: Schema.Types.ObjectId,
        ref: 'User', // This links the mod to a user in your Users collection
        required: true
    },
    downloads: {
        type: Number,
        default: 0
    },
    ratingValue: {
        type: Number,
        default: 4.5,
        min: 1,
        max: 5
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
});

module.exports = mongoose.model('Mod', ModSchema);