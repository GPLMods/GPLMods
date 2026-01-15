const mongoose = require('mongoose');
const { Schema } = mongoose; // Destructured Schema for easier access

const FileSchema = new Schema({
    name: { type: String, required: true },
    version: { type: String, required: true },
    modDescription: { type: String, required: true },
    officialDescription: { type: String },
    
    // --- STORAGE KEYS (S3/Cloud) ---
    iconKey: { type: String, required: true },
    screenshotKeys: { type: [String], required: true },
    videoUrl: { type: String }, 
    fileKey: { type: String, required: true },

    // --- CATEGORIZATION ---
    category: { 
        type: String, 
        required: true, 
        enum: ['windows', 'android', 'ios', 'wordpress'] 
    },
    subCategory: { 
        type: String 
    },
    platforms: { type: [String], required: true },
    tags: { type: [String] },

    // --- FILE INFO ---
    fileSize: { type: Number, required: true },
    originalFilename: { type: String, required: true },
    uploader: { type: String, default: "Anonymous" },
    developer: {
        type: String,
        trim: true,
        default: 'N/A' // Name of the original creator/developer
    },

    // --- VERSION CONTROL SYSTEM ---
    isLatestVersion: {
        type: Boolean,
        default: true
    },
    // Links a new version to its original "parent" entry
    parentFile: {
        type: Schema.Types.ObjectId,
        ref: 'File',
        default: null
    },
    // Array on the parent file linking to all its child versions
    olderVersions: [{
        type: Schema.Types.ObjectId,
        ref: 'File'
    }],
    
    // --- TRACKING, STATS & RATINGS ---
    downloads: { type: Number, default: 0 },
    averageRating: { 
        type: Number, 
        default: 0 
    },
    ratingCount: { 
        type: Number, 
        default: 0 
    },
    whitelistCount: {
        type: Number,
        default: 0
    },

    // --- WORKING STATUS VOTES ---
    workingVoteCount: {
        type: Number,
        default: 0
    },
    notWorkingVoteCount: {
        type: Number,
        default: 0
    },
    // Array to store the IDs of users who have voted on this file's status
    votedOnStatusBy: [{
        type: Schema.Types.ObjectId,
        ref: 'User'
    }],

    certification: {
        type: String,
        enum: ['none', 'certified', 'community-tested'],
        default: 'none'
    },

    virusTotalScanDate: {
        type: Date
    },
    virusTotalPositiveCount: {
        type: Number,
        default: 0
    },
    virusTotalTotalScans: {
        type: Number,
        default: 0
    },

    virusTotalAnalysisId: { type: String },

}, { timestamps: true }); // Adds createdAt and updatedAt automatically

module.exports = mongoose.model('File', FileSchema);