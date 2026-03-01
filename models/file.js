const mongoose = require('mongoose');
const { Schema } = mongoose; // Destructured Schema for easier access

const FileSchema = new Schema({
    // --- DYNAMICALLY REQUIRED FIELDS ---
    // These are NOT required during the initial 'processing' step, 
    // but they ARE required once the user submits the final form.
    name: { type: String, required: function() { return this.status !== 'processing'; } },
    version: { type: String, required: function() { return this.status !== 'processing'; } },
    modDescription: { type: String, required: function() { return this.status !== 'processing'; } },
    modFeatures: { type: String, required: function() { return this.status !== 'processing'; } },
    officialDescription: { type: String },
    whatsNew: { type: String },
    
    // --- STORAGE KEYS (S3/Cloud) ---
    iconKey: { type: String, required: function() { return this.status !== 'processing'; } },
    screenshotKeys: { type: [String], required: function() { return this.status !== 'processing'; } },
    videoUrl: { type: String }, 
    fileKey: { type: String, required: true }, // This is always required from Step 1

    // --- CATEGORIZATION ---
    category: { 
        type: String, 
        required: function() { return this.status !== 'processing'; }, 
        enum:['windows', 'android', 'ios', 'wordpress'] 
    },
    subCategory: { 
        type: String 
    },
    platforms: { type: [String], required: function() { return this.status !== 'processing'; } },
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
    votedOnStatusBy:[{
        type: Schema.Types.ObjectId,
        ref: 'User'
    }],

    certification: {
        type: String,
        enum:['none', 'certified', 'community-tested'],
        default: 'none'
    },

    status: {
        type: String,
        // ADDED 'processing' to the enum array so Mongoose doesn't reject it
        enum: ['processing', 'pending', 'live', 'rejected'], 
        default: 'pending' // All new uploads will require admin approval
    },
    rejectionReason: { // To store why a mod was rejected
        type: String,
        trim: true
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
    virusTotalId: { type: String },
    
// The first argument (schema definition) ends here
}, { 
    // The second argument is for options, like timestamps
    timestamps: true 
}); 

module.exports = mongoose.model('File', FileSchema);