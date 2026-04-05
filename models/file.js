const mongoose = require('mongoose');
const { Schema } = mongoose; // Destructured Schema for easier access

const FileSchema = new Schema({
    // --- DYNAMICALLY REQUIRED FIELDS ---
    // These are NOT required during the initial 'processing' step, 
    // but they ARE required once the user submits the final form.
    name: { type: String, required: function() { return this.status !== 'processing'; } },
 // --- NEW: THE URL SLUG ---
    slug: { 
        type: String, 
        lowercase: true,
        trim: true,
        // It's not required during initial 'processing'
    },
    version: { type: String, required: function() { return this.status !== 'processing'; } },
    modDescription: { type: String, required: function() { return this.status !== 'processing'; } },
    modFeatures: { type: String, required: function() { return this.status !== 'processing'; } },
    officialDescription: { type: String },
    whatsNew: { type: String },
// --- NEW: IMPORTANT NOTE FIELD ---
    importantNote: { 
        type: String,
        trim: true
    },
    
    // --- STORAGE KEYS (S3/Cloud) ---
    iconKey: { type: String, required: function() { return this.status !== 'processing'; } },
    screenshotKeys: { type: [String], required: function() { return this.status !== 'processing'; } },
    videoUrl: { type: String }, 
    
    // Make fileKey optional ONLY IF an external link is provided
    fileKey: { type: String, required: function() { return !this.externalDownloadUrl && this.status !== 'processing'; } }, 
    
    // --- ADD EXTERNAL LINK FIELD ---
    externalDownloadUrl: { type: String, trim: true },

// --- NEW: MULTI-PART DOWNLOADS ---
    isMultiPart: {
        type: Boolean,
        default: false
    },
    downloadParts: [{
        partName: { type: String, required: true }, // e.g., "Part 1 (5GB)"
        partUrl: { type: String, required: true }   // e.g., Google Drive link
    }],
    installationInstructions: {
        type: String,
        default: 'Extract all parts into the same folder and run the installer.'
    },

    // --- CATEGORIZATION ---
    category: { 
        type: String, 
        required: function() { return this.status !== 'processing'; }, 
        enum:['windows', 'android', 'ios-jailed', 'ios-jailbroken', 'wordpress'] 
    },
    subCategory: { 
        type: String 
    },
    platforms: { type: [String], required: function() { return this.status !== 'processing'; } },
    tags: { type: [String] },

    // --- FILE INFO ---
    // Make these optional if using an external link
    fileSize: { type: Number, required: function() { return !this.externalDownloadUrl && this.status !== 'processing'; }, default: 0 },
    originalFilename: { type: String, required: function() { return !this.externalDownloadUrl && this.status !== 'processing'; }, default: 'External File' },
    uploader: { type: String, default: "Anonymous" },
    developer: {
        type: String,
        trim: true,
        default: 'N/A' // Name of the original creator/developer
    },

    // --- VERSION & VARIANT CONTROL SYSTEM ---
    isLatestVersion: {
        type: Boolean,
        default: true
    },
    parentFile: {
        type: Schema.Types.ObjectId,
        ref: 'File',
        default: null
    },
    olderVersions: [{
        type: Schema.Types.ObjectId,
        ref: 'File'
    }],
    
    // --- NEW: VARIANT SYSTEM ---
    isVariant: {
        type: Boolean,
        default: false
    },
    // The "Master" file that holds the main description and icon
    masterFile: {
        type: Schema.Types.ObjectId,
        ref: 'File',
        default: null
    },
    // An array on the Master file linking to all its alternative variants
    variants: [{
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
showInSitemap: {
        type: Boolean,
        default: true // Automatically true for new uploads
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