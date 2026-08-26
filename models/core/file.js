const mongoose = require('mongoose');
const { Schema } = mongoose;

const FileSchema = new Schema({
    name: { type: String, required: function() { return this.status !== 'processing' && this.status !== 'draft'; } },
    slug: { 
        type: String, 
        lowercase: true,
        trim: true,
    },
    version: { type: String, required: function() { return this.status !== 'processing' && this.status !== 'draft'; } },
    modDescription: { type: String, required: function() { return this.status !== 'processing' && this.status !== 'draft'; } },
    modFeatures: { type: String, required: function() { return this.status !== 'processing' && this.status !== 'draft'; } },
    officialDescription: { type: String },
    whatsNew: { type: String },
    importantNote: { type: String, trim: true },

    ageRating: {
        type: String,
        enum:['NA', '3+', '7+', '12+', '16+', '18+'],
        default: 'NA'
    },
    
    iconKey: { type: String, required: function() { return this.status !== 'processing' && this.status !== 'draft'; } },
    screenshotKeys: { type: [String], required: function() { return this.status !== 'processing' && this.status !== 'draft'; } },
    videoUrl: { type: String }, 
    directDownloadUrl: { type: String, trim: true },
    iosPackageId: { type: String, trim: true },   
    fileKey: { type: String, required: function() { return !this.externalDownloadUrl && this.status !== 'processing'; } }, 
    
    externalDownloadUrl: { type: String, trim: true },
    customAdLink: { type: String, trim: true },
    manualFileScanUrl: { type: String, trim: true },
    manualSiteScanUrl: { type: String, trim: true },
    alternativeLinks:[{
        providerName: { type: String, required: true },
        url: { type: String, required: true }
    }],

    isMultiPart: {
        type: Boolean,
        default: false
    },
    downloadParts: [{
        partName: { type: String, required: true },
        partUrl: { type: String, required: true },
        mirror1Provider: { type: String, trim: true },
        mirror1Url: { type: String, trim: true },
        mirror2Provider: { type: String, trim: true },
        mirror2Url: { type: String, trim: true },
        directAdminLink: { type: String, trim: true },
        manualFileScanUrl: { type: String, trim: true },
        manualSiteScanUrl: { type: String, trim: true },
        partVirusTotalId: { type: String, trim: true },
        partVirusTotalScanDate: { type: Date },
        partVirusTotalPositiveCount: { type: Number, default: 0 },
        partVirusTotalTotalScans: { type: Number, default: 0 }
    }],
    installationInstructions: {
        type: String,
        default: 'Extract all parts into the same folder and run the installer.'
    },

    category: { type: String, required: function() { return this.status !== 'processing' && this.status !== 'draft'; }, enum:['windows', 'android', 'ios-jailed', 'ios-jailbroken', 'wordpress', 'n/a'] },
    license: {
        type: Schema.Types.ObjectId,
        ref: 'License',
        default: null
    },
    subCategory: { type: String },
    platforms: { type: [String], required: function() { return this.status !== 'processing' && this.status !== 'draft'; } },
    tags: { type: [String] },
    architectures: { 
        type: [String], 
        default:[] 
    },
    minOsVersion: { 
        type: String, 
        trim: true,
        default: ''
    },

    fileSize: { type: Number, required: function() { return !this.externalDownloadUrl && this.status !== 'processing'; }, default: 0 },
    originalFilename: { type: String, required: function() { return !this.externalDownloadUrl && this.status !== 'processing'; }, default: 'External File' },
    uploader: { type: String, default: "GPL Community" },
    developer: {
        type: String,
        trim: true,
        default: 'N/A'
    },

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
    
    isVariant: {
        type: Boolean,
        default: false
    },
    masterFile: {
        type: Schema.Types.ObjectId,
        ref: 'File',
        default: null
    },
    variants: [{
        type: Schema.Types.ObjectId,
        ref: 'File'
    }],
    
    downloads: { type: Number, default: 0 },
    averageRating: { 
        type: Number, 
        default: 0 
    },
    views: { 
        type: Number, 
        default: 0 
    },
    viewedBy: [{ 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User' 
    }],
    downloadedBy: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    ratingCount: { 
        type: Number, 
        default: 0 
    },
    whitelistCount: {
        type: Number,
        default: 0
    },

    workingVoteCount: {
        type: Number,
        default: 0
    },
    notWorkingVoteCount: {
        type: Number,
        default: 0
    },
    votedWorkingBy: [{
        type: Schema.Types.ObjectId,
        ref: 'User'
    }],
    votedNotWorkingBy: [{
        type: Schema.Types.ObjectId,
        ref: 'User'
    }],

    certification: {
        type: String,
        enum:['none', 'certified', 'community-tested'],
        default: 'none'
    },
    isEditorsChoice: {
        type: Boolean,
        default: false
    },
    editorsChoiceDescription: {
        type: String,
        trim: true
    },

    status: {
        type: String,
        enum: ['processing', 'pending', 'live', 'rejected', 'draft'], 
        default: 'pending'
    },
    rejectionReason: {
        type: String,
        trim: true
    },
    showInSitemap: {
        type: Boolean,
        default: true
    },
    showInRepo: {
        type: Boolean,
        default: true
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
    
}, { 
    timestamps: true 
}); 

module.exports = mongoose.model('File', FileSchema);
