const mongoose = require('mongoose');
const { Schema } = mongoose;

const FileSchema = new Schema({
    // --- CORE METADATA ---
    name: {
        type: String,
        required: function() { return this.status !== 'processing' && this.status !== 'draft'; },
        trim: true
    },
    slug: {
        type: String,
        lowercase: true,
        trim: true,
        sparse: true,
        index: true
    },
    version: {
        type: String,
        required: function() { return this.status !== 'processing' && this.status !== 'draft'; },
        trim: true
    },
    // --- DESCRIPTIONS & CONTENT ---
    modDescription: {
        type: String,
        required: function() { return this.status !== 'processing' && this.status !== 'draft'; },
        default: ''
    },
    modFeatures: {
        type: String,
        required: function() { return this.status !== 'processing' && this.status !== 'draft'; },
        default: ''
    },
    officialDescription: {
        type: String,
        default: '',
        trim: true
    },
    whatsNew: {
        type: String,
        default: '',
        trim: true
    },
    importantNote: {
        type: String,
        trim: true,
        default: ''
    },
    // --- AGE RATING ---
    ageRating: {
        type: String,
        enum: ['NA', '3+', '7+', '12+', '16+', '18+'],
        default: 'NA'
    },
    // --- MEDIA & STORAGE ---
    iconKey: {
        type: String,
        required: function() { return this.status !== 'processing' && this.status !== 'draft'; },
        default: null
    },
    screenshotKeys: {
        type: [{
            type: String,
            trim: true
        }],
        required: function() { return this.status !== 'processing' && this.status !== 'draft'; },
        default: []
    },
    videoUrl: {
        type: String,
        trim: true,
        default: null
    },
    // --- FILE STORAGE & DOWNLOADS ---
    fileKey: {
        type: String,
        required: function() { return !this.externalDownloadUrl && this.status !== 'processing'; },
        default: null
    },
    fileSize: {
        type: Number,
        required: function() { return !this.externalDownloadUrl && this.status !== 'processing'; },
        default: 0
    },
    originalFilename: {
        type: String,
        required: function() { return !this.externalDownloadUrl && this.status !== 'processing'; },
        default: 'External File'
    },
    externalDownloadUrl: {
        type: String,
        trim: true,
        default: null
    },
    customAdLink: {
        type: String,
        trim: true,
        default: null
    },
    manualFileScanUrl: {
        type: String,
        trim: true,
        default: null
    },
    manualSiteScanUrl: {
        type: String,
        trim: true,
        default: null
    },
    // --- ALTERNATIVE DOWNLOAD LINKS ---
    alternativeLinks: {
        type: [{
            providerName: {
                type: String,
                required: true,
                trim: true
            },
            url: {
                type: String,
                required: true,
                trim: true
            }
        }],
        default: []
    },
    // --- MULTI-PART DOWNLOADS ---
    isMultiPart: {
        type: Boolean,
        default: false
    },
    downloadParts: {
        type: [{
            partName: {
                type: String,
                required: true,
                trim: true
            },
            partUrl: {
                type: String,
                required: true,
                trim: true
            },
            partVirusTotalId: {
                type: String,
                trim: true,
                default: null
            },
            partVirusTotalScanDate: {
                type: Date,
                default: null
            },
            partVirusTotalPositiveCount: {
                type: Number,
                default: 0
            },
            partVirusTotalTotalScans: {
                type: Number,
                default: 0
            }
        }],
        default: []
    },
    installationInstructions: {
        type: String,
        default: 'Extract all parts into the same folder and run the installer.'
    },
    // --- CATEGORIZATION ---
    category: {
        type: String,
        required: function() { return this.status !== 'processing' && this.status !== 'draft'; },
        enum: ['windows', 'android', 'ios-jailed', 'ios-jailbroken', 'wordpress', 'n/a'],
        index: true
    },
    subCategory: {
        type: String,
        trim: true,
        default: null
    },
    platforms: {
        type: [{
            type: String,
            trim: true
        }],
        required: function() { return this.status !== 'processing' && this.status !== 'draft'; },
        default: []
    },
    tags: {
        type: [{
            type: String,
            trim: true,
            lowercase: true
        }],
        default: []
    },
    // --- DEVELOPER INFO ---
    uploader: {
        type: String,
        default: 'GPL Community',
        trim: true
    },
    developer: {
        type: String,
        trim: true,
        default: 'N/A'
    },
    // --- VERSION & VARIANT CONTROL ---
    isLatestVersion: {
        type: Boolean,
        default: true,
        index: true
    },
    parentFile: {
        type: Schema.Types.ObjectId,
        ref: 'File',
        default: null
    },
    olderVersions: {
        type: [{
            type: Schema.Types.ObjectId,
            ref: 'File'
        }],
        default: []
    },
    isVariant: {
        type: Boolean,
        default: false,
        index: true
    },
    masterFile: {
        type: Schema.Types.ObjectId,
        ref: 'File',
        default: null,
        index: true
    },
    variants: {
        type: [{
            type: Schema.Types.ObjectId,
            ref: 'File'
        }],
        default: []
    },
    // --- STATS & RATINGS ---
    downloads: {
        type: Number,
        default: 0,
        index: true
    },
    averageRating: {
        type: Number,
        default: 0,
        min: 0,
        max: 5
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
    votedOnStatusBy: {
        type: [{
            type: Schema.Types.ObjectId,
            ref: 'User'
        }],
        default: []
    },
    // --- CERTIFICATION & STATUS ---
    certification: {
        type: String,
        enum: ['none', 'certified', 'community-tested'],
        default: 'none'
    },
    status: {
        type: String,
        enum: ['processing', 'pending', 'live', 'rejected', 'draft'],
        default: 'pending',
        index: true
    },
    rejectionReason: {
        type: String,
        trim: true,
        default: ''
    },
    showInSitemap: {
        type: Boolean,
        default: true
    },
    // --- VIRUS TOTAL SCANNING ---
    virusTotalId: {
        type: String,
        default: null
    },
    virusTotalAnalysisId: {
        type: String,
        default: null
    },
    virusTotalScanDate: {
        type: Date,
        default: null
    },
    virusTotalPositiveCount: {
        type: Number,
        default: 0
    },
    virusTotalTotalScans: {
        type: Number,
        default: 0
    }
}, {
    timestamps: true,
    collection: 'files'
});

module.exports = mongoose.model('File', FileSchema);