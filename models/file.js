const mongoose = require('mongoose');

const FileSchema = new mongoose.Schema({
    name: { type: String, required: true },
    version: { type: String, required: true },
    modDescription: { type: String, required: true },
    officialDescription: { type: String },
    
    // --- FIELD NAME UPDATES ---
    // Change 'Url' to 'Key' to better represent the data stored
    iconKey: { type: String, required: true },
    screenshotKeys: { type: [String], required: true },
    videoUrl: { type: String }, // YouTube/Vimeo URLs are already public
    fileKey: { type: String, required: true },

    category: { type: String, required: true, enum: ['windows', 'android', 'ios', 'wordpress'] },
    platforms: { type: [String], required: true },
    tags: { type: [String] },

    fileSize: { type: Number, required: true },
    
    // ADD THIS NEW FIELD
    originalFilename: { type: String, required: true },

    uploader: { type: String, default: "Anonymous" }, // Will later be a mongoose.Schema.Types.ObjectId
    
    // Tracking & Stats
    downloads: { type: Number, default: 0 },
    ratings: { type: Number, default: 0 },
    virusTotalAnalysisId: { type: String },

}, { timestamps: true }); // Automatically adds createdAt and updatedAt fields

module.exports = mongoose.model('File', FileSchema);