const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const RequestSchema = new Schema({
    user: { 
        type: Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    username: { type: String, required: true },
    
    requestType: {
        type: String,
        enum:['new-mod', 'update', 're-upload'],
        required: true
    },
    
    appName: { type: String, required: true },
    
    // The official link (Play Store, App Store, Steam, etc.)
    officialLink: { type: String, required: true },
    
    // If it's an update/re-upload, they can link to the existing mod on your site
    existingModLink: { type: String },
    
    platform: {
        type: String,
        enum:['android', 'ios-jailed', 'ios-jailbroken', 'windows', 'wordpress', 'other'],
        required: true
    },
    
    requestedVersion: { type: String }, // e.g., "v2.5.1"
    
    modFeaturesRequested: { type: String, required: true }, // e.g., "Unlimited money, unlocked premium"
    
    additionalNotes: { type: String },
    
    status: {
        type: String,
        enum:['pending', 'in-progress', 'completed', 'rejected'],
        default: 'pending'
    },
    
    adminNotes: { type: String } // For you to leave notes (e.g., "Working on it", "Not possible")

}, { timestamps: true });

module.exports = mongoose.model('Request', RequestSchema);