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
    officialLink: { type: String, required: true },
    existingModLink: { type: String },
    
    platform: {
        type: String,
        enum:['android', 'ios-jailed', 'ios-jailbroken', 'windows', 'wordpress', 'other'],
        required: true
    },
    
    requestedVersion: { type: String },
    modFeaturesRequested: { type: String, required: true },
    additionalNotes: { type: String },
    
    status: {
        type: String,
        enum:['pending', 'in-progress', 'completed', 'rejected'],
        default: 'pending'
    },
    
    adminNotes: { type: String },
    mediaKeys: [{ type: String }]

}, { timestamps: true });

module.exports = mongoose.model('Request', RequestSchema);
