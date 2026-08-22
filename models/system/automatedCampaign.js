const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const AutomatedCampaignSchema = new Schema({
    title: { type: String, required: true },
    notificationTitle: { type: String, required: true },
    notificationMessage: { type: String, required: true },
    notificationType: {
        type: String,
        enum: ['info', 'warning', 'success', 'error'],
        default: 'info'
    },
    targetGroup: {
        type: String,
        enum: ['all-users', 'premium-only', 'distributors-only', 'android-uploaders', 'ios-uploaders'],
        default: 'all-users'
    },
    scheduledDate: { 
        type: Date, 
        required: true 
    },
    status: {
        type: String,
        enum: ['scheduled', 'processing', 'completed', 'cancelled'],
        default: 'scheduled'
    }
}, { timestamps: true });

module.exports = mongoose.model('AutomatedCampaign', AutomatedCampaignSchema);
