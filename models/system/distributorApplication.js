const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const DistributorApplicationSchema = new Schema({
    user: { 
        type: Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    username: { type: String, required: true },
    email: { type: String, required: true },
    organizationName: { type: String, required: true, trim: true },
    primaryDistributionPlatform: { 
        type: String, 
        enum:['Telegram Channel', 'Website', 'Discord Server', 'YouTube Channel', 'Other'],
        required: true 
    },
    platformUrl: { type: String, required: true },
    monetizationMethod: { type: String, required: true },
    adminContactName: { type: String, required: true },
    adminSocialLink: { type: String, required: true },
    socialTelegram: { type: String },
    socialDiscord: { type: String },
    socialWebsite: { type: String },
    socialYoutube: { type: String },
    agreedToTerms: { type: Boolean, required: true },
    status: {
        type: String,
        enum: ['pending', 'under-review', 'approved', 'rejected'],
        default: 'pending'
    },
    adminNotes: { type: String },
    proofMediaKeys: [{ type: String }]
}, { timestamps: true });

module.exports = mongoose.model('DistributorApplication', DistributorApplicationSchema);
