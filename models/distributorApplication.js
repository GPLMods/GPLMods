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
    
    // Organization Details
    organizationName: { type: String, required: true, trim: true },
    primaryDistributionPlatform: { 
        type: String, 
        enum:['Telegram Channel', 'Website', 'Discord Server', 'YouTube Channel', 'Other'],
        required: true 
    },
    platformUrl: { type: String, required: true }, // Link to their Telegram/Website
    
    // Monetization Details
    monetizationMethod: { type: String, required: true }, // e.g., "Linkvertise", "10drives", "Direct Ads"
    
    // Admin Contact
    adminContactName: { type: String, required: true },
    adminSocialLink: { type: String, required: true }, // e.g., Telegram username, Twitter profile
    
    // Social Links for their Profile (Optional but encouraged)
    socialTelegram: { type: String },
    socialDiscord: { type: String },
    socialWebsite: { type: String },
    socialYoutube: { type: String },

    // Agreement & Status
    agreedToTerms: { type: Boolean, required: true },
    status: {
        type: String,
        enum: ['pending', 'under-review', 'approved', 'rejected'],
        default: 'pending'
    },
    adminNotes: { type: String } // For internal admin use

}, { timestamps: true });

module.exports = mongoose.model('DistributorApplication', DistributorApplicationSchema);