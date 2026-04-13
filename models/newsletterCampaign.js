const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const NewsletterCampaignSchema = new Schema({
    subject: { type: String, required: true },
    
    // Which template to use (we will define these in our mailer utility)
    template: {
        type: String,
        enum: ['standard-update', 'new-mod-alert', 'special-announcement'],
        default: 'standard-update'
    },
    
    // Who receives the email
    audience: {
        type: String,
        enum: ['all-subscribers', 'registered-only', 'guests-only', 'premium-only', 'test-admin-only'],
        default: 'test-admin-only' // Default to test so you don't accidentally email everyone
    },

    // The main content of the email (HTML supported via AdminJS rich text)
    content: { type: String, required: true },
    
    // An optional link (e.g., to a specific mod or update page)
    callToActionUrl: { type: String },
    callToActionText: { type: String, default: 'Read More' },

    status: {
        type: String,
        enum: ['draft', 'sending', 'sent', 'failed'],
        default: 'draft'
    },
    
    // Tracking
    sentCount: { type: Number, default: 0 }

}, { timestamps: true });

module.exports = mongoose.model('NewsletterCampaign', NewsletterCampaignSchema);