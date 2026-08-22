const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const NewsletterCampaignSchema = new Schema({
    subject: { type: String, required: true },
    template: {
        type: String,
        enum: ['standard-update', 'new-mod-alert', 'special-announcement'],
        default: 'standard-update'
    },
    audience: {
        type: String,
        enum: ['all-subscribers', 'registered-only', 'guests-only', 'premium-only', 'test-admin-only'],
        default: 'test-admin-only'
    },
    content: { type: String, required: true },
    callToActionUrl: { type: String },
    callToActionText: { type: String, default: 'Read More' },
    status: {
        type: String,
        enum: ['draft', 'sending', 'sent', 'failed'],
        default: 'draft'
    },
    sentCount: { type: Number, default: 0 }
}, { timestamps: true });

module.exports = mongoose.model('NewsletterCampaign', NewsletterCampaignSchema);
