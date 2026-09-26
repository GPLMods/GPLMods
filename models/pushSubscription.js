const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const PushSubscriptionSchema = new Schema({
    user: { 
        type: Schema.Types.ObjectId, 
        ref: 'User', 
        default: null 
    },
    endpoint: { 
        type: String, 
        required: true, 
        unique: true 
    },
    keys: {
        p256dh: { type: String, required: true },
        auth: { type: String, required: true }
    },
    preferences: {
        newUploads: { type: Boolean, default: true },
        clubUpdates: { type: Boolean, default: true },
        adminMessages: { type: Boolean, default: true },
        soundEnabled: { type: Boolean, default: true }
    },
    userAgent: { type: String, default: '' },
    lastNotifiedAt: { type: Date, default: null }
}, { timestamps: true });

// Index endpoint for ultra-fast lookup
PushSubscriptionSchema.index({ endpoint: 1 });
PushSubscriptionSchema.index({ user: 1 });

module.exports = mongoose.model('PushSubscription', PushSubscriptionSchema);
