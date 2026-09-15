const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const MembershipOrderSchema = new Schema({
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    orderId: { type: String, required: true, unique: true, index: true },
    subscriptionId: { type: String, index: true },
    planId: { type: String },
    isSubscription: { type: Boolean, default: false },
    paymentSessionId: { type: String },
    subscriptionSessionId: { type: String },
    cfPaymentId: { type: String },
    amount: { type: Number, required: true },
    currency: { type: String, default: 'INR' },
    duration: { 
        type: String, 
        enum: ['monthly', '6months', 'yearly', 'lifetime'], 
        required: true 
    },
    status: { 
        type: String, 
        enum: ['pending', 'paid', 'failed', 'cancelled'], 
        default: 'pending' 
    },
    paymentMethod: { type: String },
    membershipExpiresAt: { type: Date },
    rawWebhookData: { type: Schema.Types.Mixed }
}, { timestamps: true });

module.exports = mongoose.model('MembershipOrder', MembershipOrderSchema);
