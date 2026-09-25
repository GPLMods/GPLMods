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
    originalAmount: { type: Number },
    discountAmount: { type: Number, default: 0 },
    couponCode: { type: String, default: null },
    currency: { type: String, default: 'INR' },
    tier: { type: String, enum: ['lite', 'plus', 'premium'], default: 'plus' },
    duration: { 
        type: String, 
        enum: [
            'monthly', '6months', 'yearly', 'lifetime',
            'lite_monthly', 'lite_6months', 'lite_yearly',
            'plus_monthly', 'plus_6months', 'plus_yearly', 'plus_lifetime'
        ], 
        required: true 
    },
    status: { 
        type: String, 
        enum: ['pending', 'paid', 'failed', 'cancelled', 'refund_requested', 'refunded'], 
        default: 'pending' 
    },
    autoRenew: { type: Boolean, default: true },
    refundStatus: { 
        type: String, 
        enum: ['none', 'pending', 'approved', 'rejected'], 
        default: 'none' 
    },
    refundRequestedAt: { type: Date },
    refundProcessedAt: { type: Date },
    refundAmount: { type: Number, default: 0 },
    refundReason: { type: String, default: '' },
    scheduledPlanChange: { type: Schema.Types.Mixed, default: null },
    paymentMethod: { type: String },
    membershipExpiresAt: { type: Date },
    rawWebhookData: { type: Schema.Types.Mixed }
}, { timestamps: true });

module.exports = mongoose.model('MembershipOrder', MembershipOrderSchema);
