const mongoose = require('mongoose');
const { Schema } = mongoose;

const ModPromotionSchema = new Schema({
    file: {
        type: Schema.Types.ObjectId,
        ref: 'File',
        required: true,
        index: true
    },
    user: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    days: {
        type: Number,
        required: true,
        min: 1
    },
    amount: {
        type: Number,
        required: true,
        default: 0
    },
    currency: {
        type: String,
        default: 'INR',
        enum: ['INR', 'USD']
    },
    tier: {
        type: String,
        enum: ['standard', 'featured', 'spotlight'],
        default: 'standard'
    },
    startDate: {
        type: Date,
        default: Date.now
    },
    endDate: {
        type: Date,
        required: true,
        index: true
    },
    status: {
        type: String,
        enum: ['pending', 'active', 'expired', 'cancelled'],
        default: 'active',
        index: true
    },
    paymentMethod: {
        type: String,
        default: 'simulated'
    },
    paymentOrderId: {
        type: String,
        default: null
    },
    impressions: {
        type: Number,
        default: 0
    },
    clicks: {
        type: Number,
        default: 0
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('ModPromotion', ModPromotionSchema);
