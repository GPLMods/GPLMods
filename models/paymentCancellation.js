const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const PaymentCancellationSchema = new Schema({
    orderId: { type: String, index: true },
    type: { 
        type: String, 
        enum: ['membership', 'donation', 'volunteer', 'subscription', 'other'], 
        default: 'membership' 
    },
    user: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    username: { type: String, default: 'Guest' },
    reason: { 
        type: String, 
        required: true,
        enum: [
            "Don't want to purchase it",
            "Don't find payment method I need",
            "Click by mistake",
            "Network issue",
            "Other",
            "Pricing too high / Looking for discount",
            "Timed out after 10 minutes"
        ]
    },
    notes: { type: String, default: '', trim: true },
    amount: { type: Number, default: 0 },
    currency: { type: String, default: 'INR' },
    ipAddress: { type: String, default: null },
    userAgent: { type: String, default: null }
}, { timestamps: true });

module.exports = mongoose.model('PaymentCancellation', PaymentCancellationSchema);
