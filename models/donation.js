const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const DonationSchema = new Schema({
    // If the user is logged in, link it to their account
    user: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    username: { type: String, default: 'Guest' },
    
    amount: { type: Number, required: true }, // Store in base currency (e.g., USD or INR)
    currency: { type: String, default: 'INR' },
    
    orderId: { type: String, index: true },
    paymentSessionId: { type: String },
    cfPaymentId: { type: String },
    paymentMethod: { type: String },
    donorEmail: { type: String },
    donorPhone: { type: String },
    transactionId: { type: String },
    guestId: { type: String, index: true, default: null },
    donorIp: { type: String, default: null },
    status: { type: String, enum: ['pending', 'successful', 'failed'], default: 'pending' }
}, { timestamps: true });

module.exports = mongoose.model('Donation', DonationSchema);