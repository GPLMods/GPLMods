const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const DonationSchema = new Schema({
    // If the user is logged in, link it to their account
    user: { type: Schema.Types.ObjectId, ref: 'User', default: null },
    username: { type: String, default: 'Guest' },
    
    amount: { type: Number, required: true }, // Store in base currency (e.g., USD or INR)
    currency: { type: String, default: 'INR' },
    
    transactionId: { type: String },
    status: { type: String, enum: ['pending', 'successful', 'failed'], default: 'pending' }
}, { timestamps: true });

module.exports = mongoose.model('Donation', DonationSchema);