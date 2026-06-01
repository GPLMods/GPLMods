const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const PointHistorySchema = new Schema({
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true }, // e.g., 50 (earned) or -10 (deducted)
    reason: { type: String, required: true }, // e.g., "Uploaded a Mod", "Admin Reward"
    customMessage: { type: String, default: '' } // For admin notes
}, { timestamps: true });

module.exports = mongoose.model('PointHistory', PointHistorySchema);