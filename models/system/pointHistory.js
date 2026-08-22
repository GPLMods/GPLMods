const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const PointHistorySchema = new Schema({
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    amount: { type: Number, required: true },
    reason: { type: String, required: true },
    customMessage: { type: String, default: '' }
}, { timestamps: true });

module.exports = mongoose.model('PointHistory', PointHistorySchema);
