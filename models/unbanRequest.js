const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UnbanRequestSchema = new Schema({
    user: { 
        type: Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    username: { type: String, required: true },
    email: { type: String, required: true },
    appealMessage: { type: String, required: true },
    status: {
        type: String,
        enum: ['pending', 'reviewed', 'rejected'],
        default: 'pending'
    }
}, { timestamps: true });

module.exports = mongoose.model('UnbanRequest', UnbanRequestSchema);