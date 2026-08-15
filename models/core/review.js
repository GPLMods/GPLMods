const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ReviewSchema = new Schema({
    file: { 
        type: Schema.Types.ObjectId, 
        ref: 'File', 
        required: true 
    },
    user: { 
        type: Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    username: { 
        type: String, 
        required: true 
    },
    rating: {
        type: Number,
        required: true,
        min: 1,
        max: 5
    },
    comment: {
        type: String,
        required: true,
        trim: true
    },
    isHelpfulCount: {
        type: Number,
        default: 0
    },
    uploaderReply: {
        text: { type: String, trim: true },
        createdAt: { type: Date }
    },
    votedBy: {
        type: [Schema.Types.ObjectId],
        ref: 'User',
        default:[]
    }
}, { timestamps: true });

module.exports = mongoose.model('Review', ReviewSchema);
