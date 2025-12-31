const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ReviewSchema = new Schema({
    // Link to the File model
    file: { 
        type: Schema.Types.ObjectId, 
        ref: 'File', 
        required: true 
    },
    // Link to the User model
    user: { 
        type: Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    // The username is stored directly for easy display without extra database queries
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
    // An array that stores the user IDs of everyone who voted on this review
    // to prevent duplicate voting
    votedBy: [{
        type: Schema.Types.ObjectId,
        ref: 'User'
    }]
}, { timestamps: true });

module.exports = mongoose.model('Review', ReviewSchema);