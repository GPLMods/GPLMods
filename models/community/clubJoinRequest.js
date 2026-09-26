const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ClubJoinRequestSchema = new Schema({
    club: {
        type: Schema.Types.ObjectId,
        ref: 'Club',
        required: true,
        index: true
    },
    user: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending'
    },
    message: {
        type: String,
        default: '',
        maxlength: 500
    },
    reviewedBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
    },
    reviewedAt: {
        type: Date
    }
}, {
    timestamps: true
});

ClubJoinRequestSchema.index({ club: 1, user: 1, status: 1 });

module.exports = mongoose.model('ClubJoinRequest', ClubJoinRequestSchema);
