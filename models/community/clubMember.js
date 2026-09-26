const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ClubMemberSchema = new Schema({
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
    roles: [{
        type: Schema.Types.ObjectId,
        ref: 'ClubRole'
    }],
    isCreator: {
        type: Boolean,
        default: false
    },
    status: {
        type: String,
        enum: ['active', 'pending_approval', 'banned'],
        default: 'active'
    },
    joinedAt: {
        type: Date,
        default: Date.now
    },
    invitedBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
    }
}, {
    timestamps: true
});

ClubMemberSchema.index({ club: 1, user: 1 }, { unique: true });

module.exports = mongoose.model('ClubMember', ClubMemberSchema);
