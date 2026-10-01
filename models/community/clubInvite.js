const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ClubInviteSchema = new Schema({
    club: {
        type: Schema.Types.ObjectId,
        ref: 'Club',
        required: true,
        index: true
    },
    inviter: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true,
        index: true
    },
    code: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        index: true
    },
    uses: {
        type: Number,
        default: 0
    },
    maxUses: {
        type: Number,
        default: null
    },
    expiresAt: {
        type: Date,
        default: null
    }
}, {
    timestamps: true
});

module.exports = mongoose.model('ClubInvite', ClubInviteSchema);
