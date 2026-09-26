const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ClubRoleSchema = new Schema({
    club: {
        type: Schema.Types.ObjectId,
        ref: 'Club',
        required: true,
        index: true
    },
    name: {
        type: String,
        required: true,
        trim: true,
        maxlength: 40
    },
    color: {
        type: String,
        default: '#99aab5',
        trim: true
    },
    badgeIcon: {
        type: String,
        default: '🔰'
    },
    position: {
        type: Number,
        default: 0
    },
    isDefault: {
        type: Boolean,
        default: false
    },
    permissions: {
        canManageClub: { type: Boolean, default: false },
        canManageChannels: { type: Boolean, default: false },
        canManageRoles: { type: Boolean, default: false },
        canKickMembers: { type: Boolean, default: false },
        canSendMessages: { type: Boolean, default: true },
        canPostPolls: { type: Boolean, default: true },
        canAuditPrivate: { type: Boolean, default: false }
    }
}, {
    timestamps: true
});

ClubRoleSchema.index({ club: 1, position: -1 });

module.exports = mongoose.model('ClubRole', ClubRoleSchema);
