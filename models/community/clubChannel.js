const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ClubChannelSchema = new Schema({
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
        lowercase: true,
        maxlength: 50
    },
    topic: {
        type: String,
        default: '',
        maxlength: 300
    },
    type: {
        type: String,
        enum: ['text', 'announcements', 'rules', 'new-uploads', 'new-updates', 'polls'],
        default: 'text'
    },
    isPrivate: {
        type: Boolean,
        default: false
    },
    allowedRoles: [{
        type: Schema.Types.ObjectId,
        ref: 'ClubRole'
    }],
    isReadOnly: {
        type: Boolean,
        default: false
    },
    position: {
        type: Number,
        default: 0
    }
}, {
    timestamps: true
});

ClubChannelSchema.index({ club: 1, name: 1 });

module.exports = mongoose.model('ClubChannel', ClubChannelSchema);
