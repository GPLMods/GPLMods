const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ReactionSchema = new Schema({
    emoji: {
        type: String,
        required: true,
        trim: true
    },
    users: [{
        type: Schema.Types.ObjectId,
        ref: 'User'
    }]
}, { _id: false });

const PollOptionSchema = new Schema({
    text: {
        type: String,
        required: true,
        trim: true
    },
    votes: [{
        type: Schema.Types.ObjectId,
        ref: 'User'
    }]
});

const PollSchema = new Schema({
    question: {
        type: String,
        required: true,
        trim: true
    },
    options: [PollOptionSchema],
    closed: {
        type: Boolean,
        default: false
    },
    expiresAt: {
        type: Date
    }
}, { _id: false });

const ModUpdateEmbedSchema = new Schema({
    modId: {
        type: Schema.Types.ObjectId,
        ref: 'File'
    },
    name: String,
    iconUrl: String,
    version: String,
    category: String,
    downloadUrl: String,
    changelog: String,
    isNewUpload: {
        type: Boolean,
        default: true
    }
}, { _id: false });

const ClubMessageSchema = new Schema({
    club: {
        type: Schema.Types.ObjectId,
        ref: 'Club',
        required: true,
        index: true
    },
    channel: {
        type: Schema.Types.ObjectId,
        ref: 'ClubChannel',
        required: true,
        index: true
    },
    sender: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: function() { return !this.isSystemMessage; }
    },
    content: {
        type: String,
        default: '',
        maxlength: 3000
    },
    translatedContent: {
        type: Map,
        of: String,
        default: {}
    },
    reactions: [ReactionSchema],
    poll: PollSchema,
    modUpdate: ModUpdateEmbedSchema,
    isSystemMessage: {
        type: Boolean,
        default: false
    }
}, {
    timestamps: true
});

ClubMessageSchema.index({ channel: 1, createdAt: -1 });

module.exports = mongoose.model('ClubMessage', ClubMessageSchema);
