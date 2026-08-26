const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const SourceCodeSchema = new Schema({
    title: { type: String, required: true, trim: true },
    slug: { type: String, required: true, unique: true, lowercase: true, trim: true },

    githubOwner: { type: String, required: true, trim: true },
    githubRepo: { type: String, required: true, trim: true },
    isPrivate: { type: Boolean, default: false },

    description: { type: String, default: '', trim: true },

    allowedRoles: [{
        type: String,
        enum: ['member', 'distributor', 'admin']
    }],
    allowedUsers: [{
        type: Schema.Types.ObjectId,
        ref: 'User'
    }],

    status: {
        type: String,
        enum: ['live', 'hidden'],
        default: 'live'
    }
}, { timestamps: true });

module.exports = mongoose.model('SourceCode', SourceCodeSchema);
