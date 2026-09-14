const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const SourceCodeSchema = new Schema({
    title: { type: String, required: true, trim: true },
    slug: { type: String, required: true, unique: true, lowercase: true, trim: true },

    githubOwner: { type: String, required: true, trim: true, lowercase: true },
    githubRepo: { type: String, required: true, trim: true, lowercase: true },
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

// Pre-save sanitization: strip any leading URL prefixes and force clean lowercase identifiers
SourceCodeSchema.pre('save', function(next) {
    if (this.githubOwner) {
        this.githubOwner = this.githubOwner.replace(/^https?:\/\/github\.com\//i, '').replace(/\/.*$/, '').trim().toLowerCase();
    }
    if (this.githubRepo) {
        this.githubRepo = this.githubRepo.replace(/^https?:\/\/github\.com\/[^/]+\//i, '').replace(/\.git$/i, '').replace(/\/.*$/, '').trim().toLowerCase();
    }
    if (this.slug) {
        this.slug = this.slug.trim().toLowerCase();
    }
    next();
});

module.exports = mongoose.model('SourceCode', SourceCodeSchema);
