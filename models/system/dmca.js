const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const DmcaSchema = new Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true },
    copyrightHolder: { type: String, required: true },
    originalWorkUrl: { type: String, required: true },
    infringingUrl: { type: String, required: true },
    infringingUrls: [{ type: String }],
    reportedFiles: [{
        file: { type: Schema.Types.ObjectId, ref: 'File' },
        originalUrl: { type: String },
        targetType: { type: String, enum: ['main', 'variant'], default: 'main' },
        isHidden: { type: Boolean, default: false },
        originalStatus: { type: String },
        promotedVariant: { type: Schema.Types.ObjectId, ref: 'File', default: null }
    }],
    signature: { type: String, required: true },
    scheduledHideAt: { type: Date },
    isAutomatedHidden: { type: Boolean, default: false },
    hiddenAt: { type: Date },
    status: {
        type: String,
        enum: ['open', 'auto-hidden', 'action-taken', 'false-claim', 'rejected'],
        default: 'open'
    },
    adminResolution: {
        resolvedBy: { type: String },
        resolvedAt: { type: Date },
        resolutionType: { type: String },
        notes: { type: String }
    },
    proofMediaKeys: [{ type: String }]
}, { timestamps: true });

module.exports = mongoose.model('Dmca', DmcaSchema);
