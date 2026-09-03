const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const DraftSnapshotSchema = new Schema({
    file: { type: Schema.Types.ObjectId, ref: 'File', required: true, index: true },
    createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    label: { type: String, default: 'Autosaved draft' },
    data: { type: Schema.Types.Mixed, required: true }
}, { timestamps: true });

DraftSnapshotSchema.index({ file: 1, createdAt: -1 });

module.exports = mongoose.model('DraftSnapshot', DraftSnapshotSchema);
