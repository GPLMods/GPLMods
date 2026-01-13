const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const DmcaSchema = new Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true },
    copyrightHolder: { type: String, required: true },
    originalWorkUrl: { type: String, required: true },
    infringingUrl: { type: String, required: true },
    signature: { type: String, required: true },
    status: {
        type: String,
        enum: ['open', 'action-taken', 'rejected'],
        default: 'open'
    }
}, { timestamps: true });
module.exports = mongoose.model('Dmca', DmcaSchema);