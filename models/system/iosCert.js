const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const IosCertSchema = new Schema({
    name: { type: String, required: true },
    status: { type: String, enum: ['Signed', 'Revoked'], default: 'Signed' },
    
    apps: [{
        appName: { type: String, required: true },
        iconUrl: { type: String },
        plistUrl: { type: String, required: true }
    }],
    mediaKeys: [{ type: String }]
}, { timestamps: true });

module.exports = mongoose.model('IosCert', IosCertSchema);
