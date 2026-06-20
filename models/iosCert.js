const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const IosCertSchema = new Schema({
    name: { type: String, required: true }, // e.g., "China CITIC Bank"
    status: { type: String, enum: ['Signed', 'Revoked'], default: 'Signed' },
    
    // We store an array of apps available under this certificate
    apps: [{
        appName: { type: String, required: true }, // e.g., "ESign", "Scarlet"
        iconUrl: { type: String },
        plistUrl: { type: String, required: true } // Link to the .plist manifest
    }]
}, { timestamps: true });

module.exports = mongoose.model('IosCert', IosCertSchema);