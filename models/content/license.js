const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const LicenseSchema = new Schema({
    name: { type: String, required: true, unique: true, trim: true },
    slug: { type: String, required: true, unique: true, trim: true, lowercase: true },
    shortDescription: { type: String, default: '', trim: true },
    content: { type: String, required: true }
}, { timestamps: true });

module.exports = mongoose.model('License', LicenseSchema);