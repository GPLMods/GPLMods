const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const TranslationQuotaSchema = new Schema({
    monthYear: { 
        type: String, 
        required: true, 
        unique: true // Format: "YYYY-MM" (e.g., "2026-06")
    },
    characterCount: { 
        type: Number, 
        default: 0 
    }
}, { timestamps: true });

module.exports = mongoose.model('TranslationQuota', TranslationQuotaSchema);