const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// This model stores translations to prevent unnecessary API calls to Google
const TranslationCacheSchema = new Schema({
    originalText: { type: String, required: true, index: true },
    targetLanguage: { type: String, required: true, index: true },
    translatedText: { type: String, required: true }
});

// Compound index to quickly find a specific string in a specific language
TranslationCacheSchema.index({ originalText: 1, targetLanguage: 1 }, { unique: true });

module.exports = mongoose.model('TranslationCache', TranslationCacheSchema);