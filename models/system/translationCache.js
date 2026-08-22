const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const TranslationCacheSchema = new Schema({
    originalText: { type: String, required: true, index: true },
    targetLanguage: { type: String, required: true, index: true },
    translatedText: { type: String, required: true }
});

TranslationCacheSchema.index({ originalText: 1, targetLanguage: 1 }, { unique: true });

module.exports = mongoose.model('TranslationCache', TranslationCacheSchema);
