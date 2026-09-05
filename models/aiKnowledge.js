const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const AIKnowledgeSchema = new Schema({
    topic: { type: String, required: true },
    keywords: { type: String, required: true, description: "Comma separated keywords" },
    response: { type: String, required: true },
    isActive: { type: Boolean, default: true }
}, { timestamps: true });

module.exports = mongoose.model('AIKnowledge', AIKnowledgeSchema);
