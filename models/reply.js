const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ReplySchema = new Schema({
    issue: { type: Schema.Types.ObjectId, ref: 'Issue', required: true },
    author: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    
    content: { type: String, required: true }, // Rich HTML from Quill.js
    
    isSolution: { type: Boolean, default: false }, // Marked true if this fixed the issue
    
    isAdminReply: { type: Boolean, default: false } // To highlight admin responses visually
    
}, { timestamps: true });

module.exports = mongoose.model('Reply', ReplySchema);