const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const IssueSchema = new Schema({
    title: { type: String, required: true, trim: true },
    slug: { type: String, required: true, unique: true }, // For SEO friendly URLs
    
    content: { type: String, required: true }, // Will hold the rich HTML from Quill.js
    
    author: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    
    category: { 
        type: String, 
        required: true,
        enum: ['general', 'mod-help', 'bug-report', 'request', 'tutorial'] 
    },
    
    status: { 
        type: String, 
        enum: ['open', 'resolved', 'closed'], 
        default: 'open' 
    },
    
    views: { type: Number, default: 0 }
    
}, { timestamps: true });

module.exports = mongoose.model('Issue', IssueSchema);