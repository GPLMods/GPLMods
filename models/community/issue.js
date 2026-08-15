const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const IssueSchema = new Schema({
    title: { type: String, required: true, trim: true },
    slug: { type: String, required: true, unique: true },
    
    content: { type: String, required: true },
    
    author: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    
    category: { 
        type: String, 
        required: true,
        enum: ['general', 'mod-help', 'bug-report', 'request', 'tutorial'] 
    },
    
    status: { 
        type: String, 
        enum: ['open', 'solved', 'unsolved', 're-open'], 
        default: 'open' 
    },
    
    mediaKeys: [{ type: String }],

    views: { type: Number, default: 0 }
    
}, { timestamps: true });

module.exports = mongoose.model('Issue', IssueSchema);
