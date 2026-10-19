const mongoose = require('mongoose');

const keywordCacheSchema = new mongoose.Schema({
    key: { 
        type: String, 
        required: true, 
        unique: true, 
        index: true 
    },
    modId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'File', 
        index: true, 
        default: null 
    },
    type: { 
        type: String, 
        enum: ['mod_keywords', 'google_suggest', 'ddg_suggest', 'search_console', 'global_pool'],
        default: 'mod_keywords',
        index: true 
    },
    keywords: { 
        type: [String], 
        default: [] 
    },
    lastFetchedAt: { 
        type: Date, 
        default: Date.now,
        index: true 
    }
}, { 
    timestamps: true 
});

module.exports = mongoose.model('KeywordCache', keywordCacheSchema);
