const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const DocPageSchema = new Schema({
    title: { 
        type: String, 
        required: true, 
        trim: true 
    },
    slug: { 
        type: String, 
        required: true, 
        unique: true, 
        trim: true, 
        lowercase: true 
    },
    category: { 
        type: Schema.Types.ObjectId, 
        ref: 'DocCategory', 
        required: true 
    },
    content: { 
        type: String, 
        required: true 
    },
    featuredImageKey: { 
        type: String, 
        description: 'Direct URL or Backblaze B2 key for the cover image' 
    },
    order: { 
        type: Number, 
        default: 0 
    }
}, { timestamps: true });

module.exports = mongoose.model('DocPage', DocPageSchema);
