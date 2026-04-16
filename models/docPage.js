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
    }, // This will hold the Rich Text HTML
    order: { 
        type: Number, 
        default: 0 
    } // To order pages within a category
}, { timestamps: true });

module.exports = mongoose.model('DocPage', DocPageSchema);