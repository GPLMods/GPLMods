const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const DocCategorySchema = new Schema({
    name: { 
        type: String, 
        required: true, 
        trim: true 
    },
    // To order the categories in the sidebar (e.g., 1 for 'Getting Started', 2 for 'Android')
    order: { 
        type: Number, 
        default: 0 
    }
}, { timestamps: true });

module.exports = mongoose.model('DocCategory', DocCategorySchema);