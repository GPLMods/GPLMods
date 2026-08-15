const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const DocCategorySchema = new Schema({
    name: { 
        type: String, 
        required: true, 
        trim: true 
    },
    order: { 
        type: Number, 
        default: 0 
    }
}, { timestamps: true });

module.exports = mongoose.model('DocCategory', DocCategorySchema);
