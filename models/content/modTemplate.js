const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ModTemplateSchema = new Schema({
    title: { 
        type: String, 
        required: true, 
        trim: true 
    },
    targetField: { 
        type: String, 
        required: true, 
        enum: ['modDescription', 'modFeatures', 'importantNote', 'whatsNew'],
        default: 'modDescription' 
    },
    category: { 
        type: String, 
        enum: ['general', 'game', 'app', 'tool', 'guide', 'other'],
        default: 'general' 
    },
    content: { 
        type: String, 
        required: true 
    },
    isActive: { 
        type: Boolean, 
        default: true 
    },
    sortOrder: { 
        type: Number, 
        default: 0 
    }
}, { timestamps: true });

module.exports = mongoose.model('ModTemplate', ModTemplateSchema);
