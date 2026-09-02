const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const StaticPageSchema = new Schema({
    slug: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    title: {
        type: String,
        required: true,
        trim: true
    },
    content: {
        type: String,
        required: true
    },
    isPublished: {
        type: Boolean,
        default: true
    }
}, { timestamps: true });

module.exports = mongoose.model('StaticPage', StaticPageSchema);
