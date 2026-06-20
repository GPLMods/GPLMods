const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const IosDnsSchema = new Schema({
    name: { type: String, required: true },
    description: { type: String, required: true },
    iconUrl: { type: String, default: 'https://cdn-icons-png.flaticon.com/512/3003/3003509.png' },
    configUrl: { type: String, required: true }, // Link to the .mobileconfig file
    isRecommended: { type: Boolean, default: false }
}, { timestamps: true });

module.exports = mongoose.model('IosDns', IosDnsSchema);