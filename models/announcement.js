const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const AnnouncementSchema = new Schema({
    title: { type: String, required: true },
    content: { type: String, required: true },
    author: { type: String, required: true }
}, { timestamps: true });
module.exports = mongoose.model('Announcement', AnnouncementSchema);