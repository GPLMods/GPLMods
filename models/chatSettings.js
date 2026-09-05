const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ChatSettingsSchema = new Schema({
    singletonId: { type: String, default: 'chat-settings', unique: true },
    headerColor: { type: String, default: '#0a0a0a' },
    headerImageUrl: { type: String, default: '' },
    botName: { type: String, default: 'GPL Assistant' },
    botAvatar: { type: String, default: '/images/team-logo.png' },
    isEnabled: { type: Boolean, default: true }
});

module.exports = mongoose.model('ChatSettings', ChatSettingsSchema);
