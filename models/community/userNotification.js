const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const UserNotificationSchema = new Schema({
    user: { 
        type: Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    title: { 
        type: String, 
        required: true 
    },
    message: { 
        type: String, 
        required: true 
    },
    type: {
        type: String,
        enum: ['info', 'warning', 'success', 'error', 'mod-update-request'],
        default: 'info'
    },
    isRead: {
        type: Boolean,
        default: false
    },
    metadata: {
        file: { type: Schema.Types.ObjectId, ref: 'File' },
        requester: { type: Schema.Types.ObjectId, ref: 'User' }
    }
}, { timestamps: true });

module.exports = mongoose.model('UserNotification', UserNotificationSchema);
