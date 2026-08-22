const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const SubscriberSchema = new Schema({
    email: { 
        type: String, 
        required: true, 
        unique: true, 
        trim: true, 
        lowercase: true 
    },
    user: { 
        type: Schema.Types.ObjectId, 
        ref: 'User',
        default: null
    },
    isSubscribed: {
        type: Boolean,
        default: true
    },
    subscribedAt: {
        type: Date,
        default: Date.now
    },
    source: {
        type: String,
        default: 'popup'
    }
}, { timestamps: true });

module.exports = mongoose.model('Subscriber', SubscriberSchema);
