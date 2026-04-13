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
    // Optional: If a registered user subscribes, we can link their account
    user: { 
        type: Schema.Types.ObjectId, 
        ref: 'User',
        default: null
    },
    isSubscribed: {
        type: Boolean,
        default: true
    },
    // To track when they signed up and from what page
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