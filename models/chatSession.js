const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ChatSessionSchema = new Schema({
    // If null, it's a guest
    user: { type: Schema.Types.ObjectId, ref: 'User' },
    guestEmail: { type: String, trim: true },
    guestId: { type: String }, // Browser fingerprint or socket ID
    adminNotes: { type: String, default: '' },

    status: { 
        type: String, 
        enum: ['bot', 'waiting-for-agent', 'active-agent', 'closed'], 
        default: 'bot' 
    },
    assignedTo: { type: Schema.Types.ObjectId, ref: 'User' }, // The support member handling it

    messages: [{
        sender: { type: String, enum: ['user', 'bot', 'agent', 'system'] },
        senderName: { type: String },
        text: { type: String },
        mediaUrls: [{ type: String }], // For premium/distributor images/videos
        timestamp: { type: Date, default: Date.now }
    }],

    // --- AUTO-DELETE LOGIC ---
    // MongoDB will automatically delete this document when the current time reaches this date
    expiresAt: { type: Date, required: true }

}, { timestamps: true });

// Create the TTL Index in MongoDB
ChatSessionSchema.index({ "expiresAt": 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('ChatSession', ChatSessionSchema);
