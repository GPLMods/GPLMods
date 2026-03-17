const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const SupportTicketSchema = new Schema({
    user: { 
        type: Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    username: { type: String, required: true },
    email: { type: String, required: true },
    
    subject: { 
        type: String, 
        required: true,
        trim: true
    },
    category: {
        type: String,
        enum: ['account', 'upload-issue', 'download-issue', 'billing', 'bug-report', 'other'],
        required: true
    },
    message: { 
        type: String, 
        required: true 
    },
    status: {
        type: String,
        enum: ['open', 'in-progress', 'resolved', 'closed'],
        default: 'open'
    },
    adminNotes: { 
        type: String 
    } // For internal admin use
}, { timestamps: true });

module.exports = mongoose.model('SupportTicket', SupportTicketSchema);