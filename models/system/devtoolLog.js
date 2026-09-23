const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const DevtoolLogSchema = new Schema({
    ip: { 
        type: String, 
        trim: true 
    },
    userAgent: { 
        type: String 
    },
    user: { 
        type: Schema.Types.ObjectId, 
        ref: 'User', 
        default: null 
    },
    username: { 
        type: String, 
        default: 'Guest' 
    },
    url: { 
        type: String 
    },
    path: { 
        type: String 
    },
    triggerType: { 
        type: String, 
        default: 'devtool-opened' 
    },
    status: {
        type: String,
        enum: ['blocked', 'authorized-by-code', 'authorized-by-master-key', 'cleared'],
        default: 'blocked'
    },
    accessCodeUsed: { 
        type: String, 
        default: null 
    },
    screenDetails: { 
        type: Schema.Types.Mixed 
    },
    resolvedAt: { 
        type: Date, 
        default: null 
    }
}, { timestamps: true });

// Index for efficient audit queries and sorting
DevtoolLogSchema.index({ createdAt: -1 });

module.exports = mongoose.model('DevtoolLog', DevtoolLogSchema);
