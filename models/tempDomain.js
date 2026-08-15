const mongoose = require('mongoose');
const Schema = mongoose.Schema;

/**
 * TempDomain Schema
 * Stores cached domain check results from TempMailDetector API.
 */
const TempDomainSchema = new Schema({
    domain: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true,
        index: true
    },
    score: {
        type: Number,
        required: true,
        default: 0
    },
    isDisposable: {
        type: Boolean,
        required: true,
        default: false
    },
    block_list: {
        type: Boolean,
        default: false
    },
    domain_age: {
        type: Number,
        default: -1
    },
    website_resolves: {
        type: Boolean,
        default: false
    },
    accepts_all_addresses: {
        type: Boolean,
        default: false
    },
    valid_email_security: {
        type: Boolean,
        default: false
    },
    forwarding: {
        type: Boolean,
        default: false
    },
    rawMeta: {
        type: Object,
        default: {}
    },
    checkedAt: {
        type: Date,
        default: Date.now
    }
}, { timestamps: true });

module.exports = mongoose.model('TempDomain', TempDomainSchema);
