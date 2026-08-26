const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ApiLimitSchema = new Schema({
    service: {
        type: String,
        required: true,
        trim: true,
        lowercase: true
    },
    metric: {
        type: String,
        required: true,
        trim: true,
        lowercase: true
    },
    period: {
        type: String,
        enum: ['hourly', 'daily', 'weekly', 'monthly'],
        required: true
    },
    unit: {
        type: String,
        required: true,
        trim: true
    },
    resetDay: {
        type: Number,
        min: 1,
        max: 28,
        default: 1
    },
    rolling: {
        type: Boolean,
        default: false
    },
    trackingOnly: {
        type: Boolean,
        default: false
    },
    limit: {
        type: Number,
        required: true,
        min: 0
    },
    used: {
        type: Number,
        default: 0,
        min: 0
    },
    enabled: {
        type: Boolean,
        default: true
    },
    autoDisableOnError: {
        type: Boolean,
        default: true
    },
    autoDisabled: {
        type: Boolean,
        default: false
    },
    disabledReason: {
        type: String,
        default: ''
    },
    windowStart: {
        type: Date,
        required: true
    },
    windowEnd: {
        type: Date,
        required: true
    },
    lastErrorAt: Date
}, { timestamps: true });

ApiLimitSchema.index({ service: 1, metric: 1, period: 1 }, { unique: true });

module.exports = mongoose.model('ApiLimit', ApiLimitSchema);
