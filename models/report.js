const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ReportSchema = new Schema({
    // Link to the File being reported
    file: { 
        type: Schema.Types.ObjectId, 
        ref: 'File', 
        required: true 
    },
    // Link to the User who submitted the report
    reportingUser: { 
        type: Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    // For easy display
    reportedFileName: {
        type: String,
        required: true
    },
    reportingUsername: {
        type: String,
        required: true
    },
    reason: {
        type: String,
        required: true,
        enum: ['malware', 'broken-file', 'incorrect-info', 'copyright', 'other'] // Predefined reasons
    },
    additionalComments: {
        type: String,
        trim: true
    },
    status: {
        type: String,
        enum: ['open', 'resolved', 'ignored'],
        default: 'open'
    }
}, { timestamps: true });

module.exports = mongoose.model('Report', ReportSchema);