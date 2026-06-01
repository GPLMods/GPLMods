const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const DailyStatSchema = new Schema({
    file: { type: Schema.Types.ObjectId, ref: 'File', required: true },
    uploader: { type: String, required: true },
    dateString: { type: String, required: true }, // Format: "YYYY-MM-DD"
    views: { type: Number, default: 0 },
    downloads: { type: Number, default: 0 }
});

// Index to ensure we only have one document per file, per day for fast updating
DailyStatSchema.index({ file: 1, dateString: 1 }, { unique: true });

module.exports = mongoose.model('DailyStat', DailyStatSchema);