const mongoose = require('mongoose');
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    avatar: { type: String, default: '/resources/images/default-avatar.png' },
    isVerified: { type: Boolean, default: false },
    emailVerificationToken: String,
    createdAt: { type: Date, default: Date.now }
});
module.exports = mongoose.model('User', UserSchema);