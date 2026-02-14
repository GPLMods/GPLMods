const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: false
    },
    googleId: {
        type: String
    },
    role: {
        type: String,
        enum: ['member', 'admin'],
        default: 'member'
    },
    membership: {
        type: String,
        enum: ['free', 'premium'],
        default: 'free'
    },
    profileImageUrl: {
        type: String,
        default: ''
    },
    bio: {
        type: String,
        trim: true,
        maxlength: 250
    },
    lastSeen: {
        type: Date,
        default: Date.now
    },
    whitelist: [{
        type: Schema.Types.ObjectId,
        ref: 'File'
    }],
    isVerified: {
        type: Boolean,
        default: false
    },
    // --- NEW OTP FIELDS ---
    verificationOtp: {
        type: String
    },
    otpExpires: {
        type: Date
    },
    // --- NEW FIELDS ADDED FOR PASSWORD RESET ---
    passwordResetToken: {
        type: String
    },
    passwordResetExpires: {
        type: Date
    }
}, { timestamps: true }); // <--- Schema closes here, followed by options

// Pre-save hook to hash the password before saving a new user
UserSchema.pre('save', async function(next) {
    if (!this.isModified('password')) {
        return next();
    }
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Method to compare candidate password with the stored hashed password
UserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);
