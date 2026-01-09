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
        required: true
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
        default: '' // Default to an empty string (or a URL to a default avatar)
    },
    // --- NEW FIELD ADDED ---
    whitelist: [{
        type: Schema.Types.ObjectId,
        ref: 'File'
    }],
    // -----------------------
    isVerified: {
        type: Boolean,
        default: false
    },
    verificationToken: {
        type: String
    }
}, { timestamps: true });

// Pre-save hook to hash the password before saving a new user
UserSchema.pre('save', async function(next) {
    // Only hash the password if it has been modified (or is new)
    if (!this.isModified('password')) {
        return next();
    }
    try {
        const salt = await bcrypt.genSalt(10); // Generate a salt
        this.password = await bcrypt.hash(this.password, salt); // Hash the password
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