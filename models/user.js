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
    githubId: {
        type: String
    },
    microsoftId: {
        type: String
    },
    role: {
        type: String,
        enum: ['member', 'distributor', 'admin'],
        default: 'member'
    },
isBanned: {
        type: Boolean,
        default: false
    },
    banReason: {
        type: String,
        trim: true,
        default: ''
    },
    membership: {
        type: String,
        enum: ['free', 'premium'],
        default: 'free'
    },
profileImageKey: {
    type: String // Stores the path like 'avatars/12345-image.png'
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
    whitelist: {
        type: [Schema.Types.ObjectId],
        ref: 'File',
        default:[]
    },
    isVerified: {
        type: Boolean,
        default: false
    },
// --- NEW FIELDS FOR DISTRIBUTORS ---
    organizationName: { type: String },
    socialLinks: {
        telegram: { type: String },
        discord: { type: String },
        website: { type: String },
        youtube: { type: String }
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

// Modern Pre-save hook: No need for 'next' when using async/await!
UserSchema.pre('save', async function() {
    // If password is not modified, just return and let Mongoose continue
    if (!this.isModified('password')) {
        return;
    }
    
    // Hash the password
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// Method to compare candidate password with the stored hashed password
UserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);
