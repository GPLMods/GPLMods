const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const Schema = mongoose.Schema;

const UserSchema = new Schema({
    // --- AUTHENTICATION FIELDS ---
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: false
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
        required: false,
        default: null
    },
    // --- SOCIAL LOGIN IDs ---
    googleId: {
        type: String,
        default: null
    },
    githubId: {
        type: String,
        default: null
    },
    microsoftId: {
        type: String,
        default: null
    },
    // --- ACCOUNT STATUS ---
    role: {
        type: String,
        enum: ['member', 'distributor', 'admin'],
        default: 'member'
    },
    isBanned: {
        type: Boolean,
        default: false,
        index: true
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
    isVerified: {
        type: Boolean,
        default: false,
        index: true
    },
    // --- PROFILE INFORMATION ---
    profileImageKey: {
        type: String,
        default: null
    },
    bio: {
        type: String,
        trim: true,
        maxlength: 250,
        default: ''
    },
    dateOfBirth: {
        type: Date,
        default: null
    },
    organizationName: {
        type: String,
        trim: true,
        default: null
    },
    // --- SOCIAL LINKS ---
    socialLinks: {
        type: {
            telegram: {
                type: String,
                trim: true,
                default: null
            },
            discord: {
                type: String,
                trim: true,
                default: null
            },
            website: {
                type: String,
                trim: true,
                default: null
            },
            youtube: {
                type: String,
                trim: true,
                default: null
            }
        },
        default: {}
    },
    // --- USER RELATIONSHIPS ---
    whitelist: {
        type: [{
            type: Schema.Types.ObjectId,
            ref: 'File'
        }],
        default: []
    },
    following: {
        type: [{
            type: Schema.Types.ObjectId,
            ref: 'User'
        }],
        default: []
    },
    followers: {
        type: [{
            type: Schema.Types.ObjectId,
            ref: 'User'
        }],
        default: []
    },
    // --- OTP & PASSWORD RESET ---
    verificationOtp: {
        type: String,
        default: null
    },
    otpExpires: {
        type: Date,
        default: null
    },
    passwordResetToken: {
        type: String,
        default: null
    },
    passwordResetExpires: {
        type: Date,
        default: null
    },
    // --- ACTIVITY TRACKING ---
    lastSeen: {
        type: Date,
        default: Date.now,
        index: true
    }
}, { 
    timestamps: true,
    collection: 'users'
}); // <--- Schema closes here, followed by options

// --- PRE-SAVE MIDDLEWARE ---
UserSchema.pre('save', async function() {
    // If password is not modified, just return and let Mongoose continue
    if (!this.isModified('password') || !this.password) {
        return;
    }
    
    // Hash the password
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

// --- INSTANCE METHODS ---
UserSchema.methods.comparePassword = async function(candidatePassword) {
    if (!this.password || !candidatePassword) return false;
    return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', UserSchema);
