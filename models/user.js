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
    // ======== NEW: REFERRAL SYSTEM ========
    referralCode: {
        type: String,
        unique: true,
        sparse: true // Allows nulls while ensuring uniqueness for existing codes
    },
    referredBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
    },
    referralCount: {
        type: Number,
        default: 0
    },
    // ======================================
profileImageKey: {
    type: String // Stores the path like 'avatars/12345-image.png'
},
    bio: {
        type: String,
        trim: true,
        maxlength: 250
    },
 dateOfBirth: {
        type: Date
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
   following: [{
        type: Schema.Types.ObjectId,
        ref: 'User'
    }],
    followers: [{
        type: Schema.Types.ObjectId,
        ref: 'User'
    }],
    isVerified: {
        type: Boolean,
        default: false
    },
    // --- NEW: VERIFIED ACCOUNT BADGE ---
    isVerifiedAccount: {
        type: Boolean,
        default: false
    },
    verifiedBadgeText: {
        type: String,
        trim: true,
        default: 'Verified Mod Distributor'
    },
    // --- NEW: COUNTRY ---
    country: {
        type: String,
        trim: true,
        default: '' // Empty means no country selected
    },
    // ======== NEW: COMMUNITY FORUM GAMIFICATION ========
    forumPoints: {
        type: Number,
        default: 0
    },
    // ===================================================
// --- NEW FIELDS FOR DISTRIBUTORS AND ADMIN ---
    organizationName: { type: String },
    // Define the nested object correctly
    socialLinks: {
        telegram: { type: String, trim: true },
        discord: { type: String, trim: true },
        website: { type: String, trim: true },
        youtube: { type: String, trim: true }
    },
    // ---------------------------------------------
    // --- NEW OTP FIELDS ---
    verificationOtp: {
        type: String
    },
    // --- ADD THIS NEW FIELD ---
    isSubscribedToNewsletter: {
        type: Boolean,
        default: false
    },
    otpExpires: {
        type: Date
    },
// --- ADD THIS NEW FIELD ---
    activeSessionId: {
        type: String
    },
    // --- NEW FIELDS ADDED FOR PASSWORD RESET ---
    passwordResetToken: {
        type: String
    },
    passwordResetExpires: {
        type: Date
    },
    // --- NEW: SECURE DELETION ---
    deletionOtp: { type: String },
    deletionOtpExpires: { type: Date },

    // --- NEW: TWO-FACTOR AUTHENTICATION ---
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorMethod: { 
        type: String, 
        enum: ['none', 'email', 'totp', 'passkey', 'social'],
        default: 'none' 
    },
    twoFactorSecret: { type: String }, // Stores the TOTP secret key
    // ✅ ADD THIS NEW FIELD:
    twoFactorRecoveryCodes: [{ type: String }],
    // --- NEW: SOCIAL 2FA & PASSKEYS ---
    twoFactorSocialProvider: { 
        type: String, 
        enum: ['google', 'github', 'microsoft', 'none'], 
        default: 'none' 
    },
    // Passkeys require storing a credential ID, Public Key, and Counter
    passkeys: [{
        credentialID: String,
        credentialPublicKey: String,
        counter: Number,
        transports: [String]
    }],
    // Temporary challenge string used during WebAuthn handshakes
    webAuthnChallenge: { type: String }, 
    // ----------------------------------------
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

// Helper methods for safe forum point adjustments
UserSchema.statics.adjustForumPoints = async function(userId, delta) {
    if (!userId || typeof delta !== 'number') return null;
    const user = await this.findById(userId);
    if (!user) return null;
    user.forumPoints = Math.max(0, (user.forumPoints || 0) + delta);
    await user.save();
    return user;
};

UserSchema.statics.awardForumPoints = function(userId, amount = 0) {
    return this.adjustForumPoints(userId, Math.max(0, amount));
};

UserSchema.statics.deductForumPoints = function(userId, amount = 0) {
    return this.adjustForumPoints(userId, -Math.abs(amount));
};

// Ensure forum points never go negative before saving
UserSchema.pre('save', async function() {
    if (typeof this.forumPoints === 'number' && this.forumPoints < 0) {
        this.forumPoints = 0;
    }
});

// --- VIRTUAL: Calculate Forum Rank dynamically based on points ---
UserSchema.virtual('forumRank').get(function() {
    const pts = this.forumPoints || 0;
    
    // Customize your points thresholds and colors here!
    if (pts >= 1000) return { name: 'Diamond Expert', color: '#003e54', lottie: 'level-5.json' };
    if (pts >= 500)  return { name: 'Platinum Expert', color: '#770087', lottie: 'level-4.json' };
    if (pts >= 250)  return { name: 'Gold Expert', color: '#FFD700', lottie: 'level-3.json' };
    if (pts >= 100)  return { name: 'Silver Expert', color: '#c0c0c0', lottie: 'level-2.json' };
    if (pts >= 25)   return { name: 'Bronze Member', color: '#cd7f32', lottie: 'level-1.json' };
    
    return { name: 'Novice', color: 'var(--silver)', lottie: null }; // Default
});

// Ensure virtuals are included when converting to JSON/Objects
UserSchema.set('toObject', { virtuals: true });
UserSchema.set('toJSON', { virtuals: true });

module.exports = mongoose.model('User', UserSchema);
