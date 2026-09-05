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
        enum: ['member', 'distributor', 'support', 'admin'],
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
    referralCode: {
        type: String,
        unique: true,
        sparse: true
    },
    referredBy: {
        type: Schema.Types.ObjectId,
        ref: 'User'
    },
    referralCount: {
        type: Number,
        default: 0
    },
    profileImageKey: {
        type: String
    },
    currentSessionId: {
        type: String
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
    isVerifiedAccount: {
        type: Boolean,
        default: false
    },
    verifiedBadgeText: {
        type: String,
        trim: true,
        default: 'Verified Mod Distributor'
    },
    country: {
        type: String,
        trim: true,
        default: ''
    },
    forumPoints: {
        type: Number,
        default: 0
    },
    organizationName: { type: String },
    socialLinks: {
        telegram: { type: String, trim: true },
        discord: { type: String, trim: true },
        website: { type: String, trim: true },
        youtube: { type: String, trim: true }
    },
    // Custom Work Email Fields (ImprovMX)
    customEmailAlias: { 
        type: String, 
        trim: true 
    },
    hasSmtpAccess: { 
        type: Boolean, 
        default: false 
    },
    verificationOtp: {
        type: String
    },
    isSubscribedToNewsletter: {
        type: Boolean,
        default: false
    },
    otpExpires: {
        type: Date
    },
    activeSessionId: {
        type: String
    },
    passwordResetToken: {
        type: String
    },
    passwordResetExpires: {
        type: Date
    },
    safetyEmailsEnabled: {
        type: Boolean,
        default: false
    },
    loginAlertEmailsEnabled: {
        type: Boolean,
        default: false
    },
    failedLoginAlertEmailsEnabled: {
        type: Boolean,
        default: false
    },
    autoSaveEnabled: {
        type: Boolean,
        default: false
    },
    failedLoginAttempts: {
        type: Number,
        default: 0
    },
    sessionVersion: {
        type: Number,
        default: 0
    },
    loginAlertTokens: [{
        token: { type: String, required: true },
        sessionId: String,
        deviceInfo: String,
        ipAddress: String,
        createdAt: { type: Date, default: Date.now },
        status: { type: String, enum: ['pending', 'verified', 'revoked'], default: 'pending' },
        respondedAt: { type: Date }
    }],
    deletionOtp: { type: String },
    deletionOtpExpires: { type: Date },

    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorMethod: { 
        type: String, 
        enum: ['none', 'email', 'totp', 'passkey', 'social'],
        default: 'none' 
    },
    twoFactorSecret: { type: String },
    twoFactorRecoveryCodes: [{ type: String }],
    twoFactorSocialProvider: { 
        type: String, 
        enum: ['google', 'github', 'microsoft', 'none'], 
        default: 'none' 
    },
    passkeys: [{
        credentialID: String,
        credentialPublicKey: String,
        counter: Number,
        transports: [String]
    }],
    webAuthnChallenge: { type: String }, 
}, { timestamps: true });

UserSchema.pre('save', async function() {
    if (!this.isModified('password')) {
        return;
    }
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
});

UserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

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

UserSchema.pre('save', async function() {
    if (typeof this.forumPoints === 'number' && this.forumPoints < 0) {
        this.forumPoints = 0;
    }
});

UserSchema.virtual('forumRank').get(function() {
    const pts = this.forumPoints || 0;
    if (pts >= 1000) return { name: 'Diamond Expert', color: '#003e54', lottie: 'level-5.json' };
    if (pts >= 500)  return { name: 'Platinum Expert', color: '#770087', lottie: 'level-4.json' };
    if (pts >= 250)  return { name: 'Gold Expert', color: '#FFD700', lottie: 'level-3.json' };
    if (pts >= 100)  return { name: 'Silver Expert', color: '#c0c0c0', lottie: 'level-2.json' };
    if (pts >= 25)   return { name: 'Bronze Member', color: '#cd7f32', lottie: 'level-1.json' };
    return { name: 'Novice', color: '#FFFFFF', lottie: null };
});

UserSchema.virtual('userCategory').get(function() {
    if (!this.isVerified) return 'unverified';
    if (this.role === 'admin') return 'admin';
    if (this.role === 'distributor') return 'distributor';
    if (this.membership === 'premium') return 'premium';
    return 'members';
});

UserSchema.statics.findByCategory = function(categoryQuery) {
    const cat = (categoryQuery || '').toLowerCase();
    switch (cat) {
        case 'unverified':
            return this.find({ isVerified: false });
        case 'admin':
            return this.find({ role: 'admin' });
        case 'distributor':
            return this.find({ role: 'distributor' });
        case 'premium':
            return this.find({ membership: 'premium', isVerified: true });
        case 'members':
        default:
            return this.find({ role: 'member', isVerified: true });
    }
};

UserSchema.set('toObject', { virtuals: true });
UserSchema.set('toJSON', { virtuals: true });

module.exports = mongoose.model('User', UserSchema);
