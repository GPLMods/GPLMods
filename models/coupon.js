const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const CouponSchema = new Schema({
    code: {
        type: String,
        required: true,
        unique: true,
        uppercase: true,
        trim: true
    },
    description: {
        type: String,
        default: ''
    },
    discountType: {
        type: String,
        enum: ['percent', 'percentage', 'flat'],
        default: 'percent'
    },
    discountValue: {
        type: Number,
        required: true,
        min: 0
    },
    applicablePlans: {
        type: [String],
        default: ['all'] // 'all' or specific plan IDs like 'lite_monthly', 'lite_6months', 'lite_yearly', 'plus_monthly', 'plus_6months', 'plus_yearly', 'plus_lifetime'
    },
    maxUses: {
        type: Number,
        default: null // null = unlimited
    },
    usedCount: {
        type: Number,
        default: 0
    },
    minOrderAmount: {
        type: Number,
        default: 0
    },
    expiresAt: {
        type: Date,
        default: null
    },
    isActive: {
        type: Boolean,
        default: true
    },
    createdBy: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        default: null
    }
}, { timestamps: true });

CouponSchema.methods.isValid = function (planKey, orderAmount = 0) {
    if (!this.isActive) return { valid: false, reason: 'This coupon is no longer active.' };
    if (this.expiresAt && new Date() > this.expiresAt) return { valid: false, reason: 'This coupon has expired.' };
    if (this.maxUses !== null && this.usedCount >= this.maxUses) return { valid: false, reason: 'This coupon has reached its maximum usage limit.' };
    if (this.minOrderAmount && orderAmount < this.minOrderAmount) return { valid: false, reason: `Minimum order amount of ₹${this.minOrderAmount} required.` };

    if (!this.applicablePlans.includes('all')) {
        const matchesPlan = this.applicablePlans.some(p => p.toLowerCase() === planKey.toLowerCase() || planKey.toLowerCase().includes(p.toLowerCase()));
        if (!matchesPlan) return { valid: false, reason: 'This coupon is not applicable to the selected plan.' };
    }

    return { valid: true };
};

CouponSchema.methods.calculateDiscount = function (originalAmount) {
    if (this.discountType === 'percent' || this.discountType === 'percentage') {
        const discount = (originalAmount * this.discountValue) / 100;
        return Math.min(originalAmount, Math.round(discount));
    } else {
        return Math.min(originalAmount, Math.round(this.discountValue));
    }
};

module.exports = mongoose.model('Coupon', CouponSchema);
