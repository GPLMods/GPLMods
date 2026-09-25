const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const VolunteerApplicationSchema = new Schema({
    user: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    fullName: { type: String, required: true, trim: true },
    email: { type: String, required: true, trim: true, lowercase: true },
    phone: { type: String, required: true, trim: true },
    dateOfBirth: { type: Date, required: true },
    
    // Detailed Address
    address: {
        street: { type: String, required: true, trim: true },
        city: { type: String, required: true, trim: true },
        district: { type: String, required: true, trim: true },
        state: { type: String, required: true, trim: true },
        pincode: { type: String, required: true, trim: true },
        country: { type: String, required: true, trim: true, default: 'India' }
    },

    // Socials
    socialHandles: {
        discord: { type: String, trim: true },
        telegram: { type: String, trim: true },
        github: { type: String, trim: true },
        twitter: { type: String, trim: true }
    },

    role: { 
        type: String, 
        enum: ['support', 'admin'], 
        required: true 
    },
    
    // Languages: At least one of 'hindi', 'english', 'hinglish' mandatory
    languages: [{ type: String, trim: true }],

    experience: { type: String, required: true, trim: true },
    kycDocumentKey: { type: String, trim: true },

    // Mandatory Legal / Term Agreements
    isVoluntaryAgreed: { type: Boolean, default: false, required: true }, // No salary
    oneMonthLockinAgreed: { type: Boolean, default: false, required: true }, // Cannot leave before 1 month
    eighteenPlusConfirmed: { type: Boolean, default: false, required: true }, // 18+ age verification
    codeOfConductAgreed: { type: Boolean, default: false, required: true },

    // Platform Safety Commitment Fee (Cashfree PG)
    feeAmount: { type: Number, required: true }, // 150 for support, 300 for admin
    feeCurrency: { type: String, default: 'INR' },
    orderId: { type: String, unique: true, sparse: true, index: true },
    cfPaymentId: { type: String },
    paymentStatus: { 
        type: String, 
        enum: ['pending', 'paid', 'failed', 'refunded'], 
        default: 'pending' 
    },
    paidAt: { type: Date },

    // Refund window tracking (7-day money-back guarantee)
    refundStatus: { 
        type: String, 
        enum: ['none', 'pending', 'approved', 'rejected'], 
        default: 'none' 
    },
    refundRequestedAt: { type: Date },
    refundProcessedAt: { type: Date },
    refundReason: { type: String, trim: true },

    // Application Status
    applicationStatus: { 
        type: String, 
        enum: ['draft', 'submitted', 'under_review', 'interview_scheduled', 'approved', 'rejected'], 
        default: 'submitted' 
    },
    adminNotes: { type: String, trim: true }
}, { timestamps: true });

// Helper to check 18+ age
VolunteerApplicationSchema.methods.isEighteenPlus = function() {
    if (!this.dateOfBirth) return false;
    const diffMs = Date.now() - new Date(this.dateOfBirth).getTime();
    const ageDate = new Date(diffMs);
    const age = Math.abs(ageDate.getUTCFullYear() - 1970);
    return age >= 18;
};

module.exports = mongoose.model('VolunteerApplication', VolunteerApplicationSchema);
