// models/Review.js

const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const ReviewSchema = new Schema({
    text: {
        type: String,
        required: true,
        trim: true
    },
    rating: {
        type: Number,
        required: true,
        min: 1,
        max: 5
    },
    author: {
        type: Schema.Types.ObjectId,
        ref: 'User', // This links the review to the user who wrote it
        required: true
    },
    mod: {
        type: Schema.Types.ObjectId,
        ref: 'Mod', // This links the review to the mod it's about
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
});

// Middleware to update the 'updatedAt' field on save
ReviewSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

module.exports = mongoose.model('Review', ReviewSchema);```

### How to Use These Files

Now, in your route files (like `routes/api/mods.js` or a new `routes/api/reviews.js`), you can easily access these models by requiring them at the top of the file:

```javascript
// Example at the top of routes/api/mods.js
const Mod = require('../../models/Mod');
const User = require('../../models/User'); // If you need user data

// Now you can use commands like:
// const mods = await Mod.find({ platform: 'android' });
// const newMod = new Mod({ ... });
// await newMod.save();