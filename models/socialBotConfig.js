const mongoose = require('mongoose');

const socialBotConfigSchema = new mongoose.Schema({
    singletonId: {
        type: String,
        default: 'master-social-bot-config',
        unique: true
    },
    // Promo Bot Rate Limiting: 4 messages/day, 1 every 6 hours
    promoLastSentAt: {
        type: Date,
        default: null
    },
    promoDailyCount: {
        type: Number,
        default: 0
    },
    promoLastDate: {
        type: String,
        default: () => new Date().toISOString().split('T')[0]
    },
    promoAdText: {
        type: String,
        default: '🔥 Discover premium unlocked apps, games & mods on GPLMods. 100% Virus-scanned, direct high-speed downloads!'
    },
    promoAdUrl: {
        type: String,
        default: 'https://gplmods.webredirect.org'
    },
    // Discord Channel Routing
    discordUploadsWebhook: {
        type: String,
        default: ''
    },
    discordUpdatesWebhook: {
        type: String,
        default: ''
    },
    discordPromoWebhook: {
        type: String,
        default: ''
    },
    discordSupportWebhook: {
        type: String,
        default: ''
    },
    discordSearchWebhook: {
        type: String,
        default: ''
    },
    // Telegram Configuration
    telegramChannelId: {
        type: String,
        default: ''
    },
    telegramBotToken: {
        type: String,
        default: ''
    },
    // Reddit Configuration
    redditSubreddit: {
        type: String,
        default: 'GPLMods'
    },
    redditClientId: {
        type: String,
        default: ''
    },
    redditClientSecret: {
        type: String,
        default: ''
    },
    redditUsername: {
        type: String,
        default: ''
    },
    redditPassword: {
        type: String,
        default: ''
    },
    // Platform Hourly Rate Limits
    hourlyLimits: {
        discord: { type: Number, default: 30 },
        telegram: { type: Number, default: 20 },
        reddit: { type: Number, default: 4 }
    },
    hourlyCounters: {
        discord: { type: Number, default: 0 },
        telegram: { type: Number, default: 0 },
        reddit: { type: Number, default: 0 },
        lastHour: { type: Number, default: () => new Date().getHours() }
    }
}, {
    timestamps: true
});

socialBotConfigSchema.statics.getOrCreate = async function() {
    let config = await this.findOne({ singletonId: 'master-social-bot-config' });
    if (!config) {
        config = await this.create({ singletonId: 'master-social-bot-config' });
    }
    return config;
};

module.exports = mongoose.model('SocialBotConfig', socialBotConfigSchema);
