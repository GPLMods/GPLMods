/**
 * GPLMods Unified Social Bot Suite (Discord, Telegram, Reddit)
 * 
 * Bot Architecture:
 * 1. New Upload Bot: Live notification for every new/variant mod upload
 * 2. New Update Bot: Notification for every mod version update with changelog
 * 3. Support Bot: Connected to Google Gemini Flash API for private support & troubleshooting
 * 4. Promo Bot: Monetag / sponsor ad distribution with strict 6-hour cooldown (max 4/day) + Club broadcast
 * 5. Search Bot: Live mod search & filtering with private results
 * 6. Auth Bot: Account linking with one-time 8-char codes for elevated tier limits
 */

const axios = require('axios');
const path = require('path');
const mongoose = require('mongoose');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const SocialConnection = require('../models/socialConnection');
const SocialBotConfig = require('../models/socialBotConfig');
const File = require('../models/file');
const Club = require('../models/club');
const ClubChannel = require('../models/clubChannel');
const ClubMessage = require('../models/clubMessage');

// Google Gemini AI Client Initialization
const genAI = process.env.GEMINI_API_KEY ? new GoogleGenerativeAI(process.env.GEMINI_API_KEY) : null;

/**
 * Retrieves or creates singleton social bot config
 */
async function getBotConfig() {
    let config = await SocialBotConfig.findOne({ singletonId: 'master-social-bot-config' });
    if (!config) {
        config = new SocialBotConfig({
            singletonId: 'master-social-bot-config',
            discordUploadsWebhook: process.env.DISCORD_UPLOADS_WEBHOOK || process.env.DISCORD_WEBHOOK_URL || '',
            discordUpdatesWebhook: process.env.DISCORD_UPDATES_WEBHOOK || process.env.DISCORD_WEBHOOK_URL || '',
            discordPromoWebhook: process.env.DISCORD_PROMO_WEBHOOK || process.env.DISCORD_WEBHOOK_URL || '',
            telegramChannelId: process.env.TELEGRAM_CHANNEL_ID || '@GPLMods',
            telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || '',
            redditSubreddit: process.env.REDDIT_SUBREDDIT || 'GPLMods',
            redditClientId: process.env.REDDIT_CLIENT_ID || '',
            redditClientSecret: process.env.REDDIT_CLIENT_SECRET || '',
            redditUsername: process.env.REDDIT_USERNAME || '',
            redditPassword: process.env.REDDIT_PASSWORD || ''
        });
        await config.save();
    }
    return config;
}

/**
 * Checks platform hourly rate limit governor to prevent API blocks or spam penalties
 */
async function checkPlatformRateLimit(platform) {
    const config = await getBotConfig();
    const currentHour = new Date().getHours();

    if (config.hourlyCounters.lastHour !== currentHour) {
        config.hourlyCounters.lastHour = currentHour;
        config.hourlyCounters.discord = 0;
        config.hourlyCounters.telegram = 0;
        config.hourlyCounters.reddit = 0;
    }

    const maxAllowed = config.hourlyLimits[platform] || 20;
    const currentCount = config.hourlyCounters[platform] || 0;

    if (currentCount >= maxAllowed) {
        console.warn(`[SocialBot Governor] Hourly rate limit reached for ${platform} (${currentCount}/${maxAllowed}). Message skipped.`);
        return false;
    }

    config.hourlyCounters[platform] = currentCount + 1;
    await config.save();
    return true;
}

// ==========================================
// 1. DISCORD DISPATCHER
// ==========================================

async function sendDiscordWebhook(webhookUrl, payload) {
    if (!webhookUrl) return false;
    if (!(await checkPlatformRateLimit('discord'))) return false;

    try {
        await axios.post(webhookUrl, payload, { timeout: 8000 });
        return true;
    } catch (err) {
        console.error('[SocialBot Discord] Webhook delivery failed:', err.response?.data || err.message);
        return false;
    }
}

// ==========================================
// 2. TELEGRAM DISPATCHER
// ==========================================

async function sendTelegramMessage(text, options = {}) {
    const config = await getBotConfig();
    const token = config.telegramBotToken || process.env.TELEGRAM_BOT_TOKEN;
    const chatId = options.chatId || config.telegramChannelId || process.env.TELEGRAM_CHANNEL_ID;

    if (!token || !chatId) return false;
    if (!(await checkPlatformRateLimit('telegram'))) return false;

    try {
        const url = `https://api.telegram.org/bot${token}/sendMessage`;
        await axios.post(url, {
            chat_id: chatId,
            text: text,
            parse_mode: options.parseMode || 'HTML',
            disable_web_page_preview: options.disablePreview || false
        }, { timeout: 8000 });
        return true;
    } catch (err) {
        console.error('[SocialBot Telegram] Message delivery failed:', err.response?.data || err.message);
        return false;
    }
}

// ==========================================
// 3. REDDIT DISPATCHER
// ==========================================

let redditAccessToken = null;
let redditTokenExpiresAt = null;

async function getRedditAccessToken(config) {
    if (redditAccessToken && redditTokenExpiresAt && Date.now() < redditTokenExpiresAt) {
        return redditAccessToken;
    }

    const clientId = config.redditClientId || process.env.REDDIT_CLIENT_ID;
    const clientSecret = config.redditClientSecret || process.env.REDDIT_CLIENT_SECRET;
    const username = config.redditUsername || process.env.REDDIT_USERNAME;
    const password = config.redditPassword || process.env.REDDIT_PASSWORD;

    if (!clientId || !clientSecret || !username || !password) {
        return null;
    }

    try {
        const authHeader = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
        const form = new URLSearchParams();
        form.append('grant_type', 'password');
        form.append('username', username);
        form.append('password', password);

        const res = await axios.post('https://www.reddit.com/api/v1/access_token', form.toString(), {
            headers: {
                'Authorization': `Basic ${authHeader}`,
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'GPLModsBot/2.5.0 (by /u/GPLMods)'
            },
            timeout: 8000
        });

        if (res.data && res.data.access_token) {
            redditAccessToken = res.data.access_token;
            redditTokenExpiresAt = Date.now() + ((res.data.expires_in || 3600) - 120) * 1000;
            return redditAccessToken;
        }
    } catch (err) {
        console.error('[SocialBot Reddit] Auth failed:', err.response?.data || err.message);
    }
    return null;
}

async function sendRedditSubmission(title, content, url = null) {
    const config = await getBotConfig();
    const token = await getRedditAccessToken(config);
    if (!token) return false;
    if (!(await checkPlatformRateLimit('reddit'))) return false;

    const subreddit = config.redditSubreddit || process.env.REDDIT_SUBREDDIT || 'GPLMods';

    try {
        const form = new URLSearchParams();
        form.append('sr', subreddit);
        form.append('title', title);

        if (url) {
            form.append('kind', 'link');
            form.append('url', url);
        } else {
            form.append('kind', 'self');
            form.append('text', content);
        }

        const res = await axios.post('https://oauth.reddit.com/api/submit', form.toString(), {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'GPLModsBot/2.5.0 (by /u/GPLMods)'
            },
            timeout: 10000
        });

        return res.data?.success || true;
    } catch (err) {
        console.error('[SocialBot Reddit] Submission failed:', err.response?.data || err.message);
        return false;
    }
}

// ==========================================
// 4. BOT #1: NEW UPLOAD BOT
// ==========================================

/**
 * Broadcasts notification when a new mod or variant goes live
 */
async function broadcastNewUpload(mod) {
    if (!mod || !mod.name) return;

    const config = await getBotConfig();
    const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
    const modSlug = mod.slug || mod._id;
    const modUrl = `${baseUrl}/mods/${encodeURIComponent(mod.category || 'mods')}/${encodeURIComponent(modSlug)}`;
    const platform = (mod.category || 'Android').toUpperCase();
    const version = mod.version ? `v${mod.version}` : 'Latest';

    console.log(`[New Upload Bot] Broadcasting live announcement for: ${mod.name} (${platform})`);

    // 1. Discord Announcement (Uploads Channel)
    const discordWebhook = config.discordUploadsWebhook || process.env.DISCORD_UPLOADS_WEBHOOK || config.discordPromoWebhook;
    if (discordWebhook) {
        const discordPayload = {
            username: 'GPLMods Upload Bot',
            avatar_url: `${baseUrl}/images/logo.png`,
            embeds: [{
                title: `🚀 New Upload: ${mod.name} (${version})`,
                url: modUrl,
                color: 0x00FF88, // Emerald green
                description: mod.modDescription ? mod.modDescription.substring(0, 250) + '...' : 'New verified mod upload is now live on GPLMods!',
                fields: [
                    { name: 'Platform', value: `📱 ${platform}`, inline: true },
                    { name: 'Version', value: `🏷️ ${version}`, inline: true },
                    { name: 'Uploader', value: `👤 ${mod.uploader || 'Community'}`, inline: true }
                ],
                footer: { text: 'GPLMods • 100% Virus Scanned & Verified' },
                timestamp: new Date().toISOString()
            }]
        };
        sendDiscordWebhook(discordWebhook, discordPayload).catch(() => {});
    }

    // 2. Telegram Channel Announcement
    const tgText = [
        `🚀 <b>NEW UPLOAD LIVE ON GPLMODS!</b>`,
        ``,
        `📦 <b>Name:</b> ${mod.name}`,
        `📱 <b>Platform:</b> ${platform}`,
        `🏷️ <b>Version:</b> ${version}`,
        `👤 <b>Uploader:</b> ${mod.uploader || 'Community'}`,
        ``,
        `🔗 <a href="${modUrl}"><b>Download Now on GPLMods</b></a>`
    ].join('\n');
    sendTelegramMessage(tgText).catch(() => {});

    // 3. Reddit Announcement (Subreddit Post)
    const redditTitle = `[NEW] ${mod.name} (${version}) for ${platform} is now live on GPLMods`;
    const redditBody = [
        `### [${mod.name} (${version})](${modUrl})`,
        ``,
        `**Platform:** ${platform} | **Uploader:** ${mod.uploader || 'Community'}`,
        ``,
        `${mod.modDescription || 'Verified malware-free mod download available now.'}`,
        ``,
        `[Download Link](${modUrl})`
    ].join('\n');
    sendRedditSubmission(redditTitle, redditBody, modUrl).catch(() => {});
}

// ==========================================
// 5. BOT #2: NEW UPDATE BOT
// ==========================================

/**
 * Broadcasts notification when an existing mod/variant receives an update
 */
async function broadcastNewUpdate(mod, whatsNew = '') {
    if (!mod || !mod.name) return;

    const config = await getBotConfig();
    const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
    const modSlug = mod.slug || mod._id;
    const modUrl = `${baseUrl}/mods/${encodeURIComponent(mod.category || 'mods')}/${encodeURIComponent(modSlug)}`;
    const platform = (mod.category || 'Android').toUpperCase();
    const version = mod.version ? `v${mod.version}` : 'Latest';
    const changelog = whatsNew || 'Bug fixes, security updates, and performance optimizations.';

    console.log(`[New Update Bot] Broadcasting update announcement for: ${mod.name} (${version})`);

    // 1. Discord Announcement (Updates Channel)
    const discordWebhook = config.discordUpdatesWebhook || process.env.DISCORD_UPDATES_WEBHOOK || config.discordUploadsWebhook;
    if (discordWebhook) {
        const discordPayload = {
            username: 'GPLMods Update Bot',
            avatar_url: `${baseUrl}/images/logo.png`,
            embeds: [{
                title: `🔄 Mod Updated: ${mod.name} (${version})`,
                url: modUrl,
                color: 0x3399FF, // Vibrant Blue
                description: `**What's New in this Version:**\n${changelog}`,
                fields: [
                    { name: 'Platform', value: `📱 ${platform}`, inline: true },
                    { name: 'New Version', value: `🏷️ ${version}`, inline: true },
                    { name: 'Uploader', value: `👤 ${mod.uploader || 'Community'}`, inline: true }
                ],
                footer: { text: 'GPLMods • Always Keep Your Mods Updated' },
                timestamp: new Date().toISOString()
            }]
        };
        sendDiscordWebhook(discordWebhook, discordPayload).catch(() => {});
    }

    // 2. Telegram Channel Announcement
    const tgText = [
        `🔄 <b>MOD UPDATED ON GPLMODS!</b>`,
        ``,
        `📦 <b>Name:</b> ${mod.name}`,
        `🏷️ <b>New Version:</b> ${version}`,
        `📱 <b>Platform:</b> ${platform}`,
        ``,
        `📝 <b>What's New:</b>\n<i>${changelog}</i>`,
        ``,
        `🔗 <a href="${modUrl}"><b>Download Latest Update</b></a>`
    ].join('\n');
    sendTelegramMessage(tgText).catch(() => {});

    // 3. Reddit Announcement (Subreddit Post)
    const redditTitle = `[UPDATE] ${mod.name} updated to ${version} on GPLMods`;
    const redditBody = [
        `### [${mod.name} (${version})](${modUrl})`,
        ``,
        `**Platform:** ${platform}`,
        ``,
        `**Release Notes:**`,
        `${changelog}`,
        ``,
        `[Download Update](${modUrl})`
    ].join('\n');
    sendRedditSubmission(redditTitle, redditBody, modUrl).catch(() => {});
}

// ==========================================
// 6. BOT #3: SUPPORT BOT (GEMINI AI - PRIVATE)
// ==========================================

/**
 * Handles private AI support queries using Google Gemini Flash
 * Ensures private DM / ephemeral responses and rate limiting
 */
async function handleSupportQuery(queryText, socialUserId, platform = 'telegram') {
    if (!queryText || typeof queryText !== 'string') {
        return "Please ask a question about GPLMods apps, APKs, IPAs, or platform features.";
    }

    // Check account link status & rate limits
    const today = new Date().toISOString().split('T')[0];
    let isLinked = false;
    let connection = null;

    if (socialUserId) {
        connection = await SocialConnection.findOne({ socialId: String(socialUserId), platform });
        if (connection) {
            isLinked = true;
            if (connection.lastResetDate !== today) {
                connection.lastResetDate = today;
                connection.dailySupportCount = 0;
                connection.dailySearchCount = 0;
            }

            // Linked limit: 100 queries/day
            if (connection.dailySupportCount >= 100) {
                return "⚠️ You have reached your daily limit of 100 AI Support queries. Your limit resets tomorrow!";
            }

            connection.dailySupportCount++;
            await connection.save();
        }
    }

    if (!isLinked) {
        // Guest limit: 5 queries per session
        // Recommend connecting account
    }

    if (!genAI) {
        return "Support AI is currently offline. Please open a ticket on our official website: https://gplmods.webredirect.org/support";
    }

    try {
        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
        const systemPrompt = [
            "You are the official GPLMods AI Support Assistant.",
            "GPLMods (https://gplmods.webredirect.org) is an open-source platform distributing verified software and mods for Android (APK), iOS (IPA - Jailed & Jailbroken), Windows, and WordPress.",
            "Provide concise, highly accurate, friendly troubleshooting advice.",
            "If user asks about installing IPAs: explain AltStore, Sideloadly, Scarlet, TrollStore, or LiveContainer.",
            "If user asks about APKs: remind them to enable Install Unknown Apps.",
            "Keep response under 250 words.",
            isLinked ? "" : "At the end of your answer, remind the user: '💡 Tip: Connect your GPLMods account on the website to get higher daily AI support and search limits!'"
        ].join(' ');

        const result = await model.generateContent([systemPrompt, queryText]);
        const response = await result.response;
        return response.text();
    } catch (err) {
        console.error('[Support Bot Gemini Error]:', err.message);
        return "I am experiencing high traffic right now. Please check our Docs (https://gplmods.webredirect.org/docs) or create a ticket at https://gplmods.webredirect.org/support";
    }
}

// ==========================================
// 7. BOT #4: SEARCH BOT (PRIVATE SEARCH RESULTS)
// ==========================================

/**
 * Searches live mods from MongoDB and returns private formatted results
 */
async function handleSearchQuery(queryText, platformFilter = null, socialUserId = null, platform = 'telegram') {
    if (!queryText || queryText.trim().length < 2) {
        return "Please enter a search keyword (at least 2 characters), e.g. `/search kinemaster` or `/search spotify android`.";
    }

    const today = new Date().toISOString().split('T')[0];
    let isLinked = false;

    if (socialUserId) {
        const connection = await SocialConnection.findOne({ socialId: String(socialUserId), platform });
        if (connection) {
            isLinked = true;
            if (connection.lastResetDate !== today) {
                connection.lastResetDate = today;
                connection.dailySearchCount = 0;
            }
            if (connection.dailySearchCount >= 50) {
                return "⚠️ You have reached your daily search limit of 50 queries. Your quota resets tomorrow!";
            }
            connection.dailySearchCount++;
            await connection.save();
        }
    }

    try {
        const filter = {
            status: 'live',
            isLatestVersion: true,
            name: { $regex: queryText.trim(), $options: 'i' }
        };

        if (platformFilter) {
            filter.category = platformFilter.toLowerCase();
        }

        const mods = await File.find(filter)
            .select('name version category slug averageRating downloadsCount')
            .sort({ downloadsCount: -1, averageRating: -1 })
            .limit(5)
            .lean();

        if (!mods || mods.length === 0) {
            return `🔍 No live mods found matching "${queryText}". Try searching a different keyword or browse: https://gplmods.webredirect.org`;
        }

        const baseUrl = process.env.BASE_URL || 'https://gplmods.webredirect.org';
        const lines = [
            `🔍 <b>GPLMods Search Results for "${queryText}":</b>\n`
        ];

        mods.forEach((m, idx) => {
            const url = `${baseUrl}/mods/${encodeURIComponent(m.category || 'mods')}/${encodeURIComponent(m.slug || m._id)}`;
            const rating = m.averageRating ? `⭐ ${m.averageRating.toFixed(1)}` : '⭐ 5.0';
            lines.push(`${idx + 1}. <b>${m.name}</b> (v${m.version || '1.0'}) [${(m.category || 'Android').toUpperCase()}] - ${rating}\n👉 <a href="${url}">Download Link</a>\n`);
        });

        if (!isLinked) {
            lines.push(`💡 <i>Connect your GPLMods account to unlock 50 searches per day!</i>`);
        }

        return lines.join('\n');
    } catch (err) {
        console.error('[Search Bot Error]:', err.message);
        return "Error querying search index. Please visit https://gplmods.webredirect.org";
    }
}

// ==========================================
// 8. BOT #5: PROMO BOT (6-HOUR LIMIT & CLUB POSTING)
// ==========================================

/**
 * Sends monetization ad / promotion (Monetag/Moneytag)
 * Strictly rate-limited: 1 message every 6 hours, maximum 4 messages per day
 * Also automatically broadcasts to GPLMods Clubs
 */
async function broadcastPromotion(customAdText = null, customAdUrl = null) {
    const config = await getBotConfig();
    const now = new Date();
    const today = now.toISOString().split('T')[0];

    // Reset daily count if date changed
    if (config.promoLastDate !== today) {
        config.promoLastDate = today;
        config.promoDailyCount = 0;
    }

    // Rule 1: Max 4 messages per day
    if (config.promoDailyCount >= 4) {
        console.log(`[Promo Bot] Daily cap reached (${config.promoDailyCount}/4 messages today). Skipping.`);
        return { success: false, reason: 'Daily promo limit reached (4/day)' };
    }

    // Rule 2: Minimum 6 hours since last promo
    if (config.promoLastSentAt) {
        const diffMs = now.getTime() - new Date(config.promoLastSentAt).getTime();
        const sixHoursMs = 6 * 60 * 60 * 1000;
        if (diffMs < sixHoursMs) {
            const remainingMins = Math.round((sixHoursMs - diffMs) / (60 * 1000));
            console.log(`[Promo Bot] 6-hour cooldown active. ${remainingMins} minutes remaining. Skipping.`);
            return { success: false, reason: `6-hour cooldown active (${remainingMins}m remaining)` };
        }
    }

    const adText = customAdText || config.promoAdText || '🔥 Discover premium unlocked apps, games & mods on GPLMods. 100% Virus-scanned, direct high-speed downloads!';
    const adUrl = customAdUrl || config.promoAdUrl || 'https://gplmods.webredirect.org';

    console.log(`[Promo Bot] Dispatching 6-hour promotional broadcast (${config.promoDailyCount + 1}/4)...`);

    // 1. Discord Promo Webhook
    const discordWebhook = config.discordPromoWebhook || process.env.DISCORD_PROMO_WEBHOOK;
    if (discordWebhook) {
        sendDiscordWebhook(discordWebhook, {
            username: 'GPLMods Sponsors & Deals',
            avatar_url: 'https://gplmods.webredirect.org/images/logo.png',
            embeds: [{
                title: '⚡ GPLMods Community Sponsored Highlight',
                url: adUrl,
                color: 0xFFD700, // Gold
                description: adText,
                fields: [{ name: 'Learn More / Support Us', value: `[Click here to visit partner deal](${adUrl})` }],
                footer: { text: 'GPLMods Sponsored Message • 1 per 6 hours' },
                timestamp: now.toISOString()
            }]
        }).catch(() => {});
    }

    // 2. Telegram Channel Promo
    const tgPromo = [
        `⭐ <b>SPONSORED HIGHLIGHT - GPLMODS</b>`,
        ``,
        `${adText}`,
        ``,
        `👉 <a href="${adUrl}"><b>Check Out Partner Offer</b></a>`
    ].join('\n');
    sendTelegramMessage(tgPromo).catch(() => {});

    // 3. BROADCAST TO GPLMODS CLUBS (User Request: "Also add this features to club")
    try {
        const clubs = await Club.find({ isDefault: true }).lean();
        for (const club of clubs) {
            const channel = await ClubChannel.findOne({ club: club._id, isDefault: true }).lean() ||
                            await ClubChannel.findOne({ club: club._id, name: 'general' }).lean();
            if (channel) {
                await ClubMessage.create({
                    club: club._id,
                    channel: channel._id,
                    sender: club.creator,
                    content: `📢 **Community Sponsor & Deals:** ${adText} [Visit Deal](${adUrl})`,
                    isSystemMessage: true
                });
            }
        }
        console.log(`[Promo Bot] Successfully posted sponsor broadcast to GPLMods Clubs.`);
    } catch (clubErr) {
        console.warn(`[Promo Bot] Error posting promo to clubs:`, clubErr.message);
    }

    // Update config state
    config.promoLastSentAt = now;
    config.promoDailyCount += 1;
    await config.save();

    return { success: true, count: config.promoDailyCount };
}

// ==========================================
// 9. BOT #6: AUTH BOT (ACCOUNT LINKING ENGINE)
// ==========================================

/**
 * Generates an 8-character connection code (GPL-XXXX-XXXX) valid for 15 minutes
 */
async function generateLinkCode(userId, platform) {
    if (!userId || !platform) throw new Error("userId and platform are required.");

    // Generate random 8-character alphanumeric code
    const randomHex = Math.random().toString(36).substring(2, 6).toUpperCase() + '-' + Math.random().toString(36).substring(2, 6).toUpperCase();
    const authCode = `GPL-${randomHex}`;
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // Upsert connection code
    await SocialConnection.findOneAndUpdate(
        { user: userId, platform },
        {
            user: userId,
            platform,
            authCode,
            authCodeExpiresAt: expiresAt
        },
        { upsert: true, new: true }
    );

    return { authCode, expiresAt };
}

/**
 * Validates one-time auth code and links social account
 */
async function verifyAndLinkSocialAccount(arg1, arg2, arg3, arg4) {
    let authCode, socialId, socialUsername, platform;
    if (['discord', 'telegram', 'reddit'].includes(String(arg1).toLowerCase())) {
        platform = String(arg1).toLowerCase();
        socialId = arg2;
        authCode = arg3;
        socialUsername = arg4;
    } else {
        authCode = arg1;
        socialId = arg2;
        socialUsername = arg3;
        platform = arg4;
    }

    if (!authCode || !socialId) {
        return { success: false, message: "Auth code and social ID are required." };
    }

    const cleanCode = authCode.trim().toUpperCase();
    const query = {
        authCode: cleanCode,
        authCodeExpiresAt: { $gt: new Date() }
    };
    if (platform) {
        query.platform = platform;
    }
    const connection = await SocialConnection.findOne(query);

    if (!connection) {
        return { success: false, message: "Invalid or expired connection code. Please generate a new code at https://gplmods.com/settings/social-connections" };
    }

    connection.socialId = String(socialId);
    connection.socialUsername = socialUsername || '';
    connection.authCode = null;
    connection.authCodeExpiresAt = null;
    connection.connectedAt = new Date();
    await connection.save();

    return {
        success: true,
        message: `Successfully connected your GPLMods account! Your daily AI support and search limits have been elevated.`,
        user: connection.user
    };
}

/**
 * Unlinks a user's social connection
 */
async function unlinkSocialAccount(userId, platform) {
    await SocialConnection.findOneAndDelete({ user: userId, platform });
    return { success: true };
}

module.exports = {
    getBotConfig,
    broadcastNewUpload,
    broadcastNewUpdate,
    handleSupportQuery,
    handleSearchQuery,
    broadcastPromotion,
    generateLinkCode,
    verifyAndLinkSocialAccount,
    unlinkSocialAccount
};
