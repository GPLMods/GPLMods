/**
 * ============================================================================
 * WEB PUSH & DYNAMIC NOTIFICATIONS UTILITY
 * Handles VAPID signing, push subscription persistence, category routing,
 * anti-spam throttling, and PWA dynamic notifications with custom audio.
 * ============================================================================
 */

const webpush = require('web-push');
const PushSubscription = require('../models/pushSubscription');

// VAPID Credentials
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || 'BJ0RjiG4c8moiskxblugQBwf_OBG1lLx2CtWOlw-MiESjCSCkKS6S-ns4dS2AvUGN2B_3ajA_5uQ9JaSR71x9Qo';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || 'oiV_2To3VJFci3mAv2eGJFVCUIWP184jBRbDgRYNj8s';
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:support@gplmods.webredirect.org';

try {
    webpush.setVapidDetails(VAPID_SUBJECT, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
} catch (e) {
    console.error('[WebPush] Error configuring VAPID details:', e.message);
}

// Anti-spam throttling cooldown (ms) - Prevents flooding users with multiple notifications
const categoryLastBroadcast = {
    'new-uploads': 0,
    'club-updates': 0,
    'admin-messages': 0
};
const BROADCAST_COOLDOWN_MS = 45 * 1000; // 45 seconds minimum between broadcasts of the same category

function getPublicKey() {
    return VAPID_PUBLIC_KEY;
}

/**
 * Save or update a push subscription from client
 */
async function saveSubscription(subData, userId = null, preferences = {}, userAgent = '') {
    if (!subData || !subData.endpoint || !subData.keys) return null;

    const updateDoc = {
        endpoint: subData.endpoint,
        keys: {
            p256dh: subData.keys.p256dh,
            auth: subData.keys.auth
        },
        preferences: {
            newUploads: preferences.newUploads !== false,
            clubUpdates: preferences.clubUpdates !== false,
            adminMessages: preferences.adminMessages !== false,
            soundEnabled: preferences.soundEnabled !== false
        },
        userAgent: userAgent || ''
    };

    if (userId) {
        updateDoc.user = userId;
    }

    return await PushSubscription.findOneAndUpdate(
        { endpoint: subData.endpoint },
        { $set: updateDoc },
        { upsert: true, new: true }
    );
}

/**
 * Remove an expired or unsubscribed endpoint
 */
async function removeSubscription(endpoint) {
    if (!endpoint) return;
    try {
        await PushSubscription.deleteOne({ endpoint });
    } catch (e) {
        console.error('[WebPush] removeSubscription error:', e.message);
    }
}

/**
 * Update user preferences for all endpoints registered to a user or endpoint
 */
async function updatePreferences(identifier, preferences = {}) {
    try {
        const query = (typeof identifier === 'string' && identifier.startsWith('http'))
            ? { endpoint: identifier }
            : { user: identifier };

        const update = {};
        if (preferences.newUploads !== undefined) update['preferences.newUploads'] = Boolean(preferences.newUploads);
        if (preferences.clubUpdates !== undefined) update['preferences.clubUpdates'] = Boolean(preferences.clubUpdates);
        if (preferences.adminMessages !== undefined) update['preferences.adminMessages'] = Boolean(preferences.adminMessages);
        if (preferences.soundEnabled !== undefined) update['preferences.soundEnabled'] = Boolean(preferences.soundEnabled);

        await PushSubscription.updateMany(query, { $set: update });
        return true;
    } catch (e) {
        console.error('[WebPush] updatePreferences error:', e.message);
        return false;
    }
}

/**
 * Send a push notification to an individual subscription
 */
async function sendPushNotification(subscription, payload) {
    try {
        const pushConfig = {
            endpoint: subscription.endpoint,
            keys: subscription.keys
        };
        const payloadString = JSON.stringify(payload);
        await webpush.sendNotification(pushConfig, payloadString, {
            TTL: 86400 // 24 hours
        });
        return true;
    } catch (err) {
        if (err.statusCode === 404 || err.statusCode === 410) {
            // Subscription expired or unregistered
            await removeSubscription(subscription.endpoint);
        } else {
            console.error('[WebPush] Send notification failed:', err.statusCode, err.message);
        }
        return false;
    }
}

/**
 * Broadcast notification with category preferences filtering and anti-spam throttling
 * @param {string} category - 'new-uploads' | 'club-updates' | 'admin-messages'
 * @param {object} payload - { title, body, url, tag, icon, badge, sound }
 * @param {object} io - optional Socket.io instance for live in-app toast & sound
 */
async function broadcastPushNotification(category, payload, io = null) {
    try {
        const now = Date.now();

        // 1. Anti-spam throttling check (don't fill user with multiple notification)
        if (categoryLastBroadcast[category] && (now - categoryLastBroadcast[category]) < BROADCAST_COOLDOWN_MS) {
            console.log(`[WebPush] Throttling broadcast for category "${category}" (cooldown active)`);
            return { sent: 0, throttled: true };
        }
        categoryLastBroadcast[category] = now;

        // 2. Standardized notification payload
        const finalPayload = {
            title: payload.title || 'GPL Mods',
            body: payload.body || 'New updates are available on GPL Mods.',
            url: payload.url || '/',
            icon: payload.icon || '/images/icon-192x192.png',
            badge: payload.badge || '/images/icon-192x192.png',
            tag: payload.tag || `gplmods-${category}`, // Distinct tag replaces previous notification card instead of spamming lockscreen
            category: category,
            sound: payload.sound !== false ? '/sfx/notification.mp3' : false,
            timestamp: now
        };

        // 3. Emit via Socket.io for active visitors/PWA users currently in-app
        if (io) {
            io.emit('gpl_live_notification', finalPayload);
        }

        // 4. Query matching subscriptions based on category preference
        const query = {};
        if (category === 'new-uploads') {
            query['preferences.newUploads'] = { $ne: false };
        } else if (category === 'club-updates') {
            query['preferences.clubUpdates'] = { $ne: false };
        } else if (category === 'admin-messages') {
            query['preferences.adminMessages'] = { $ne: false };
        }

        const subscriptions = await PushSubscription.find(query).lean();
        if (!subscriptions || subscriptions.length === 0) {
            return { sent: 0, total: 0 };
        }

        // 5. Send in concurrent batches (batch size 20)
        let successCount = 0;
        const BATCH_SIZE = 20;
        for (let i = 0; i < subscriptions.length; i += BATCH_SIZE) {
            const batch = subscriptions.slice(i, i + BATCH_SIZE);
            await Promise.allSettled(batch.map(async sub => {
                const ok = await sendPushNotification(sub, finalPayload);
                if (ok) successCount++;
            }));
        }

        console.log(`[WebPush] Broadcast [${category}] dispatched to ${successCount}/${subscriptions.length} devices.`);
        return { sent: successCount, total: subscriptions.length };
    } catch (err) {
        console.error('[WebPush] broadcastPushNotification error:', err);
        return { error: err.message };
    }
}

module.exports = {
    getPublicKey,
    saveSubscription,
    removeSubscription,
    updatePreferences,
    sendPushNotification,
    broadcastPushNotification
};
