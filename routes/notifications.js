/**
 * ============================================================================
 * NOTIFICATIONS ROUTER
 * Handles Web Push subscription registration, dynamic notification preferences,
 * and test push delivery for PWA / browser notifications.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const pushNotification = require('../utils/pushNotification');
const PushSubscription = require('../models/pushSubscription');
const User = require('../models/core/user');

// 1. Get VAPID Public Key for client-side PushManager.subscribe()
router.get('/vapid-public-key', (req, res) => {
    try {
        const publicKey = pushNotification.getPublicKey();
        res.json({ publicKey });
    } catch (err) {
        console.error('[WebPush] Error fetching public key:', err);
        res.status(500).json({ error: 'Failed to retrieve VAPID key.' });
    }
});

// 2. Subscribe device to Web Push
router.post('/subscribe', async (req, res) => {
    try {
        const { subscription, preferences } = req.body || {};
        if (!subscription || !subscription.endpoint || !subscription.keys) {
            return res.status(400).json({ error: 'Valid PushSubscription required.' });
        }

        const userId = (req.isAuthenticated && req.isAuthenticated() && req.user) ? req.user._id : null;
        const userAgent = req.headers['user-agent'] || '';

        const saved = await pushNotification.saveSubscription(subscription, userId, preferences, userAgent);

        // Also sync with User document if signed in
        if (userId) {
            await User.findByIdAndUpdate(userId, {
                'notificationSettings.enabled': true,
                'notificationSettings.newUploads': preferences ? preferences.newUploads !== false : true,
                'notificationSettings.clubUpdates': preferences ? preferences.clubUpdates !== false : true,
                'notificationSettings.adminMessages': preferences ? preferences.adminMessages !== false : true,
                'notificationSettings.soundEnabled': preferences ? preferences.soundEnabled !== false : true
            });
        }

        res.json({ success: true, id: saved._id });
    } catch (err) {
        console.error('[WebPush] Subscribe error:', err);
        res.status(500).json({ error: 'Failed to register notification subscription.' });
    }
});

// 3. Unsubscribe device
router.post('/unsubscribe', async (req, res) => {
    try {
        const { endpoint } = req.body || {};
        if (endpoint) {
            await pushNotification.removeSubscription(endpoint);
        }
        if (req.isAuthenticated && req.isAuthenticated() && req.user) {
            await User.findByIdAndUpdate(req.user._id, { 'notificationSettings.enabled': false });
        }
        res.json({ success: true });
    } catch (err) {
        console.error('[WebPush] Unsubscribe error:', err);
        res.status(500).json({ error: 'Failed to unsubscribe.' });
    }
});

// 4. Get Current Notification Preferences
router.get('/preferences', async (req, res) => {
    try {
        if (req.isAuthenticated && req.isAuthenticated() && req.user) {
            const user = await User.findById(req.user._id).select('notificationSettings').lean();
            return res.json({
                preferences: user?.notificationSettings || {
                    enabled: true,
                    newUploads: true,
                    clubUpdates: true,
                    adminMessages: true,
                    soundEnabled: true
                }
            });
        }
        res.json({
            preferences: {
                enabled: true,
                newUploads: true,
                clubUpdates: true,
                adminMessages: true,
                soundEnabled: true
            }
        });
    } catch (err) {
        console.error('[WebPush] Get preferences error:', err);
        res.status(500).json({ error: 'Failed to retrieve notification preferences.' });
    }
});

// 5. Update Notification Preferences
router.post('/preferences', async (req, res) => {
    try {
        const { preferences, endpoint } = req.body || {};
        if (req.isAuthenticated && req.isAuthenticated() && req.user) {
            await User.findByIdAndUpdate(req.user._id, { notificationSettings: preferences });
            await pushNotification.updatePreferences(req.user._id, preferences);
        } else if (endpoint) {
            await pushNotification.updatePreferences(endpoint, preferences);
        }
        res.json({ success: true });
    } catch (err) {
        console.error('[WebPush] Update preferences error:', err);
        res.status(500).json({ error: 'Failed to update preferences.' });
    }
});

// 6. Test Push Delivery
router.post('/test', async (req, res) => {
    try {
        const { endpoint } = req.body || {};
        let sub = null;
        if (endpoint) {
            sub = await PushSubscription.findOne({ endpoint });
        } else if (req.isAuthenticated && req.isAuthenticated() && req.user) {
            sub = await PushSubscription.findOne({ user: req.user._id }).sort({ updatedAt: -1 });
        }

        if (!sub) {
            return res.status(404).json({ error: 'No active device subscription found. Please click Enable Notifications first.' });
        }

        const testPayload = {
            title: '🔔 Test Notification Successful!',
            body: 'GPL Mods dynamic notifications with custom sound effect are working on this device.',
            url: '/settings',
            category: 'admin-messages',
            tag: 'gplmods-test-' + Date.now(),
            sound: true
        };

        const sent = await pushNotification.sendPushNotification(sub, testPayload);
        res.json({ success: sent });
    } catch (err) {
        console.error('[WebPush] Test notification error:', err);
        res.status(500).json({ error: err.message });
    }
});

module.exports = router;
