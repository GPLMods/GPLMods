/**
 * ============================================================================
 * GPL MODS DYNAMIC NOTIFICATION & PWA PUSH CLIENT
 * Manages Web Push subscription, audio alerts (/sfx/notification.mp3),
 * 7-day prompt cooldown, and real-time in-app toast alerts.
 * ============================================================================
 */

(function () {
    'use strict';

    const STORAGE_KEY_ENABLED = 'gpl_push_notification_enabled';
    const STORAGE_KEY_DISMISSED = 'gpl_push_notification_prompt_dismissed';
    const STORAGE_KEY_SOUND = 'gpl_push_notification_sound';
    const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

    // 1. Audio Manager (/sfx/notification.mp3)
    let notifAudio = null;
    let audioUnlocked = false;

    function initAudio() {
        if (!notifAudio) {
            notifAudio = new Audio('/sfx/notification.mp3');
            notifAudio.preload = 'none';
            notifAudio.volume = 0.85;
        }
    }

    function playNotificationSound() {
        const soundPref = localStorage.getItem(STORAGE_KEY_SOUND);
        if (soundPref === 'false') return; // User disabled sound in settings

        initAudio();
        try {
            notifAudio.currentTime = 0;
            const playPromise = notifAudio.play();
            if (playPromise !== undefined) {
                playPromise.catch(e => console.log('[Notification SFX] Autoplay restricted:', e.message));
            }
        } catch (e) {
            console.error('[Notification SFX] Play error:', e);
        }
    }

    window.testNotificationSound = function () {
        initAudio();
        notifAudio.currentTime = 0;
        notifAudio.play().then(() => {
            console.log('[Notification SFX] Test playback successful.');
        }).catch(err => {
            if (window.showGplToast) window.showGplToast({ title: 'Audio Alert', body: 'Audio playback test error: ' + err.message });
        });
    };

    // 2. Base64 URL to Uint8Array for VAPID Key
    function urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - base64String.length % 4) % 4);
        const base64 = (base64String + padding)
            .replace(/\-/g, '+')
            .replace(/_/g, '/');
        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);
        for (let i = 0; i < rawData.length; ++i) {
            outputArray[i] = rawData.charCodeAt(i);
        }
        return outputArray;
    }

    // 3. Prompt Visibility Logic (7-day ignore cooldown, never shows if enabled)
    function shouldShowPrompt() {
        if (!('Notification' in window) || !('serviceWorker' in navigator)) {
            return false;
        }

        // STRICT POLICY GUARD: Never show notification popup before user accepted policy
        const hasAcceptedPolicy = localStorage.getItem('gplmods_policy_accepted') === 'true';
        if (!hasAcceptedPolicy) {
            return false;
        }

        // STRICT PWA GUARD: Notification popup and prompt UI only appear if user installed app as PWA
        const isPwaInstalled = window.matchMedia('(display-mode: standalone)').matches ||
            window.navigator.standalone === true ||
            localStorage.getItem('gpl_pwa_installed') === 'true' ||
            document.referrer.includes('android-app://');
        if (!isPwaInstalled) {
            return false;
        }

        // If permission already granted or user enabled, never show prompt
        if (Notification.permission === 'granted' || localStorage.getItem(STORAGE_KEY_ENABLED) === 'true' || localStorage.getItem('gpl_push_modal_seen') === 'true') {
            return false;
        }

        // If user explicitly blocked notifications in browser settings, don't nag
        if (Notification.permission === 'denied') {
            return false;
        }

        // 7-day cooldown check if previously dismissed / ignored
        const dismissedAt = localStorage.getItem(STORAGE_KEY_DISMISSED);
        if (dismissedAt) {
            const timePassed = Date.now() - parseInt(dismissedAt, 10);
            if (timePassed < SEVEN_DAYS_MS) {
                return false; // Still within 7 days cooldown
            }
        }

        return true;
    }

    // 4. Render Prompt UI
    function showNotificationPrompt() {
        if (document.getElementById('gpl-notification-prompt')) return;

        const card = document.createElement('div');
        card.id = 'gpl-notification-prompt';
        card.className = 'gpl-notif-prompt-card';
        card.innerHTML = `
            <div class="gpl-notif-prompt-header">
                <div class="gpl-notif-prompt-badge">
                    <i class="fas fa-bell"></i>
                </div>
                <div class="gpl-notif-prompt-text">
                    <h4>Never Miss a Mod Release</h4>
                    <p>Get dynamic alerts for new mod uploads, club releases &amp; important admin messages.</p>
                </div>
                <button type="button" class="gpl-notif-prompt-close" onclick="dismissNotificationPrompt()">&times;</button>
            </div>
            <div class="gpl-notif-prompt-features">
                <span class="gpl-notif-feature-chip"><i class="fas fa-rocket"></i> New Uploads</span>
                <span class="gpl-notif-feature-chip"><i class="fas fa-sync-alt"></i> Mod Updates</span>
                <span class="gpl-notif-feature-chip"><i class="fas fa-shield-alt"></i> Admin Alerts</span>
            </div>
            <div class="gpl-notif-prompt-actions">
                <button type="button" class="gpl-notif-btn-dismiss" onclick="dismissNotificationPrompt()">Maybe Later</button>
                <button type="button" class="gpl-notif-btn-enable" onclick="enablePushNotifications()">
                    <i class="fas fa-check-circle"></i> Enable Notifications
                </button>
            </div>
        `;
        document.body.appendChild(card);

        // Slide up smoothly
        setTimeout(() => {
            card.classList.add('show');
        }, 100);
    }

    window.dismissNotificationPrompt = function (permanent = false) {
        const card = document.getElementById('gpl-notification-prompt');
        if (card) {
            card.classList.remove('show');
            setTimeout(() => card.remove(), 400);
        }
        if (!permanent) {
            // Save 7-day cooldown timestamp
            localStorage.setItem(STORAGE_KEY_DISMISSED, Date.now().toString());
        }
    };

    // Render Notification Enabled Confirmation Modal
    window.showNotificationSuccessModal = function() {
        if (localStorage.getItem('gpl_push_modal_seen') === 'true') return;
        localStorage.setItem('gpl_push_modal_seen', 'true');

        let modal = document.getElementById('gpl-notif-success-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'gpl-notif-success-modal';
            modal.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.75); backdrop-filter: blur(8px); z-index: 999999; display: flex; align-items: center; justify-content: center; padding: 20px; transition: opacity 0.25s ease; opacity: 0;';
            modal.innerHTML = `
                <div style="background: linear-gradient(145deg, #181922 0%, #101117 100%); border: 1.5px solid rgba(255, 215, 0, 0.45); border-radius: 18px; max-width: 440px; width: 100%; padding: 26px 22px; box-shadow: 0 20px 50px rgba(0,0,0,0.8), 0 0 25px rgba(255, 215, 0, 0.15); text-align: center; position: relative;">
                    <div style="width: 58px; height: 58px; border-radius: 50%; background: rgba(255, 215, 0, 0.15); border: 2px solid var(--gold, #FFD700); display: flex; align-items: center; justify-content: center; margin: 0 auto 14px auto; font-size: 1.6em; color: var(--gold, #FFD700); box-shadow: 0 0 20px rgba(255, 215, 0, 0.3);">
                        <i class="fas fa-bell"></i>
                    </div>
                    <h3 style="margin: 0 0 8px 0; color: #fff; font-size: 1.25em; font-weight: 700;">Notifications Enabled!</h3>
                    <p style="color: #c0c0c0; font-size: 0.9em; line-height: 1.5; margin: 0 0 20px 0;">
                        Allow site to send notifications is now active! You will receive push alerts and audio notifications for new mod releases, club updates, and official announcements.
                    </p>
                    <div style="display: flex; gap: 10px; justify-content: center; flex-wrap: wrap;">
                        <button type="button" onclick="testNotificationSound(); if(window.sendTestNotification) window.sendTestNotification();" style="padding: 8px 16px; background: rgba(255, 215, 0, 0.15); border: 1.5px solid #FFD700; color: #FFD700; border-radius: 10px; font-weight: 600; font-size: 0.88em; cursor: pointer; display: inline-flex; align-items: center; gap: 6px;">
                            <i class="fas fa-play"></i> Test Notification
                        </button>
                        <button type="button" onclick="closeNotificationSuccessModal()" style="padding: 8px 22px; background: #FFD700; border: none; color: #000; font-weight: 700; border-radius: 10px; font-size: 0.88em; cursor: pointer; box-shadow: 0 0 15px rgba(255, 215, 0, 0.4);">
                            Got It
                        </button>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
        }
        modal.style.display = 'flex';
        requestAnimationFrame(() => {
            modal.style.opacity = '1';
        });
    };

    window.closeNotificationSuccessModal = function() {
        localStorage.setItem('gpl_push_modal_seen', 'true');
        const modal = document.getElementById('gpl-notif-success-modal');
        if (modal) {
            modal.style.opacity = '0';
            setTimeout(() => { modal.style.display = 'none'; }, 250);
        }
    };

    // 5. Subscribe to Web Push
    window.enablePushNotifications = async function () {
        try {
            if (!('Notification' in window) || !('serviceWorker' in navigator)) {
                if (window.showGplToast) window.showGplToast({ title: 'Push Not Supported', body: 'Your browser or device does not support Web Push notifications.' });
                return false;
            }

            const isAlreadyGranted = Notification.permission === 'granted';
            let permission = Notification.permission;
            if (permission !== 'granted') {
                permission = await Notification.requestPermission();
            }
            if (permission !== 'granted') {
                dismissNotificationPrompt(false);
                return false;
            }

            // User granted permission! Never show prompt again
            localStorage.setItem(STORAGE_KEY_ENABLED, 'true');
            localStorage.removeItem(STORAGE_KEY_DISMISSED);
            dismissNotificationPrompt(true);

            // Play notification sound confirmation if freshly enabled
            if (!isAlreadyGranted) {
                playNotificationSound();
            }

            // Fetch VAPID Public Key from server
            const keyRes = await fetch('/api/notifications/vapid-public-key');
            const keyData = await keyRes.json();
            if (!keyData.publicKey) {
                console.error('[WebPush] No VAPID public key received');
                showNotificationSuccessModal();
                return true;
            }

            // Wait for service worker ready
            const registration = await navigator.serviceWorker.ready;
            const convertedVapidKey = urlBase64ToUint8Array(keyData.publicKey);

            // Subscribe via PushManager
            let subscription = await registration.pushManager.getSubscription();
            if (!subscription) {
                subscription = await registration.pushManager.subscribe({
                    userVisibleOnly: true,
                    applicationServerKey: convertedVapidKey
                });
            }

            // Send subscription to server
            await fetch('/api/notifications/subscribe', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    subscription: subscription,
                    preferences: {
                        newUploads: true,
                        clubUpdates: true,
                        adminMessages: true,
                        soundEnabled: localStorage.getItem(STORAGE_KEY_SOUND) !== 'false'
                    }
                })
            });

            // Show confirmation modal ONLY if not already granted and not seen
            const hasSeenModal = localStorage.getItem('gpl_push_modal_seen') === 'true';
            if (!isAlreadyGranted && !hasSeenModal) {
                showNotificationSuccessModal();
            }

            // Show confirmation toast
            showInAppToast({
                title: '🔔 Notifications Active!',
                body: 'You will receive alerts for new uploads, club updates, and admin messages.',
                icon: '/images/icon-192x192.png'
            });

            return true;
        } catch (err) {
            console.error('[WebPush] Enable notifications error:', err);
            return false;
        }
    };

    // 5b. Unsubscribe / Disable Web Push
    window.disablePushNotifications = async function () {
        try {
            localStorage.setItem(STORAGE_KEY_ENABLED, 'false');
            if ('serviceWorker' in navigator && 'PushManager' in window) {
                try {
                    const registration = await navigator.serviceWorker.ready;
                    const subscription = await registration.pushManager.getSubscription();
                    if (subscription) {
                        await subscription.unsubscribe();
                        await fetch('/api/notifications/unsubscribe', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ endpoint: subscription.endpoint })
                        }).catch(() => {});
                    }
                } catch (se) {}
            }
            return true;
        } catch (err) {
            console.error('[WebPush] Disable notifications error:', err);
            return false;
        }
    };

    // 6. In-App Floating Toast Notification
    function getToastContainer() {
        let container = document.getElementById('gpl-toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'gpl-toast-container';
            container.className = 'gpl-toast-container';
            document.body.appendChild(container);
        }
        return container;
    }

    function showInAppToast(data = {}) {
        const container = getToastContainer();
        const toast = document.createElement('div');
        toast.className = 'gpl-toast-card';

        const iconHtml = data.icon
            ? `<img src="${data.icon}" alt="Icon" onerror="this.parentElement.innerHTML='<i class=\\'fas fa-bell\\'></i>';">`
            : '<i class="fas fa-bell"></i>';

        toast.innerHTML = `
            <div class="gpl-toast-icon-wrap">
                ${iconHtml}
            </div>
            <div class="gpl-toast-body">
                <h5 class="gpl-toast-title">${data.title || 'GPL Mods Alert'}</h5>
                <p class="gpl-toast-message">${data.body || 'New updates available.'}</p>
            </div>
            <button type="button" class="gpl-toast-close" title="Close">&times;</button>
            <div class="gpl-toast-progress"></div>
        `;

        // Click to navigate
        toast.addEventListener('click', (e) => {
            if (e.target.classList.contains('gpl-toast-close')) {
                e.stopPropagation();
                removeToast(toast);
                return;
            }
            if (data.url) {
                window.location.href = data.url;
            }
        });

        const closeBtn = toast.querySelector('.gpl-toast-close');
        if (closeBtn) {
            closeBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                removeToast(toast);
            });
        }

        container.appendChild(toast);

        // Slide in
        setTimeout(() => toast.classList.add('show'), 50);

        // Auto remove after 6 seconds
        const timer = setTimeout(() => {
            removeToast(toast);
        }, 6000);

        function removeToast(el) {
            clearTimeout(timer);
            el.classList.remove('show');
            setTimeout(() => el.remove(), 350);
        }
    }

    window.showGplToast = showInAppToast;

    // 7. Listen for Push Messages from Service Worker & Socket.IO
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.addEventListener('message', event => {
            if (event.data && event.data.type === 'GPL_PUSH_RECEIVED') {
                const payload = event.data.payload || {};
                showInAppToast(payload);
                if (payload.sound !== false) {
                    playNotificationSound();
                }
            }
        });
    }

    // Socket.IO real-time notification listener
    function bindSocketNotifications() {
        if (typeof io !== 'undefined' && window.socket) {
            window.socket.on('gpl_live_notification', data => {
                showInAppToast(data);
                if (data.sound !== false) {
                    playNotificationSound();
                }
            });
        }
    }

    // 8. Test Push Function (for Settings Page)
    window.sendTestNotification = async function () {
        try {
            const registration = await navigator.serviceWorker.ready;
            const subscription = await registration.pushManager.getSubscription();
            if (!subscription) {
                if (window.showGplToast) window.showGplToast({ title: 'Notifications Disabled', body: 'Please enable notifications first by clicking the master switch.' });
                return;
            }

            const res = await fetch('/api/notifications/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ endpoint: subscription.endpoint })
            });
            const data = await res.json();
            if (data.success) {
                playNotificationSound();
            } else {
                if (window.showGplToast) window.showGplToast({ title: 'Test Failed', body: 'Test push failed: ' + (data.error || 'Unknown error') });
            }
        } catch (e) {
            if (window.showGplToast) window.showGplToast({ title: 'Test Error', body: e.message });
        }
    };

    // 9. Initialize on Page Load
    function initNotifications() {
        initAudio();
        bindSocketNotifications();

        // Check if custom UI prompt should be shown after a small delay
        if (shouldShowPrompt()) {
            setTimeout(showNotificationPrompt, 4000);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initNotifications);
    } else {
        initNotifications();
    }
})();


    // 10. Open Notification Settings Modal directly (Especially for PWA users)
    window.openPwaNotificationSettings = function() {
        const modal = document.getElementById('globalNotificationModal');
        if (modal) {
            modal.style.display = 'flex';
        } else {
            window.location.href = '/settings#notifications';
        }
    };
    