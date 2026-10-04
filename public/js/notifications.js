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
            // STRICT PWA GUARD: Device Web Push requires PWA standalone installation
            const isPwaInstalled = (typeof window.isGplPwaInstalled === 'function' && window.isGplPwaInstalled()) ||
                window.matchMedia('(display-mode: standalone)').matches ||
                window.navigator.standalone === true ||
                localStorage.getItem('gpl_pwa_installed') === 'true' ||
                document.referrer.includes('android-app://');

            if (!isPwaInstalled) {
                if (window.showGplToast) {
                    window.showGplToast({
                        title: 'PWA Installation Required',
                        body: 'Please install GPLMods as an app to enable background push notifications on your device.'
                    });
                }
                if (typeof window.triggerPwaInstallPrompt === 'function') {
                    window.triggerPwaInstallPrompt();
                }
                return false;
            }

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

    // 6. In-App Floating Toast Notification (Supports Multiple Notifications & Action Replacement)
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

    function showInAppToast(data = {}, typeParam = null, durationParam = null, actionKeyParam = null) {
        // Support both showInAppToast('Message', 'success', 4000, 'actionKey') and showInAppToast({ title, body, ... })
        let payload = {};
        if (typeof data === 'string') {
            payload = {
                body: data,
                title: typeParam === 'success' ? 'Success' : (typeParam === 'error' ? 'Notice' : (typeParam === 'warning' ? 'Warning' : 'GPL Mods Alert')),
                type: typeParam || 'info',
                duration: durationParam || 4500,
                actionKey: actionKeyParam || null
            };
        } else if (data && typeof data === 'object') {
            payload = { ...data };
            if (!payload.body && payload.message) payload.body = payload.message;
            if (typeParam && !payload.type) payload.type = typeParam;
            if (durationParam && !payload.duration) payload.duration = durationParam;
            if (actionKeyParam && !payload.actionKey) payload.actionKey = actionKeyParam;
            if (!payload.type) payload.type = 'info';
            if (!payload.duration) payload.duration = 5000;
        }

        const container = getToastContainer();
        const duration = payload.duration || 5000;
        const toastType = payload.type || 'info';

        // Action key for deduplication and replacing old notification with new one for each action
        let actionKey = payload.actionKey;
        if (!actionKey) {
            const genericTitles = ['success', 'notice', 'warning', 'gpl mods alert', 'alert', 'error', 'info'];
            if (payload.title && !genericTitles.includes(payload.title.toLowerCase().trim())) {
                actionKey = payload.title.toLowerCase().trim().replace(/[^a-z0-9_-]/g, '_');
            } else if (payload.body) {
                actionKey = payload.body.toLowerCase().trim().slice(0, 45).replace(/[^a-z0-9_-]/g, '_');
            }
        }

        // Determine icon HTML based on type or explicit icon
        let defaultIconClass = 'fa-bell';
        if (toastType === 'success') defaultIconClass = 'fa-check-circle';
        else if (toastType === 'error') defaultIconClass = 'fa-exclamation-circle';
        else if (toastType === 'warning') defaultIconClass = 'fa-exclamation-triangle';
        else if (toastType === 'info') defaultIconClass = 'fa-info-circle';

        const iconHtml = payload.icon
            ? (payload.icon.startsWith('http') || payload.icon.startsWith('/') || payload.icon.startsWith('data:')
                ? `<img src="${payload.icon}" alt="Icon" onerror="this.parentElement.innerHTML='<i class=\\'fas ${defaultIconClass}\\'></i>';">`
                : (payload.icon.startsWith('fa-') || payload.icon.startsWith('fas ') ? `<i class="${payload.icon.startsWith('fa-') ? 'fas ' + payload.icon : payload.icon}"></i>` : `<i class="fas ${defaultIconClass}"></i>`))
            : `<i class="fas ${defaultIconClass}"></i>`;

        // Check if an existing notification with the same actionKey is currently showing
        let existingToast = null;
        if (actionKey) {
            existingToast = container.querySelector(`.gpl-toast-card[data-action-key="${actionKey}"]`);
        }

        if (existingToast) {
            // Replace the old notification with the new one for this action!
            existingToast.className = `gpl-toast-card ${toastType} show gpl-toast-pulse`;
            
            const iconWrap = existingToast.querySelector('.gpl-toast-icon-wrap');
            if (iconWrap) iconWrap.innerHTML = iconHtml;

            const titleEl = existingToast.querySelector('.gpl-toast-title');
            if (titleEl) titleEl.textContent = payload.title || (toastType === 'success' ? 'Success' : (toastType === 'error' ? 'Notice' : 'GPL Mods Alert'));

            const msgEl = existingToast.querySelector('.gpl-toast-message');
            if (msgEl) msgEl.textContent = payload.body || '';

            // Reset progress bar
            const progressBar = existingToast.querySelector('.gpl-toast-progress');
            if (progressBar) {
                progressBar.style.transition = 'none';
                progressBar.style.width = '100%';
                requestAnimationFrame(() => {
                    requestAnimationFrame(() => {
                        progressBar.style.transition = `width ${duration}ms linear`;
                        progressBar.style.width = '0%';
                    });
                });
            }

            // Reset auto remove timer
            if (existingToast._removeTimer) clearTimeout(existingToast._removeTimer);
            existingToast._removeTimer = setTimeout(() => {
                removeToast(existingToast);
            }, duration);

            setTimeout(() => existingToast.classList.remove('gpl-toast-pulse'), 450);
            return existingToast;
        }

        // Multiple notifications support: Limit to max 5 simultaneous notifications
        const activeToasts = container.querySelectorAll('.gpl-toast-card');
        if (activeToasts.length >= 5) {
            removeToast(activeToasts[0]);
        }

        const toast = document.createElement('div');
        toast.className = `gpl-toast-card ${toastType}`;
        if (actionKey) toast.setAttribute('data-action-key', actionKey);

        toast.innerHTML = `
            <div class="gpl-toast-icon-wrap">
                ${iconHtml}
            </div>
            <div class="gpl-toast-body">
                <h5 class="gpl-toast-title">${payload.title || (toastType === 'success' ? 'Success' : (toastType === 'error' ? 'Notice' : 'GPL Mods Alert'))}</h5>
                <p class="gpl-toast-message">${payload.body || 'New updates available.'}</p>
            </div>
            <button type="button" class="gpl-toast-close" title="Close">&times;</button>
            <div class="gpl-toast-progress" style="width: 100%;"></div>
        `;

        // Click to navigate
        toast.addEventListener('click', (e) => {
            if (e.target.classList.contains('gpl-toast-close')) {
                e.stopPropagation();
                removeToast(toast);
                return;
            }
            if (payload.url) {
                window.location.href = payload.url;
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
        setTimeout(() => {
            toast.classList.add('show');
            const progress = toast.querySelector('.gpl-toast-progress');
            if (progress) {
                progress.style.transition = `width ${duration}ms linear`;
                progress.style.width = '0%';
            }
        }, 30);

        // Auto remove after specified duration
        toast._removeTimer = setTimeout(() => {
            removeToast(toast);
        }, duration);

        function removeToast(el) {
            if (!el) return;
            if (el._removeTimer) clearTimeout(el._removeTimer);
            el.classList.remove('show');
            setTimeout(() => {
                if (el.parentElement) el.remove();
            }, 350);
        }

        return toast;
    }

    window.showGplToast = showInAppToast;
    window.showToast = showInAppToast;

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
    