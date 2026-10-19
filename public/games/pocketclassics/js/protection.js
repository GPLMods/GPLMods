/**
 * ============================================================================
 * POCKET CLASSICS - PROTECTION, ZOOM PREVENTION & MODERN ARCADE TOASTS
 * 1. Asset Protection & Anti-Download (Canvas, Audio, Sprites)
 * 2. Strict Mobile & Desktop Zoom Prevention (No pinch-zoom, no double-tap zoom)
 * 3. Modern Arcade Toast System (Replaces static browser alerts)
 * ============================================================================
 */
(function() {
    'use strict';

    // --- 1. ASSET PROTECTION & ANTI-DOWNLOAD ---
    document.addEventListener('contextmenu', (e) => {
        if (e.target.closest('img, canvas, video, audio, .game-iframe-wrapper, .arcade-game-card')) {
            e.preventDefault();
            return false;
        }
    }, false);

    document.addEventListener('dragstart', (e) => {
        if (e.target.nodeName === 'IMG' || e.target.nodeName === 'CANVAS' || e.target.nodeName === 'A') {
            e.preventDefault();
            return false;
        }
    }, false);

    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S' || e.key === 'u' || e.key === 'U')) {
            e.preventDefault();
            return false;
        }
    }, false);

    // --- 2. COMPREHENSIVE ZOOM PREVENTION ---
    // A. Prevent double-tap to zoom on touch devices
    let lastTouchEnd = 0;
    document.addEventListener('touchend', (e) => {
        if (e.target.closest('input, textarea, select')) return;
        const now = Date.now();
        if (now - lastTouchEnd <= 320) {
            e.preventDefault();
        }
        lastTouchEnd = now;
    }, { passive: false });

    // B. Prevent multi-touch pinch to zoom
    document.addEventListener('touchmove', (e) => {
        if (e.touches && e.touches.length > 1) {
            e.preventDefault();
        }
    }, { passive: false });

    // C. Prevent Safari iOS gesture zoom
    ['gesturestart', 'gesturechange', 'gestureend'].forEach((evName) => {
        document.addEventListener(evName, (e) => {
            e.preventDefault();
        }, { passive: false });
    });

    // D. Prevent desktop mouse wheel zoom (Ctrl + Scroll)
    document.addEventListener('wheel', (e) => {
        if (e.ctrlKey) {
            e.preventDefault();
        }
    }, { passive: false });

    // E. Prevent keyboard zoom shortcuts (Ctrl +, Ctrl -, Ctrl 0)
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey && (e.key === '+' || e.key === '-' || e.key === '=' || e.key === '_' || e.key === '0')) {
            e.preventDefault();
        }
    }, false);

    // --- 3. MODERN ARCADE TOAST ENGINE ---
    window.ArcadeToast = {
        show: function(message, type, duration) {
            type = type || 'info';
            if (duration === undefined) duration = 3500;

            let container = document.getElementById('arcadeToastContainer');
            if (!container) {
                container = document.createElement('div');
                container.id = 'arcadeToastContainer';
                document.body.appendChild(container);
            }

            const toast = document.createElement('div');
            toast.className = 'arcade-toast toast-' + type;

            let iconClass = 'fas fa-info-circle';
            if (type === 'success') iconClass = 'fas fa-check-circle';
            else if (type === 'warning') iconClass = 'fas fa-exclamation-triangle';
            else if (type === 'error') iconClass = 'fas fa-exclamation-circle';
            else if (type === 'copy') iconClass = 'fas fa-clipboard-check';
            else if (type === 'pwa') iconClass = 'fas fa-mobile-alt';

            toast.innerHTML = '<i class="' + iconClass + ' arcade-toast-icon"></i>' +
                              '<div class="arcade-toast-text">' + message + '</div>' +
                              '<button type="button" class="arcade-toast-close" aria-label="Close"><i class="fas fa-times"></i></button>';

            var dismiss = function() {
                if (toast.classList.contains('hiding')) return;
                toast.classList.add('hiding');
                setTimeout(function() {
                    if (toast.parentNode) toast.parentNode.removeChild(toast);
                }, 260);
            };

            var closeBtn = toast.querySelector('.arcade-toast-close');
            if (closeBtn) {
                closeBtn.addEventListener('click', function(e) {
                    e.stopPropagation();
                    dismiss();
                });
            }
            toast.addEventListener('click', dismiss);

            container.appendChild(toast);
            if (duration > 0) {
                setTimeout(dismiss, duration);
            }
            return toast;
        }
    };

    // Override native browser alert with modern Arcade Toast
    window.alert = function(msg) {
        if (window.ArcadeToast && typeof window.ArcadeToast.show === 'function') {
            window.ArcadeToast.show(msg, 'info');
        } else {
            console.log('Arcade Notification:', msg);
        }
    };
})();
