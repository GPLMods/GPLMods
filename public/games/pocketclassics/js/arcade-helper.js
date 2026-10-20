/**
 * ============================================================================
 * POCKET CLASSICS - UNIVERSAL ARCADE HELPER
 * Provides:
 * 1. Dedicated Main Menu Music vs In-Game Music Audio Controller
 * 2. Full Gamepad / Controller API Support (Xbox, PS, Switch, Generic)
 * 3. Keyboard & Mouse Navigation Bridge
 * 4. Touch & Gesture Optimizations with Haptic Feedback
 * 5. Device & Responsive Mode Detection (Mobile, Tablet, PC)
 * ============================================================================
 */

(function (window, document) {
    'use strict';

    // Prevent double init
    if (window.ArcadeHelper) return;

    // --- 1. DEVICE & VIEWPORT DETECTION ---
    const isTouchDevice = ('ontouchstart' in window) || (navigator.maxTouchPoints > 0);
    const isDesktop = !isTouchDevice && window.matchMedia('(hover: hover) and (pointer: fine)').matches;
    
    function updateDeviceClasses() {
        const w = window.innerWidth;
        const h = window.innerHeight;
        document.body.classList.toggle('arc-is-touch', isTouchDevice);
        document.body.classList.toggle('arc-is-desktop', isDesktop);
        document.body.classList.toggle('arc-is-mobile', w < 768);
        document.body.classList.toggle('arc-is-tablet', w >= 768 && w < 1024);
        document.body.classList.toggle('arc-is-landscape', w > h);
    }
    updateDeviceClasses();
    window.addEventListener('resize', updateDeviceClasses);

    // --- 2. UNIVERSAL AUDIO CONTROLLER (MENU MUSIC & GAMEPLAY MUSIC) ---
    class ArcadeAudioController {
        constructor(options = {}) {
            this.storagePrefix = options.storagePrefix || 'arc_';
            this.musicEnabled = localStorage.getItem(this.storagePrefix + 'music_enabled') !== 'false' && localStorage.getItem('arc_music_enabled') !== 'false';
            this.sfxEnabled = localStorage.getItem(this.storagePrefix + 'sfx_enabled') !== 'false' && localStorage.getItem('arc_sfx_enabled') !== 'false';
            this.hasInteracted = false;
            this.currentState = 'menu'; // 'menu' | 'game' | 'paused' | 'over'
            
            this.menuAudio = null;
            this.gameAudio = null;
            this.sfxMap = new Map();

            this.initElements(options);
            this.setupInteractions();
            this.listenToParent();
        }

        initElements(options = {}) {
            // Find or bind menu audio
            if (options.menuAudioId) {
                this.menuAudio = document.getElementById(options.menuAudioId);
            }
            if (options.gameAudioId) {
                this.gameAudio = document.getElementById(options.gameAudioId);
            }

            if (!this.menuAudio) {
                this.menuAudio = document.getElementById('music-menu') || 
                                 document.getElementById('menu-music') || 
                                 document.querySelector('audio[data-role="menu"]');
            }
            
            // Find or bind game audio
            if (!this.gameAudio) {
                this.gameAudio = document.getElementById('music-game') || 
                                 document.getElementById('bg-music') || 
                                 document.getElementById('background-music') || 
                                 document.querySelector('audio[data-role="game"]');
            }

            if (this.menuAudio) {
                this.menuAudio.loop = true;
                this.menuAudio.volume = 0.55;
            }
            if (this.gameAudio) {
                this.gameAudio.loop = true;
                this.gameAudio.volume = 0.5;
            }
        }

        registerTracks(menuSrc, gameSrc) {
            if (menuSrc && !this.menuAudio) {
                this.menuAudio = new Audio(menuSrc);
                this.menuAudio.id = 'music-menu';
                this.menuAudio.loop = true;
                this.menuAudio.volume = 0.55;
            }
            if (gameSrc && !this.gameAudio) {
                this.gameAudio = new Audio(gameSrc);
                this.gameAudio.id = 'music-game';
                this.gameAudio.loop = true;
                this.gameAudio.volume = 0.5;
            }
        }

        setupInteractions() {
            // Immediate autoplay attempt
            if (this.musicEnabled) {
                this.playMenuMusic();
            }

            const unlock = () => {
                if (!this.hasInteracted) {
                    this.hasInteracted = true;
                    if (this.musicEnabled) {
                        if (this.currentState === 'menu') {
                            this.playMenuMusic();
                        } else {
                            this.playGameMusic();
                        }
                    }
                    ['pointerdown', 'pointermove', 'touchstart', 'keydown', 'scroll'].forEach(evt => {
                        window.removeEventListener(evt, unlock);
                    });
                }
            };
            ['pointerdown', 'pointermove', 'touchstart', 'keydown', 'scroll'].forEach(evt => {
                window.addEventListener(evt, unlock, { passive: true });
            });
        }

        listenToParent() {
            window.addEventListener('message', (event) => {
                if (!event.data || typeof event.data !== 'object') return;
                if (event.data.type === 'ARCADE_TOGGLE_MUSIC') {
                    this.setMusicEnabled(Boolean(event.data.enabled));
                } else if (event.data.type === 'ARCADE_TOGGLE_SFX') {
                    this.setSfxEnabled(Boolean(event.data.enabled));
                }
            });
        }

        setMusicEnabled(enabled) {
            this.musicEnabled = enabled;
            localStorage.setItem('arc_music_enabled', enabled ? 'true' : 'false');
            if (!enabled) {
                this.pauseAll();
            } else if (this.hasInteracted) {
                if (this.currentState === 'menu') {
                    this.playMenuMusic();
                } else {
                    this.playGameMusic();
                }
            }
        }

        setSfxEnabled(enabled) {
            this.sfxEnabled = enabled;
            localStorage.setItem('arc_sfx_enabled', enabled ? 'true' : 'false');
        }

        toggleMusic(force) {
            const next = typeof force === 'boolean' ? force : !this.musicEnabled;
            this.setMusicEnabled(next);
            return next;
        }

        toggleSfx(force) {
            const next = typeof force === 'boolean' ? force : !this.sfxEnabled;
            this.setSfxEnabled(next);
            return next;
        }

        playMenuMusic() {
            this.currentState = 'menu';
            if (this.gameAudio && !this.gameAudio.paused) {
                try { this.gameAudio.pause(); this.gameAudio.currentTime = 0; } catch (_) {}
            }
            if (!this.musicEnabled || !this.hasInteracted || !this.menuAudio) return;
            try {
                this.menuAudio.currentTime = this.menuAudio.currentTime || 0;
                this.menuAudio.play().catch(() => {});
            } catch (_) {}
        }

        playGameMusic() {
            this.currentState = 'game';
            if (this.menuAudio && !this.menuAudio.paused) {
                try { this.menuAudio.pause(); } catch (_) {}
            }
            if (!this.musicEnabled || !this.hasInteracted || !this.gameAudio) return;
            try {
                this.gameAudio.play().catch(() => {});
            } catch (_) {}
        }

        pauseAll() {
            try { if (this.menuAudio) this.menuAudio.pause(); } catch (_) {}
            try { if (this.gameAudio) this.gameAudio.pause(); } catch (_) {}
        }

        playSfx(audioOrId) {
            if (!this.sfxEnabled) return;
            let el = typeof audioOrId === 'string' ? document.getElementById(audioOrId) : audioOrId;
            if (el && typeof el.play === 'function') {
                try {
                    el.currentTime = 0;
                    el.play().catch(() => {});
                } catch (_) {}
            }
        }
    }

    // --- 3. FULL GAMEPAD / CONTROLLER MANAGER ---
    class ArcadeGamepadController {
        constructor(options = {}) {
            this.connectedGamepads = new Map();
            this.buttonStates = new Map(); // buttonIdx -> boolean
            this.axisDebounce = { x: 0, y: 0 };
            this.listeners = {
                onDirection: [], // (dir: 'up'|'down'|'left'|'right') => void
                onAction: [],    // (action: 'A'|'B'|'X'|'Y'|'START'|'SELECT') => void
                onMoveAnalog: [] // (x: float, y: float) => void
            };
            if (typeof options.onDirectionDown === 'function') {
                this.listeners.onDirection.push(options.onDirectionDown);
            }
            if (typeof options.onActionDown === 'function') {
                this.listeners.onAction.push((action) => {
                    options.onActionDown(action.toLowerCase());
                });
            }
            if (typeof options.onMoveAnalog === 'function') {
                this.listeners.onMoveAnalog.push(options.onMoveAnalog);
            }
            this.hudEl = null;

            this.initListeners();
            this.createHud();
            this.startLoop();
        }

        onDirection(cb) { this.listeners.onDirection.push(cb); return this; }
        onAction(cb) { this.listeners.onAction.push(cb); return this; }
        onMoveAnalog(cb) { this.listeners.onMoveAnalog.push(cb); return this; }

        createHud() {
            if (document.getElementById('arc-gamepad-hud')) return;
            this.hudEl = document.createElement('div');
            this.hudEl.id = 'arc-gamepad-hud';
            this.hudEl.style.cssText = `
                position: fixed;
                bottom: 12px;
                right: 12px;
                background: rgba(15, 23, 42, 0.88);
                color: #38bdf8;
                border: 1px solid rgba(56, 189, 248, 0.4);
                box-shadow: 0 4px 16px rgba(0, 0, 0, 0.6), 0 0 10px rgba(56, 189, 248, 0.25);
                backdrop-filter: blur(8px);
                border-radius: 9999px;
                padding: 6px 14px;
                font-size: 0.76rem;
                font-weight: 700;
                display: flex;
                align-items: center;
                gap: 8px;
                z-index: 999999;
                opacity: 0;
                transform: translateY(10px);
                transition: opacity 0.3s ease, transform 0.3s ease;
                pointer-events: none;
                font-family: inherit;
            `;
            this.hudEl.innerHTML = '<i class="fas fa-gamepad" style="font-size: 0.95rem; color: #38bdf8;"></i> <span id="arc-gamepad-name">Controller Connected</span>';
            document.body.appendChild(this.hudEl);
        }

        showHud(name) {
            if (!this.hudEl) return;
            const nameEl = this.hudEl.querySelector('#arc-gamepad-name');
            if (nameEl) nameEl.textContent = name ? `${name.substring(0, 24)}` : 'Controller Connected';
            this.hudEl.style.opacity = '1';
            this.hudEl.style.transform = 'translateY(0)';
            clearTimeout(this._hudTimer);
            this._hudTimer = setTimeout(() => {
                if (this.hudEl) {
                    this.hudEl.style.opacity = '0';
                    this.hudEl.style.transform = 'translateY(10px)';
                }
            }, 3500);
        }

        initListeners() {
            window.addEventListener('gamepadconnected', (e) => {
                this.connectedGamepads.set(e.gamepad.index, e.gamepad);
                document.body.classList.add('has-gamepad');
                const cleanName = e.gamepad.id.replace(/\([^)]*\)/g, '').trim() || 'Gamepad';
                this.showHud(cleanName);
                if (window.ArcadeHelper?.audio) {
                    window.ArcadeHelper.audio.hasInteracted = true;
                }
            });

            window.addEventListener('gamepaddisconnected', (e) => {
                this.connectedGamepads.delete(e.gamepad.index);
                if (this.connectedGamepads.size === 0) {
                    document.body.classList.remove('has-gamepad');
                }
            });
        }

        onDirection(cb) { this.listeners.onDirection.push(cb); }
        onAction(cb) { this.listeners.onAction.push(cb); }
        onMoveAnalog(cb) { this.listeners.onMoveAnalog.push(cb); }

        startLoop() {
            const DEADZONE = 0.35;
            let lastPollTime = 0;

            const poll = (timestamp) => {
                const gamepads = navigator.getGamepads ? navigator.getGamepads() : [];
                let activeGp = null;
                for (let i = 0; i < gamepads.length; i++) {
                    if (gamepads[i] && gamepads[i].connected) {
                        activeGp = gamepads[i];
                        break;
                    }
                }

                if (activeGp) {
                    // 1. Analog Stick Analog updates (continuous for games like Air Hockey)
                    const rawX = activeGp.axes[0] || 0;
                    const rawY = activeGp.axes[1] || 0;
                    const normX = Math.abs(rawX) > DEADZONE ? rawX : 0;
                    const normY = Math.abs(rawY) > DEADZONE ? rawY : 0;
                    
                    if (normX !== 0 || normY !== 0) {
                        this.listeners.onMoveAnalog.forEach(cb => cb(normX, normY));
                    }

                    // 2. Discrete directional inputs (D-Pad & Stick debounced for menus / grid)
                    const dpadUp = activeGp.buttons[12]?.pressed || normY < -0.55;
                    const dpadDown = activeGp.buttons[13]?.pressed || normY > 0.55;
                    const dpadLeft = activeGp.buttons[14]?.pressed || normX < -0.55;
                    const dpadRight = activeGp.buttons[15]?.pressed || normX > 0.55;

                    const now = Date.now();
                    const throttle = 180; // ms between repeated D-pad taps

                    if (now - lastPollTime > throttle) {
                        let triggered = false;
                        if (dpadUp) { this.triggerDir('up'); triggered = true; }
                        else if (dpadDown) { this.triggerDir('down'); triggered = true; }
                        else if (dpadLeft) { this.triggerDir('left'); triggered = true; }
                        else if (dpadRight) { this.triggerDir('right'); triggered = true; }
                        if (triggered) lastPollTime = now;
                    }

                    // 3. Action Buttons (Edge-triggered on press down)
                    // Standard Gamepad: 0: A/Cross, 1: B/Circle, 2: X/Square, 3: Y/Triangle, 8: Select, 9: Start
                    const btnMap = [
                        { idx: 0, name: 'A' },
                        { idx: 1, name: 'B' },
                        { idx: 2, name: 'X' },
                        { idx: 3, name: 'Y' },
                        { idx: 8, name: 'SELECT' },
                        { idx: 9, name: 'START' }
                    ];

                    btnMap.forEach(({ idx, name }) => {
                        const isPressed = Boolean(activeGp.buttons[idx]?.pressed);
                        const wasPressed = Boolean(this.buttonStates.get(idx));
                        if (isPressed && !wasPressed) {
                            this.triggerAction(name);
                            ArcadeHelper.vibrate(18);
                        }
                        this.buttonStates.set(idx, isPressed);
                    });
                }

                requestAnimationFrame(poll);
            };

            requestAnimationFrame(poll);
        }

        triggerDir(dir) {
            this.listeners.onDirection.forEach(cb => cb(dir));
        }

        triggerAction(action) {
            this.listeners.onAction.forEach(cb => cb(action));
            
            // Standard action behaviors:
            if (action === 'A') {
                // Click currently focused element or active button
                const active = document.activeElement;
                if (active && (active.tagName === 'BUTTON' || active.classList.contains('btn'))) {
                    active.click();
                }
            } else if (action === 'B' || action === 'START') {
                // Try back button / pause button if available
                const backBtn = document.getElementById('back-to-main-btn') || 
                                document.getElementById('back-to-menu-btn') || 
                                document.getElementById('back-to-menu-game-btn') ||
                                document.getElementById('pause-btn') ||
                                document.getElementById('menu-btn');
                if (backBtn && !backBtn.classList.contains('hidden') && backBtn.offsetParent !== null) {
                    backBtn.click();
                }
            }
        }
    }

    // --- 4. TOUCH & HAPTIC UTILITIES ---
    const ArcadeHelper = {
        audio: null,
        gamepad: null,

        init(options = {}) {
            this.audio = new ArcadeAudioController();
            if (options.menuMusic || options.gameMusic) {
                this.audio.registerTracks(options.menuMusic, options.gameMusic);
            }
            this.gamepad = new ArcadeGamepadController();
            this.setupTouchDefaults();
            return this;
        },

        vibrate(pattern = 15) {
            if (navigator.vibrate && localStorage.getItem('arc_sfx_enabled') !== 'false') {
                try { navigator.vibrate(pattern); } catch (_) {}
            }
        },

        setupTouchDefaults() {
            // Prevent double-tap zooming & unwanted bouncing on canvases
            document.addEventListener('touchstart', (e) => {
                if (e.touches.length > 1) {
                    // Multi-touch pinch-to-zoom prevention in game containers
                    const target = e.target;
                    if (target.closest('canvas, #game-container, .game-board, #game-wrapper')) {
                        e.preventDefault();
                    }
                }
            }, { passive: false });
        },

        // Clean swipe detector helper
        bindSwipe(element, onSwipe) {
            if (!element) return;
            let startX = 0, startY = 0, startTime = 0;
            const threshold = 35;
            const maxTime = 600;

            element.addEventListener('touchstart', (e) => {
                if (e.touches.length === 1) {
                    startX = e.touches[0].clientX;
                    startY = e.touches[0].clientY;
                    startTime = Date.now();
                }
            }, { passive: true });

            element.addEventListener('touchend', (e) => {
                if (e.changedTouches.length === 1) {
                    const endX = e.changedTouches[0].clientX;
                    const endY = e.changedTouches[0].clientY;
                    const elapsed = Date.now() - startTime;
                    if (elapsed > maxTime) return;

                    const dx = endX - startX;
                    const dy = endY - startY;
                    const absX = Math.abs(dx);
                    const absY = Math.abs(dy);

                    if (Math.max(absX, absY) >= threshold) {
                        if (absX > absY) {
                            onSwipe(dx > 0 ? 'right' : 'left');
                        } else {
                            onSwipe(dy > 0 ? 'down' : 'up');
                        }
                    }
                }
            }, { passive: true });
        }
    };

    window.ArcadeAudioController = ArcadeAudioController;
    window.ArcadeGamepadController = ArcadeGamepadController;
    window.ArcadeHelper = ArcadeHelper;

    // Auto-init helper on DOM ready if not manually invoked
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => {
            if (!ArcadeHelper.audio) ArcadeHelper.init();
        });
    } else {
        if (!ArcadeHelper.audio) ArcadeHelper.init();
    }

})(window, document);

