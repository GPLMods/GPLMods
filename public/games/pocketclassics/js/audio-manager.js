/**
 * ============================================================================
 * POCKET CLASSICS - AUDIO MANAGER
 * Handles theme-synced background soundtrack, autoplay unlocking, SFX & persistence
 * ============================================================================
 */
(function() {
    const THEME_TRACKS = {
        classic: '/games/pocketclassics/assets/bg1.mp3',
        cyber: '/games/pocketclassics/assets/bg2.mp3',
        india: '/games/pocketclassics/assets/bg3.mp3'
    };
    const CLICK_SFX_URL = '/games/pocketclassics/assets/click.mp3';

    class AudioManager {
        constructor() {
            this.musicEnabled = localStorage.getItem('arc_music_enabled') !== 'false';
            this.sfxEnabled = localStorage.getItem('arc_sfx_enabled') !== 'false';
            
            this.bgAudio = new Audio();
            this.bgAudio.loop = true; // Loop the assigned theme track continuously
            this.bgAudio.volume = 0.4;

            this.sfxAudio = new Audio(CLICK_SFX_URL);
            this.sfxAudio.volume = 0.6;

            this.hasInteracted = false;
            
            // Initial sync with active visual theme
            const currentTheme = localStorage.getItem('arc_theme') || 'classic';
            this.setThemeTrack(currentTheme, false);

            // If we are inside a game container, Hub music must NEVER play
            if (this.isInGamePage()) {
                this.pauseMusic();
            }
            
            this.setupListeners();
        }

        isInGamePage() {
            return Boolean(window.__GAME_ID__) || 
                   Boolean(document.getElementById('gameIframe')) || 
                   (window.location.pathname.startsWith('/games/') && window.location.pathname !== '/games/hub');
        }

        isFirstLoadSplash() {
            const isSplash = window.location.pathname === '/games' || window.location.pathname === '/games/';
            const hasSeenIntro = localStorage.getItem('arc_intro_seen') === 'true';
            return isSplash && !hasSeenIntro;
        }

        setupListeners() {
            // Browser unlock on first interaction
            const unlockAudio = () => {
                if (!this.hasInteracted) {
                    this.hasInteracted = true;
                    // Don't auto-start music if on game container page or first load intro video
                    if (this.musicEnabled && !this.isInGamePage() && !this.isFirstLoadSplash()) {
                        this.playMusic();
                    }
                    window.removeEventListener('pointerdown', unlockAudio);
                    window.removeEventListener('keydown', unlockAudio);
                }
            };
            window.addEventListener('pointerdown', unlockAudio, { once: true });
            window.addEventListener('keydown', unlockAudio, { once: true });

            // Global click sound on buttons (except muted or in-game elements if disabled)
            document.addEventListener('click', (e) => {
                if (e.target.closest('button, .arc-btn, .arcade-game-card, .filter-btn, .theme-option-btn')) {
                    this.playClick();
                }
            });
        }

        setThemeTrack(themeName, autoPlay = true) {
            const trackUrl = THEME_TRACKS[themeName] || THEME_TRACKS.classic;
            const fullTrackUrl = window.location.origin + trackUrl;
            
            const isDifferent = this.bgAudio.src !== fullTrackUrl && this.bgAudio.src !== trackUrl;
            if (isDifferent) {
                const wasPlaying = !this.bgAudio.paused;
                this.bgAudio.src = trackUrl;
                this.bgAudio.loop = true;
                if ((autoPlay || wasPlaying) && this.musicEnabled && !this.isInGamePage() && !this.isFirstLoadSplash()) {
                    this.playMusic();
                }
            }
        }

        playMusic(specificUrl) {
            // Crucial: Never play Hub music inside game containers or during first video intro
            if (this.isInGamePage() || this.isFirstLoadSplash()) {
                this.pauseMusic();
                return;
            }
            if (!this.musicEnabled) return;

            if (specificUrl) {
                if (this.bgAudio.src !== window.location.origin + specificUrl && this.bgAudio.src !== specificUrl) {
                    this.bgAudio.src = specificUrl;
                }
            } else if (!this.bgAudio.src) {
                const currentTheme = localStorage.getItem('arc_theme') || 'classic';
                this.bgAudio.src = THEME_TRACKS[currentTheme] || THEME_TRACKS.classic;
            }

            this.bgAudio.loop = true;
            this.bgAudio.play().catch(() => {
                // Autoplay policy restriction until user interaction
            });
        }

        pauseMusic() {
            try { this.bgAudio.pause(); } catch (e) {}
        }

        stopMusic() {
            try {
                this.bgAudio.pause();
                this.bgAudio.currentTime = 0;
            } catch (e) {}
        }

        playClick() {
            if (!this.sfxEnabled) return;
            try {
                this.sfxAudio.currentTime = 0;
                this.sfxAudio.play().catch(() => {});
            } catch (e) {}
        }

        toggleMusic(state) {
            this.musicEnabled = typeof state === 'boolean' ? state : !this.musicEnabled;
            localStorage.setItem('arc_music_enabled', this.musicEnabled ? 'true' : 'false');
            
            if (this.musicEnabled && !this.isInGamePage() && !this.isFirstLoadSplash()) {
                this.playMusic();
            } else {
                this.pauseMusic();
            }
            
            try {
                const iframe = document.getElementById('gameIframe');
                if (iframe && iframe.contentWindow) {
                    iframe.contentWindow.postMessage({ type: 'ARCADE_TOGGLE_MUSIC', enabled: this.musicEnabled }, '*');
                }
            } catch (e) {}
            return this.musicEnabled;
        }

        toggleSfx(state) {
            this.sfxEnabled = typeof state === 'boolean' ? state : !this.sfxEnabled;
            localStorage.setItem('arc_sfx_enabled', this.sfxEnabled ? 'true' : 'false');
            try {
                const iframe = document.getElementById('gameIframe');
                if (iframe && iframe.contentWindow) {
                    iframe.contentWindow.postMessage({ type: 'ARCADE_TOGGLE_SFX', enabled: this.sfxEnabled }, '*');
                }
            } catch (e) {}
            return this.sfxEnabled;
        }
    }

    window.ArcadeAudio = new AudioManager();
})();
