/**
 * ============================================================================
 * POCKET CLASSICS - AUDIO MANAGER
 * Handles autoplay policies, rotating music tracks, SFX, and persistence
 * ============================================================================
 */
(function() {
    const MUSIC_PLAYLIST = [
        '/games/pocketclassics/assets/bg1.mp3',
        '/games/pocketclassics/assets/bg2.mp3'
    ];
    const CLICK_SFX_URL = '/games/pocketclassics/assets/click.mp3';

    class AudioManager {
        constructor() {
            this.musicEnabled = localStorage.getItem('arc_music_enabled') !== 'false';
            this.sfxEnabled = localStorage.getItem('arc_sfx_enabled') !== 'false';
            this.currentTrackIndex = Math.floor(Math.random() * MUSIC_PLAYLIST.length);
            
            this.bgAudio = new Audio();
            this.bgAudio.loop = false;
            this.bgAudio.volume = 0.4;

            this.sfxAudio = new Audio(CLICK_SFX_URL);
            this.sfxAudio.volume = 0.6;

            this.hasInteracted = false;
            
            // Check if we are inside a game container
            const isInGamePage = window.location.pathname.includes('/games/play') || Boolean(document.getElementById('gameIframe'));
            if (isInGamePage) {
                this.pauseMusic();
            }
            
            this.setupListeners();
        }

        setupListeners() {
            // Next track when current ends
            this.bgAudio.addEventListener('ended', () => {
                this.nextTrack();
            });

            // Browser unlock on first interaction
            const unlockAudio = () => {
                if (!this.hasInteracted) {
                    this.hasInteracted = true;
                    const isInGamePage = window.location.pathname.includes('/games/play') || Boolean(document.getElementById('gameIframe'));
                    if (this.musicEnabled && !isInGamePage) {
                        this.playMusic();
                    }
                    window.removeEventListener('pointerdown', unlockAudio);
                    window.removeEventListener('keydown', unlockAudio);
                }
            };
            window.addEventListener('pointerdown', unlockAudio, { once: true });
            window.addEventListener('keydown', unlockAudio, { once: true });

            // Global click sound on buttons
            document.addEventListener('click', (e) => {
                if (e.target.closest('button, .arc-btn, .game-card, .filter-btn')) {
                    this.playClick();
                }
            });
        }

        playMusic(specificUrl) {
            const isInGamePage = window.location.pathname.includes('/games/play') || Boolean(document.getElementById('gameIframe'));
            if (isInGamePage) {
                this.pauseMusic();
                return;
            }
            if (!this.musicEnabled) return;
            const src = specificUrl || MUSIC_PLAYLIST[this.currentTrackIndex];
            if (this.bgAudio.src !== window.location.origin + src && this.bgAudio.src !== src) {
                this.bgAudio.src = src;
            }
            this.bgAudio.play().catch(() => {
                // Autoplay blocked until user interaction
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

        nextTrack() {
            this.currentTrackIndex = (this.currentTrackIndex + 1) % MUSIC_PLAYLIST.length;
            this.playMusic();
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
            const isInGamePage = window.location.pathname.includes('/games/play') || Boolean(document.getElementById('gameIframe'));
            if (this.musicEnabled && !isInGamePage) {
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
