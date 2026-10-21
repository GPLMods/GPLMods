/**
 * ============================================================================
 * POCKET CLASSICS - THEME MANAGER
 * Supports Classic (GPL Gold), Cyber Neon, and India Tiranga Themes
 * Automatically syncs theme-specific audio soundtrack and controls
 * Automatically rotates to next theme when user revisits the arcade
 * ============================================================================
 */
(function() {
    const THEMES = ['classic', 'cyber', 'india'];

    class ThemeManager {
        constructor() {
            let savedTheme = localStorage.getItem('arc_theme');
            if (!savedTheme || !THEMES.includes(savedTheme)) {
                savedTheme = 'classic';
            }
            this.currentTheme = savedTheme;

            // Check if user is visiting or revisiting in a new page/tab load
            // Every fresh page entry into the Arcade (splash / games index / hub) rotates the theme
            const isArcadeEntry = !sessionStorage.getItem('arc_session_themed') || 
                                 window.location.pathname === '/games' || 
                                 window.location.pathname === '/games/';

            if (isArcadeEntry) {
                sessionStorage.setItem('arc_session_themed', 'true');
                const idx = THEMES.indexOf(this.currentTheme);
                this.currentTheme = THEMES[(idx + 1) % THEMES.length];
                this.applyTheme(this.currentTheme, false);
            } else {
                this.applyTheme(this.currentTheme, false);
            }

            // Sync with iframe on load
            window.addEventListener('load', () => {
                this.syncIframeTheme();
            });
        }

        applyTheme(themeName, shouldTriggerAudio = true) {
            if (!THEMES.includes(themeName)) themeName = 'classic';
            this.currentTheme = themeName;
            document.documentElement.setAttribute('data-theme', themeName);
            document.body.setAttribute('data-theme', themeName);
            localStorage.setItem('arc_theme', themeName);

            // Sync theme-specific music track
            if (window.ArcadeAudio) {
                window.ArcadeAudio.setThemeTrack(themeName, shouldTriggerAudio);
            }

            // Sync to any embedded game iframe
            this.syncIframeTheme();

            // Update theme radio / button UI in settings modal if present
            document.querySelectorAll('.theme-option-btn').forEach(btn => {
                const target = btn.dataset.theme;
                if (target === themeName) {
                    btn.classList.add('active');
                    btn.style.borderColor = 'var(--arc-accent)';
                    btn.style.boxShadow = '0 0 12px var(--arc-accent-glow)';
                } else {
                    btn.classList.remove('active');
                    btn.style.borderColor = 'var(--arc-border)';
                    btn.style.boxShadow = 'none';
                }
            });
        }

        syncIframeTheme() {
            const iframe = document.getElementById('gameIframe');
            if (!iframe) return;
            try {
                iframe.contentWindow?.postMessage({
                    type: 'ARCADE_SET_THEME',
                    theme: this.currentTheme
                }, '*');
                const idoc = iframe.contentDocument || iframe.contentWindow?.document;
                if (idoc) {
                    if (idoc.documentElement) idoc.documentElement.setAttribute('data-theme', this.currentTheme);
                    if (idoc.body) idoc.body.setAttribute('data-theme', this.currentTheme);
                }
            } catch (_) {}
        }

        setTheme(themeName) {
            this.applyTheme(themeName, true);
        }

        nextTheme() {
            const idx = THEMES.indexOf(this.currentTheme);
            const next = THEMES[(idx + 1) % THEMES.length];
            this.applyTheme(next, true);
            return next;
        }
    }

    window.ArcadeTheme = new ThemeManager();

    // Global listener for quick theme switch buttons
    document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('#quickThemeBtn').forEach(btn => {
            btn.addEventListener('click', () => {
                window.ArcadeTheme?.nextTheme();
            });
        });
    });
})();
