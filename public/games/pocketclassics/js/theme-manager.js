/**
 * ============================================================================
 * POCKET CLASSICS - THEME MANAGER
 * Supports Classic (GPL Gold), Cyber Neon, and India Tiranga Themes
 * Automatically syncs theme-specific audio soundtrack and controls
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
            this.applyTheme(this.currentTheme, false);
        }

        applyTheme(themeName, shouldTriggerAudio = true) {
            if (!THEMES.includes(themeName)) themeName = 'classic';
            this.currentTheme = themeName;
            document.body.setAttribute('data-theme', themeName);
            localStorage.setItem('arc_theme', themeName);

            // Sync theme-specific music track
            if (window.ArcadeAudio) {
                window.ArcadeAudio.setThemeTrack(themeName, shouldTriggerAudio);
            }

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

        setTheme(themeName) {
            this.applyTheme(themeName, true);
        }

        nextTheme() {
            const idx = THEMES.indexOf(this.currentTheme);
            const next = THEMES[(idx + 1) % THEMES.length];
            this.applyTheme(next, true);
        }
    }

    window.ArcadeTheme = new ThemeManager();
})();
