/**
 * ============================================================================
 * POCKET CLASSICS - THEME MANAGER
 * Supports Classic (GPL Gold), Cyber, and India Themes with dynamic rotation
 * ============================================================================
 */
(function() {
    const THEMES = ['classic', 'cyber', 'india'];

    class ThemeManager {
        constructor() {
            let savedTheme = localStorage.getItem('arc_theme');
            // If first time visit or dynamic rotation enabled, pick a random theme
            if (!savedTheme) {
                savedTheme = THEMES[Math.floor(Math.random() * THEMES.length)];
            }
            this.currentTheme = savedTheme;
            this.applyTheme(this.currentTheme);
        }

        applyTheme(themeName) {
            if (!THEMES.includes(themeName)) themeName = 'classic';
            this.currentTheme = themeName;
            document.body.setAttribute('data-theme', themeName);
            localStorage.setItem('arc_theme', themeName);

            // Update theme radio / button UI if present
            document.querySelectorAll('.theme-option-btn').forEach(btn => {
                const target = btn.dataset.theme;
                if (target === themeName) {
                    btn.classList.add('active');
                } else {
                    btn.classList.remove('active');
                }
            });
        }

        setTheme(themeName) {
            this.applyTheme(themeName);
        }

        nextTheme() {
            const idx = THEMES.indexOf(this.currentTheme);
            const next = THEMES[(idx + 1) % THEMES.length];
            this.applyTheme(next);
        }
    }

    window.ArcadeTheme = new ThemeManager();
})();
