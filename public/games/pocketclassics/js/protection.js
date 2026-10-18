/**
 * ============================================================================
 * POCKET CLASSICS - ASSET PROTECTION & ANTI-DOWNLOAD
 * Protects games, canvas, sprites, audio, and screenshots from unauthorized save
 * ============================================================================
 */
(function() {
    // 1. Disable Right Click Context Menu on Assets & Canvas
    document.addEventListener('contextmenu', (e) => {
        if (e.target.closest('img, canvas, video, audio, .game-iframe-wrapper, .arcade-game-card')) {
            e.preventDefault();
            return false;
        }
    }, false);

    // 2. Prevent Drag and Drop of Images and Canvas
    document.addEventListener('dragstart', (e) => {
        if (e.target.nodeName === 'IMG' || e.target.nodeName === 'CANVAS' || e.target.nodeName === 'A') {
            e.preventDefault();
            return false;
        }
    }, false);

    // 3. Prevent Save Keyboard Shortcuts (Ctrl+S / Cmd+S)
    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.key === 'S' || e.key === 'u' || e.key === 'U')) {
            e.preventDefault();
            return false;
        }
    }, false);
})();
