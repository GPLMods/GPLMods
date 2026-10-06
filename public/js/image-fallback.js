/**
 * ============================================================================
 * GPL MODS — B2 CLOUD IMAGE FALLBACK & FAILOVER SYSTEM
 * Automatically routes broken B2/S3 cloud images to backup InfinityFree mirror.
 * Connects directly to Failback.js/index.html for live diagnostics and telemetry.
 * ============================================================================
 */

// Primary backup host domain (InfinityFree mirror)
const FALLBACK_BASE_URL = "https://gplmods.great-site.net"; 

// 24-hour circuit breaker cookie name
const FALLBACK_COOKIE_NAME = "b2_image_fallback_active";

// Local storage key for failover telemetry and metrics
const FALLBACK_STATS_KEY = "gpl_failback_telemetry";

// Protected cloud storage asset folders
const MONITORED_FOLDERS = [
    "users", "mods", "clubs", "avatars", "card-avatars", 
    "card-backgrounds", "icons", "screenshots", "docs", 
    "forums", "requests", "support", "distributors", 
    "dmca", "ios-certs", "announcements"
];

const CLOUD_FOLDER_REGEX = new RegExp(`(${MONITORED_FOLDERS.join('|')})/([^\\?]+)`);

/**
 * Reads persistent stats from localStorage
 */
function getStoredStats() {
    try {
        const raw = localStorage.getItem(FALLBACK_STATS_KEY);
        if (raw) return JSON.parse(raw);
    } catch (e) {}
    return {
        totalSwaps: 0,
        lastFailureUrl: null,
        lastSwapTimestamp: null,
        sessionSwaps: 0
    };
}

/**
 * Saves persistent stats to localStorage
 */
function saveStoredStats(stats) {
    try {
        localStorage.setItem(FALLBACK_STATS_KEY, JSON.stringify(stats));
    } catch (e) {}
}

/**
 * Checks if the circuit breaker cookie exists and is active
 */
function isFallbackModeActive() {
    return document.cookie.split(';').some(c => c.trim().startsWith(`${FALLBACK_COOKIE_NAME}=`));
}

/**
 * Activates fallback circuit breaker mode for specified hours (default 24)
 */
function activateFallbackMode(hours = 24) {
    const maxAge = hours * 3600;
    document.cookie = `${FALLBACK_COOKIE_NAME}=true; max-age=${maxAge}; path=/`;
    
    const stats = getStoredStats();
    stats.circuitBreakerActive = true;
    stats.circuitBreakerActivatedAt = new Date().toISOString();
    saveStoredStats(stats);

    console.warn(`[Failover System] Activated fallback circuit breaker mode for ${hours} hours.`);
    window.dispatchEvent(new CustomEvent('gpl:circuit-breaker-changed', {
        detail: { active: true, hours }
    }));
}

/**
 * Deactivates fallback circuit breaker mode
 */
function deactivateFallbackMode() {
    document.cookie = `${FALLBACK_COOKIE_NAME}=; max-age=0; path=/`;
    
    const stats = getStoredStats();
    stats.circuitBreakerActive = false;
    saveStoredStats(stats);

    console.log("[Failover System] Reset fallback circuit breaker to Standby mode.");
    window.dispatchEvent(new CustomEvent('gpl:circuit-breaker-changed', {
        detail: { active: false }
    }));
}

/**
 * Extracts clean folder and filename from cloud signed URL
 * Example IN:  https://bucket.s3.b2.com/icons/123.png?X-Amz-Signature=...
 * Example OUT: https://gplmods.great-site.net/icons/123.png
 */
function getCleanFallbackUrl(originalSrc) {
    try {
        if (!originalSrc) return null;
        const match = originalSrc.match(CLOUD_FOLDER_REGEX);
        if (match && match[0]) {
            return `${FALLBACK_BASE_URL}/${match[0]}`;
        }
    } catch (e) {
        console.error("[Failover System] Error parsing fallback URL:", e);
    }
    return null;
}

/**
 * Applies fallback URL to an image element and records telemetry
 */
function applyFallback(imgElement) {
    if (!imgElement || imgElement.dataset.fallbackAttempted === "true") return;
    
    const originalSrc = imgElement.src || '';
    const fallbackUrl = getCleanFallbackUrl(originalSrc);
    
    if (fallbackUrl && !originalSrc.includes(FALLBACK_BASE_URL)) {
        imgElement.dataset.fallbackAttempted = "true";
        imgElement.dataset.originalCloudSrc = originalSrc;
        imgElement.src = fallbackUrl;

        // Telemetry update
        const stats = getStoredStats();
        stats.totalSwaps = (stats.totalSwaps || 0) + 1;
        stats.sessionSwaps = (stats.sessionSwaps || 0) + 1;
        stats.lastFailureUrl = originalSrc;
        stats.lastSwapTimestamp = new Date().toISOString();
        saveStoredStats(stats);

        // Notify live listeners (e.g. Failback.js/index.html)
        window.dispatchEvent(new CustomEvent('gpl:fallback-swapped', {
            detail: { originalSrc, fallbackUrl, timestamp: stats.lastSwapTimestamp }
        }));

        // Send asynchronous background beacon to backend telemetry if supported
        if (navigator.sendBeacon) {
            try {
                const blob = new Blob([JSON.stringify({ originalSrc, fallbackUrl })], { type: 'application/json' });
                navigator.sendBeacon('/api/failback/telemetry', blob);
            } catch (be) {}
        }
    }
}

// ============================================================================
// GLOBAL FAILBACK CONTROLLER API (Accessible to Failback.js/index.html)
// ============================================================================
window.GPLFailbackSystem = {
    isFallbackActive: isFallbackModeActive,
    activate: activateFallbackMode,
    deactivate: deactivateFallbackMode,
    getFallbackUrl: getCleanFallbackUrl,
    getMonitoredFolders: () => [...MONITORED_FOLDERS],
    getStats: getStoredStats,
    resetStats: () => {
        saveStoredStats({ totalSwaps: 0, lastFailureUrl: null, lastSwapTimestamp: null, sessionSwaps: 0 });
    },
    async testSingleUrl(url) {
        const cleanUrl = getCleanFallbackUrl(url) || url;
        const result = {
            testedUrl: url,
            cleanFallbackUrl: cleanUrl,
            primary: { status: 'testing', latencyMs: 0 },
            fallback: { status: 'testing', latencyMs: 0 }
        };

        // Test Primary
        const startPrimary = performance.now();
        try {
            const pRes = await fetch(url, { method: 'HEAD', mode: 'no-cors' });
            result.primary.latencyMs = Math.round(performance.now() - startPrimary);
            result.primary.status = 'accessible';
        } catch (e) {
            result.primary.latencyMs = Math.round(performance.now() - startPrimary);
            result.primary.status = 'error';
            result.primary.error = e.message;
        }

        // Test Fallback
        const startFallback = performance.now();
        try {
            const fRes = await fetch(cleanUrl, { method: 'HEAD', mode: 'no-cors' });
            result.fallback.latencyMs = Math.round(performance.now() - startFallback);
            result.fallback.status = 'accessible';
        } catch (e) {
            result.fallback.latencyMs = Math.round(performance.now() - startFallback);
            result.fallback.status = 'error';
            result.fallback.error = e.message;
        }

        return result;
    }
};

// ============================================================================
// EVENT LISTENERS
// ============================================================================

// 1. PROACTIVE: If circuit breaker cookie is active, reroute all cloud images at DOM load
document.addEventListener('DOMContentLoaded', () => {
    if (isFallbackModeActive()) {
        console.log("[Failover System] Fallback cookie active. Routing images to InfinityFree backup.");
        document.querySelectorAll('img').forEach(img => applyFallback(img));
    }
});

// 2. REACTIVE: Intercept broken image load events in real time
document.addEventListener('error', function(event) {
    if (event.target && event.target.tagName && event.target.tagName.toLowerCase() === 'img') {
        const failedImg = event.target;
        const src = failedImg.src || '';
        
        if (CLOUD_FOLDER_REGEX.test(src)) {
            activateFallbackMode();
            applyFallback(failedImg);
        }
    }
}, true);

// 3. ADMINJS: Redirect to /admin when clicking the sidebar branding
document.addEventListener('click', function(e) {
    if (!window.location.pathname.startsWith('/admin')) return;
    const target = e.target;
    if (!target) return;
    
    const brandingEl = target.closest('[data-css*="sidebar-branding"], [data-css*="branding"], .adminjs_Branding, aside [alt*="logo" i], aside [alt*="GPL" i], [data-css*="sidebar"] img, [class*="SidebarBranding"]');
    if (brandingEl) {
        if (window.location.pathname !== '/admin') {
            e.preventDefault();
            window.location.href = '/admin';
        }
    }
});