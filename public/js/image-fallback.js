/**
 * ============================================================================
 * B2 CLOUD IMAGE FALLBACK SYSTEM
 * Automatically routes broken B2 images to a backup InfinityFree host.
 * ============================================================================
 */

// ⚠️ IMPORTANT: Change this to your actual InfinityFree domain!
const FALLBACK_BASE_URL = "https://gplmods.great-site.net"; 

// The name of our 24-hour circuit breaker cookie
const FALLBACK_COOKIE_NAME = "b2_image_fallback_active";

/**
 * Checks if the 24-hour fallback cookie exists.
 */
function isFallbackModeActive() {
    return document.cookie.split(';').some(c => c.trim().startsWith(`${FALLBACK_COOKIE_NAME}=`));
}

/**
 * Activates the fallback mode for 24 hours (86400 seconds).
 */
function activateFallbackMode() {
    if (!isFallbackModeActive()) {
        console.warn("[Failover System] B2 Image failure detected. Activating backup server for 24 hours.");
        document.cookie = `${FALLBACK_COOKIE_NAME}=true; max-age=86400; path=/`;
    }
}

/**
 * Extracts the clean folder and filename from a messy B2 signed URL.
 * Example IN: https://bucket.s3.b2.com/icons/123.png?X-Amz-Signature=...
 * Example OUT: /icons/123.png
 */
function getCleanFallbackUrl(originalSrc) {
    try {
        // This Regex matches any of our cloud storage folders and grabs the relative path,
        // ignoring any '?' URL query parameters attached by Backblaze signed URLs.
        const match = originalSrc.match(/(avatars|mods|icons|screenshots|docs|forums|requests|support|distributors|dmca|ios-certs|announcements)\/([^\?]+)/);
        
        if (match) {
            // match[0] contains "folder/subfolder/.../filename.png"
            return `${FALLBACK_BASE_URL}/${match[0]}`;
        }
    } catch (e) {
        console.error("Error parsing fallback URL", e);
    }
    return null; // Return null if it's not a B2 cloud image (like your local logo.png)
}

/**
 * Applies the fallback URL to an image.
 */
function applyFallback(imgElement) {
    // Prevent an infinite loop if the backup server ALSO fails!
    if (imgElement.dataset.fallbackAttempted === "true") return;
    
    const fallbackUrl = getCleanFallbackUrl(imgElement.src);
    
    if (fallbackUrl && !imgElement.src.includes(FALLBACK_BASE_URL)) {
        imgElement.dataset.fallbackAttempted = "true"; // Mark as attempted
        imgElement.src = fallbackUrl; // Swap the image source!
    }
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================

// 1. PROACTIVE: If the cookie is active when the page loads, swap all images immediately.
document.addEventListener('DOMContentLoaded', () => {
    if (isFallbackModeActive()) {
        console.log("[Failover System] Fallback cookie is active. Routing images to backup server.");
        document.querySelectorAll('img').forEach(img => {
            applyFallback(img);
        });
    }
});

// 2. REACTIVE: Catch any image that fails to load in real-time.
// We use the 'capture' phase (true) because 'error' events on images don't bubble up.
document.addEventListener('error', function(event) {
    // Check if the element that failed is an Image
    if (event.target && event.target.tagName && event.target.tagName.toLowerCase() === 'img') {
        const failedImg = event.target;
        const src = failedImg.src || '';
        
        // Ensure it's one of our cloud images that failed, not a local asset
        const cloudFolderPattern = /(avatars|mods|icons|screenshots|docs|forums|requests|support|distributors|dmca|ios-certs|announcements)/;
        if (cloudFolderPattern.test(src)) {
            activateFallbackMode(); // Set the 24-hour cookie
            applyFallback(failedImg); // Swap the broken image with the backup
        }
    }
}, true);