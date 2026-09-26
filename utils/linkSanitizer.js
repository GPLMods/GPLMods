/**
 * ============================================================================
 * LINK SANITIZER UTILITY
 * Strictly enforces that members cannot send external links to any website.
 * Only official GPLMods site links and relative paths are allowed in:
 *  - Club chat channels
 *  - /community-chat
 * ============================================================================
 */

const ALLOWED_HOSTS = [
    'gplmods.webredirect.org',
    'webredirect.org',
    'gplmods.mytunnel.org',
    'mytunnel.org',
    'localhost',
    '127.0.0.1'
];

/**
 * Checks if the text contains any forbidden external URL.
 * @param {string} text - Message or comment text to inspect.
 * @returns {boolean} - True if forbidden external links were detected, false if safe.
 */
function containsForbiddenExternalLinks(text) {
    if (!text || typeof text !== 'string') return false;

    // 1. Detect standard URLs (http://, https://, ftp://)
    const protocolRegex = /\b(?:https?|ftp):\/\/([^\s/$.?#].[^\s]*)/gi;
    let strippedText = text;

    let match;
    while ((match = protocolRegex.exec(text)) !== null) {
        try {
            const rawUrl = match[0];
            const parsed = new URL(rawUrl);
            const host = parsed.hostname.toLowerCase();
            const isAllowed = ALLOWED_HOSTS.some(allowed => host === allowed || host.endsWith('.' + allowed));
            if (!isAllowed) {
                return true; // Forbidden external URL found!
            }
            // Strip this allowed URL from strippedText so bare domain check doesn't re-parse its components
            strippedText = strippedText.replace(rawUrl, ' ');
        } catch (e) {
            return true; // Malformed URL, block for safety
        }
    }

    // 2. Detect bare domains (e.g. google.com, discord.gg, bit.ly, etc.)
    const bareDomainRegex = /\b((?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|gg|me|app|xyz|site|online|tv|cc|ru|cn|in|info|biz|co|uk|de|eu|club|link|live|shop|tech|dev|page))\b(?:\/[^\s]*)?/gi;

    while ((match = bareDomainRegex.exec(strippedText)) !== null) {
        try {
            const rawDomain = match[1].toLowerCase();
            const isAllowed = ALLOWED_HOSTS.some(allowed => rawDomain === allowed || rawDomain.endsWith('.' + allowed));
            if (!isAllowed) {
                return true; // Forbidden external domain found!
            }
        } catch (e) {
            return true;
        }
    }

    return false;
}

/**
 * Validates message content for link restrictions.
 * @param {string} text
 * @returns {{ valid: boolean, error: string|null }}
 */
function validateMessageLinks(text) {
    if (containsForbiddenExternalLinks(text)) {
        return {
            valid: false,
            error: 'External links are strictly forbidden! Only official GPLMods site links are allowed in the chat.'
        };
    }
    return { valid: true, error: null };
}

module.exports = {
    ALLOWED_HOSTS,
    containsForbiddenExternalLinks,
    validateMessageLinks
};
