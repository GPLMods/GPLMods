/**
 * GPL Mods AdminJS Badge & Tag Colorizer
 * Automatically attaches data-badge-type and data-badge-val attributes
 * to AdminJS badges, tags, and table cells for dynamic, vibrant styling.
 */
(function() {
    const KNOWN_MAP = {
        // Roles & Ranks
        'owner': 'role-owner',
        'admin': 'role-admin',
        'moderator': 'role-moderator',
        'support': 'role-support',
        'distributor': 'role-distributor',
        'creator': 'role-creator',
        'uploader': 'role-uploader',
        'member': 'role-member',
        'user': 'role-user',

        // Memberships & Plans
        'premium': 'plan-premium',
        'standard': 'plan-standard',
        'free': 'plan-free',
        'lifetime': 'plan-lifetime',
        'vip': 'plan-vip',

        // Platforms & Categories
        'android': 'platform-android',
        'windows': 'platform-windows',
        'wordpress': 'platform-wordpress',
        'ios-jailed': 'platform-ios-jailed',
        'ios-jailbroken': 'platform-ios-jailbroken',
        'ipa': 'platform-ipa',
        'deb': 'platform-deb',
        'ios': 'platform-ios',
        'mac': 'platform-mac',
        'macos': 'platform-mac',
        'linux': 'platform-linux',

        // Statuses
        'live': 'status-live',
        'approved': 'status-approved',
        'active': 'status-active',
        'pending': 'status-pending',
        'in-review': 'status-pending',
        'open': 'status-open',
        'rejected': 'status-rejected',
        'banned': 'status-banned',
        'suspended': 'status-suspended',
        'closed': 'status-closed',
        'resolved': 'status-resolved',
        'clean': 'status-clean',
        'suspicious': 'status-suspicious',
        'malicious': 'status-malicious',

        // User Verification & Tags
        'founder': 'role-founder',
        'staff': 'role-staff',
        'partner': 'role-partner',
        'verified': 'badge-verified',
        'unverified': 'badge-unverified',
        'cardholder': 'badge-cardholder',
        '2fa enabled': 'badge-2fa-on',
        '2fa disabled': 'badge-2fa-off',
        'online': 'status-online',
        'offline': 'status-offline',

        // Mods & Featured Tags
        'editors-choice': 'tag-editors-choice',
        "editor's choice": 'tag-editors-choice',
        'featured': 'tag-featured',
        'trending': 'tag-trending',
        'paid': 'tag-paid',
        'free': 'tag-free',
        'variant': 'tag-variant',

        // Support & Priorities
        'urgent': 'priority-urgent',
        'critical': 'priority-critical',
        'high': 'priority-high',
        'medium': 'priority-medium',
        'low': 'priority-low',
        'in-progress': 'status-in-progress',
        'passed': 'status-passed',
        'failed': 'status-failed'
    };

    function colorizeBadges() {
        // 1. Colorize existing Badge and Tag components
        const badgeElements = document.querySelectorAll('span[class*="Badge"], span[class*="Tag"], .adminjs_Badge, .adminjs_Tag, div[data-css*="badge"], div[data-css*="tag"]');
        badgeElements.forEach(el => {
            const rawText = (el.innerText || el.textContent || '').trim().toLowerCase();
            if (rawText && KNOWN_MAP[rawText]) {
                el.setAttribute('data-badge-val', KNOWN_MAP[rawText]);
            }
        });

        // 2. Colorize table cells for key properties
        const cellSelectors = [
            'td[data-property-name="role"]',
            'td[data-property-name="membership"]',
            'td[data-property-name="membershipPlan"]',
            'td[data-property-name="category"]',
            'td[data-property-name="status"]',
            'td[data-property-name="securityScanStatus"]',
            'td[data-property-name="priority"]',
            'td[data-property-name="isVerified"]',
            'td[data-property-name="twoFactorEnabled"]'
        ];

        document.querySelectorAll(cellSelectors.join(',')).forEach(cell => {
            const text = (cell.innerText || cell.textContent || '').trim().toLowerCase();
            if (text && KNOWN_MAP[text]) {
                cell.setAttribute('data-badge-val', KNOWN_MAP[text]);
                // If it doesn't already have an internal badge, ensure it gets styled as a chip
                if (!cell.querySelector('span[data-badge-val]')) {
                    const span = cell.querySelector('span') || cell;
                    span.setAttribute('data-badge-val', KNOWN_MAP[text]);
                    span.classList.add('admin-custom-chip');
                }
            }
        });
    }

    // Run on initial load and setup MutationObserver for SPA changes
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', colorizeBadges);
    } else {
        colorizeBadges();
    }

    const observer = new MutationObserver(() => {
        colorizeBadges();
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
})();
