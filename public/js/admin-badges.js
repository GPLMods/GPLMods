/**
 * GPL Mods AdminJS Badges, Textures, Avatar & Action Interceptor
 * - Machine-textured badges for roles, memberships, statuses, age ratings, booleans, and variants
 * - Admin top-bar avatar loader
 * - Admin logout confirmation popup
 */
(function() {
    // Helper to read cookies
    function getCookie(name) {
        const matches = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([\.$?*|{}\(\)\[\]\\\/\+^])/g, '\\$1') + '=([^;]*)'));
        if (!matches) return null;
        let val = decodeURIComponent(matches[1]);
        if (val && (val.includes('%3A') || val.includes('%2F'))) {
            try { val = decodeURIComponent(val); } catch(e){}
        }
        return val;
    }

    const KNOWN_MAP = {
        // Booleans
        'yes': 'bool-yes',
        'no': 'bool-no',
        'true': 'bool-yes',
        'false': 'bool-no',

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
        'draft': 'status-draft',
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

        // Variants
        'master': 'variant-master',
        'variant': 'variant-child',

        // Mods & Featured Tags
        'editors-choice': 'tag-editors-choice',
        "editor's choice": 'tag-editors-choice',
        'featured': 'tag-featured',
        'trending': 'tag-trending',
        'paid': 'tag-paid',
        'free': 'tag-free',

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

    function applyChipToCell(cell, valAttr) {
        if (!cell) return;
        if (cell.getAttribute('data-admin-enhanced') === valAttr) return;

        let span = cell.querySelector('span.admin-custom-chip, span[data-badge-val], span[class*="Badge"], span[class*="Tag"], .adminjs_Badge, .adminjs_Tag, span');
        if (span) {
            if (span.getAttribute('data-badge-val') !== valAttr) {
                span.setAttribute('data-badge-val', valAttr);
            }
            if (!span.classList.contains('admin-custom-chip')) {
                span.classList.add('admin-custom-chip');
            }
        }
        cell.setAttribute('data-admin-enhanced', valAttr);
    }

    function colorizeBadges() {
        // 1. Colorize existing Badge and Tag elements
        const badgeElements = document.querySelectorAll('span[class*="Badge"], span[class*="Tag"], .adminjs_Badge, .adminjs_Tag, div[data-css*="badge"], div[data-css*="tag"]');
        badgeElements.forEach(el => {
            const rawText = (el.innerText || el.textContent || '').trim().toLowerCase();
            if (rawText && KNOWN_MAP[rawText]) {
                el.setAttribute('data-badge-val', KNOWN_MAP[rawText]);
                el.classList.add('admin-custom-chip');
            }
            // Age rating badges (e.g. "3", "7", "12", "16", "18")
            if (/^\d{1,2}\+?$/.test(rawText)) {
                const num = rawText.replace(/\D/g, '');
                el.setAttribute('data-badge-val', 'age-rating-' + num);
                el.classList.add('admin-age-badge');
            }
        });

        // 2. Specific Table Cell Handlers
        // A. Is Verified Account / isVerified
        document.querySelectorAll('td[data-property-name="isVerifiedAccount"], td[data-property-name="isVerified"], td[data-css*="isVerifiedAccount"], td[data-css*="isVerified-table-cell"]').forEach(cell => {
            const text = (cell.innerText || cell.textContent || '').trim().toLowerCase();
            if (text === 'yes' || text === 'true') {
                applyChipToCell(cell, 'user-verified-yes', 'YES');
            } else if (text === 'no' || text === 'false') {
                applyChipToCell(cell, 'user-verified-no', 'NO');
            }
        });

        // B. Is Banned
        document.querySelectorAll('td[data-property-name="isBanned"], td[data-css*="isBanned"]').forEach(cell => {
            const text = (cell.innerText || cell.textContent || '').trim().toLowerCase();
            if (text === 'no' || text === 'false') {
                applyChipToCell(cell, 'banned-no', 'NO');
            } else if (text === 'yes' || text === 'true') {
                applyChipToCell(cell, 'banned-yes', 'YES');
            }
        });

        // C. Show in Repo
        document.querySelectorAll('td[data-property-name="showInRepo"], td[data-css*="showInRepo"]').forEach(cell => {
            const text = (cell.innerText || cell.textContent || '').trim().toLowerCase();
            if (text === 'yes' || text === 'true') {
                applyChipToCell(cell, 'repo-yes', 'YES');
            } else if (text === 'no' || text === 'false') {
                applyChipToCell(cell, 'repo-no', 'NO');
            }
        });

        // D. Is Variant
        document.querySelectorAll('td[data-property-name="isVariant"], td[data-css*="isVariant"]').forEach(cell => {
            const text = (cell.innerText || cell.textContent || '').trim().toLowerCase();
            if (text.includes('master')) {
                applyChipToCell(cell, 'variant-master', 'MASTER');
            } else if (text.includes('variant') || text === 'child' || text === 'yes') {
                applyChipToCell(cell, 'variant-child', 'VARIANT');
            }
        });

        // E. Age Rating
        document.querySelectorAll('td[data-property-name="ageRating"], td[data-css*="ageRating"]').forEach(cell => {
            const text = (cell.innerText || cell.textContent || '').trim();
            const num = text.replace(/\D/g, '') || text;
            if (num) {
                applyChipToCell(cell, 'age-rating-' + num, text);
                const span = cell.querySelector('span');
                if (span) span.classList.add('admin-age-badge');
            }
        });

        // F. Status
        document.querySelectorAll('td[data-property-name="status"], td[data-css*="status-table-cell"]').forEach(cell => {
            const text = (cell.innerText || cell.textContent || '').trim().toLowerCase();
            if (text === 'draft') {
                applyChipToCell(cell, 'status-draft', 'DRAFT');
            } else if (text === 'live') {
                applyChipToCell(cell, 'status-live', 'LIVE');
            } else if (KNOWN_MAP[text]) {
                applyChipToCell(cell, KNOWN_MAP[text], text.toUpperCase());
            }
        });

        // G. All other key properties (role, membership, category, etc.)
        const cellSelectors = [
            'td[data-property-name="role"]',
            'td[data-property-name="membership"]',
            'td[data-property-name="membershipPlan"]',
            'td[data-property-name="category"]',
            'td[data-property-name="securityScanStatus"]',
            'td[data-property-name="priority"]',
            'td[data-property-name="twoFactorEnabled"]',
            'td[data-property-name="isActive"]'
        ];

        document.querySelectorAll(cellSelectors.join(',')).forEach(cell => {
            const text = (cell.innerText || cell.textContent || '').trim().toLowerCase();
            if (text && KNOWN_MAP[text]) {
                applyChipToCell(cell, KNOWN_MAP[text]);
            }
        });

        // H. Generic fallback: any table cell with raw "YES" or "NO"
        document.querySelectorAll('td').forEach(cell => {
            if (cell.getAttribute('data-admin-enhanced')) return;
            const text = (cell.innerText || cell.textContent || '').trim().toLowerCase();
            if (text === 'yes' || text === 'true') {
                applyChipToCell(cell, 'bool-yes', 'YES');
            } else if (text === 'no' || text === 'false') {
                applyChipToCell(cell, 'bool-no', 'NO');
            }
        });
    }

    // 3. Admin Top-Bar Avatar Enhancer
    function updateTopBarAvatar() {
        let avatarUrl = getCookie('admin_avatar');
        if (!avatarUrl || avatarUrl === 'undefined' || avatarUrl === 'null') {
            avatarUrl = '/images/default-avatar.png';
        }

        // Target avatar containers inside current user nav or navbar
        const userNavs = document.querySelectorAll('[class*="CurrentUserNav"], [class*="CurrentUser"], header [class*="NavBar"]');
        userNavs.forEach(nav => {
            const potentialAvatars = nav.querySelectorAll('[class*="Avatar"], div, span');
            potentialAvatars.forEach(el => {
                if (el.querySelector('img.admin-topbar-avatar') || el.getAttribute('data-avatar-set') === 'true') return;
                const txt = (el.innerText || el.textContent || '').trim();
                // Single letter avatar circle (e.g. "G")
                if (txt.length === 1 && /^[a-zA-Z]$/.test(txt) && el.children.length === 0) {
                    el.setAttribute('data-avatar-set', 'true');
                    el.innerHTML = `<img src="${avatarUrl}" class="admin-topbar-avatar" alt="Admin Avatar" onerror="this.onerror=null; this.src='/images/default-avatar.png';" />`;
                    el.style.background = 'transparent';
                    el.style.border = 'none';
                    el.style.boxShadow = 'none';
                    el.style.padding = '0';
                    el.style.display = 'inline-flex';
                    el.style.alignItems = 'center';
                    el.style.justifyContent = 'center';
                }
            });

            // Images inside user nav get the gold ring
            nav.querySelectorAll('img').forEach(img => {
                if (!img.classList.contains('admin-topbar-avatar') && (img.src.includes('avatar') || img.alt.toLowerCase().includes('avatar') || img.closest('[class*="CurrentUserNav"]'))) {
                    img.classList.add('admin-topbar-avatar');
                }
            });
        });
    }

    // 4. AdminJS Logout Confirmation Modal
    function setupLogoutConfirmation() {
        if (document.getElementById('adminLogoutModal')) return;

        const modalHtml = `
            <div id="adminLogoutModal" class="admin-logout-modal-backdrop">
                <div class="admin-logout-modal-card">
                    <div style="width: 56px; height: 56px; margin: 0 auto 16px; border-radius: 50%; background: rgba(244, 67, 54, 0.12); border: 1px solid rgba(244, 67, 54, 0.4); display: flex; align-items: center; justify-content: center; color: #ff5252; font-size: 1.5rem; box-shadow: 0 0 20px rgba(244, 67, 54, 0.3);">
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg>
                    </div>
                    <h3 style="color: #fff; font-size: 1.3rem; font-weight: 700; margin: 0 0 10px; letter-spacing: -0.01em;">Confirm Admin Logout</h3>
                    <p style="color: #94a3b8; font-size: 0.95rem; line-height: 1.5; margin: 0 0 24px;">
                        Are you sure you want to end your administrator session? You will need to authenticate again to access the Admin Control Center.
                    </p>
                    <div style="display: flex; gap: 12px; justify-content: center;">
                        <button type="button" id="adminCancelLogoutBtn" style="flex: 1; padding: 12px 16px; background: rgba(255, 255, 255, 0.08); border: 1px solid rgba(255, 255, 255, 0.15); color: #e2e8f0; border-radius: 10px; font-weight: 600; font-size: 0.95rem; cursor: pointer; font-family: 'Poppins', sans-serif; transition: all 0.2s;">
                            Stay in Admin
                        </button>
                        <a href="/admin/logout" id="adminConfirmLogoutBtn" style="flex: 1; padding: 12px 16px; background: linear-gradient(135deg, #f44336 0%, #d32f2f 100%); border: 1px solid rgba(255, 255, 255, 0.2); color: #fff; border-radius: 10px; font-weight: 600; font-size: 0.95rem; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; gap: 8px; box-shadow: 0 6px 18px rgba(244, 67, 54, 0.4); cursor: pointer; font-family: 'Poppins', sans-serif;">
                            Log Out Now
                        </a>
                    </div>
                </div>
            </div>
        `;

        const div = document.createElement('div');
        div.innerHTML = modalHtml;
        document.body.appendChild(div.firstElementChild);

        const modal = document.getElementById('adminLogoutModal');
        const cancelBtn = document.getElementById('adminCancelLogoutBtn');

        function closeModal() {
            if (modal) modal.classList.remove('show');
        }

        if (cancelBtn) {
            cancelBtn.addEventListener('click', closeModal);
        }

        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) closeModal();
            });
        }

        // Global click listener in capture phase to intercept AdminJS logout links
        document.addEventListener('click', (e) => {
            const target = e.target.closest('a, button, [role="button"], [class*="DropDownItem"]');
            if (!target) return;

            const href = target.getAttribute('href') || '';
            const text = (target.innerText || target.textContent || '').trim().toLowerCase();

            const isLogoutLink = href.includes('/admin/logout') || href.includes('/logout') || text === 'log out' || text === 'logout';

            if (isLogoutLink && target.id !== 'adminConfirmLogoutBtn') {
                e.preventDefault();
                e.stopPropagation();
                if (modal) modal.classList.add('show');
            }
        }, true);
    }

    let isMutating = false;
    let debounceTimer = null;

    function runAll() {
        if (isMutating) return;
        isMutating = true;
        try {
            colorizeBadges();
            updateTopBarAvatar();
            setupLogoutConfirmation();
        } catch (e) {
            console.error('[AdminJS Badges Error]', e);
        } finally {
            setTimeout(() => {
                isMutating = false;
            }, 50);
        }
    }

    function scheduleRun() {
        if (isMutating) return;
        if (debounceTimer) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(runAll, 80);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', runAll);
    } else {
        runAll();
    }

    const observer = new MutationObserver((mutations) => {
        if (isMutating) return;
        let hasRelevantMutation = false;
        for (let i = 0; i < mutations.length; i++) {
            const m = mutations[i];
            if (m.type === 'childList' && m.addedNodes.length > 0) {
                for (let j = 0; j < m.addedNodes.length; j++) {
                    const node = m.addedNodes[j];
                    if (node.nodeType === 1) { // Element node
                        if (
                            node.id === 'adminLogoutModal' || 
                            (node.classList && (
                                node.classList.contains('admin-logout-modal-backdrop') ||
                                node.classList.contains('admin-topbar-avatar')
                            ))
                        ) {
                            continue;
                        }
                        hasRelevantMutation = true;
                        break;
                    }
                }
            }
            if (hasRelevantMutation) break;
        }
        if (hasRelevantMutation) {
            scheduleRun();
        }
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
})();
