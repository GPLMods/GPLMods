/**
 * ==================================================================================
 * GPL MODS GLOBAL JAVASCRIPT
 * ==================================================================================
 * Table of Contents:
 * 0. Document Ready Initializer (with Try/Catch Safety)
 * 1. Homepage Tab Navigation
 * 2. Star Rating System
 * 3. VPN DETECTION SYSTEM (Timezone Mismatch Method)
 * 4. Search Bar Handler (Dynamic Animation)
 * 5. Search History & Suggestions
 * 6. Mobile Navigation Handler
 * 7. Policy Acceptance Banner and PWA  and Newsletter Sequence
 * 8. Robust Footer Music Player
 * 9. Smart Audio Handler (YouTube/Vimeo pauses BG music)
 * 10. Notifications Logic
 * 11. Newsletter Logic
 * 12. REUSABLE SOCIAL CAROUSEL LOGIC
 * 13. GLOBAL CUSTOM SELECT DROPDOWNS
 * 14. MULTI-LANGUAGE & LIVE TRANSLATION ENGINE
 * ==================================================================================
 */

console.log("GPL Mods main.js is loading...");

// ==================================================================================
// 0. DOCUMENT READY INITIALIZER
// ==================================================================================
document.addEventListener('DOMContentLoaded', () => {
    console.log("DOM loaded. Running initializers...");
    
    const runInitializers = async () => {        
try { initializeMobileMenu(); } catch (e) { console.error("Mobile Menu Error:", e); }
try { initializeStarRatings(); } catch (e) { console.error("Star Ratings Error:", e); }
try { initializeHomepageTabs(); } catch (e) { console.error("Homepage Tabs Error:", e); }
try { initializeSmartAudioHandler(); } catch (e) { console.error("Smart Audio Error:", e); }
try { initializePolicyBanner(); } catch (e) { console.error("Policy Banner Error:", e); }
try { initializeMusicPlayer(); } catch (e) { console.error("Music Player Error:", e); }
try { initializeNewsletter(); } catch (e) { console.error("Newsletter Error:", e); }
try { initializeNotificationsAndPWA(); } catch (e) { console.error("PWA/Notif Error:", e); }
try { initializeVpnDetector(); } catch (e) { console.error("VPN Detector Error:", e); }
try { await initializeSearchBar(); } catch (e) { console.error("Search Bar Error:", e); }
try { initializeLanguageSystem(); } catch (e) { console.error("Language System Error:", e); }
try { initializeSocialCarousels(); } catch (e) { console.error("Carousel Error:", e); }
        console.log("All initializers finished.");
    };

    runInitializers();
});

/**
 * ==================================================================================
 * 1. HOMEPAGE 2-TIER TAB NAVIGATION
 * Handles main tabs and iOS sub-tabs
 * ==================================================================================
 */
function initializeHomepageTabs() {
    const mainTabNav = document.getElementById('main-tabs-nav');
    const iosSubTabsContainer = document.getElementById('ios-sub-tabs-container');
    const iosTabNav = document.getElementById('ios-tabs-nav');

    if (!mainTabNav) return;

    const allTabContents = document.querySelectorAll('.tab-content');
    const mainTabHighlight = document.getElementById('main-tab-highlight');
    const iosTabHighlight = document.getElementById('ios-tab-highlight');

    // Helper to animate the golden pill
    function moveHighlight(targetTab, highlightElement) {
        if (!targetTab || !highlightElement) return;
        requestAnimationFrame(() => {
            highlightElement.style.width = `${targetTab.offsetWidth}px`;
            highlightElement.style.transform = `translateX(${targetTab.offsetLeft}px)`;
        });
    }

    // Generic setup function for a tab row
    function setupTabGroup(navElement, highlightElement, isMainGroup) {
        if (!navElement) return;
        const tabButtons = navElement.querySelectorAll('.tab-button');
        const initialActiveTab = navElement.querySelector('.tab-button.active');
        if (initialActiveTab) moveHighlight(initialActiveTab, highlightElement);

        tabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const targetTabId = button.dataset.tab;

                // Update active classes
                tabButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');
                moveHighlight(button, highlightElement);

                // Logic for Main Tabs vs Sub Tabs
                if (isMainGroup) {
                    if (targetTabId === 'ios') {
                        // Open iOS sub-tabs, default to Jailed
                        if (iosSubTabsContainer) iosSubTabsContainer.style.display = 'block';
                        const defaultSubTab = iosTabNav.querySelector('[data-tab="ios-jailed"]');
                        iosTabNav.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
                        defaultSubTab.classList.add('active');
                        moveHighlight(defaultSubTab, iosTabHighlight);
                        
                        allTabContents.forEach(content => content.classList.remove('active'));
                        document.getElementById('ios-jailed-mods').classList.add('active');
                    } else {
                        // Standard tab clicked, hide sub-tabs
                        if (iosSubTabsContainer) iosSubTabsContainer.style.display = 'none';
                        allTabContents.forEach(content => content.classList.remove('active'));
                        const targetContent = document.getElementById(`${targetTabId}-mods`);
                        if (targetContent) targetContent.classList.add('active');
                    }
                } else {
                    // Sub-tab clicked (Jailed or Jailbroken)
                    allTabContents.forEach(content => content.classList.remove('active'));
                    const targetContent = document.getElementById(`${targetTabId}-mods`);
                    if (targetContent) targetContent.classList.add('active');
                }

                button.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' });
            });
        });
    }

    // Initialize both groups
    setupTabGroup(mainTabNav, mainTabHighlight, true);
    setupTabGroup(iosTabNav, iosTabHighlight, false);

    // Keep highlights perfectly sized on window resize
    window.addEventListener('resize', () => {
        const activeMain = mainTabNav.querySelector('.tab-button.active');
        if (activeMain) moveHighlight(activeMain, mainTabHighlight);
        
        if (iosTabNav && iosSubTabsContainer.style.display === 'block') {
            const activeIos = iosTabNav.querySelector('.tab-button.active');
            if (activeIos) moveHighlight(activeIos, iosTabHighlight);
        }
    });
}

/**
 * ==================================================================================
 * 2. STAR RATING SYSTEM
 * ==================================================================================
 */
function initializeStarRatings() {
    const allRatingContainers = document.querySelectorAll('.star-rating');
    allRatingContainers.forEach(container => {
        const rating = parseFloat(container.dataset.rating);
        if (isNaN(rating)) return;

        const stars = container.querySelectorAll('.star');
        const fullStars = Math.floor(rating);
        const partialStarPercentage = (rating % 1) * 100;

        for (let i = 0; i < fullStars; i++) {
            if (stars[i]) stars[i].classList.add('filled');
        }

        if (fullStars < 5 && partialStarPercentage > 0 && stars[fullStars]) {
            const partialStar = stars[fullStars];
            partialStar.style.setProperty('--fill-percentage', `${partialStarPercentage}%`);
            partialStar.classList.add('partial');
        }
    });
}

/**
 * ==================================================================================
 * 3. VPN DETECTION SYSTEM (Multi-API Reliable Detection Method)
 * ==================================================================================
 */
async function initializeVpnDetector() {
    const vpnModal = document.getElementById('vpn-modal-container');
    const understoodBtn = document.getElementById('understoodVpnBtn');

    // 1. Check if they already dismissed it
    if (!vpnModal || !understoodBtn || localStorage.getItem('gplmods_vpn_dismissed') === 'true') {
        return; 
    }

    try {
        // 2. Use multiple VPN detection APIs for higher reliability
        const isVpnDetected = await checkVpnStatus();

        if (isVpnDetected) {
            console.log("VPN/Proxy/Datacenter IP Detected.");
            
            // Show the modal
            vpnModal.style.display = 'flex'; 
            vpnModal.classList.add('show');
            
            setTimeout(() => {
                const contentBox = vpnModal.querySelector('.policy-modal-content');
                if (contentBox) contentBox.classList.add('active');
            }, 10);
        } else {
            console.log("Clean IP detected. No VPN active.");
        }
    } catch (error) {
        console.error("VPN detection error:", error);
    }

    // 3. Handle the "Understood!" Button Click and Confetti
    understoodBtn.addEventListener('click', () => {
        localStorage.setItem('gplmods_vpn_dismissed', 'true');
        
        const contentBox = vpnModal.querySelector('.policy-modal-content');
        if (contentBox) contentBox.classList.remove('active');
        
        setTimeout(() => {
            vpnModal.classList.remove('show');
            vpnModal.style.display = 'none'; 
        }, 300);

        // Trigger the Colorful Party Popper (Confetti) Effect!
        const duration = 2000;
        const end = Date.now() + duration;

        (function frame() {
            confetti({
                particleCount: 5,
                angle: 60,
                spread: 55,
                origin: { x: 0 },
                colors: ['#FFD700', '#c0c0c0', '#2196F3', '#e53935', '#43a047'] 
            });
            confetti({
                particleCount: 5,
                angle: 120,
                spread: 55,
                origin: { x: 1 },
                colors: ['#FFD700', '#c0c0c0', '#2196F3', '#e53935', '#43a047']
            });

            if (Date.now() < end) {
                requestAnimationFrame(frame);
            }
        }());
    });
}

/**
 * Check VPN status using multiple API sources for better detection
 */
async function checkVpnStatus() {
    // Try primary API first (ip-api.com)
    try {
        const response = await fetch('https://ip-api.com/json/?fields=status,proxy,hosting', {
            method: 'GET'
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log("ip-api.com response:", data);
            
            if (data && data.status === 'success') {
                if (data.proxy === true || data.hosting === true) {
                    console.log("VPN detected via ip-api.com - proxy:", data.proxy, "hosting:", data.hosting);
                    return true;
                }
            }
        }
    } catch (error) {
        console.warn("Primary VPN detection API failed:", error);
    }

    // Try secondary API (ipqualityscore.com - free tier, no key required)
    try {
        const response = await fetch('https://ipqualityscore.com/api/json/ip', {
            method: 'GET'
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log("ipqualityscore.com response:", data);
            
            // Check for VPN/Proxy indicators
            if (data && (data.proxy === true || data.is_crawler === true || data.is_vpn === true)) {
                console.log("VPN detected via ipqualityscore.com");
                return true;
            }
        }
    } catch (error) {
        console.warn("Secondary VPN detection API failed:", error);
    }

    // Try tertiary API (iphub.info - free tier)
    try {
        const response = await fetch('https://iphub.info/api/ip', {
            method: 'GET',
            headers: {
                'X-IPHub-Key': 'free' // Free tier uses 'free' as key
            }
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log("iphub.info response:", data);
            
            // block: 0 = residential, 1 = non-residential/datacenter, 2 = VPN/Proxy
            if (data && data.block >= 1) {
                console.log("VPN/Proxy detected via iphub.info - block level:", data.block);
                return true;
            }
        }
    } catch (error) {
        console.warn("Tertiary VPN detection API failed:", error);
    }

    // If all APIs fail or don't detect VPN, return false
    console.log("All VPN detection checks completed. No VPN detected.");
    return false;
}
/**
 * ==================================================================================
 * 4. SEARCH BAR HANDLER (DYNAMIC ANIMATION & SUGGESTIONS)
 * ==================================================================================
 */
async function initializeSearchBar() {
    const searchInput = document.getElementById('searchInput');
    const suggestionsBox = document.getElementById('searchSuggestions');
    const searchHistoryBox = document.getElementById('searchHistory');
    const searchBar = document.getElementById('animatedSearchBar');

    if (!searchInput) return;

    // --- 1. Focus & Blur Handling ---
    let blurTimeout;

    searchInput.addEventListener('focus', () => {
        if(searchBar) searchBar.classList.add('active');
        // Only show history if the input is empty
        if (searchInput.value.trim() === '') {
            displaySearchHistory();
        }
    });

    searchInput.addEventListener('blur', () => {
        // Use a timeout to allow clicks inside the dropdown to register first
        blurTimeout = setTimeout(() => {
            if (searchBar) searchBar.classList.remove('active');
            if (suggestionsBox) suggestionsBox.style.display = 'none';
            if (searchHistoryBox) searchHistoryBox.style.display = 'none';
        }, 200); 
    });

    // --- 2. Live Typing (Input Handling) ---
    searchInput.addEventListener('input', () => {
        const query = searchInput.value.trim();
        if (query.length > 1) {
            fetchAndDisplaySuggestions(query);
            if(searchHistoryBox) searchHistoryBox.style.display = 'none';
        } else {
            if(suggestionsBox) suggestionsBox.style.display = 'none';
            if(query.length === 0) displaySearchHistory(); // Show history again if cleared
        }
    });

    // --- 3. Form Submission Handling ---
    if (searchBar) {
        const searchForm = searchBar.querySelector('form');
        if (searchForm) {
            searchForm.addEventListener('submit', (e) => {
                const query = searchInput.value.trim();
                if (query) {
                    saveSearchTerm(normalizeSearchTerm(query));
                }
            });
        }
    }

    // --- 4. Keyboard "Enter" Handling ---
    searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === 'Go' || e.key === 'Search') {
            const query = searchInput.value.trim();
            if (query) {
                saveSearchTerm(normalizeSearchTerm(query));
            }
        }
    });

    // --- 5. IMPORTANT FIX: Handle Clicks INSIDE the Dropdown ---
    // Mousedown fires before blur, ensuring the click is registered
    const handleDropdownClick = (e) => {
        const link = e.target.closest('a');
        if (link) {
            // Cancel the blur timeout so the box doesn't disappear
            clearTimeout(blurTimeout);
            
            // Get the text they clicked on
            // (Using innerText/textContent might grab HTML if you bolded things, 
            // so we grab it from the href or a data attribute if available. 
            // Here, we'll try to extract the clean query from the href)
            try {
                const url = new URL(link.href);
                const queryParam = url.searchParams.get('q');
                if (queryParam) {
                    saveSearchTerm(queryParam);
                }
            } catch (err) {
                 // Fallback if URL parsing fails
                 saveSearchTerm(link.textContent);
            }
            
            // Let the browser follow the link naturally
        }
    };

    if (suggestionsBox) {
        suggestionsBox.addEventListener('mousedown', handleDropdownClick);
    }
    if (searchHistoryBox) {
        searchHistoryBox.addEventListener('mousedown', handleDropdownClick);
    }


    // --- 6. Dynamic Typing Animation ---
    let searchTerms = ["Search for mods..."]; 
    try {
        const response = await fetch('/api/trending-searches');
        if (response.ok) {
            const trending = await response.json();
            if (trending.length > 0) searchTerms = trending.map(term => `${term}...`);
        }
    } catch (error) {
        console.error("Could not fetch trending searches:", error);
    }

    const themeColors = ["var(--gold)", "var(--silver)"];
    let termIndex = 0, letterIndex = 0, currentTerm = '', isDeleting = false, typingTimeout;
    let colorIndex = 0; 

    function typeAnimation() {
        if (document.activeElement === searchInput) return;
        const fullTerm = searchTerms[termIndex] || "Search...";

        if (isDeleting) {
            currentTerm = fullTerm.substring(0, letterIndex - 1);
            letterIndex--;
        } else {
            currentTerm = fullTerm.substring(0, letterIndex + 1);
            letterIndex++;
        }

        searchInput.placeholder = currentTerm;
        let typeSpeed = isDeleting ? 60 : 120;

        if (!isDeleting && letterIndex === fullTerm.length) {
            isDeleting = true;
            typeSpeed = 1500;
        } else if (isDeleting && letterIndex === 0) {
            isDeleting = false;
            termIndex = (termIndex + 1) % searchTerms.length;
            colorIndex++;
            searchInput.style.setProperty('--placeholder-color', themeColors[colorIndex % 2]);
            typeSpeed = 300;
        }
        typingTimeout = setTimeout(typeAnimation, typeSpeed);
    }

    searchInput.style.setProperty('--placeholder-color', 'var(--gold)');
    typeAnimation();

    searchInput.addEventListener('focus', () => {
        clearTimeout(typingTimeout);
        searchInput.placeholder = "Search for mods...";
        searchInput.style.setProperty('--placeholder-color', 'var(--silver)');
    });

    searchInput.addEventListener('blur', () => {
        if (searchInput.value === '') {
            searchInput.placeholder = "";
            letterIndex = 0;
            isDeleting = false;
            termIndex = (termIndex + 1) % searchTerms.length;
            typeAnimation();
        }
    });
}

/**
 * ==================================================================================
 * 5. SEARCH HISTORY & SUGGESTIONS
 * ==================================================================================
 */
const SEARCH_HISTORY_KEY = 'gplmods_search_history';
const MAX_HISTORY_ITEMS = 5;

function getSearchHistory() {
    const historyJSON = localStorage.getItem(SEARCH_HISTORY_KEY);
    return historyJSON ? JSON.parse(historyJSON) :[];
}

function normalizeSearchTerm(term) {
    return term.replace(/\s+/g, ' ').trim();
}

function saveSearchTerm(term) {
    const normalized = normalizeSearchTerm(term);
    if (!normalized) return;

    let history = getSearchHistory();
    history = history.filter(item => item.toLowerCase() !== normalized.toLowerCase());
    history.unshift(normalized);
    if (history.length > MAX_HISTORY_ITEMS) history.pop();
    localStorage.setItem(SEARCH_HISTORY_KEY, JSON.stringify(history));
}

function displaySearchHistory() {
    const history = getSearchHistory();
    const historyBox = document.getElementById('searchHistory');
    const suggestionsBox = document.getElementById('searchSuggestions');
    if (!historyBox) return;

    historyBox.innerHTML = '';
    if (history.length > 0) {
        const title = document.createElement('h4');
        title.textContent = 'Recent Searches';
        historyBox.appendChild(title);
        const list = document.createElement('ul');
        history.forEach(term => {
            const listItem = document.createElement('li');
            listItem.innerHTML = `<a href="/search?q=${encodeURIComponent(term)}">${term}</a>`;
            list.appendChild(listItem);
        });
        historyBox.appendChild(list);
        historyBox.style.display = 'block';
        if(suggestionsBox) suggestionsBox.style.display = 'none';
    } else {
        historyBox.style.display = 'none';
    }
}

async function fetchAndDisplaySuggestions(query) {
    const suggestionsBox = document.getElementById('searchSuggestions');
    if (!suggestionsBox) return;

    try {
        const response = await fetch(`/api/search/suggestions?q=${encodeURIComponent(query)}`);
        if (!response.ok) throw new Error('Network error');
        const suggestions = await response.json();
        suggestionsBox.innerHTML = '';

        if (suggestions.length > 0) {
            const list = document.createElement('ul');
            suggestions.forEach(suggestion => {
                const listItem = document.createElement('li');
                const escapedQuery = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const regex = new RegExp(escapedQuery, 'gi');
                const boldedSuggestion = suggestion.replace(regex, (match) => `<b>${match}</b>`);
                listItem.innerHTML = `<a href="/search?q=${encodeURIComponent(suggestion)}">${boldedSuggestion}</a>`;
                list.appendChild(listItem);
            });
            suggestionsBox.appendChild(list);
            suggestionsBox.style.display = 'block';
        } else {
            suggestionsBox.style.display = 'none';
        }
    } catch (error) {
        suggestionsBox.style.display = 'none';
    }
}

/**
 * ==================================================================================
 * 6. ROBUST MOBILE NAVIGATION
 * ==================================================================================
 */
function initializeMobileMenu() {
    const hamburger = document.getElementById('hamburger');
    const mobileNav = document.getElementById('mobileNav');
    
    if (!hamburger || !mobileNav) {
        console.warn("Mobile menu elements not found.");
        return;
    }

    const openNav = () => {
        mobileNav.style.display = 'block';
        hamburger.classList.add('open');
        hamburger.innerHTML = '&times;'; // Show an 'X' icon
    };

    const closeNav = () => {
        mobileNav.style.display = 'none';
        hamburger.classList.remove('open');
        hamburger.innerHTML = '&#9776;'; // Show the hamburger icon
    };

    // Toggle on hamburger click
    hamburger.addEventListener('click', (e) => {
        e.stopPropagation(); // Stop the click from bubbling up to the document listener
        if (mobileNav.style.display === 'block') {
            closeNav();
        } else {
            openNav();
        }
    });

    // Close when a normal menu link is clicked
    mobileNav.querySelectorAll('a').forEach(link => {
        if (!link.classList.contains('collapsible-trigger')) {
            link.addEventListener('click', closeNav);
        }
    });

    // Handle collapsible sub-menus
    const collapsibleTriggers = mobileNav.querySelectorAll('.collapsible-trigger');
    collapsibleTriggers.forEach(trigger => {
        trigger.addEventListener('click', function(e) {
            e.preventDefault();
            this.parentElement.classList.toggle('open');
        });
    });

    // Close when clicking outside the nav or hamburger
    document.addEventListener('click', (event) => {
        if (mobileNav.style.display === 'block' &&
            !mobileNav.contains(event.target) &&
            !hamburger.contains(event.target)) {
            closeNav();
        }
    });
    
    // Close safely on Escape key
    document.addEventListener('keydown', (ev) => {
        if (ev.key === 'Escape' && mobileNav.style.display === 'block') {
            closeNav();
        }
    });
}

/**
 * ==================================================================================
 * 7. POLICY BANNER & SEQUENCE ORCHESTRATOR
 * This controls the TOS, PWA, and Newsletter sequence.
 * ==================================================================================
 */
function initializePolicyBanner() {
    const policyModal = document.getElementById('policy-modal-container');
    const acceptBtn = document.getElementById('acceptPolicy');
    const declineBtn = document.getElementById('declinePolicy');

    // 1. Safety Check: If HTML is missing, exit gracefully
    if (!policyModal || !acceptBtn || !declineBtn) return;

    // Check current page: Don't show TOS if they are reading the policies!
    const currentPath = window.location.pathname;
    const isPolicyPage = currentPath === '/tos' || currentPath === '/privacy-policy';

    if (isPolicyPage) {
        policyModal.style.display = 'none';
        return;
    }

    const hasAcceptedTOS = localStorage.getItem('gplmods_policy_accepted') === 'true';

    if (!hasAcceptedTOS) {
        // --- PHASE 1: Show TOS Modal ---
        policyModal.style.display = 'flex';
        policyModal.classList.add('show');

        setTimeout(() => {
            const contentBox = policyModal.querySelector('.policy-modal-content');
            if (contentBox) contentBox.classList.add('active');
        }, 10);

        acceptBtn.addEventListener('click', () => {
            localStorage.setItem('gplmods_policy_accepted', 'true');
            const contentBox = policyModal.querySelector('.policy-modal-content');
            if (contentBox) contentBox.classList.remove('active');
            
            setTimeout(() => {
                policyModal.classList.remove('show');
                policyModal.style.display = 'none';
                
                // --- PHASE 2: Start the PWA/Newsletter Sequence ---
                startEngagementSequence();
            }, 300);
        }, { once: true });

        declineBtn.addEventListener('click', () => {
            const contentBox = policyModal.querySelector('.policy-modal-content');
            if (contentBox) {
                contentBox.innerHTML = `
                    <h2 style="color: var(--red); margin-bottom: 15px; font-size: 1.8em;">Policies Declined</h2>
                    <p style="color: var(--silver); margin-bottom: 25px; font-size: 1em;">
                        To continue using GPL Mods, you must accept our Terms of Service and Privacy Policy.
                    </p>
                    <button onclick="location.reload()" style="background-color: var(--gold); color: var(--black); padding: 12px 30px; border-radius: 25px; text-decoration: none; font-weight: bold; border: none; cursor: pointer; font-size: 1.1em; box-shadow: 0 0 15px var(--glow-gold);">
                        Refresh Page
                    </button>
                `;
            }
        }, { once: true });

    } else {
        // They already accepted TOS previously. Just run the sequence logic.
        startEngagementSequence();
    }
}

/**
 * ORCHESTRATOR: Handles the timing of PWA and Newsletter banners
 */
function startEngagementSequence() {
    // Timers in milliseconds (Adjusted for testing, change back to 3/2 mins for production)
    // const pwaDelay = 3 * 60 * 1000; // 3 minutes
    // const newsletterFallbackDelay = 5 * 60 * 1000; // 5 minutes
    // const newsletterAfterPwaDelay = 2 * 60 * 1000; // 2 minutes
    // For Testing
    // const pwaDelay = 10000; //10 Seconds
    // const newsletterFallbackDelay = 20000; // 20 Seconds
    // const newsletterAfterPwaDelay = 10000; // 10 Seconds
    // For testing right now, change the value to 10 seconds, 20 seconds, and 10 seconds
    const pwaDelay = 3 * 60 * 1000; 
    const newsletterFallbackDelay = 5 * 60 * 1000; 
    const newsletterAfterPwaDelay = 2 * 60 * 1000; 

    // --- PWA LOGIC ---
    let deferredPrompt;
    let pwaShown = false;
    const pwaBanner = document.getElementById('pwa-install-banner');
    const installBtn = document.getElementById('pwa-install');
    const dismissBtn = document.getElementById('pwa-dismiss');
    
    const isPwaDismissed = localStorage.getItem('pwaDismissed') === 'true';
    const isPwaInstalled = window.matchMedia('(display-mode: standalone)').matches;

    // We set a fallback timer for the newsletter in case the PWA prompt NEVER fires
    // (e.g., they are on an unsupported browser or already installed it)
    let newsletterTimer = setTimeout(() => {
        if (!pwaShown) triggerNewsletter();
    }, newsletterFallbackDelay);

    if (!isPwaDismissed && !isPwaInstalled) {
        window.addEventListener('beforeinstallprompt', (e) => {
            e.preventDefault();
            deferredPrompt = e;
            
            // The browser is ready. Now wait for our programmed delay.
            setTimeout(() => {
                if (pwaBanner) {
                    pwaBanner.classList.add('show');
                    pwaShown = true;
                    clearTimeout(newsletterTimer); // Cancel fallback timer
                }
            }, pwaDelay);
        });

        if (installBtn) {
            installBtn.addEventListener('click', async () => {
                if (pwaBanner) pwaBanner.classList.remove('show');
                if (deferredPrompt) {
                    deferredPrompt.prompt();
                    await deferredPrompt.userChoice;
                    deferredPrompt = null;
                }
                // They handled PWA, queue the Newsletter
                setTimeout(triggerNewsletter, newsletterAfterPwaDelay);
            });
        }

        if (dismissBtn) {
            dismissBtn.addEventListener('click', () => {
                if (pwaBanner) pwaBanner.classList.remove('show');
                localStorage.setItem('pwaDismissed', 'true');
                // They handled PWA, queue the Newsletter
                setTimeout(triggerNewsletter, newsletterAfterPwaDelay);
            });
        }

        window.addEventListener('appinstalled', () => {
            if (pwaBanner) pwaBanner.classList.remove('show');
            localStorage.setItem('pwaDismissed', 'true');
            deferredPrompt = null;
        });
    }

    // --- NEWSLETTER TRIGGER ---
    function triggerNewsletter() {
        const popup = document.getElementById('newsletter-popup');
        const isSubscribed = localStorage.getItem('gplmods_subscribed') === 'true';
        const dismissedTime = localStorage.getItem('gplmods_newsletter_dismissed');
        const now = new Date().getTime();
        
        let shouldShow = !isSubscribed;
        if (dismissedTime && (now - parseInt(dismissedTime)) < (3 * 24 * 60 * 60 * 1000)) {
            shouldShow = false; // Dismissed less than 3 days ago
        }

        if (shouldShow && popup) {
            popup.classList.add('show');
        }
    }
}

/**
 * ==================================================================================
 * 8. ROBUST DUAL-SOURCE MUSIC PLAYER WITH TIMELINE
 * ==================================================================================
 */
function initializeMusicPlayer() {
    const playerContainer = document.getElementById('floating-music-player');
    const toggleBtn = document.getElementById('music-toggle-btn');
    const audioPlayer = document.getElementById('background-audio'); 
    const playPauseBtn = document.getElementById('music-play-pause-btn'); 
    const playPauseIcon = document.getElementById('play-pause-icon');
    const prevBtn = document.getElementById('music-prev-btn'); 
    const nextBtn = document.getElementById('music-next-btn'); 
    const trackNameDisplay = document.getElementById('music-track-name'); 
    const volumeSlider = document.getElementById('music-volume-slider');
    
    // Timeline Elements
    const timeline = document.getElementById('music-timeline');
    const currentTimeDisplay = document.getElementById('music-current-time');
    const durationDisplay = document.getElementById('music-duration');
    let ytProgressInterval;

    // Premium YT Elements
    const customYtInput = document.getElementById('custom-yt-url');
    const loadYtBtn = document.getElementById('load-yt-btn');
    const ytStatusMsg = document.getElementById('yt-status-msg');

    if (!audioPlayer || !playPauseBtn || !trackNameDisplay) return; 

    // --- 1. Sliding Toggle Logic ---
    if (toggleBtn && playerContainer) {
        toggleBtn.addEventListener('click', () => playerContainer.classList.toggle('open'));
    }

    // --- 2. Default Playlist ---
    const playlist =[
        { title: 'Whoopty', src: '/audio/bgm-1.mp3' },
        { title: 'Nekozilla', src: '/audio/bgm-2.mp3' },
        { title: 'Heroes Tonight', src: '/audio/bgm-3.mp3' },
        { title: 'Dreams', src: '/audio/bgm-4.mp3' },
        { title: 'Royalty', src: '/audio/bgm-5.mp3' },
        { title: 'Mortals', src: '/audio/bgm-6.mp3' },
        { title: 'On & On', src: '/audio/bgm-7.mp3' }
    ];
    
    // --- 3. State Management ---
    let currentSource = localStorage.getItem('musicSource') || 'local';
    let trackIndex = parseInt(localStorage.getItem('musicTrackIndex')) || 0;
    if (trackIndex >= playlist.length || trackIndex < 0) trackIndex = 0;
    
    let ytVideoId = localStorage.getItem('customYtId') || null;
    let ytPlayer = null;
    let isYtReady = false;

    // --- Formatting Helper for Time ---
    function formatTime(seconds) {
        if (!seconds || isNaN(seconds)) return "0:00";
        const m = Math.floor(seconds / 60);
        const s = Math.floor(seconds % 60);
        return `${m}:${s < 10 ? '0' : ''}${s}`;
    }

    // --- 4. YouTube IFrame API Initialization ---
    const tag = document.createElement('script');
    tag.src = "https://www.youtube.com/iframe_api";
    const firstScriptTag = document.getElementsByTagName('script')[0];
    firstScriptTag.parentNode.insertBefore(tag, firstScriptTag);

    window.onYouTubeIframeAPIReady = function() {
        ytPlayer = new YT.Player('yt-player-container', {
            height: '0', width: '0',
            videoId: ytVideoId || '', 
            playerVars: { 'autoplay': 0, 'controls': 0, 'disablekb': 1, 'fs': 0, 'playsinline': 1, 'loop': 1, 'playlist': ytVideoId || '' },
            events: {
                'onReady': onPlayerReady,
                'onStateChange': onPlayerStateChange
            }
        });
    };

    function onPlayerReady(event) {
        isYtReady = true;
        setGlobalVolume(volumeSlider.value); 
        if (currentSource === 'youtube' && localStorage.getItem('musicState') === 'playing') {
            ytPlayer.playVideo();
        }
    }

    function onPlayerStateChange(event) {
        if (event.data === 0) ytPlayer.playVideo(); // Loop if ended

        if (event.data === 1 && currentSource === 'youtube') {
            const videoData = ytPlayer.getVideoData();
            if (videoData && videoData.title) trackNameDisplay.textContent = "YT: " + videoData.title;
            startYtProgress(); // Start polling YT time
        } else {
            stopYtProgress();
        }
    }

    // --- 5. Core Control Functions ---
    function updatePlayIcon(isPlaying) {
        if (!playPauseIcon) return;
        playPauseIcon.className = isPlaying ? 'fas fa-pause' : 'fas fa-play';
        playPauseBtn.title = isPlaying ? "Pause Music" : "Play Music";
    }

    function loadLocalTrack(index) {
        currentSource = 'local';
        localStorage.setItem('musicSource', 'local');
        localStorage.setItem('musicTrackIndex', index);
        
        if (isYtReady) ytPlayer.pauseVideo();
        stopYtProgress();
        
        const track = playlist[index];
        audioPlayer.src = track.src;
        trackNameDisplay.textContent = track.title;
        setGlobalVolume(volumeSlider.value);
    }

    function playMusic() {
        localStorage.setItem('musicState', 'playing');
        if (currentSource === 'local') {
            audioPlayer.play().then(() => updatePlayIcon(true)).catch(e => pauseMusic());
        } else if (currentSource === 'youtube' && isYtReady && ytVideoId) {
            ytPlayer.playVideo();
            updatePlayIcon(true);
            trackNameDisplay.textContent = "Loading YT Track...";
        }
    }

    function pauseMusic() {
        localStorage.setItem('musicState', 'paused');
        updatePlayIcon(false);
        audioPlayer.pause();
        if (isYtReady) ytPlayer.pauseVideo();
    }

    function setGlobalVolume(val) {
        audioPlayer.volume = val;
        if (isYtReady) ytPlayer.setVolume(val * 100); 
        localStorage.setItem('musicVolume', val);
    }

    // --- 6. TIMELINE & SEEKING LOGIC ---
    
    // A. Local Audio Time Updates
    audioPlayer.addEventListener('loadedmetadata', () => {
        if (currentSource === 'local') {
            timeline.max = audioPlayer.duration;
            durationDisplay.textContent = formatTime(audioPlayer.duration);
        }
    });

    audioPlayer.addEventListener('timeupdate', () => {
        if (currentSource === 'local') {
            timeline.value = audioPlayer.currentTime;
            currentTimeDisplay.textContent = formatTime(audioPlayer.currentTime);
            if (!audioPlayer.paused) localStorage.setItem('musicCurrentTime', audioPlayer.currentTime);
        }
    });

    // B. YouTube Time Updates (Polling)
    function startYtProgress() {
        stopYtProgress();
        ytProgressInterval = setInterval(() => {
            if (ytPlayer && ytPlayer.getPlayerState() === 1) {
                const curr = ytPlayer.getCurrentTime();
                const dur = ytPlayer.getDuration();
                timeline.max = dur;
                timeline.value = curr;
                currentTimeDisplay.textContent = formatTime(curr);
                durationDisplay.textContent = formatTime(dur);
                localStorage.setItem('musicCurrentTime', curr);
            }
        }, 1000);
    }
    function stopYtProgress() { clearInterval(ytProgressInterval); }

    // C. User Dragging the Timeline (Both Local & YT)
    if (timeline) {
        timeline.addEventListener('input', (e) => {
            const seekTo = parseFloat(e.target.value);
            currentTimeDisplay.textContent = formatTime(seekTo);
            
            if (currentSource === 'local') {
                audioPlayer.currentTime = seekTo;
            } else if (currentSource === 'youtube' && isYtReady) {
                ytPlayer.seekTo(seekTo, true);
            }
        });
    }

    // --- 7. Event Listeners ---
    playPauseBtn.addEventListener('click', () => {
        const isPlaying = (currentSource === 'local' && !audioPlayer.paused) || 
                          (currentSource === 'youtube' && isYtReady && ytPlayer.getPlayerState() === 1);
        if (isPlaying) pauseMusic();
        else playMusic();
    });

    nextBtn.addEventListener('click', () => {
        trackIndex = (trackIndex + 1) % playlist.length;
        loadLocalTrack(trackIndex);
        playMusic();
    });

    prevBtn.addEventListener('click', () => {
        trackIndex = (trackIndex - 1 + playlist.length) % playlist.length;
        loadLocalTrack(trackIndex);
        playMusic();
    });

    audioPlayer.addEventListener('ended', () => nextBtn.click());
    
    volumeSlider.addEventListener('input', (e) => {
        setGlobalVolume(e.target.value);
    });

    // Custom YouTube Input Logic
    if (customYtInput && loadYtBtn) {
        loadYtBtn.addEventListener('click', () => {
            const url = customYtInput.value.trim();
            const match = url.match(/(?:v=|youtu\.be\/|youtube\.com\/embed\/|music\.youtube\.com\/watch\?v=)([^&?]+)/);
            
            if (match && match[1]) {
                ytVideoId = match[1];
                currentSource = 'youtube';
                localStorage.setItem('musicSource', 'youtube');
                localStorage.setItem('customYtId', ytVideoId);
                
                audioPlayer.pause(); 
                
                if (isYtReady) {
                    ytPlayer.loadVideoById({videoId: ytVideoId});
                    playMusic();
                }
                
                customYtInput.value = '';
                ytStatusMsg.style.display = 'block';
                setTimeout(() => ytStatusMsg.style.display = 'none', 3000);
            } else {
                alert("Invalid YouTube or YouTube Music URL!");
            }
        });
    }

    // Initialize on Page Load
    if (currentSource === 'local') {
        loadLocalTrack(trackIndex);
        const savedTime = localStorage.getItem('musicCurrentTime');
        if (savedTime && localStorage.getItem('musicState') === 'playing') {
            audioPlayer.currentTime = parseFloat(savedTime);
        }
    } else {
        trackNameDisplay.textContent = "Loading YT Track...";
    }

    if (localStorage.getItem('musicState') === 'playing') {
        if (currentSource === 'local') {
            const playPromise = audioPlayer.play();
            if (playPromise !== undefined) {
                playPromise.then(() => updatePlayIcon(true)).catch(() => {
                    updatePlayIcon(false);
                    localStorage.setItem('musicState', 'paused');
                });
            }
        }
    } else {
        updatePlayIcon(false);
    }
}
/**
 * ==================================================================================
 * 9. SMART AUDIO HANDLER
 * Pauses background music dynamically if user interacts with media players.
 * ==================================================================================
 */
function initializeSmartAudioHandler() {
    const backgroundAudio = document.getElementById('background-audio');
    if (!backgroundAudio) return;
    const mediaPlayers = document.querySelectorAll('iframe[src*="youtube.com"], iframe[src*="vimeo.com"], video');
    mediaPlayers.forEach(player => {
        player.addEventListener('mouseenter', () => { 
            if (!backgroundAudio.paused) { 
                backgroundAudio.dataset.wasPlaying = 'true'; 
                backgroundAudio.pause(); 
            }
        });
        player.addEventListener('mouseleave', () => { 
            if (backgroundAudio.dataset.wasPlaying === 'true') { 
                backgroundAudio.play(); 
                backgroundAudio.dataset.wasPlaying = 'false'; 
            }
        });
    });
}

/**
 * ==================================================================================
 * 10. NOTIFICATIONS (Just the Bell Logic)
 * ==================================================================================
 */
function initializeNotificationsAndPWA() {
    // --- NOTIFICATION BADGE LOGIC (SMART MULTI-CHECK) ---
    const bellLink = document.getElementById('nav-bell-link');
    const badge = document.getElementById('notification-badge');
    
    if (bellLink && badge) {
        const userId = bellLink.dataset.userId || 'guest';
        const storageKey = (key) => `gplmods_notifications_${userId}_${key}`;

        // Fetch current counts from the server (via data attributes)
        const curUpdates = parseInt(bellLink.getAttribute('data-updates') || '0', 10);
        const curUploads = parseInt(bellLink.getAttribute('data-uploads') || '0', 10);
        const curModsUpd = parseInt(bellLink.getAttribute('data-modsupdates') || '0', 10);
        const curPersonal = parseInt(bellLink.getAttribute('data-personal') || '0', 10);
        
        // Fetch last seen counts from user's browser using namespaced keys
        const seenUpdates = parseInt(localStorage.getItem(storageKey('lastSeenUpdates')) || '0', 10);
        const seenUploads = parseInt(localStorage.getItem(storageKey('lastSeenUploads')) || '0', 10);
        const seenModsUpd = parseInt(localStorage.getItem(storageKey('lastSeenModsUpd')) || '0', 10);
        // Calculate Total Unread
        let totalUnread = curPersonal; // Admin messages are tracked by the database, so they are always accurate
        
        if (curUpdates > seenUpdates) totalUnread += (curUpdates - seenUpdates);
        if (curUploads > seenUploads) totalUnread += (curUploads - seenUploads);
        if (curModsUpd > seenModsUpd) totalUnread += (curModsUpd - seenModsUpd);
        
        if (totalUnread > 0) {
            badge.style.display = 'flex';
            badge.textContent = totalUnread > 9 ? '9+' : totalUnread;
        } else {
            badge.style.display = 'none';
            badge.textContent = '';
        }
        
        // ✅ FIX: We removed the event listener here! 
        // The bell no longer resets itself when clicked. The individual items 
        // will reset when you click them inside the Hub page!
    }

    // Register Service Worker (Keep this outside the sequence so it always registers)
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('/sw.js')
                .then(reg => console.log('SW registered successfully.'))
                .catch(err => console.error('SW registration failed: ', err));
        });
    }
}
/**
 * ==================================================================================
 * 11. NEWSLETTER FORM HANDLER
 * ==================================================================================
 */
function initializeNewsletter() {
    const popup = document.getElementById('newsletter-popup');
    const closeBtn = document.getElementById('newsletter-close-btn');
    const form = document.getElementById('newsletter-form');
    const emailInput = document.getElementById('newsletter-email');
    const submitBtn = document.getElementById('newsletter-submit');
    const msgDiv = document.getElementById('newsletter-msg');

    if (closeBtn && popup) {
        closeBtn.addEventListener('click', () => {
            popup.classList.remove('show');
            localStorage.setItem('gplmods_newsletter_dismissed', new Date().getTime().toString());
        });
    }

    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = emailInput.value.trim();
            if (!email) return;

            submitBtn.disabled = true;
            submitBtn.textContent = 'Subscribing...';
            msgDiv.className = 'newsletter-msg';

            try {
                const response = await fetch('/api/subscribe', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ email: email, source: 'footer_popup' })
                });

                const data = await response.json();

                if (response.ok) {
                    msgDiv.textContent = data.message;
                    msgDiv.classList.add('success');
                    localStorage.setItem('gplmods_subscribed', 'true');
                    setTimeout(() => { popup.classList.remove('show'); }, 3000);
                } else {
                    msgDiv.textContent = data.error || 'Failed to subscribe.';
                    msgDiv.classList.add('error');
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Subscribe Now';
                }
            } catch (err) {
                msgDiv.textContent = 'A network error occurred.';
                msgDiv.classList.add('error');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Subscribe Now';
            }
       });
    }
}

/**
 * ==================================================================================
 * 12. REUSABLE SOCIAL CAROUSEL LOGIC
 * Handles the sliding animation for social icon groups (Footer, Profiles, etc.)
 * ==================================================================================
 */
function initializeSocialCarousels() {
    // Find every carousel container on the page
    const carouselContainers = document.querySelectorAll('.social-carousel-container');

    carouselContainers.forEach(container => {
        // We find the specific elements INSIDE this specific container
        const track = container.querySelector('.social-icons-track');
        const prevBtn = container.querySelector('.social-nav-btn[title="Previous"]');
        const nextBtn = container.querySelector('.social-nav-btn[title="Next"]');
        
        if (!track || !prevBtn || !nextBtn) return;

        const icons = track.querySelectorAll('a');
        const totalIcons = icons.length;
        
        // If 3 or fewer icons, hide arrows and disable carousel logic
        if (totalIcons <= 3) {
            prevBtn.style.display = 'none';
            nextBtn.style.display = 'none';
            return; 
        }

        let currentIndex = 0;
        const visibleIconsCount = 3;
        const slideAmount = 48; // Approx width (28px) + gap (20px)

        function updateCarousel() {
            track.style.transform = `translateX(-${currentIndex * slideAmount}px)`;

            if (currentIndex === 0) {
                prevBtn.disabled = true;
                prevBtn.style.opacity = '0.3';
            } else {
                prevBtn.disabled = false;
                prevBtn.style.opacity = '1';
            }

            if (currentIndex >= (totalIcons - visibleIconsCount)) {
                nextBtn.disabled = true;
                nextBtn.style.opacity = '0.3';
            } else {
                nextBtn.disabled = false;
                nextBtn.style.opacity = '1';
            }
        }

        nextBtn.addEventListener('click', () => {
            if (currentIndex < totalIcons - visibleIconsCount) {
                currentIndex++;
                updateCarousel();
            }
        });

        prevBtn.addEventListener('click', () => {
            if (currentIndex > 0) {
                currentIndex--;
                updateCarousel();
            }
        });

        updateCarousel(); // Initialize state
    });
}
/**
 * ==================================================================================
 * 13. GLOBAL CUSTOM SELECT DROPDOWNS
 * Replaces native <select> elements with stylable divs.
 * ==================================================================================
 */
function setupCustomSelect(wrapperId, nativeSelectId) {
    const wrapper = document.getElementById(wrapperId);
    const nativeSelect = document.getElementById(nativeSelectId);
    if (!wrapper || !nativeSelect) return;
    
    const customSelect = wrapper.querySelector('.custom-select');
    const selectedText = wrapper.querySelector('.selected-text');
    const optionsContainer = wrapper.querySelector('.custom-options');

    // Hide the native select
    nativeSelect.style.display = 'none';

    // Set initial text
    const initialSelectedOption = nativeSelect.options[nativeSelect.selectedIndex];
    if (initialSelectedOption) {
        selectedText.textContent = initialSelectedOption.text;
    }

    // Toggle dropdown
    customSelect.addEventListener('click', (e) => {
        // Close others
        document.querySelectorAll('.custom-select-wrapper.open').forEach(w => { 
            if (w !== wrapper) w.classList.remove('open'); 
        });
        wrapper.classList.toggle('open');
        e.stopPropagation(); 
    });

    // Handle selection
    optionsContainer.addEventListener('click', (e) => {
        const optionEl = e.target.closest('.custom-option');
        if (!optionEl) return;
        
        // Update UI
        selectedText.textContent = optionEl.textContent;
        wrapper.querySelectorAll('.custom-option').forEach(opt => opt.classList.remove('selected'));
        optionEl.classList.add('selected');
        wrapper.classList.remove('open');
        
        // Update the hidden native select value!
        nativeSelect.value = optionEl.getAttribute('data-value');
        
        // Disptach a 'change' event on the native select in case other scripts are listening to it!
        nativeSelect.dispatchEvent(new Event('change', { bubbles: true }));
    });
}

// Close dropdowns if clicked outside
document.addEventListener('click', () => {
    document.querySelectorAll('.custom-select-wrapper.open').forEach(w => w.classList.remove('open'));
});
/**
 * ==================================================================================
 * 14. CUSTOM MULTI-LANGUAGE ENGINE (VIA GOOGLE CLOUD API)
 * ==================================================================================
 */
function initializeLanguageSystem() {
    const langBtn = document.getElementById('lang-btn');
    const langMenu = document.getElementById('lang-menu');
    
    if (!langBtn || !langMenu) return;

    // --- 1. Custom UI Logic ---
    langBtn.addEventListener('click', (e) => {
        e.preventDefault();
        langMenu.classList.toggle('show');
    });

    document.addEventListener('click', (e) => {
        if (!langBtn.contains(e.target) && !langMenu.contains(e.target)) {
            langMenu.classList.remove('show');
        }
    });

    // --- 2. Change Language ---
    const langOptions = langMenu.querySelectorAll('a');
    langOptions.forEach(opt => {
        opt.addEventListener('click', (e) => {
            e.preventDefault();
            const selectedLang = opt.getAttribute('data-lang');
            localStorage.setItem('site_language', selectedLang);
            window.location.reload(); // Reload to translate from fresh English DOM
        });
    });

    // --- 3. DOM Text Extraction & Translation Execution ---
    const currentLang = localStorage.getItem('site_language');

    // Auto-detect if no language is set
    if (!currentLang) {
        const userLangRaw = navigator.language || navigator.userLanguage;
        const userLangCode = userLangRaw.split('-')[0];
        if (userLangCode !== 'en' && Array.from(langOptions).some(a => a.dataset.lang === userLangCode)) {
            localStorage.setItem('site_language', userLangCode);
            // Translate on next tick
            setTimeout(() => executeTranslation(userLangCode), 100);
        }
    } 
    // Translate if language is set and is not English
    else if (currentLang !== 'en') {
        executeTranslation(currentLang);
    }
}

async function executeTranslation(targetLang, rootElement = document.body) {
    console.log(`Translating to ${targetLang}...`);
    
    // 1. Traverse the DOM to find all visible Text Nodes
    const textNodes = [];
    const walker = document.createTreeWalker(rootElement, NodeFilter.SHOW_TEXT, null, false);
    let node;
    
    // Elements we DO NOT want to translate
    const ignoreTags = ['SCRIPT', 'STYLE', 'NOSCRIPT', 'CODE', 'PRE'];

    while (node = walker.nextNode()) {
        const parentElement = node.parentElement;
        if (!parentElement) continue;

        const parentTag = parentElement.tagName;
        const text = node.nodeValue.trim();
        
        // ✅ THE FIX: Check if this element or ANY of its parents have the 'notranslate' class
        const isNotranslate = parentElement.closest('.notranslate') !== null;
        
        // Only push if it has text, isn't an ignored tag, AND isn't marked as notranslate
        if (text && !ignoreTags.includes(parentTag) && !isNotranslate) {
            textNodes.push(node);
        }
    }

    if (textNodes.length === 0) return;

    // Extract the raw string values
    const textsToTranslate = textNodes.map(n => n.nodeValue);

    // 2. Send to our Backend API in chunks
    const CHUNK_SIZE = 100; 
    
    for (let i = 0; i < textsToTranslate.length; i += CHUNK_SIZE) {
        const chunk = textsToTranslate.slice(i, i + CHUNK_SIZE);
        const nodeChunk = textNodes.slice(i, i + CHUNK_SIZE);

        try {
            const response = await fetch('/api/translate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ texts: chunk, targetLanguage: targetLang })
            });

            const data = await response.json();

            if (data.translations) {
                // 3. Replace the original text nodes with translated text
                data.translations.forEach((translatedText, index) => {
                    nodeChunk[index].nodeValue = translatedText; 
                });
            }
        } catch (err) {
            console.error('Translation chunk failed:', err);
        }
    }
}