/**
 * ==================================================================================
 * GPL MODS GLOBAL JAVASCRIPT
 * ==================================================================================
 * Table of Contents:
 * 1. Document Ready Initializer (with Try/Catch Safety)
 * 2. Homepage Tab Navigation
 * 3. Star Rating System
 * 4. Search Bar Handler (Dynamic Animation)
 * 5. Search History & Suggestions
 * 6. Mobile Navigation Handler
 * 7. Policy Acceptance Banner and PWA  and Newsletter Sequence
 * 8. Robust Sidebar Music Player
 * 9. Smart Audio Handler (YouTube/Vimeo pauses BG music)
 * 10. Notifications Logic
 * 11. Newsletter Logic
 * 12. REUSABLE SOCIAL CAROUSEL LOGIC
 * ==================================================================================
 */

console.log("GPL Mods main.js is loading...");

// ==================================================================================
// 1. DOCUMENT READY INITIALIZER
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
try { await initializeSearchBar(); } catch (e) { console.error("Search Bar Error:", e); }
try { initializeSocialCarousels(); } catch (e) { console.error("Carousel Error:", e); }
        console.log("All initializers finished.");
    };

    runInitializers();
});

/**
 * ==================================================================================
 * 2. HOMEPAGE 2-TIER TAB NAVIGATION
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
 * 3. STAR RATING SYSTEM
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
 * 4. SEARCH BAR HANDLER (DYNAMIC ANIMATION)
 * ==================================================================================
 */
async function initializeSearchBar() {
    const searchInput = document.getElementById('searchInput');
    const suggestionsBox = document.getElementById('searchSuggestions');
    const searchHistoryBox = document.getElementById('searchHistory');
    const searchBar = document.getElementById('animatedSearchBar');

    if (!searchInput) return;

    searchInput.addEventListener('focus', () => {
        if(searchBar) searchBar.classList.add('active');
        displaySearchHistory();
    });

    searchInput.addEventListener('blur', () => {
        setTimeout(() => {
            if (suggestionsBox && searchHistoryBox && !suggestionsBox.contains(document.activeElement) && !searchHistoryBox.contains(document.activeElement)) {
                 if(searchBar) searchBar.classList.remove('active');
                 suggestionsBox.style.display = 'none';
                 searchHistoryBox.style.display = 'none';
            }
        }, 200);
    });

    searchInput.addEventListener('input', () => {
        const query = searchInput.value.trim();
        if (query.length > 1) {
            fetchAndDisplaySuggestions(query);
            if(searchHistoryBox) searchHistoryBox.style.display = 'none';
        } else {
            if(suggestionsBox) suggestionsBox.style.display = 'none';
            displaySearchHistory();
        }
    });

    // Form submission handler to save search history
    if (searchBar) {
        const searchForm = searchBar.querySelector('form');
        if (searchForm) {
            searchForm.addEventListener('submit', () => {
                const query = searchInput.value.trim();
                if (query) saveSearchTerm(query);
            });
        }
    }

    // Dynamic typing animation setup
    let searchTerms =["Search for mods..."]; 
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
            searchInput.style.setProperty('--placeholder-color', themeColors[termIndex % themeColors.length]);
            typeSpeed = 300;
        }
        typingTimeout = setTimeout(typeAnimation, typeSpeed);
    }

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

function saveSearchTerm(term) {
    let history = getSearchHistory();
    history = history.filter(item => item.toLowerCase() !== term.toLowerCase());
    history.unshift(term);
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
 * 8. ROBUST SIDEBAR MUSIC PLAYER (FIXED)
 * ==================================================================================
 */
function initializeMusicPlayer() {
    const audioPlayer = document.getElementById('background-audio'); 
    const playPauseBtn = document.getElementById('music-play-pause-btn'); 
    const prevBtn = document.getElementById('music-prev-btn'); 
    const nextBtn = document.getElementById('music-next-btn'); 
    const trackNameDisplay = document.getElementById('music-track-name'); 

    if (!audioPlayer) {
    console.warn("Audio element not found — creating fallback #background-audio.");
    audioPlayer = document.createElement('audio');
    audioPlayer.id = 'background-audio';
    audioPlayer.preload = 'auto';
    document.body.appendChild(audioPlayer);
}

if (!playPauseBtn || !prevBtn || !nextBtn || !trackNameDisplay) {
    console.warn("Music Player controls or display missing. Player disabled.");
    return;
}

    const playlist =[
        { title: 'Whoopty', src: '/audio/bgm-1.mp3' },
        { title: 'Nekozilla', src: '/audio/bgm-2.mp3' },
        { title: 'Heroes Tonight', src: '/audio/bgm-3.mp3' },
        { title: 'Dreams', src: '/audio/bgm-4.mp3' },
        { title: 'Royalty', src: '/audio/bgm-5.mp3' },
        { title: 'Mortals', src: '/audio/bgm-6.mp3' },
        { title: 'On & On', src: '/audio/bgm-7.mp3' },
        { title: 'Rise Up', src: '/audio/bgm-8.mp3' },
        { title: 'Wrong Side Out', src: '/audio/bgm-9.mp3' },
    ];
    
    let trackIndex = parseInt(localStorage.getItem('musicTrackIndex')) || 0;
    if (trackIndex >= playlist.length || trackIndex < 0) trackIndex = 0;
    
    audioPlayer.volume = 0.25;

    function loadTrack(index) {
        const track = playlist[index];
        if (!track) {
             trackNameDisplay.textContent = "Select a track"; // ✅ FIX 5: Fallback text
             return;
        }
        audioPlayer.src = track.src;
        trackNameDisplay.textContent = track.title;
        localStorage.setItem('musicTrackIndex', index);
    }

    // ✅ FIX: Correctly toggle FontAwesome classes, even if the <i> tag itself was clicked
    function updatePlayIcon(isPlaying) {
        // Find the icon by its specific ID to ensure we always get it
        const icon = document.getElementById('play-pause-icon');
        if (!icon) return;

        if (isPlaying) {
            icon.className = 'fas fa-pause'; // Change to pause icon
            playPauseBtn.title = "Pause Music";
            trackNameDisplay.textContent = playlist[trackIndex].title; // Show name when playing
        } else {
            icon.className = 'fas fa-play'; // Change to play icon
            playPauseBtn.title = "Play Music";
            trackNameDisplay.textContent = "Paused"; // Show paused status
        }
    }

    function playTrack() {
        audioPlayer.play().then(() => {
            updatePlayIcon(true); 
            localStorage.setItem('musicState', 'playing');
        }).catch(e => {
            console.warn("Browser prevented autoplay.", e);
            pauseTrack(); 
        });
    }

    function pauseTrack() {
        audioPlayer.pause();
        updatePlayIcon(false); 
        localStorage.setItem('musicState', 'paused');
    }
    
    playPauseBtn.addEventListener('click', () => {
        if (audioPlayer.paused) {
            playTrack();
        } else {
            pauseTrack();
        }
    });

    nextBtn.addEventListener('click', () => {
        trackIndex = (trackIndex + 1) % playlist.length;
        loadTrack(trackIndex);
        playTrack();
    });

    prevBtn.addEventListener('click', () => {
        trackIndex = (trackIndex - 1 + playlist.length) % playlist.length;
        loadTrack(trackIndex);
        playTrack();
    });
    
    audioPlayer.addEventListener('ended', () => { nextBtn.click(); });
    
    audioPlayer.addEventListener('timeupdate', () => {
        if (!audioPlayer.paused) localStorage.setItem('musicCurrentTime', audioPlayer.currentTime);
    });

    
    // Initialize state
    loadTrack(trackIndex);
    
    // We set the initial icon state immediately
    const savedState = localStorage.getItem('musicState');
    if (savedState === 'playing') {
        updatePlayIcon(true);
    } else {
        updatePlayIcon(false);
        trackNameDisplay.textContent = "Select a track"; // ✅ FIX 5: Ensure paused state shows this
    }

    const savedTime = localStorage.getItem('musicCurrentTime');

    if (savedState === 'playing') {
        if (savedTime) audioPlayer.currentTime = parseFloat(savedTime);
        
        const playPromise = audioPlayer.play();
        if (playPromise !== undefined) {
            playPromise.catch(error => {
                console.warn("Browser blocked autoplay on new page load.");
                updatePlayIcon(false); 
                localStorage.setItem('musicState', 'paused');
            });
        }
    } else {
        audioPlayer.pause(); 
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
    // --- NOTIFICATION BADGE LOGIC (WITH NUMBERS) ---
    const bellLink = document.getElementById('nav-bell-link');
    const badge = document.getElementById('notification-badge');
    
    if (bellLink && badge) {
        const currentTotalUpdates = parseInt(bellLink.getAttribute('data-total-updates') || '0', 10);
        const lastSeenTotal = parseInt(localStorage.getItem('lastSeenTotalUpdates') || '0', 10);
        const unreadCount = currentTotalUpdates - lastSeenTotal;
        
        if (unreadCount > 0) {
            badge.style.display = 'flex';
            badge.textContent = unreadCount > 9 ? '9+' : unreadCount;
        }
        
        bellLink.addEventListener('click', () => {
            localStorage.setItem('lastSeenTotalUpdates', currentTotalUpdates.toString());
        });
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