/**
 * ==================================================================================
 * GPL MODS GLOBAL JAVASCRIPT (BULLETPROOF VERSION)
 * ==================================================================================
 * Table of Contents:
 * 1. Document Ready Initializer (with Try/Catch Safety)
 * 2. Homepage Tab Navigation
 * 3. Star Rating System
 * 4. Search Bar Handler (Dynamic Animation)
 * 5. Search History & Suggestions
 * 6. Mobile Navigation Handler
 * 7. Policy Acceptance Banner
 * 8. Robust Sidebar Music Player
 * 9. Smart Audio Handler (YouTube/Vimeo pauses BG music)
 * 10. Notifications & PWA Install Banner
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
try { initializeMusicPlayer(); } catch (e) { console.error("Music Player Error:", e); } // <-- ADD THIS LINE
try { initializeNotificationsAndPWA(); } catch (e) { console.error("PWA/Notif Error:", e); } // Added here!
try { await initializeSearchBar(); } catch (e) { console.error("Search Bar Error:", e); }
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
 * 7. POLICY BANNER
 * ==================================================================================
 */
function initializePolicyBanner() {
    const policyModal = document.getElementById('policy-modal-container');
    const acceptBtn = document.getElementById('acceptPolicy');
    const declineBtn = document.getElementById('declinePolicy');

    if (!policyModal || !acceptBtn || !declineBtn) return; 

    if (localStorage.getItem('gplmods_policy_accepted') === 'true') return; 

    const currentPath = window.location.pathname;
    const isPolicyPage = currentPath === '/tos' || currentPath === '/privacy-policy';

    if (isPolicyPage) {
        policyModal.style.display = 'none';
        return; 
    }

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
        { title: 'CJ Whoopty', src: '/audio/bgm-1.mp3' },
        { title: 'NCS 1', src: '/audio/bgm-2.mp3' },
        { title: 'NCS 2', src: '/audio/bgm-3.mp3' },
        { title: 'NCS 3', src: '/audio/bgm-4.mp3' },
        { title: 'NCS 4', src: '/audio/bgm-5.mp3' },
        { title: 'NCS 5', src: '/audio/bgm-6.mp3' },
        { title: 'NCS 6', src: '/audio/bgm-7.mp3' },
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

    // ✅ FIX: Correctly toggle FontAwesome classes
    function updatePlayIcon(isPlaying) {
        // We find the <i> tag inside the button
        const icon = playPauseBtn.querySelector('i');
        if (!icon) return;

        if (isPlaying) {
            icon.className = 'fas fa-pause'; // Change to pause icon
            playPauseBtn.title = "Pause Music";
        } else {
            icon.className = 'fas fa-play'; // Change to play icon
            playPauseBtn.title = "Play Music";
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
 * 10. NOTIFICATIONS & PWA INSTALL BANNER
 * ==================================================================================
 */
function initializeNotificationsAndPWA() {
    // --- 1. NOTIFICATION BADGE LOGIC (WITH NUMBERS) ---
    const bellLink = document.getElementById('nav-bell-link');
    const badge = document.getElementById('notification-badge');
    
    if (bellLink && badge) {
        const currentTotalUpdates = parseInt(bellLink.getAttribute('data-total-updates') || '0', 10);
        const unreadPersonal = parseInt(bellLink.getAttribute('data-unread-personal') || '0', 10);
        const lastSeenTotal = parseInt(localStorage.getItem('lastSeenTotalUpdates') || '0', 10);
        
        const unreadGlobalCount = currentTotalUpdates - lastSeenTotal;
        
        // Calculate total unread (Global + Personal)
        const totalUnread = (unreadGlobalCount > 0 ? unreadGlobalCount : 0) + unreadPersonal;
        
        if (totalUnread > 0) {
            badge.style.display = 'flex';
            badge.textContent = totalUnread > 9 ? '9+' : totalUnread;
        }
        
        bellLink.addEventListener('click', () => {
            // We only clear the GLOBAL counter in local storage.
            // Personal notifications must be marked 'read' in the database (handled on the /updates page).
            localStorage.setItem('lastSeenTotalUpdates', currentTotalUpdates.toString());
        });
    }

    // --- 2. PWA INSTALL LOGIC ---
    let deferredPrompt;
    const pwaBanner = document.getElementById('pwa-install-banner');
    const installBtn = document.getElementById('pwa-install');
    const dismissBtn = document.getElementById('pwa-dismiss');

    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('/sw.js')
                .then(registration => console.log('SW registered'))
                .catch(err => console.log('SW failed: ', err));
        });
    }

    window.addEventListener('beforeinstallprompt', (e) => {
        e.preventDefault();
        deferredPrompt = e;
        
        const isDismissed = localStorage.getItem('pwaDismissed') === 'true';
        
        if (!isDismissed && pwaBanner) {
            setTimeout(() => {
                pwaBanner.classList.add('show');
            }, 3000); 
        }
    });

    if (installBtn) {
        installBtn.addEventListener('click', async () => {
            if (pwaBanner) pwaBanner.classList.remove('show');
            if (deferredPrompt) {
                deferredPrompt.prompt();
                const { outcome } = await deferredPrompt.userChoice;
                deferredPrompt = null;
            }
        });
    }

    if (dismissBtn) {
        dismissBtn.addEventListener('click', () => {
            if (pwaBanner) pwaBanner.classList.remove('show');
            localStorage.setItem('pwaDismissed', 'true');
            setTimeout(() => localStorage.removeItem('pwaDismissed'), 7 * 24 * 60 * 60 * 1000); 
        });
    }
    
    window.addEventListener('appinstalled', () => {
        if (pwaBanner) pwaBanner.classList.remove('show');
        deferredPrompt = null;
    });
}