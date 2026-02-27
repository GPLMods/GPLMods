/**
 * ==================================================================================
 * GPL MODS GLOBAL JAVASCRIPT
 * ==================================================================================
 * This file contains the core client-side functionality for the GPL Mods website.
 *
 * Table of Contents:
 * 1. Document Ready Initializer
 * 2. NEW: HOMEPAGE TAB NAVIGATION
 * 3. Star Rating System
 * 4. Search Bar Handler with DYNAMIC Animation
 * 5. Search History Management (for all users)
 * 6. Search Suggestions FETCHER (Updated with Live API)
 * 7. Mobile Navigation Handler (CORRECTED)
 * 8. Background Music Player Controls
 * 9. Smart Audio Handler
 * 10. POLICY ACCEPTANCE BANNER (UPGRADED with Decline Logic)
 * ==================================================================================
 */

// 1. Waits for the entire HTML document to be loaded and parsed
document.addEventListener('DOMContentLoaded', () => {

    const runInitializers = async () => {
        try {
            initializeMobileMenu();
            initializeStarRatings();
            initializeHomepageTabs();
            // initializeMusicPlayer(); // <-- This is now controlled by the policy banner
            initializeSmartAudioHandler();

            // --- Let the policy banner control the music player ---
            initializePolicyBanner();

            await initializeSearchBar();

        } catch (error) {
            console.error("An error occurred during page initialization:", error);
        }
    };

    runInitializers();
});

/**
 * ==================================================================================
 * 2. NEW: HOMEPAGE TAB NAVIGATION
 * Handles the animated tab switching for the main categories on the homepage.
 * ==================================================================================
 */
function initializeHomepageTabs() {
    const mainTabNav = document.getElementById('main-tabs-nav');

    // --- Important: Only run this code if we are on the homepage ---
    // This prevents errors on other pages that don't have these elements.
    if (!mainTabNav) {
        return;
    }

    const allTabContents = document.querySelectorAll('.tab-content');
    const mainTabHighlight = document.getElementById('main-tab-highlight');
    const tabButtons = mainTabNav.querySelectorAll('.tab-button');

    // Function to move the highlight bar under the clicked tab
    function moveHighlight(targetTab) {
        if (!targetTab) return;
        // The requestAnimationFrame ensures the browser has calculated the new layout
        // before we try to move the highlight, making the animation smoother.
        requestAnimationFrame(() => {
            mainTabHighlight.style.width = `${targetTab.offsetWidth}px`;
            mainTabHighlight.style.transform = `translateX(${targetTab.offsetLeft}px)`;
        });
    }

    // --- Set the initial position of the highlight ---
    const initialActiveTab = mainTabNav.querySelector('.tab-button.active');
    if (initialActiveTab) {
        moveHighlight(initialActiveTab);
    }

    // --- Add click event listeners to all tab buttons ---
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTabId = button.dataset.tab;

            // --- Update button active state ---
            tabButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');

            // --- Animate the highlight ---
            moveHighlight(button);

            // --- Show/Hide the correct content section ---
            allTabContents.forEach(content => {
                if (content.id === `${targetTabId}-mods`) {
                    content.classList.add('active');
                } else {
                    content.classList.remove('active');
                }
            });

            // Scroll the tabs into view if they are off-screen on mobile
            button.scrollIntoView({
                behavior: 'smooth',
                inline: 'center',
                block: 'nearest'
            });
        });
    });

    // --- Recalculate highlight position on window resize ---
    window.addEventListener('resize', () => {
        const activeTab = mainTabNav.querySelector('.tab-button.active');
        if (activeTab) {
            moveHighlight(activeTab);
        }
    });
}


/**
 * ----------------------------------------------------------------------------------
 * 3. STAR RATING SYSTEM
 * Fills the static star icons with the correct color based on a data attribute.
 * ----------------------------------------------------------------------------------
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
            stars[i].classList.add('filled');
        }

        if (fullStars < 5 && partialStarPercentage > 0) {
            const partialStar = stars[fullStars];
            partialStar.style.setProperty('--fill-percentage', `${partialStarPercentage}%`);
            partialStar.classList.add('partial');
        }
    });
}


/**
 * ==================================================================================
 * 4. SEARCH BAR HANDLER with DYNAMIC Animation
 * ==================================================================================
 */
async function initializeSearchBar() {
    const searchInput = document.getElementById('searchInput');
    const suggestionsBox = document.getElementById('searchSuggestions');
    const searchHistoryBox = document.getElementById('searchHistory');
    const searchBar = document.getElementById('animatedSearchBar');

    if (!searchInput) {
        console.warn("Search input not found.");
        return;
    }

    searchInput.addEventListener('focus', () => {
        if (searchBar) searchBar.classList.add('active');
        displaySearchHistory();
    });

    searchInput.addEventListener('blur', () => {
        setTimeout(() => {
            if (!suggestionsBox.contains(document.activeElement) && !searchHistoryBox.contains(document.activeElement)) {
                if (searchBar) searchBar.classList.remove('active');
                suggestionsBox.style.display = 'none';
                searchHistoryBox.style.display = 'none';
            }
        }, 200);
    });

    searchInput.addEventListener('input', () => {
        const query = searchInput.value.trim();
        if (query.length > 1) {
            fetchAndDisplaySuggestions(query);
            searchHistoryBox.style.display = 'none';
        } else {
            suggestionsBox.style.display = 'none';
            displaySearchHistory();
        }
    });

    // --- DYNAMIC Placeholder Typing Animation ---
    let searchTerms = ["Search for mods..."];
    try {
        const response = await fetch('/api/trending-searches');
        if (response.ok) {
            const trending = await response.json();
            if (trending.length > 0) {
                searchTerms = trending.map(term => `${term}...`);
            }
        }
    } catch (error) {
        console.error("Could not fetch trending search terms:", error);
    }

    const themeColors = ["var(--gold)", "var(--silver)"];
    let termIndex = 0,
        letterIndex = 0,
        currentTerm = '',
        isDeleting = false;
    let typingTimeout;

    function typeAnimation() {
        if (document.activeElement === searchInput) return;

        const fullTerm = searchTerms[termIndex];
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

    const searchForm = searchBar.querySelector('form');
    if (searchForm) {
        searchForm.addEventListener('submit', () => {
            const query = searchInput.value.trim();
            if (query) saveSearchTerm(query);
        });
    }
}


/**
 * ----------------------------------------------------------------------------------
 * 5. SEARCH HISTORY MANAGEMENT
 * ----------------------------------------------------------------------------------
 */
const SEARCH_HISTORY_KEY = 'gplmods_search_history';
const MAX_HISTORY_ITEMS = 5;

function getSearchHistory() {
    const historyJSON = localStorage.getItem(SEARCH_HISTORY_KEY);
    return historyJSON ? JSON.parse(historyJSON) : [];
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
        suggestionsBox.style.display = 'none';
    } else {
        historyBox.style.display = 'none';
    }
}


/**
 * ----------------------------------------------------------------------------------
 * 6. SEARCH SUGGESTIONS FETCHER
 * ----------------------------------------------------------------------------------
 */
async function fetchAndDisplaySuggestions(query) {
    const suggestionsBox = document.getElementById('searchSuggestions');
    if (!suggestionsBox) return;

    try {
        const response = await fetch(`/api/search/suggestions?q=${encodeURIComponent(query)}`);
        if (!response.ok) throw new Error('Network response was not ok');

        const suggestions = await response.json();
        suggestionsBox.innerHTML = '';

        if (suggestions.length > 0) {
            const list = document.createElement('ul');
            suggestions.forEach(suggestion => {
                const listItem = document.createElement('li');
                const regex = new RegExp(query, 'gi');
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
        console.error('Error fetching search suggestions:', error);
        suggestionsBox.style.display = 'none';
    }
}

/**
 * =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 * 7. MOBILE NAVIGATION HANDLER (CORRECTED)
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
 */
function initializeMobileMenu() {
    // --- Use the CORRECT IDs from your header.ejs file ---
    const hamburger = document.getElementById('hamburger');
    const mobileNav = document.getElementById('mobileNav');

    if (!hamburger || !mobileNav) {
        console.warn("Mobile menu elements not found. Check IDs: 'hamburger' and 'mobileNav'");
        return;
    }

    // --- Toggle display on hamburger click ---
    hamburger.addEventListener('click', (event) => {
        // Stop the click from bubbling up to the document
        event.stopPropagation();
        const isVisible = mobileNav.style.display === 'block';
        mobileNav.style.display = isVisible ? 'none' : 'block';
    });

    // --- Accordion for sub-menus ---
    const collapsibleTriggers = mobileNav.querySelectorAll('.collapsible-trigger');
    collapsibleTriggers.forEach(trigger => {
        trigger.addEventListener('click', function(e) {
            e.preventDefault();
            this.parentElement.classList.toggle('open');
        });
    });

    // --- Close nav when a main link is clicked ---
    const mobileNavLinks = mobileNav.querySelectorAll('a');
    mobileNavLinks.forEach(link => {
        if (!link.classList.contains('collapsible-trigger')) {
            link.addEventListener('click', () => {
                mobileNav.style.display = 'none';
            });
        }
    });

    // --- Close the menu if the user clicks anywhere else on the page ---
    document.addEventListener('click', (event) => {
        // If the menu is open AND the click was NOT inside the menu itself...
        if (mobileNav.style.display === 'block' && !mobileNav.contains(event.target)) {
            mobileNav.style.display = 'none';
        }
    });
}

/**
 * ==================================================================================
 * 8. ANIMATED FOOTER MUSIC PLAYER (with Playback Persistence)
 * ==================================================================================
 */
function initializeMusicPlayer() {
    const playerContainer = document.getElementById('footer-player');
    const trackTitleDisplay = document.getElementById('footer-track-title');
    const playPauseBtn = document.getElementById('footer-play-pause-btn');
    const prevBtn = document.getElementById('footer-prev-btn');
    const nextBtn = document.getElementById('footer-next-btn');
    const toggleBtn = document.getElementById('player-toggle-btn');

    if (!playerContainer || !playPauseBtn || !toggleBtn) return;

    // --- SVG Icons ---
    const playIconSVG = `<svg class="player-icon" viewBox="0 0 24 24"><path d="M8 5v14l11-7z"></path></svg>`;
    const pauseIconSVG = `<svg class="player-icon" viewBox="0 0 24 24"><path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"></path></svg>`;

    const playlist = [{
        title: 'CJ Whoopty',
        src: '/audio/bgm-1.mp3'
    }, {
        title: 'NCS 2',
        src: '/audio/bgm-2.mp3'
    }, {
        title: 'NCS 3',
        src: '/audio/bgm-3.mp3'
    }, {
        title: 'NCS 4',
        src: '/audio/bgm-4.mp3'
    }, {
        title: 'NCS 5',
        src: '/audio/bgm-5.mp3'
    }, {
        title: 'NCS 6',
        src: '/audio/bgm-6.mp3'
    }, {
        title: 'NCS 7',
        src: '/audio/bgm-7.mp3'
    }, ];

    const audio = new Audio();
    audio.volume = 0.25;
    let trackIndex = 0;

    function loadTrack(index) {
        if (!playlist[index]) return;
        audio.src = playlist[index].src;
        trackTitleDisplay.textContent = playlist[index].title;
        localStorage.setItem('musicTrackIndex', index);
    }

    function playTrack() {
        audio.play().then(() => {
            playPauseBtn.innerHTML = pauseIconSVG; // Use pause icon when playing
            playerContainer.classList.add('playing'); // Add class for spin animation
            localStorage.setItem('musicState', 'playing');
        }).catch(e => {
            console.warn("Browser prevented autoplay.");
            pauseTrack(); // If play fails, ensure state is paused
        });
    }

    function pauseTrack() {
        audio.pause();
        playPauseBtn.innerHTML = playIconSVG; // Use play icon when paused
        playerContainer.classList.remove('playing'); // Remove class to stop spin
        localStorage.setItem('musicState', 'paused');
    }

    playPauseBtn.addEventListener('click', () => {
        if (audio.paused) playTrack();
        else pauseTrack();
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

    audio.addEventListener('ended', () => {
        nextBtn.click();
    });

    // --- NEW: SAVE CURRENT TIME PERIODICALLY ---
    audio.addEventListener('timeupdate', () => {
        if (!audio.paused) { // Only save while it's actively playing
            localStorage.setItem('musicCurrentTime', audio.currentTime);
        }
    });

    toggleBtn.addEventListener('click', () => {
        playerContainer.classList.toggle('minimized');
        if (playerContainer.classList.contains('minimized')) {
            localStorage.setItem('musicPlayerState', 'minimized');
        } else {
            localStorage.setItem('musicPlayerState', 'maximized');
        }
    });

    // --- Initialize on Page Load (UPGRADED LOGIC) ---
    const savedTrackIndex = localStorage.getItem('musicTrackIndex');
    if (savedTrackIndex) {
        trackIndex = parseInt(savedTrackIndex, 10);
    }
    loadTrack(trackIndex);

    // Make the player visible
    playerContainer.classList.add('visible');

    // Check for saved minimized/maximized state
    if (localStorage.getItem('musicPlayerState') === 'minimized') {
        playerContainer.classList.add('minimized');
    }

    const savedState = localStorage.getItem('musicState');
    const savedTime = localStorage.getItem('musicCurrentTime');

    if (savedState === 'playing') {
        // If there's a saved time from the last page, start from there.
        if (savedTime) {
            // Wait for the audio metadata to load before setting the time
            audio.addEventListener('loadedmetadata', () => {
                audio.currentTime = parseFloat(savedTime);
                playTrack();
            }, {
                once: true
            }); // This listener runs only once
        } else {
            playTrack(); // If no saved time, just play from beginning
        }
    } else {
        pauseTrack(); // This correctly sets the initial play icon
    }
}


/**
 * ==================================================================================
 * 9. SMART AUDIO HANDLER (FIXED)
 * Pauses music when hovering videos, Resumes when leaving.
 * ==================================================================================
 */
function initializeSmartAudioHandler() {
    const backgroundAudio = document.getElementById('background-audio');
    if (!backgroundAudio) return;

    // specific selectors for common embeds and video tags
    const mediaSelectors = 'iframe[src*="youtube.com"], iframe[src*="vimeo.com"], video';
    const allMediaPlayers = document.querySelectorAll(mediaSelectors);

    allMediaPlayers.forEach(player => {
        // When mouse enters video: Pause music if it was playing
        player.addEventListener('mouseenter', () => {
            if (!backgroundAudio.paused) {
                // Save a "flag" on the element so we know to resume it later
                backgroundAudio.dataset.wasPlaying = 'true';
                backgroundAudio.pause();

                // Optional: Update the play/pause buttons visually
                const playBtn = document.getElementById('play-music-btn-mobile');
                const pauseBtn = document.getElementById('pause-music-btn-mobile');
                if (playBtn && pauseBtn) {
                    playBtn.style.display = 'block';
                    pauseBtn.style.display = 'none';
                }
            }
        });

        // When mouse leaves video: Resume ONLY if it was paused by us
        player.addEventListener('mouseleave', () => {
            if (backgroundAudio.dataset.wasPlaying === 'true') {
                backgroundAudio.play().catch(e => console.log("Resume failed:", e));
                backgroundAudio.dataset.wasPlaying = 'false'; // Reset flag

                // Update buttons back to "Playing" state
                const playBtn = document.getElementById('play-music-btn-mobile');
                const pauseBtn = document.getElementById('pause-music-btn-mobile');
                if (playBtn && pauseBtn) {
                    playBtn.style.display = 'none';
                    pauseBtn.style.display = 'block';
                }
            }
        });
    });
}

/**
 * ==================================================================================
 * 10. POLICY ACCEPTANCE MODAL (CENTERED & SIMPLIFIED)
 * ==================================================================================
 */
function initializePolicyBanner() {
    const policyModal = document.getElementById('policy-modal-container');
    const acceptBtn = document.getElementById('acceptPolicy');
    const declineBtn = document.getElementById('declinePolicy');

    if (!policyModal || !acceptBtn || !declineBtn) {
        initializeMusicPlayer(); // Ensure music player always initializes if banner is absent
        return;
    }

    const hasAccepted = localStorage.getItem('gplmods_policy_accepted');

    if (hasAccepted === 'true') {
        initializeMusicPlayer(); // User has accepted, play music
        return;
    }

    // If not accepted, show the modal. Music player remains uninitialized.
    policyModal.style.display = 'flex'; // Use flex to center the content

    // --- Event Listeners ---
    acceptBtn.addEventListener('click', () => {
        localStorage.setItem('gplmods_policy_accepted', 'true');
        policyModal.style.display = 'none'; // Simply hide the modal
        initializeMusicPlayer(); // NOW initialize the music player
    });

    declineBtn.addEventListener('click', () => {
        // When user declines, simply provide an alert and do nothing.
        // The modal remains open, blocking the site.
        alert('You must accept the Terms of Service to continue using this site.');
    });
}