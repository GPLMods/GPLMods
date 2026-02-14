/**
 * ==================================================================================
 * GPL MODS GLOBAL JAVASCRIPT
 * ==================================================================================
 * This file contains the core client-side functionality for the GPL Mods website.
 *
 * Table of Contents:
 * 1. Document Ready Initializer
 * 2. Star Rating System
 * 3. Search Bar Handler with DYNAMIC Animation
 * 4. Search History Management (for all users)
 * 5. Search Suggestions FETCHER (Updated with Live API)
 * 6. Mobile Navigation Handler (CORRECTED)
 * 7. Background Music Player Controls
 * 8. Smart Audio Handler
 * ==================================================================================
 */

// 1. Waits for the entire HTML document to be loaded and parsed
document.addEventListener('DOMContentLoaded', () => {
    
    const runInitializers = async () => {
        try {
            // Run functions that do NOT depend on external data first
            initializeMobileMenu(); 
            initializeStarRatings();
            initializeMusicPlayer(); 
            initializeSmartAudioHandler();

            // Now, run the async function that fetches data
            await initializeSearchBar();
            
        } catch (error) {
            console.error("An error occurred during page initialization:", error);
        }
    };

    runInitializers();
});


/**
 * ----------------------------------------------------------------------------------
 * 2. STAR RATING SYSTEM
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
 * 3. SEARCH BAR HANDLER with DYNAMIC Animation
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
        if(searchBar) searchBar.classList.add('active');
        displaySearchHistory();
    });

    searchInput.addEventListener('blur', () => {
        setTimeout(() => {
            if (!suggestionsBox.contains(document.activeElement) && !searchHistoryBox.contains(document.activeElement)) {
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
    let termIndex = 0, letterIndex = 0, currentTerm = '', isDeleting = false;
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
    if(searchForm) {
        searchForm.addEventListener('submit', () => {
            const query = searchInput.value.trim();
            if (query) saveSearchTerm(query);
        });
    }
}


/**
 * ----------------------------------------------------------------------------------
 * 4. SEARCH HISTORY MANAGEMENT
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
 * 5. SEARCH SUGGESTIONS FETCHER
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
 * 6. MOBILE NAVIGATION HANDLER (CORRECTED)
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
 * 7. BACKGROUND MUSIC PLAYER CONTROLS (FIXED)
 * ==================================================================================
 */
function initializeMusicPlayer() {
    const audioPlayer = document.getElementById('background-audio');
    const playBtn = document.getElementById('play-music-btn-mobile');
    const pauseBtn = document.getElementById('pause-music-btn-mobile');
    const trackSelector = document.getElementById('music-track-selector-mobile');

    // Safety check: ensure all elements exist before running
    if (!audioPlayer || !playBtn || !pauseBtn || !trackSelector) {
        console.warn("Music Player Error: One or more ID elements are missing in the HTML.");
        return;
    }

    // 1. Helper to toggle Play/Pause buttons
    const updateButtons = (isPlaying) => {
        playBtn.style.display = isPlaying ? 'none' : 'block';
        pauseBtn.style.display = isPlaying ? 'block' : 'none';
    };

    // 2. Set Default Volume
    audioPlayer.volume = 0.25;

    // 3. Load Saved Preferences
    const savedState = localStorage.getItem('musicState'); // 'playing' or 'paused'
    const savedTrack = localStorage.getItem('musicTrack');

    // 4. Initialize Track Source (CRITICAL FIX)
    // If a track is saved, use it. Otherwise, default to the first option in the dropdown.
    if (savedTrack) {
        audioPlayer.src = savedTrack;
        trackSelector.value = savedTrack;
    } else if (trackSelector.options.length > 0) {
        const defaultTrack = trackSelector.options[0].value;
        audioPlayer.src = defaultTrack;
        trackSelector.value = defaultTrack;
    }

    // 5. Robust Play Function
    const attemptPlay = async () => {
        if (!audioPlayer.src) return; 

        try {
            await audioPlayer.play();
            updateButtons(true);
            localStorage.setItem('musicState', 'playing');
        } catch (error) {
            // This catches the "Autoplay prevented" browser error
            console.warn("Autoplay blocked. Waiting for user interaction...");
            updateButtons(false); 
        }
    };

    // 6. Handle Initial State on Page Load
    if (savedState === 'playing') {
        attemptPlay();
    } else {
        updateButtons(false);
    }

    // 7. Event Listeners for Buttons
    playBtn.addEventListener('click', attemptPlay);
    
    pauseBtn.addEventListener('click', () => {
        audioPlayer.pause();
        updateButtons(false);
        localStorage.setItem('musicState', 'paused');
    });

    // 8. Track Change Listener
    trackSelector.addEventListener('change', () => {
        audioPlayer.src = trackSelector.value;
        localStorage.setItem('musicTrack', trackSelector.value);
        // Automatically play when user manually selects a new song
        attemptPlay();
    });

    // 9. BROWSER AUTOPLAY FIX (The "Magic" Unlocker)
    // If music should be playing but is paused (due to browser block), 
    // try playing again on the very first click anywhere on the document.
    document.addEventListener('click', () => {
        if (localStorage.getItem('musicState') === 'playing' && audioPlayer.paused) {
            attemptPlay();
        }
    }, { once: true }); // This runs only once
}

/**
 * ==================================================================================
 * 8. SMART AUDIO HANDLER (FIXED)
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
                if(playBtn && pauseBtn) {
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
                if(playBtn && pauseBtn) {
                     playBtn.style.display = 'none';
                     pauseBtn.style.display = 'block';
                }
            }
        });
    });
}