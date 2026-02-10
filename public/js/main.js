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
 * 7. BACKGROUND MUSIC PLAYER CONTROLS
 * ==================================================================================
 */
function initializeMusicPlayer() {
    const audioPlayer = document.getElementById('background-audio');
    const playBtn = document.getElementById('play-music-btn-mobile');
    const pauseBtn = document.getElementById('pause-music-btn-mobile');
    const trackSelector = document.getElementById('music-track-selector-mobile');

    if (!audioPlayer || !playBtn || !pauseBtn || !trackSelector) return;

    const updateButtons = (isPlaying) => {
        playBtn.style.display = isPlaying ? 'none' : 'block';
        pauseBtn.style.display = isPlaying ? 'block' : 'none';
    };

    audioPlayer.volume = 0.25;
    const musicStatePreference = localStorage.getItem('musicState');
    const musicTrackPreference = localStorage.getItem('musicTrack');

    if (musicTrackPreference) {
        audioPlayer.src = musicTrackPreference;
        trackSelector.value = musicTrackPreference;
    }

    const startPlayback = async () => {
        try {
            await audioPlayer.play();
            updateButtons(true);
            localStorage.setItem('musicState', 'playing');
        } catch (error) {
            console.warn("Autoplay prevented.");
            updateButtons(false);
            localStorage.setItem('musicState', 'paused');
        }
    };

    if (musicStatePreference === 'playing') {
        startPlayback();
    } else {
        audioPlayer.pause();
        updateButtons(false);
    }

    playBtn.addEventListener('click', () => {
        audioPlayer.play();
        updateButtons(true);
        localStorage.setItem('musicState', 'playing');
    });

    pauseBtn.addEventListener('click', () => {
        audioPlayer.pause();
        updateButtons(false);
        localStorage.setItem('musicState', 'paused');
    });

    trackSelector.addEventListener('change', () => {
        const newTrack = trackSelector.value;
        audioPlayer.src = newTrack;
        localStorage.setItem('musicTrack', newTrack);
        if (localStorage.getItem('musicState') === 'playing') startPlayback();
    });
}

/**
 * ==================================================================================
 * 8. SMART AUDIO HANDLER
 * ==================================================================================
 */
function initializeSmartAudioHandler() {
    const backgroundAudio = document.getElementById('background-audio');
    if (!backgroundAudio) return;

    const allMediaPlayers = document.querySelectorAll('iframe[src*="youtube.com"], iframe[src*="vimeo.com"], video');

    allMediaPlayers.forEach(player => {
        player.addEventListener('mouseenter', () => {
            const isMusicPlaying = localStorage.getItem('musicState') === 'playing';
            if (isMusicPlaying) backgroundAudio.pause();
        });
    });
}