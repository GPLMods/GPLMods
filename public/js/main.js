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
 * 6. Mobile Menu Toggle
 * 7. Background Music Player Controls
 * 8. Smart Audio Handler
 * ==================================================================================
 */

// 1. Waits for the entire HTML document to be loaded and parsed
// This is the main entry point for all client-side JavaScript
document.addEventListener('DOMContentLoaded', () => {
    
    // --- Define a single async function to run all initializers ---
    const runInitializers = async () => {
        try {
            // Run functions that do NOT depend on external data first
            initializeMobileMenu(); // This has no dependencies, let's run it early
            initializeStarRatings();
            initializeMusicPlayer(); // Or your new sidebar music player logic
            initializeSmartAudioHandler();

            // Now, run the async function that fetches data
            await initializeSearchBar();

            // You can add other initializers here
            
        } catch (error) {
            console.error("An error occurred during page initialization:", error);
        }
    };

    // --- Execute the main function ---
    runInitializers();
    
});


/**
 * ----------------------------------------------------------------------------------
 * 2. STAR RATING SYSTEM
 * Fills the static star icons with the correct color based on a data attribute.
 * ----------------------------------------------------------------------------------
 */
function initializeStarRatings() {
    // Find all containers with the class 'star-rating'
    const allRatingContainers = document.querySelectorAll('.star-rating');

    allRatingContainers.forEach(container => {
        // Retrieve the rating value from the 'data-rating' attribute (e.g., "4.7")
        const rating = parseFloat(container.dataset.rating);
        if (isNaN(rating)) return; // Skip if the rating is not a valid number

        // Get all the star icons within this container
        const stars = container.querySelectorAll('.star');

        // Calculate how many full and partial stars to show
        const fullStars = Math.floor(rating);
        const partialStarPercentage = (rating % 1) * 100;

        // Fill the full stars
        for (let i = 0; i < fullStars; i++) {
            stars[i].classList.add('filled');
        }

        // Fill the partial star if there is one
        if (fullStars < 5 && partialStarPercentage > 0) {
            const partialStar = stars[fullStars];
            // Use a linear-gradient to fill only a percentage of the star
            partialStar.style.setProperty('--fill-percentage', `${partialStarPercentage}%`);
            partialStar.classList.add('partial');
        }
    });
}


/**
 * ==================================================================================
 * REVISED: 3. SEARCH BAR HANDLER with DYNAMIC Animation
 * ==================================================================================
 */
async function initializeSearchBar() {
    const searchInput = document.getElementById('searchInput');
    const suggestionsBox = document.getElementById('searchSuggestions');
    const searchHistoryBox = document.getElementById('searchHistory');
    const searchBar = document.getElementById('animatedSearchBar'); // Keep for focus animation

    if (!searchInput) {
        console.warn("Search input not found.");
        return;
    }

    // --- Live Suggestions & History Logic ---
    searchInput.addEventListener('focus', () => {
        if(searchBar) searchBar.classList.add('active');
        displaySearchHistory();
    });

    searchInput.addEventListener('blur', () => {
        // A small delay allows clicks on suggestion items to register before hiding
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
            searchHistoryBox.style.display = 'none'; // Hide history when showing suggestions
        } else {
            suggestionsBox.style.display = 'none';
            displaySearchHistory();
        }
    });

    // --- DYNAMIC Placeholder Typing Animation ---

    // 1. Fetch the trending search terms from our API
    let searchTerms = ["Search for mods..."]; // Default fallback
    try {
        const response = await fetch('/api/trending-searches');
        if (response.ok) {
            const trending = await response.json();
            if (trending.length > 0) {
                // Add "..." to each term for the typing effect
                searchTerms = trending.map(term => `${term}...`);
            }
        }
    } catch (error) {
        console.error("Could not fetch trending search terms:", error);
        // The animation will proceed with the default fallback term.
    }

    // 2. The animation logic
    const themeColors = ["var(--gold)", "var(--silver)"];
    let termIndex = 0,
        letterIndex = 0,
        currentTerm = '',
        isDeleting = false;
    let typingTimeout;

    function typeAnimation() {
        // Stop animation if the user is focused on the input
        if (document.activeElement === searchInput) return;

        const fullTerm = searchTerms[termIndex];

        if (isDeleting) {
            // Subtract letters
            currentTerm = fullTerm.substring(0, letterIndex - 1);
            letterIndex--;
        } else {
            // Add letters
            currentTerm = fullTerm.substring(0, letterIndex + 1);
            letterIndex++;
        }

        searchInput.placeholder = currentTerm;
        let typeSpeed = isDeleting ? 60 : 120;

        if (!isDeleting && letterIndex === fullTerm.length) {
            // Pause at the end of the term
            isDeleting = true;
            typeSpeed = 1500;
        } else if (isDeleting && letterIndex === 0) {
            // Move to the next term
            isDeleting = false;
            termIndex = (termIndex + 1) % searchTerms.length;
            // Update color for the next term
            searchInput.style.setProperty('--placeholder-color', themeColors[termIndex % themeColors.length]);
            typeSpeed = 300;
        }

        typingTimeout = setTimeout(typeAnimation, typeSpeed);
    }

    // 3. Start the animation and set up controlling event listeners
    typeAnimation(); // Initial call to start

    searchInput.addEventListener('focus', () => {
        clearTimeout(typingTimeout); // Stop animation
        searchInput.placeholder = "Search for mods..."; // Set a static placeholder
        searchInput.style.setProperty('--placeholder-color', 'var(--silver)'); // Reset color
    });

    searchInput.addEventListener('blur', () => {
        // If the input is empty when the user clicks away, restart the animation
        if (searchInput.value === '') {
            searchInput.placeholder = ""; // Clear immediately
            letterIndex = 0;
            isDeleting = false;
            // Start with the next term for variety
            termIndex = (termIndex + 1) % searchTerms.length;
            typeAnimation();
        }
    });
    
    // Add event listener for form submission to save the search term
    const searchForm = searchBar.querySelector('form');
    if(searchForm) {
        searchForm.addEventListener('submit', () => {
            const query = searchInput.value.trim();
            if (query) {
                saveSearchTerm(query);
            }
        });
    }
}


/**
 * ----------------------------------------------------------------------------------
 * 4. SEARCH HISTORY MANAGEMENT (using localStorage)
 * Saves and retrieves the 5 most recent search terms for unregistered users.
 * This is temporary and stored in the user's browser.
 * ----------------------------------------------------------------------------------
 */
const SEARCH_HISTORY_KEY = 'gplmods_search_history';
const MAX_HISTORY_ITEMS = 5;

// Function to get the search history from localStorage
function getSearchHistory() {
    const historyJSON = localStorage.getItem(SEARCH_HISTORY_KEY);
    return historyJSON ? JSON.parse(historyJSON) : [];
}

// Function to save a new search term
function saveSearchTerm(term) {
    let history = getSearchHistory();
    // Remove the term if it already exists to avoid duplicates and move it to the top
    history = history.filter(item => item.toLowerCase() !== term.toLowerCase());

    // Add the new term to the beginning of the array
    history.unshift(term);

    // Ensure the history does not exceed the maximum size
    if (history.length > MAX_HISTORY_ITEMS) {
        history.pop();
    }

    // Save the updated history back to localStorage
    localStorage.setItem(SEARCH_HISTORY_KEY, JSON.stringify(history));
}

// Function to display the search history in its container
function displaySearchHistory() {
    const history = getSearchHistory();
    const historyBox = document.getElementById('searchHistory');
    const suggestionsBox = document.getElementById('searchSuggestions');

    if (!historyBox) return;

    historyBox.innerHTML = ''; // Clear previous history items

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
        suggestionsBox.style.display = 'none'; // Ensure suggestions are hidden
    } else {
        historyBox.style.display = 'none';
    }
}


/**
 * ----------------------------------------------------------------------------------
 * 5. SEARCH SUGGESTIONS FETCHER
 * Fetches search suggestions from the server as the user types.
 * ----------------------------------------------------------------------------------
 */
async function fetchAndDisplaySuggestions(query) {
    const suggestionsBox = document.getElementById('searchSuggestions');
    if (!suggestionsBox) return;

    // --- Make a live API call to our backend ---
    try {
        // Use encodeURIComponent to safely handle special characters in the query
        const response = await fetch(`/api/search/suggestions?q=${encodeURIComponent(query)}`);

        if (!response.ok) {
            // If the server response is not OK (e.g., 500 error), throw an error
            throw new Error('Network response was not ok');
        }

        const suggestions = await response.json(); // Parse the JSON array of strings

        suggestionsBox.innerHTML = ''; // Clear old suggestions

        if (suggestions.length > 0) {
            const list = document.createElement('ul');
            suggestions.forEach(suggestion => {
                const listItem = document.createElement('li');
                // Create a case-insensitive regex to find the matching part
                const regex = new RegExp(query, 'gi');
                // Bold the part of the suggestion that matches the user's query
                const boldedSuggestion = suggestion.replace(regex, (match) => `<b>${match}</b>`);

                listItem.innerHTML = `<a href="/search?q=${encodeURIComponent(suggestion)}">${boldedSuggestion}</a>`;
                list.appendChild(listItem);
            });
            suggestionsBox.appendChild(list);
            suggestionsBox.style.display = 'block';
        } else {
            // If no suggestions are found, hide the box
            suggestionsBox.style.display = 'none';
        }

    } catch (error) {
        console.error('Error fetching search suggestions:', error);
        suggestionsBox.style.display = 'none'; // Hide on any error
    }
}

/**
 * ----------------------------------------------------------------------------------
 * 6. MOBILE MENU TOGGLE
 * Handles the opening and closing of the mobile navigation menu.
 * ----------------------------------------------------------------------------------
 */
function initializeMobileMenu() {
    const hamburgerBtn = document.getElementById('hamburger-btn');
    const mobileNavMenu = document.getElementById('mobile-nav-menu');

    if (!hamburgerBtn || !mobileNavMenu) {
        return; // Exit if the elements don't exist
    }

    hamburgerBtn.addEventListener('click', () => {
        // Toggle the .is-open class on the menu
        mobileNavMenu.classList.toggle('is-open');
    });

    // Optional: Close the menu if the user clicks outside of it
    document.addEventListener('click', (event) => {
        if (!mobileNavMenu.contains(event.target) && !hamburgerBtn.contains(event.target)) {
            mobileNavMenu.classList.remove('is-open');
        }
    });
}

/**
 * ==================================================================================
 * 7. BACKGROUND MUSIC PLAYER CONTROLS
 * Handles the logic for playing, pausing, and remembering user's music preference.
 * ==================================================================================
 */
function initializeMusicPlayer() {
    const audioPlayer = document.getElementById('background-audio');
    const playBtn = document.getElementById('play-music-btn-mobile');
    const pauseBtn = document.getElementById('pause-music-btn-mobile');
    const trackSelector = document.getElementById('music-track-selector-mobile');

    // Exit if the controls (which are only in the mobile menu) are not found
    if (!audioPlayer || !playBtn || !pauseBtn || !trackSelector) {
        return;
    }

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
            console.warn("Autoplay was prevented by the browser.");
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
        if (localStorage.getItem('musicState') === 'playing') {
            startPlayback();
        }
    });
}

/**
 * ==================================================================================
 * 8. SMART AUDIO HANDLER
 * Pauses background music when other media (like YouTube embeds) starts playing.
 * ==================================================================================
 */
function initializeSmartAudioHandler() {
    const backgroundAudio = document.getElementById('background-audio');
    if (!backgroundAudio) return;

    // Find all media elements that could play sound. This is great for mod video embeds.
    // We are targeting iframes (YouTube, Vimeo) and standard <video> tags.
    const allMediaPlayers = document.querySelectorAll('iframe[src*="youtube.com"], iframe[src*="vimeo.com"], video');

    allMediaPlayers.forEach(player => {
        // This is a simple but effective approach. When the mouse enters the video/iframe area,
        // we anticipate the user might click play, so we pause our music.
        player.addEventListener('mouseenter', () => {
            const isMusicPlaying = localStorage.getItem('musicState') === 'playing';
            if (isMusicPlaying) {
                backgroundAudio.pause();
                // We don't change the 'state' in localStorage, so the music can resume later.
                // You could add logic here to show the play button if you want.
            }
        });

        // When the mouse leaves the media area, you could potentially resume,
        // but it's often better to let the user resume it manually.
    });

    // An even more advanced method would involve using the YouTube IFrame Player API
    // to listen for actual 'play' events, but that is much more complex.
    // This mouseenter approach is a very good and simple approximation.
}