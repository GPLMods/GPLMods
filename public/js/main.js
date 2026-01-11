/**
 * ==================================================================================
 * GPL MODS GLOBAL JAVASCRIPT
 * ==================================================================================
 * This file contains the core client-side functionality for the GPL Mods website.
 *
 * Table of Contents:
 * 1. Document Ready Initializer
 * 2. Star Rating System
 * 3. Search Bar Animation & Functionality
 * 4. Search History Management (for all users)
 * 5. Search Suggestions FETCHER (Updated with Live API)
 * 6. Mobile Menu Toggle
 * 7. Background Music Player Controls
 * ==================================================================================
 */

// 1. Waits for the entire HTML document to be loaded and parsed
document.addEventListener('DOMContentLoaded', () => {

    // --- INITIALIZE ALL GLOBAL FUNCTIONS ---

    // Initialize all star rating displays on the page
    initializeStarRatings();

    // Initialize the interactive search bar
    initializeSearchBar();

    // Initialize the mobile menu toggle
    initializeMobileMenu(); 
    
    // Initialize the music player
    initializeMusicPlayer(); // <-- THIS LINE WAS ADDED

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
 * ----------------------------------------------------------------------------------
 * 3. SEARCH BAR ANIMATION & FUNCTIONALITY
 * Handles the visual effects and user interactions for the search bar.
 * ----------------------------------------------------------------------------------
 */
function initializeSearchBar() {
    const searchBar = document.getElementById('animatedSearchBar');
    const searchInput = document.getElementById('searchInput');
    const suggestionsBox = document.getElementById('searchSuggestions');
    const searchHistoryBox = document.getElementById('searchHistory');

    if (!searchBar || !searchInput) return;

    // Add a class for animation when the user clicks/taps into the search input
    searchInput.addEventListener('focus', () => {
        searchBar.classList.add('active');
        // Show recent searches when the user focuses on the input
        displaySearchHistory();
    });

    // Remove the class when the user clicks away, unless they are clicking into the suggestions
    searchInput.addEventListener('blur', () => {
        // A small delay allows clicks on suggestion items to register before hiding
        setTimeout(() => {
            if (!suggestionsBox.contains(document.activeElement)) {
                searchBar.classList.remove('active');
            }
        }, 200);
    });
    
    // Listen for user typing to fetch suggestions
    searchInput.addEventListener('input', () => {
        const query = searchInput.value.trim();
        if (query.length > 1) {
            // Fetch and display live search suggestions
            fetchAndDisplaySuggestions(query);
            searchHistoryBox.style.display = 'none'; // Hide history when showing suggestions
        } else {
            // If the query is too short, hide suggestions and show history again
            suggestionsBox.style.display = 'none';
            displaySearchHistory();
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
    
    if(!historyBox) return;

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

    // Make sure both elements exist before adding a listener
    if (hamburgerBtn && mobileNavMenu) {
        hamburgerBtn.addEventListener('click', () => {
            // Toggle the 'active' class on both the button (for the X animation)
            // and the menu (to show/hide it).
            hamburgerBtn.classList.toggle('active');
            mobileNavMenu.classList.toggle('active');
        });
    }
}

/**
 * ==================================================================================
 * 7. BACKGROUND MUSIC PLAYER CONTROLS
 * Handles the logic for playing, pausing, and remembering user's music preference.
 * ==================================================================================
 */
function initializeMusicPlayer() {
    const audioPlayer = document.getElementById('background-audio');
    const playBtn = document.getElementById('play-music-btn');
    const pauseBtn = document.getElementById('pause-music-btn');
    
    // Check if the necessary elements exist on the page
    if (!audioPlayer || !playBtn || !pauseBtn) {
        return;
    }

    // --- The key part: check localStorage for the user's preference ---
    // The key is 'musicState' and its value can be 'playing' or 'paused'.
    const musicPreference = localStorage.getItem('musicState');

    // Autoplay logic: browsers often block autoplay until the user interacts with the page.
    // This is a safety feature. We'll try to play and handle the browser's decision gracefully.
    const startPlayback = async () => {
        try {
            // Attempt to play the audio
            await audioPlayer.play();
            // If successful, update UI and state
            playBtn.style.display = 'none';
            pauseBtn.style.display = 'flex';
            localStorage.setItem('musicState', 'playing');
        } catch (error) {
            console.warn("Autoplay was prevented by the browser. User must click 'Play' manually.");
            // If autoplay fails, update UI to show the Play button
            playBtn.style.display = 'flex';
            pauseBtn.style.display = 'none';
            localStorage.setItem('musicState', 'paused'); // Mark as paused since it couldn't start
        }
    };


    // --- Decide initial state on page load ---
    if (musicPreference === 'playing') {
        // If the user's last state was 'playing', try to start the music.
        startPlayback();
    } else {
        // If they last chose 'paused' (or it's their first visit), show the 'Play' button.
        audioPlayer.pause();
        playBtn.style.display = 'flex';
        pauseBtn.style.display = 'none';
        localStorage.setItem('musicState', 'paused'); // Set default state
    }

    // --- Event Listeners for Buttons ---
    playBtn.addEventListener('click', () => {
        audioPlayer.play();
        playBtn.style.display = 'none';
        pauseBtn.style.display = 'flex';
        localStorage.setItem('musicState', 'playing'); // Remember this choice
    });

    pauseBtn.addEventListener('click', () => {
        audioPlayer.pause();
        playBtn.style.display = 'flex';
        pauseBtn.style.display = 'none';
        localStorage.setItem('musicState', 'paused'); // Remember this choice
    });
}