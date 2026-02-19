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
            
            // --- ADD THE NEW FUNCTION CALL HERE ---
            initializeHomepageTabs(); 

            initializeMusicPlayer(); 
            initializeSmartAudioHandler();
            
            // --- ADD THIS NEW FUNCTION CALL ---
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
            button.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' });
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
 * 8. BACKGROUND MUSIC PLAYER CONTROLS (UNIFIED & CORRECTED)
 * This version is self-contained and matches the new header.ejs sidebar player.
 * ==================================================================================
 */
function initializeMusicPlayer() {
    // --- Find the UI elements in the sidebar ---
    const trackNameDisplay = document.getElementById('track-name');
    const playPauseBtn = document.getElementById('play-pause-btn');
    const prevTrackBtn = document.getElementById('prev-track-btn');
    const nextTrackBtn = document.getElementById('next-track-btn');

    // If these elements don't exist (i.e., we're not on a page with the sidebar), stop.
    if (!trackNameDisplay || !playPauseBtn || !prevTrackBtn || !nextTrackBtn) {
        return;
    }

    // --- Define the playlist with correct absolute paths ---
    const playlist = [
        { title: 'NCS 1', src: '/audio/bgm-1.mp3' },
        { title: 'NCS 2', src: '/audio/bgm-2.mp3' },
        { title: 'NCS 3', src: '/audio/bgm-3.mp3' },
        { title: 'NCS 4', src: '/audio/bgm-4.mp3' },
        { title: 'NCS 5', src: '/audio/bgm-5.mp3' },
        { title: 'NCS 6', src: '/audio/bgm-6.mp3' },
    ];
    
    // --- Create a single, global audio object ---
    const audio = new Audio();
    // audio.loop = true; // Loop is removed to allow advancing to the next track
    audio.volume = 0.25; // Set a comfortable default volume

    let trackIndex = 0;

    // --- Core Functions ---
    function loadTrack(index) {
        audio.src = playlist[index].src;
        trackNameDisplay.textContent = playlist[index].title;
        localStorage.setItem('musicTrackIndex', index); // Save the current track index
    }

    function playTrack() {
        audio.play().catch(e => console.warn("Browser prevented autoplay. User must interact first."));
        playPauseBtn.textContent = '⏸️';
        localStorage.setItem('musicState', 'playing');
    }

    function pauseTrack() {
        audio.pause();
        playPauseBtn.textContent = '▶️';
        localStorage.setItem('musicState', 'paused');
    }

    // --- Event Listeners ---
    playPauseBtn.addEventListener('click', () => {
        if (audio.paused) {
            playTrack();
        } else {
            pauseTrack();
        }
    });

    nextTrackBtn.addEventListener('click', () => {
        trackIndex = (trackIndex + 1) % playlist.length;
        loadTrack(trackIndex);
        playTrack(); // Automatically play the next track
    });

    prevTrackBtn.addEventListener('click', () => {
        trackIndex = (trackIndex - 1 + playlist.length) % playlist.length;
        loadTrack(trackIndex);
        playTrack(); // Automatically play the previous track
    });
    
    // --- ADDED: When the current song finishes, automatically play the next one. ---
    audio.addEventListener('ended', () => {
        console.log("Track ended, playing next...");
        trackIndex = (trackIndex + 1) % playlist.length;
        localStorage.setItem('musicTrackIndex', trackIndex);
        loadTrack(trackIndex);
        playTrack();
    });

    // --- Initialize on Page Load ---
    const savedTrackIndex = localStorage.getItem('musicTrackIndex');
    if (savedTrackIndex) {
        trackIndex = parseInt(savedTrackIndex, 10);
    }
    loadTrack(trackIndex);

    // Check if the music should be playing from the last session
    if (localStorage.getItem('musicState') === 'playing') {
        playTrack();
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

/**
 * ==================================================================================
 * 10. POLICY ACCEPTANCE MODAL (FINAL, UNIFIED LOGIC)
 * ==================================================================================
 */
function initializePolicyBanner() {
    const policyModal = document.getElementById('policy-modal-container');
    const policyContent = policyModal.querySelector('.policy-modal-content');
    const acceptBtn = document.getElementById('acceptPolicy');
    const declineBtn = document.getElementById('declinePolicy');

    if (!policyModal || !acceptBtn || !declineBtn) {
        return; // Exit if elements are missing
    }

    // --- Check permanent storage ---
    const hasAccepted = localStorage.getItem('gplmods_policy_accepted');

    // --- Main Logic on Page Load ---
    if (hasAccepted !== 'true') {
        // If user has not accepted, show the modal.
        policyModal.style.display = 'block'; // Show the container and its background
        // Animate the content sliding up from the bottom
        setTimeout(() => {
            policyContent.style.transform = 'translateY(0)';
        }, 100); // A tiny delay to allow the CSS transition to work
    }

    // --- Event Listeners ---
    acceptBtn.addEventListener('click', () => {
        // Save choice permanently and hide the modal
        localStorage.setItem('gplmods_policy_accepted', 'true');
        policyContent.style.transform = 'translateY(100%)'; // Animate out
        // Wait for animation to finish before hiding the container
        setTimeout(() => {
            policyModal.style.display = 'none';
        }, 400);
    });

    declineBtn.addEventListener('click', () => {
        // When user declines, we just block interaction by leaving the modal open.
        // We can update the content to give them instructions.
        const contentDiv = policyModal.querySelector('div > div'); // Find the inner content div
        contentDiv.innerHTML = `
            <h2 style="color: var(--gold);">Policies Declined</h2>
            <p>You must accept the policies to use this site. Please click "Accept" or close this browser tab.</p>
             <div class="policy-buttons" style="margin-top: 15px; display: flex; gap: 10px; justify-content: center;">
                <button class="policy-button" id="acceptPolicyAgain">Accept</button>
            </div>
        `;
        
        // We need to re-add the event listener to the new "Accept" button
        document.getElementById('acceptPolicyAgain').addEventListener('click', () => {
             localStorage.setItem('gplmods_policy_accepted', 'true');
             policyContent.style.transform = 'translateY(100%)';
             setTimeout(() => { policyModal.style.display = 'none'; }, 400);
        });
    });
}