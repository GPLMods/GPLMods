/* ===================================================================
   TABLE OF CONTENTS
   ===================================================================
   1.  Global DOMContentLoaded Wrapper
   2.  Mobile Menu & Sidebar Accordion
   3.  Animated Search Bar Placeholder
   4.  Back to Top Button & Conditional Banner
   5.  Advanced Tab Navigation (Homepage & Mod Pages)
   6.  DYNAMIC CONTENT LOADING
       - Homepage Carousel Loader
       - Dynamic Mod List Page Loader (`mod-list.html`)
       - Dynamic Mod Detail Page Loader (`mod.html`)
   7.  Login/Sign-Up Modal Logic (for index.html)
   8.  FORM FUNCTIONALITY & HELPERS
   9.  FAQ Accordion
   10. Special Page Scripts (Countdown Timer)
   =================================================================== */

document.addEventListener('DOMContentLoaded', function() {

    // --- 2. Mobile Menu & Sidebar Accordion ---
    const hamburger = document.getElementById('hamburger');
    const mobileNav = document.getElementById('mobileNav');
    if (hamburger && mobileNav) {
        hamburger.addEventListener('click', () => {
            const isVisible = mobileNav.style.display === 'block';
            mobileNav.style.display = isVisible ? 'none' : 'block';
        });
    }
    const collapsibleTrigger = document.querySelector('.mobile-nav .collapsible-trigger');
    if (collapsibleTrigger) {
        collapsibleTrigger.addEventListener('click', function(e) {
            e.preventDefault();
            this.parentElement.classList.toggle('open');
        });
    }

    // --- 3. Animated Search Bar Placeholder ---
    const searchInput = document.getElementById('animated-search');
    if (searchInput) {
        const searchTerms = ["Kinemaster...", "Roblox...", "Minecraft...", "Spotify...", "Elementor..."];
        const themeColors = ["var(--gold)", "var(--silver)"];
        let termIndex = 0,
            letterIndex = 0,
            currentTerm = '',
            isDeleting = false,
            typingTimeout;

        function typeAnimation() {
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
        });
        searchInput.addEventListener('blur', () => {
            if (searchInput.value === '') {
                searchInput.placeholder = "";
                letterIndex = 0;
                isDeleting = false;
                typeAnimation();
            }
        });
    }


    // --- 4. Back to Top Button & Conditional Banner ---
    const backToTopButton = document.getElementById('backToTop');
    const appBanner = document.getElementById('appBanner');
    if (backToTopButton) {
        window.onscroll = function() {
            const scrollPosition = document.body.scrollTop || document.documentElement.scrollTop;
            backToTopButton.style.display = (scrollPosition > 100) ? "flex" : "none";
            if (appBanner) {
                if (scrollPosition > 200) {
                    appBanner.classList.add('visible');
                    if (window.innerWidth < 1024) backToTopButton.classList.add('raised');
                } else {
                    appBanner.classList.remove('visible');
                    backToTopButton.classList.remove('raised');
                }
            }
        };
        backToTopButton.addEventListener('click', () => window.scrollTo({
            top: 0,
            behavior: 'smooth'
        }));
    }

    // --- 5. Advanced Tab Navigation ---
    function initializeTabs(navElement, highlightElement) {
        if (!navElement || !highlightElement) return;
        const tabButtons = navElement.querySelectorAll('.tab-button');
        const moveHighlight = (targetTab) => {
            if (!targetTab) return;
            requestAnimationFrame(() => {
                highlightElement.style.width = `${targetTab.offsetWidth}px`;
                highlightElement.style.transform = `translateX(${targetTab.offsetLeft}px)`;
            });
        };
        tabButtons.forEach(button => button.addEventListener('click', () => moveHighlight(button)));
        window.addEventListener('resize', () => moveHighlight(navElement.querySelector('.tab-button.active')));
        const activeTab = navElement.querySelector('.tab-button.active');
        if (activeTab) setTimeout(() => moveHighlight(activeTab), 150);
    }
    const mainTabNav = document.getElementById('main-tabs-nav');
    const iosTabNav = document.getElementById('ios-tabs-nav');
    if (mainTabNav) initializeTabs(mainTabNav, document.getElementById('main-tab-highlight'));
    if (iosTabNav) initializeTabs(iosTabNav, document.getElementById('ios-tab-highlight'));

    // --- CORRECTED & SIMPLIFIED Tab Switching Logic ---
    const allTabContents = document.querySelectorAll('.tab-content');
    if (mainTabNav) { // Only run this logic if we are on the homepage
        const iosSubTabsContainer = document.getElementById('ios-sub-tabs-container');

        mainTabNav.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', () => {
                const targetTabId = button.dataset.tab;
                allTabContents.forEach(c => c.classList.remove('active'));
                document.querySelectorAll('#main-tabs-nav .tab-button').forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');


                if (targetTabId === 'ios') {
                    iosSubTabsContainer.style.display = 'block';
                    document.querySelector('#ios-tabs-nav .tab-button')?.click();
                } else {
                    iosSubTabsContainer.style.display = 'none';
                    document.getElementById(targetTabId + '-mods')?.classList.add('active');
                }
            });
        });

        if (iosTabNav) {
            iosTabNav.querySelectorAll('.tab-button').forEach(button => {
                button.addEventListener('click', () => {
                    document.querySelectorAll('#ios-tabs-nav .tab-button').forEach(btn => btn.classList.remove('active'));
                    button.classList.add('active');
                    
                    allTabContents.forEach(c => c.classList.remove('active'));
                    const targetContent = document.getElementById(button.dataset.tab + '-mods');
                    if (targetContent) targetContent.classList.add('active');
                });
            });
        }
    }
    const detailTabsNav = document.querySelector('.details-panel .tabs-nav');
    if (detailTabsNav) {
        detailTabsNav.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', () => {
                detailTabsNav.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
                document.querySelectorAll('.details-panel .tab-content').forEach(content => content.classList.remove('active'));
                button.classList.add('active');
                document.getElementById(button.dataset.tab).classList.add('active');
            });
        });
    }
    // --- End of Corrected Tab Logic ---

    // --- 6. DYNAMIC CONTENT LOADING ---
    async function loadModsForCarousel(platform, carouselId, sortBy = 'new') {
        const carousel = document.getElementById(carouselId);
        if (!carousel) return;
        try {
            const response = await fetch(`/api/mods/homepage/${platform}?sort=${sortBy}`);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const mods = await response.json();
            carousel.innerHTML = '';
            if (mods.length === 0) {
                carousel.innerHTML = '<p style="color: var(--silver); padding-left: 15px;">No mods found yet.</p>';
                return;
            }
            mods.forEach(mod => {
                const starPercentage = (mod.ratingValue / 5) * 100;
                const modCardHTML = `
                    <a href="/mod.html?id=${mod._id}" class="mod-card-link">
                        <div class="mod-card">
                            <div class="app-feature-tag">${mod.fileType.toUpperCase()}</div>
                            <div class="mod-type-tag">${mod.modType}</div>
                            <img src="/${mod.iconPath}" alt="${mod.name}" class="mod-card-image">
                            <div class="mod-card-content">
                                <h3>${mod.name}</h3>
                                <p>${mod.description}</p>
                                <div class="rating">
                                    <div class="stars-outer">
                                        <div class="stars-inner" style="width: ${starPercentage}%;"></div>
                                    </div>
                                    <span class="rating-text">${mod.ratingValue.toFixed(1)}</span>
                                </div>
                            </div>
                            <div class="download-overlay">
                                <a href="/apps/gpl-mart/gpl-mart.html" class="overlay-button overlay-btn-primary">⚡ Fast Download With GPL Mart</a>
                                <a href="/mod.html?id=${mod._id}" class="overlay-button overlay-btn-secondary">Download .${mod.fileType}</a>
                            </div>
                        </div>
                    </a>
                `;
                carousel.innerHTML += modCardHTML;
            });
        } catch (error) {
            console.error(`Failed to load mods for carousel #${carouselId}:`, error);
            carousel.innerHTML = '<p style="color: var(--red); padding-left: 15px;">Error loading mods.</p>';
        }
    }
    if (document.getElementById('mods-container')) {
        loadModsForCarousel('android', 'android-working-carousel', 'working');
        loadModsForCarousel('android', 'android-popular-carousel', 'popular');
        loadModsForCarousel('android', 'android-new-carousel', 'new');
        loadModsForCarousel('ios-jailed', 'ipa-working-carousel', 'working');
        loadModsForCarousel('ios-jailed', 'ipa-popular-carousel', 'popular');
        loadModsForCarousel('ios-jailed', 'ipa-new-carousel', 'new');
        loadModsForCarousel('ios-jailbroken', 'deb-working-carousel', 'working');
        loadModsForCarousel('ios-jailbroken', 'deb-popular-carousel', 'popular');
        loadModsForCarousel('ios-jailbroken', 'deb-new-carousel', 'new');
        loadModsForCarousel('wordpress', 'wordpress-working-carousel', 'working');
        loadModsForCarousel('wordpress', 'wordpress-popular-carousel', 'popular');
        loadModsForCarousel('wordpress', 'wordpress-new-carousel', 'new');
        loadModsForCarousel('windows', 'windows-working-carousel', 'working');
        loadModsForCarousel('windows', 'windows-popular-carousel', 'popular');
        loadModsForCarousel('windows', 'windows-new-carousel', 'new');
    }
    const modListContainer = document.getElementById('mod-grid-container');
    if (modListContainer) {
        async function loadModListPage() {
            const urlParams = new URLSearchParams(window.location.search);
            const platform = urlParams.get('platform');
            const sortBy = urlParams.get('sort');
            const page = urlParams.get('page') || 1;
            const featuredSection = document.getElementById('special-featured-section');

            if (!platform) {
                modListContainer.innerHTML = "<p>Platform not specified in URL.</p>";
                return;
            }

            if (featuredSection) {
                try {
                    const featuredResponse = await fetch(`/api/mods/featured/${platform}`);
                    const featuredMod = await featuredResponse.json();
                    if (featuredMod && featuredMod._id) {
                        featuredSection.style.display = 'block';
                        featuredSection.innerHTML = `
                        <div class="container">
                            <div class="featured-card">
                                <img src="/${featuredMod.iconPath}" alt="${featuredMod.name} Icon" class="featured-icon">
                                <div class="featured-content">
                                    <h2>Editor's Choice: <span>${featuredMod.name}</span></h2>
                                    <p>${featuredMod.description}</p>
                                    <div class="featured-buttons">
                                        <a href="/apps/gpl-mart/gpl-mart.html" class="featured-button btn-primary">⚡ Fast Download</a>
                                        <a href="/mod.html?id=${featuredMod._id}" class="featured-button btn-secondary">Learn More</a>
                                    </div>
                                </div>
                            </div>
                        </div>`;
                    } else {
                        featuredSection.style.display = 'none';
                    }
                } catch (error) {
                    console.error("Could not load featured mod:", error);
                    featuredSection.style.display = 'none';
                }
            }

            const pageTitle = document.getElementById('page-title');
            if (pageTitle) {
                const formattedPlatform = platform.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                const formattedSort = sortBy ? sortBy.replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) : 'All';
                const titleText = (sortBy && sortBy !== 'all') ? `${formattedSort} ${formattedPlatform} Mods` : `All ${formattedPlatform} Mods`;
                pageTitle.textContent = titleText;
                document.title = `${titleText} - GPL Mods`;
            }

            modListContainer.innerHTML = '<p style="color: var(--silver); text-align: center;">Loading...</p>';
            try {
                const apiSortBy = (sortBy === 'all' || !sortBy) ? 'new' : sortBy;
                const response = await fetch(`/api/mods?platform=${platform}&sort=${apiSortBy}&page=${page}`);
                if (!response.ok) throw new Error(`HTTP Error: ${response.status}`);
                const data = await response.json();

                modListContainer.innerHTML = '';
                if (data.mods && data.mods.length > 0) {
                    data.mods.forEach(mod => {
                        const modCardHTML = `<a href="/mod.html?id=${mod._id}" class="mod-card-link"><div class="mod-card"><img src="/${mod.iconPath}" alt="${mod.name}" class="mod-card-image"><div class="mod-card-content"><h3>${mod.name}</h3><p>${mod.description}</p></div></div></a>`;
                        modListContainer.innerHTML += modCardHTML;
                    });
                } else {
                    modListContainer.innerHTML = '<p style="color: var(--silver); text-align: center;">No mods found for this category yet.</p>';
                }

                const resultsCountEl = document.getElementById('results-count');
                if (resultsCountEl) resultsCountEl.textContent = `Showing results ${data.startItem}-${data.endItem} of ${data.totalMods}`;

                const paginationContainer = document.getElementById('pagination-container');
                if (paginationContainer) {
                    paginationContainer.innerHTML = '';
                    if (data.totalPages > 1) {
                        for (let i = 1; i <= data.totalPages; i++) {
                            const pageLink = `<a href="?platform=${platform}&sort=${sortBy || 'all'}&page=${i}" class="${i == data.currentPage ? 'active' : ''}">${i}</a>`;
                            paginationContainer.innerHTML += pageLink;
                        }
                    }
                }
            } catch (error) {
                modListContainer.innerHTML = "<p style='color: var(--red); text-align: center;'>Error loading mods.</p>";
                console.error("Failed to load mod list:", error);
            }
        }
        loadModListPage();
    }

    if (document.querySelector('.download-layout')) {
        async function loadModDetails() {
            const urlParams = new URLSearchParams(window.location.search);
            const modId = urlParams.get('id');
            const mainContent = document.querySelector('.download-layout');

            if (!modId) {
                mainContent.innerHTML = '<div class="container"><h1 style="color: var(--red);">Error: Mod ID not provided.</h1></div>';
                return;
            }

            try {
                const response = await fetch(`/api/mod/${modId}`);
                if (!response.ok) throw new Error('Mod not found');
                const mod = await response.json();

                document.title = `Download ${mod.name} - GPL Mods`;
                document.getElementById('mod-icon').src = `/${mod.iconPath}`;
                document.getElementById('mod-name').textContent = mod.name;
                document.getElementById('mod-version').textContent = `Version: ${mod.version}`;
                document.getElementById('mod-file-size').textContent = `Size: ${mod.fileSize}`;
                document.getElementById('mod-platform').textContent = `Platform: ${mod.platform.replace(/\b\w/g, l => l.toUpperCase())}`;
                document.getElementById('mod-upload-date').textContent = `Uploaded: ${new Date(mod.uploadDate).toLocaleDateString()}`;
                
                const starPercentage = (mod.ratingValue / 5) * 100;
                document.querySelector('.stars-inner').style.width = `${starPercentage}%`;
                document.querySelector('.rating-text').textContent = `${mod.ratingValue.toFixed(1)} (${mod.ratingCount} reviews)`;

                document.getElementById('description-content').innerHTML = mod.description;
                document.getElementById('changelog-content').innerHTML = mod.changelog;

                const versionsContainer = document.getElementById('versions-list');
                versionsContainer.innerHTML = ''; 
                mod.versions.forEach(v => {
                    const versionHTML = `
                        <div class="version-item">
                            <div class="version-info">
                                <h4>${mod.name} <span>v${v.version}</span></h4>
                                <p>Release Date: ${new Date(v.date).toLocaleDateString()} | Size: ${v.size}</p>
                            </div>
                            <a href="${v.downloadLink}" class="download-button-small">Download</a>
                        </div>
                    `;
                    versionsContainer.innerHTML += versionHTML;
                });

            } catch (error) {
                console.error("Error loading mod details:", error);
                mainContent.innerHTML = `<div class="container"><h1 style="color: var(--red);">Error: Could not load mod details.</h1><p>The mod may have been removed or the link is incorrect.</p></div>`;
            }
        }
        loadModDetails();
    }

    // --- 7. Login/Sign-Up Modal Logic (for index.html) ---
    const loginModal = document.getElementById('loginModal');
    if (loginModal) { 
        const signupModal = document.getElementById('signupModal');
        const showModal = (modal) => modal?.classList.add('visible');
        const hideModal = (modal) => modal?.classList.remove('visible');
        document.querySelectorAll('#loginBtnHeader, #loginBtnMobile').forEach(btn => btn.addEventListener('click', (e) => {
            e.preventDefault();
            showModal(loginModal);
        }));
        document.querySelectorAll('#signupBtnHeader, #signupBtnMobile').forEach(btn => btn.addEventListener('click', (e) => {
            e.preventDefault();
            showModal(signupModal);
        }));
        document.querySelectorAll('#loginModalClose, #signupModalClose').forEach(btn => btn.addEventListener('click', () => {
            hideModal(loginModal);
            hideModal(signupModal);
        }));
        [loginModal, signupModal].forEach(modal => modal?.addEventListener('click', (e) => {
            if (e.target === modal) hideModal(modal);
        }));
        document.getElementById('switchToSignup')?.addEventListener('click', (e) => {
            e.preventDefault();
            hideModal(loginModal);
            showModal(signupModal);
        });
        document.getElementById('switchToLogin')?.addEventListener('click', (e) => {
            e.preventDefault();
            hideModal(signupModal);
            showModal(loginModal);
        });
    }

    // --- 8. FORM FUNCTIONALITY & HELPERS ---
    const loginForm = document.getElementById('login-form') || document.getElementById('loginForm');
    if (loginForm) loginForm.addEventListener('submit', (e) => {
        e.preventDefault();
        alert('Login successful! (Simulation)');
        if (loginModal) {
            hideModal(loginModal);
            loginForm.reset();
        } else {
            window.location.href = 'index.html';
        }
    });
    const signupForm = document.getElementById('signup-form') || document.getElementById('signupForm');
    if (signupForm) signupForm.addEventListener('submit', (e) => {
        e.preventDefault();
        alert('Account created successfully!');
        if (signupModal) {
            hideModal(signupModal);
            signupForm.reset();
        } else {
            window.location.href = 'login.html';
        }
    });

    document.getElementById('profile-details-form')?.addEventListener('submit', (e) => {
        e.preventDefault();
        alert('Profile details updated!');
    });
    document.getElementById('password-change-form')?.addEventListener('submit', (e) => {
        e.preventDefault();
        alert('Password changed!');
        e.target.reset();
    });
    document.getElementById('delete-account-btn')?.addEventListener('click', () => {
        if (confirm('Are you absolutely sure you want to delete your account?')) {
            if (confirm('FINAL WARNING: All data will be erased.')) alert('Account deleted.');
        }
    });

    const modForm = document.getElementById('modForm');
    if (modForm) {
        modForm.addEventListener('submit', async function(event) {
            event.preventDefault();
            const fileInput = document.getElementById('modFile');
            const file = fileInput.files[0];
            if (!file) {
                alert('Please select a file to upload.');
                return;
            }
            alert('Uploading and scanning file... This may take a moment.');
            const formData = new FormData();
            formData.append('modFile', file);
            formData.append('modName', document.getElementById('modName').value);
            try {
                const response = await fetch('/scan-file', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                if (!response.ok) {
                    alert(`Error: ${result.message}`);
                } else {
                    alert(`Success: ${result.message}`);
                    modForm.reset();
                    document.getElementById('modFileName').textContent = 'No file selected';
                    document.getElementById('imageFileName').textContent = 'No file selected';
                    const categorySelect = document.getElementById('modCategory');
                    if (categorySelect) {
                        categorySelect.innerHTML = '<option value="" disabled selected>Select a platform first...</option>';
                        categorySelect.disabled = true;
                    }
                }
            } catch (error) {
                console.error('Full upload error details:', error);
                alert(`Upload failed! There was a network or server error. Please check the browser console for more details (Press F12 > Console).`);
            }
        });

        function handleMultiFileInput(inputId, spanId) {
            const fileInput = document.getElementById(inputId);
            const fileNameSpan = document.getElementById(spanId);
            if(fileInput && fileNameSpan) {
                fileInput.addEventListener('change', function() {
                    if (this.files.length > 1) {
                        fileNameSpan.textContent = `${this.files.length} files selected`;
                    } else if (this.files.length === 1) {
                        fileNameSpan.textContent = this.files[0].name;
                    } else {
                        fileNameSpan.textContent = 'No files selected';
                    }
                });
            }
        }
        handleMultiFileInput('screenshots', 'screenshotsFileName');
    }

    const avatarInput = document.getElementById('avatar-input');
    const avatarPreview = document.getElementById('avatar-preview');
    if (avatarInput) {
        avatarInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    avatarPreview.src = e.target.result;
                }
                reader.readAsDataURL(this.files[0]);
            }
        });
    }

    const platformSelect = document.getElementById('modPlatform');
    const categorySelect = document.getElementById('modCategory');
    if (platformSelect && categorySelect) {
        const categoriesByPlatform = {
            android: ['Game', 'App', 'Tools'],
            'ios-jailed': ['Game', 'App'],
            'ios-jailbroken': ['Tweak', 'Theme', 'Utility'],
            windows: ['Game', 'Software'],
            wordpress: ['Plugin', 'Theme']
        };
        platformSelect.addEventListener('change', function() {
            const categories = categoriesByPlatform[this.value] || [];
            categorySelect.innerHTML = '<option value="" disabled selected>Select a platform first...</option>';
            categorySelect.disabled = true;
            if (categories.length > 0) {
                categorySelect.disabled = false;
                categorySelect.innerHTML = '<option value="" disabled selected>Select a category...</option>';
                categories.forEach(cat => categorySelect.add(new Option(cat, cat.toLowerCase())));
            }
        });
    }

    function setupFileInput(inputId, displayId) {
        const input = document.getElementById(inputId);
        const display = document.getElementById(displayId);
        if (input && display) {
            input.addEventListener('change', function() {
                display.textContent = this.files.length > 0 ? this.files[0].name : 'No file selected';
            });
        }
    }
    setupFileInput('modFile', 'modFileName');
    setupFileInput('imageFile', 'imageFileName');

    document.querySelectorAll('.delete-btn').forEach(button => {
        button.addEventListener('click', function(event) {
            event.preventDefault();
            if (confirm('Are you sure you want to delete this?')) {
                this.closest('.upload-item')?.remove();
                alert('Item deleted.');
            }
        });
    });
    document.querySelector('.download-button[href="#versions"]')?.addEventListener('click', (e) => {
        e.preventDefault();
        document.querySelector('.tab-button[data-tab="versions"]')?.click();
        document.querySelector('.details-panel')?.scrollIntoView({
            behavior: 'smooth'
        });
    });


    // --- 9. FAQ Accordion ---
    const faqItems = document.querySelectorAll('.faq-item');
    if(faqItems.length > 0) {
        faqItems.forEach(item => {
            item.querySelector('.faq-question')?.addEventListener('click', () => {
                const active = item.classList.contains('active');
                faqItems.forEach(i => i.classList.remove('active'));
                if (!active) item.classList.add('active');
            });
        });
    }

    // --- 10. Special Page Scripts ---
    const daysEl = document.getElementById('days');
    if (daysEl) {
        const countDownDate = new Date();
        countDownDate.setDate(countDownDate.getDate() + 30);
        const timer = setInterval(() => {
            const distance = countDownDate - new Date().getTime();
            if (distance < 0) {
                clearInterval(timer);
                document.getElementById('countdown').innerHTML = "<h2>We're Live!</h2>";
                return;
            }
            document.getElementById('days').textContent = String(Math.floor(distance / (1000 * 60 * 60 * 24))).padStart(2, '0');
            document.getElementById('hours').textContent = String(Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60))).padStart(2, '0');
            document.getElementById('minutes').textContent = String(Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60))).padStart(2, '0');
            document.getElementById('seconds').textContent = String(Math.floor((distance % (1000 * 60)) / 1000)).padStart(2, '0');
        }, 1000);
         document.getElementById('notify-form')?.addEventListener('submit', (e) => { e.preventDefault(); alert('Thank you! You will be notified on launch.'); e.target.reset(); });
    }
});