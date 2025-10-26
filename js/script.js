/* script.js (Revised & Improved) */

document.addEventListener('DOMContentLoaded', function() {

    // --- COMMON: Mobile Menu Toggle ---
    const hamburger = document.getElementById('hamburger');
    const mobileNav = document.getElementById('mobileNav');
    if (hamburger && mobileNav) {
        hamburger.addEventListener('click', () => {
            mobileNav.style.display = mobileNav.style.display === 'block' ? 'none' : 'block';
        });
    }

    // --- COMMON: Animated Search Bar Placeholder ---
    const searchInput = document.getElementById('animated-search');
    if (searchInput) {
        const searchTerms = [
            "Search my mods...", "Galaxy Invaders...", "Find rejected...", "Free Fire...", "Roblox...", "Minecraft...", 
            "Spotify Premium...", "Search settings...", "Find user...", "Help...", "Account...", "KineMaster...", 
            "Asphalt Racers...", "Pixel Editor...", "Streamify...", "Secure VPN..."
        ];
        const themeColors = ["var(--gold)", "var(--silver)"];
        let termIndex = 0, letterIndex = 0, currentTerm = '', isDeleting = false, typingTimeout;

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
                typeSpeed = 1500;
                isDeleting = true;
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

    // --- COMMON: Back to Top Button ---
    const backToTopButton = document.getElementById('backToTop');
    if (backToTopButton) {
        const appBanner = document.getElementById('appBanner');
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
        backToTopButton.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
    }

    // --- PAGE-SPECIFIC SCRIPTS ---

    // My Uploads Page: Delete Confirmation
    const deleteButtons = document.querySelectorAll('.delete-btn');
    if (deleteButtons.length > 0) {
        deleteButtons.forEach(button => {
            button.addEventListener('click', function(event) {
                event.preventDefault();
                if (confirm('Are you sure you want to permanently delete this mod? This action cannot be undone.')) {
                    const itemToRemove = this.closest('.upload-item');
                    itemToRemove.style.transition = 'opacity 0.5s ease';
                    itemToRemove.style.opacity = '0';
                    setTimeout(() => {
                        itemToRemove.remove();
                        alert('Mod deleted successfully.');
                    }, 500);
                }
            });
        });
    }

    // Profile Page: Avatar Preview & Form Simulation & Delete Account
    const profileDetailsForm = document.getElementById('profile-details-form');
    if (profileDetailsForm) {
        const avatarInput = document.getElementById('avatar-input');
        const avatarPreview = document.getElementById('avatar-preview');
        avatarInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                const reader = new FileReader();
                reader.onload = (e) => { avatarPreview.src = e.target.result; }
                reader.readAsDataURL(this.files[0]);
            }
        });

        profileDetailsForm.addEventListener('submit', (e) => {
            e.preventDefault();
            alert('Profile details updated successfully!');
        });

        const passwordChangeForm = document.getElementById('password-change-form');
        passwordChangeForm.addEventListener('submit', (e) => {
            e.preventDefault();
            alert('Password changed successfully!');
            e.target.reset();
        });

        const deleteAccountBtn = document.getElementById('delete-account-btn');
        deleteAccountBtn.addEventListener('click', function() {
            if (confirm('Are you absolutely sure you want to delete your account? This is permanent.')) {
                if (confirm('This is your final warning. All your data will be permanently erased. Are you sure?')) {
                    alert('Your account has been successfully deleted.');
                }
            }
        });
    }

    // Mod Download Pages: Tab Functionality (Scoped to .details-panel)
    const detailsPanel = document.querySelector('.details-panel');
    if (detailsPanel) {
        const tabButtons = detailsPanel.querySelectorAll('.tab-button');
        const tabContents = detailsPanel.querySelectorAll('.tab-content');
        if (tabButtons.length > 0) {
            tabButtons.forEach(button => {
                button.addEventListener('click', () => {
                    const targetTabId = button.getAttribute('data-tab');
                    tabButtons.forEach(btn => btn.classList.remove('active'));
                    tabContents.forEach(content => content.classList.remove('active'));
                    button.classList.add('active');
                    document.getElementById(targetTabId).classList.add('active');
                });
            });
        }
    }

    // Login/Signup Page: Form Switching
    const loginSection = document.getElementById('login-section');
    if (loginSection) {
        const signupSection = document.getElementById('signup-section');
        const accountSection = document.getElementById('account-section');
        const showSignupLink = document.getElementById('show-signup-link');
        const showLoginLink = document.getElementById('show-login-link');
        const loginForm = document.getElementById('login-form');
        const signupForm = document.getElementById('signup-form');
        const logoutButton = document.getElementById('logout-button');
        const usernameSpan = document.getElementById('username-span');

        if(showSignupLink) showSignupLink.addEventListener('click', (e) => {
            e.preventDefault();
            loginSection.style.display = 'none';
            signupSection.style.display = 'block';
        });

        if(showLoginLink) showLoginLink.addEventListener('click', (e) => {
            e.preventDefault();
            signupSection.style.display = 'none';
            loginSection.style.display = 'block';
        });

        if(loginForm) loginForm.addEventListener('submit', (e) => {
            e.preventDefault();
            const username = document.getElementById('loginUsername').value;
            if(usernameSpan) usernameSpan.textContent = username;
            loginSection.style.display = 'none';
            accountSection.style.display = 'block';
        });

        if(signupForm) signupForm.addEventListener('submit', (e) => {
            e.preventDefault();
            alert('Account created successfully! Please log in.');
            signupSection.style.display = 'none';
            loginSection.style.display = 'block';
        });

        if(logoutButton) logoutButton.addEventListener('click', (e) => {
            e.preventDefault();
            accountSection.style.display = 'none';
            loginSection.style.display = 'block';
            if(loginForm) loginForm.reset();
        });
    }

    // Mod Upload Page: Dynamic Category & File Name Display
    const platformSelect = document.getElementById('modPlatform');
    if (platformSelect) {
        const categorySelect = document.getElementById('modCategory');
        const categoriesByPlatform = {
            android: ['Game - Action', 'Game - Adventure', 'Game - Puzzle', 'Game - RPG', 'App - Productivity', 'App - Social', 'App - Tools', 'Other'],
            'ios-jailed': ['Game - Action', 'Game - Adventure', 'Game - Puzzle', 'Game - RPG', 'App - Productivity', 'App - Social', 'App - Tools', 'Other'],
            'ios-jailbroken': ['Tweak', 'Theme', 'Utility', 'Widget', 'Other'],
            windows: ['Software - Utility', 'Software - Multimedia', 'Software - Security', 'Software - Development', 'Game', 'Other'],
            wordpress: ['Plugin - SEO', 'Plugin - Security', 'Plugin - E-commerce', 'Plugin - Page Builder', 'Theme - Portfolio', 'Theme - E-commerce', 'Theme - Blog', 'Other']
        };

        platformSelect.addEventListener('change', function() {
            const selectedPlatform = this.value;
            const categories = categoriesByPlatform[selectedPlatform] || [];
            categorySelect.innerHTML = '';
            if (categories.length > 0) {
                categorySelect.disabled = false;
                let defaultOption = new Option('Select a category...', '', true, true);
                defaultOption.disabled = true;
                categorySelect.add(defaultOption);
                categories.forEach(category => {
                    let option = new Option(category, category.toLowerCase().replace(/ /g, '-'));
                    categorySelect.add(option);
                });
            } else {
                let defaultOption = new Option('Select a platform first...', '', true, true);
                defaultOption.disabled = true;
                categorySelect.add(defaultOption);
                categorySelect.disabled = true;
            }
        });

        function handleFileInput(inputId, spanId) {
            const fileInput = document.getElementById(inputId);
            const fileNameSpan = document.getElementById(spanId);
            if (fileInput && fileNameSpan) {
                fileInput.addEventListener('change', function() {
                    fileNameSpan.textContent = this.files.length > 0 ? this.files[0].name : 'No file selected';
                });
            }
        }
        handleFileInput('modFile', 'modFileName');
        handleFileInput('imageFile', 'imageFileName');

        const modForm = document.getElementById('modForm');
        modForm.addEventListener('submit', function(event) {
            event.preventDefault();
            alert('Thank you! Your mod has been submitted for review.');
            modForm.reset();
            document.getElementById('modFileName').textContent = 'No file selected';
            document.getElementById('imageFileName').textContent = 'No file selected';
            categorySelect.innerHTML = '<option value="" disabled selected>Select a platform first...</option>';
            categorySelect.disabled = true;
        });
    }

    // FAQ Page: Accordion
    const faqContainer = document.querySelector('.faq-container');
    if (faqContainer) {
        const faqItems = faqContainer.querySelectorAll('.faq-item');
        faqItems.forEach(item => {
            const question = item.querySelector('.faq-question');
            question.addEventListener('click', () => {
                const isAlreadyActive = item.classList.contains('active');
                faqItems.forEach(i => i.classList.remove('active'));
                if (!isAlreadyActive) {
                    item.classList.add('active');
                }
            });
        });
    }

    // Index Page: Advanced Tabs, Sidebar Accordion, Modals
    const mainTabNav = document.getElementById('main-tabs-nav');
    if (mainTabNav) {
        const allTabContents = document.querySelectorAll('.tab-content'); // Used by both main and sub-tabs
        const iosSubTabsContainer = document.getElementById('ios-sub-tabs-container');
        const mainTabHighlight = document.getElementById('main-tab-highlight');
        const iosTabNav = document.getElementById('ios-tabs-nav');
        const iosTabHighlight = document.getElementById('ios-tab-highlight');

        function moveHighlight(targetTab, highlightElement) {
            if (!targetTab || !highlightElement) return;
            requestAnimationFrame(() => {
                highlightElement.style.width = `${targetTab.offsetWidth}px`;
                highlightElement.style.transform = `translateX(${targetTab.offsetLeft}px)`;
            });
        }

        function initializeTabs(navElement, highlightElement, isMainTabs) {
            if (!navElement || !highlightElement) return;
            const tabButtons = navElement.querySelectorAll('.tab-button');
            const initialActiveTab = navElement.querySelector('.tab-button.active');
            moveHighlight(initialActiveTab, highlightElement);

            tabButtons.forEach(button => {
                button.addEventListener('click', () => {
                    const targetTabId = button.dataset.tab;
                    button.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' });
                    
                    // Deactivate all buttons within the CURRENT nav
                    tabButtons.forEach(btn => btn.classList.remove('active'));
                    button.classList.add('active');
                    moveHighlight(button, highlightElement);
                    
                    // Deactivate all tab content panels on the page
                    allTabContents.forEach(content => content.classList.remove('active'));

                    if (isMainTabs) {
                        if (targetTabId === 'ios') {
                            iosSubTabsContainer.style.display = 'block';
                            // Activate the default iOS sub-tab
                            const defaultIosSubTab = iosTabNav.querySelector('.tab-button[data-tab="ios-jailed"]');
                            iosTabNav.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
                            defaultIosSubTab.classList.add('active');
                            moveHighlight(defaultIosSubTab, iosTabHighlight);
                            document.getElementById('ios-jailed-mods').classList.add('active');
                        } else {
                            iosSubTabsContainer.style.display = 'none';
                            document.getElementById(targetTabId + '-mods').classList.add('active');
                        }
                    } else { // This is an iOS sub-tab
                        const mainIosTab = mainTabNav.querySelector('.tab-button[data-tab="ios"]');
                        mainTabNav.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
                        mainIosTab.classList.add('active');
                        moveHighlight(mainIosTab, mainTabHighlight);
                        document.getElementById(targetTabId + '-mods').classList.add('active');
                    }
                });
            });

            window.addEventListener('resize', () => {
                const activeTab = navElement.querySelector('.tab-button.active');
                moveHighlight(activeTab, highlightElement);
            });
        }
        
        initializeTabs(mainTabNav, mainTabHighlight, true);
        initializeTabs(iosTabNav, iosTabHighlight, false);

        const collapsibleTrigger = document.querySelector('.collapsible-trigger');
        if (collapsibleTrigger) {
            collapsibleTrigger.addEventListener('click', function(e) {
                e.preventDefault();
                this.parentElement.classList.toggle('open');
            });
        }
        
        const loginModal = document.getElementById('loginModal');
        const signupModal = document.getElementById('signupModal');
        if (loginModal && signupModal) {
            const modalTriggers = document.querySelectorAll('#loginBtnHeader, #signupBtnHeader, #loginBtnMobile, #signupBtnMobile');
            const closeButtons = document.querySelectorAll('.modal-close');
            const switchToSignup = document.getElementById('switchToSignup');
            const switchToLogin = document.getElementById('switchToLogin');

            const showModal = (modal) => modal.classList.add('visible');
            const hideAllModals = () => {
                loginModal.classList.remove('visible');
                signupModal.classList.remove('visible');
            };

            modalTriggers.forEach(btn => {
                btn.addEventListener('click', (e) => {
                    e.preventDefault();
                    if(btn.id.includes('login')){
                        showModal(loginModal);
                    } else {
                        showModal(signupModal);
                    }
                });
            });

            closeButtons.forEach(btn => btn.addEventListener('click', hideAllModals));
            
            [loginModal, signupModal].forEach(modal => modal.addEventListener('click', (e) => {
                if (e.target === modal) hideAllModals();
            }));

            switchToSignup.addEventListener('click', (e) => { e.preventDefault(); hideAllModals(); showModal(signupModal); });
            switchToLogin.addEventListener('click', (e) => { e.preventDefault(); hideAllModals(); showModal(loginModal); });

            const loginForm = document.getElementById('loginForm');
            const signupForm = document.getElementById('signupForm');
            if(loginForm) loginForm.addEventListener('submit', (e) => { e.preventDefault(); alert('Login successful! (Simulation)'); hideAllModals(); loginForm.reset(); });
            if(signupForm) signupForm.addEventListener('submit', (e) => { e.preventDefault(); alert('Account created! (Simulation)'); hideAllModals(); signupForm.reset(); });
        }
    }
});