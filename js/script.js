/* ===================================================================
   TABLE OF CONTENTS
   ===================================================================
   1.  DOM Ready Event Listener
   2.  Global Functionality (Runs on all pages if elements exist)
       - Mobile Menu Toggle
       - Animated Search Bar Placeholder
       - Back to Top & Banner Visibility
       - Modal Logic (Login/Sign-up) & Form Simulations
   3.  Homepage-Specific Functionality
       - Advanced Tab Navigation with Sliding Highlight
   4.  Mod Download Page Functionality
       - Simple Tab Navigation
       - "Download" button scroll to Versions tab
   5.  FAQ Page Functionality
       - Accordion for Questions
   6.  Mod Upload Page Functionality
       - Dynamic Category Dropdown
       - File Input Name Display
   7.  User Profile/Settings Pages Functionality
       - Profile Tabs
       - Live Avatar Preview
       - Form Submission Simulations (Settings)
       - Delete Account Confirmation
   8.  My Uploads Page Functionality
       - Delete Upload Confirmation
   =================================================================== */

document.addEventListener('DOMContentLoaded', function() {

    // ===================================================================
    // 2. Global Functionality
    // ===================================================================

    // --- Mobile Menu Toggle ---
    const hamburger = document.getElementById('hamburger');
    const mobileNav = document.getElementById('mobileNav');
    if (hamburger && mobileNav) {
        hamburger.addEventListener('click', () => {
            mobileNav.style.display = mobileNav.style.display === 'block' ? 'none' : 'block';
        });
    }

    // --- Sidebar Accordion for Categories ---
    const collapsibleTrigger = document.querySelector('.mobile-nav .collapsible-trigger');
    if (collapsibleTrigger) {
        collapsibleTrigger.addEventListener('click', function(e) {
            e.preventDefault();
            this.parentElement.classList.toggle('open');
        });
    }
    
    // --- Animated Search Bar Placeholder ---
    const searchInput = document.getElementById('animated-search');
    if (searchInput && !searchInput.value) { // Don't run animation if a value is already present (e.g., search results page)
        const searchTerms = ["Search for mods...", "Roblox...", "Minecraft...", "Elementor...", "Picsart..."];
        let termIndex = 0, letterIndex = 0, currentTerm = '', isDeleting = false;
        let typingTimeout;

        function typeAnimation() {
            const fullTerm = searchTerms[termIndex];
            if (isDeleting) {
                currentTerm = fullTerm.substring(0, letterIndex - 1); letterIndex--;
            } else {
                currentTerm = fullTerm.substring(0, letterIndex + 1); letterIndex++;
            }
            searchInput.placeholder = currentTerm;
            let typeSpeed = isDeleting ? 60 : 120;
            if (!isDeleting && letterIndex === fullTerm.length) {
                isDeleting = true; typeSpeed = 1500;
            } else if (isDeleting && letterIndex === 0) {
                isDeleting = false;
                termIndex = (termIndex + 1) % searchTerms.length;
                typeSpeed = 300;
            }
            typingTimeout = setTimeout(typeAnimation, typeSpeed);
        }
        typeAnimation();
        searchInput.addEventListener('focus', () => clearTimeout(typingTimeout));
        searchInput.addEventListener('blur', () => {
            if (searchInput.value === '') { typeAnimation(); }
        });
    }

    // --- Back to Top & Banner Visibility ---
    const backToTopButton = document.getElementById('backToTop');
    if (backToTopButton) {
        const appBanner = document.getElementById('appBanner');
        window.addEventListener('scroll', function() {
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
        });
        backToTopButton.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
    }
    
    // --- Modal Logic & Form Simulations ---
    const loginModal = document.getElementById('loginModal');
    const signupModal = document.getElementById('signupModal');
    if (loginModal && signupModal) {
        const loginButtons = document.querySelectorAll('#loginBtnHeader, #loginBtnMobile, #switchToLogin');
        const signupButtons = document.querySelectorAll('#signupBtnHeader, #signupBtnMobile, #switchToSignup');
        const closeModalButtons = document.querySelectorAll('.modal-close');
        const loginForm = document.getElementById('loginForm');
        const signupForm = document.getElementById('signupForm');

        const showModal = (modal) => modal.classList.add('visible');
        const hideAllModals = () => {
            loginModal.classList.remove('visible');
            signupModal.classList.remove('visible');
        };

        loginButtons.forEach(btn => btn.addEventListener('click', (e) => { e.preventDefault(); hideAllModals(); showModal(loginModal); }));
        signupButtons.forEach(btn => btn.addEventListener('click', (e) => { e.preventDefault(); hideAllModals(); showModal(signupModal); }));
        closeModalButtons.forEach(btn => btn.addEventListener('click', hideAllModals));
        [loginModal, signupModal].forEach(modal => modal.addEventListener('click', (e) => { if (e.target === modal) hideAllModals(); }));

        loginForm.addEventListener('submit', (e) => { e.preventDefault(); alert('Login successful! (Simulation)'); hideAllModals(); loginForm.reset(); });
        signupForm.addEventListener('submit', (e) => { e.preventDefault(); alert('Account created! (Simulation)'); hideAllModals(); signupForm.reset(); });
    }
    
    // ===================================================================
    // 3. Homepage-Specific Functionality
    // ===================================================================
    
    const mainTabNav = document.getElementById('main-tabs-nav');
    if (mainTabNav) {
        const mainTabHighlight = document.getElementById('main-tab-highlight');
        const iosTabNav = document.getElementById('ios-tabs-nav');
        const iosTabHighlight = document.getElementById('ios-tab-highlight');
        const allTabContents = document.querySelectorAll('#mods-container .tab-content');
        const iosSubTabsContainer = document.getElementById('ios-sub-tabs-container');

        const moveHighlight = (targetTab, highlightElement) => {
            if (!targetTab || !highlightElement) return;
            requestAnimationFrame(() => {
                highlightElement.style.width = `${targetTab.offsetWidth}px`;
                highlightElement.style.transform = `translateX(${targetTab.offsetLeft}px)`;
            });
        };

        const initializeTabs = (navElement, highlightElement, isMainTabs) => {
            if (!navElement || !highlightElement) return;
            const tabButtons = navElement.querySelectorAll('.tab-button');
            const initialActiveTab = navElement.querySelector('.tab-button.active');
            if (initialActiveTab) moveHighlight(initialActiveTab, highlightElement);

            tabButtons.forEach(button => {
                button.addEventListener('click', () => {
                    const targetTabId = button.dataset.tab;
                    button.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' });
                    
                    navElement.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
                    button.classList.add('active');
                    moveHighlight(button, highlightElement);
                    
                    allTabContents.forEach(content => content.classList.remove('active'));

                    if (isMainTabs) {
                        if (targetTabId === 'ios') {
                            iosSubTabsContainer.style.display = 'block';
                            const defaultIosSubTab = iosTabNav.querySelector('.tab-button[data-tab="ios-jailed"]');
                            if(defaultIosSubTab) defaultIosSubTab.click(); 
                        } else {
                            iosSubTabsContainer.style.display = 'none';
                            const targetContent = document.getElementById(targetTabId + '-mods');
                            if (targetContent) targetContent.classList.add('active');
                        }
                    } else { // It's an iOS sub-tab
                        const targetContent = document.getElementById(targetTabId + '-mods');
                        if (targetContent) targetContent.classList.add('active');
                    }
                });
            });
            window.addEventListener('resize', () => {
                const activeTab = navElement.querySelector('.tab-button.active');
                if (activeTab) moveHighlight(activeTab, highlightElement);
            });
        };
        initializeTabs(mainTabNav, mainTabHighlight, true);
        initializeTabs(iosTabNav, iosTabHighlight, false);
    }
    
    // ===================================================================
    // 4. Mod Download Page Functionality
    // ===================================================================

    const detailsPanel = document.querySelector('.details-panel');
    if (detailsPanel) {
        const detailsTabButtons = detailsPanel.querySelectorAll('.tab-button');
        const detailsTabContents = detailsPanel.querySelectorAll('.tab-content');

        detailsTabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const targetTabId = button.getAttribute('data-tab');
                const targetContent = detailsPanel.querySelector(`#${targetTabId}`);
                
                detailsTabButtons.forEach(btn => btn.classList.remove('active'));
                detailsTabContents.forEach(content => content.classList.remove('active'));
                
                button.classList.add('active');
                if (targetContent) targetContent.classList.add('active');
            });
        });

        const downloadButtonModPage = document.querySelector('.download-layout .download-button');
        const versionsTabButton = detailsPanel.querySelector('button[data-tab="versions"]');
        if (downloadButtonModPage && versionsTabButton) {
            downloadButtonModPage.addEventListener('click', function(e) {
                e.preventDefault();
                versionsTabButton.click();
                detailsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
            });
        }
    }

    // ===================================================================
    // 5. FAQ Page Functionality
    // ===================================================================
    const faqItems = document.querySelectorAll('.faq-item');
    if (faqItems.length > 0) {
        faqItems.forEach(item => {
            const question = item.querySelector('.faq-question');
            if(question) {
                question.addEventListener('click', () => {
                    const isAlreadyActive = item.classList.contains('active');
                    faqItems.forEach(i => i.classList.remove('active'));
                    if (!isAlreadyActive) item.classList.add('active');
                });
            }
        });
    }

    // ===================================================================
    // 6. Mod Upload Page Functionality
    // ===================================================================
    const modForm = document.getElementById('modForm');
    if (modForm) {
        const platformSelect = document.getElementById('modPlatform');
        const categorySelect = document.getElementById('modCategory');
        const categoriesByPlatform = {
            android: ['Game - Action', 'Game - Adventure', 'Game - Puzzle', 'Game - RPG', 'App - Productivity', 'App - Social', 'App - Tools', 'Other'],
            'ios-jailed': ['Game - Action', 'Game - Adventure', 'App - Productivity', 'App - Social', 'Other'],
            'ios-jailbroken': ['Tweak', 'Theme', 'Utility', 'Widget', 'Other'],
            windows: ['Software - Utility', 'Software - Multimedia', 'Game', 'Other'],
            wordpress: ['Plugin - SEO', 'Plugin - E-commerce', 'Theme - Blog', 'Other']
        };

        platformSelect.addEventListener('change', function() {
            const categories = categoriesByPlatform[this.value] || [];
            categorySelect.innerHTML = ''; // Clear current options
            if (categories.length > 0) {
                categorySelect.disabled = false;
                categorySelect.add(new Option('Select a category...', '', true, true));
                categories.forEach(cat => categorySelect.add(new Option(cat, cat.toLowerCase().replace(/ /g, '-'))));
            } else {
                categorySelect.disabled = true;
                categorySelect.add(new Option('Select a platform first...', '', true, true));
            }
        });
        
        modForm.addEventListener('submit', (e) => { e.preventDefault(); alert('Mod submitted for review! (Simulation)'); modForm.reset(); });
        
        const modFileInput = document.getElementById('modFile');
        const modFileNameSpan = document.getElementById('modFileName');
        modFileInput.addEventListener('change', function() { modFileNameSpan.textContent = this.files.length > 0 ? this.files[0].name : 'No file selected'; });
        
        const imageFileInput = document.getElementById('imageFile');
        const imageFileNameSpan = document.getElementById('imageFileName');
        imageFileInput.addEventListener('change', function() { imageFileNameSpan.textContent = this.files.length > 0 ? this.files[0].name : 'No file selected'; });
    }

    // ===================================================================
    // 7. User Profile/Settings Pages Functionality
    // ===================================================================
    const profileContent = document.querySelector('.profile-content');
    if (profileContent) {
        const profileTabButtons = profileContent.querySelectorAll('.tab-button');
        const profileTabContents = profileContent.querySelectorAll('.tab-content');
        profileTabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const targetTabId = button.getAttribute('data-tab');
                profileTabButtons.forEach(btn => btn.classList.remove('active'));
                profileTabContents.forEach(content => content.classList.remove('active'));
                button.classList.add('active');
                profileContent.querySelector(`#${targetTabId}`).classList.add('active');
            });
        });
    }

    const avatarInput = document.getElementById('avatar-input');
    if (avatarInput) {
        const avatarPreview = document.getElementById('avatar-preview');
        avatarInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                const reader = new FileReader();
                reader.onload = (e) => { avatarPreview.src = e.target.result; }
                reader.readAsDataURL(this.files[0]);
            }
        });

        document.getElementById('profile-details-form').addEventListener('submit', (e) => { e.preventDefault(); alert('Profile details updated successfully!'); });
        document.getElementById('password-change-form').addEventListener('submit', (e) => { e.preventDefault(); alert('Password changed successfully!'); e.target.reset(); });
        
        document.getElementById('delete-account-btn').addEventListener('click', () => {
            if (confirm('Are you absolutely sure you want to delete your account? This is permanent.')) {
                if (confirm('This is your final warning. All your data will be permanently erased. Are you sure?')) {
                    alert('Your account has been successfully deleted. (Simulation)');
                    // In a real app: window.location.href = '/logout';
                }
            }
        });
    }

    // ===================================================================
    // 8. My Uploads Page Functionality
    // ===================================================================
    const deleteUploadButtons = document.querySelectorAll('.item-actions .delete-btn');
    if (deleteUploadButtons.length > 0) {
        deleteUploadButtons.forEach(button => {
            button.addEventListener('click', function(event) {
                event.preventDefault();
                if (confirm('Are you sure you want to permanently delete this mod? This action cannot be undone.')) {
                    const itemToRemove = this.closest('.upload-item');
                    if (itemToRemove) {
                        itemToRemove.style.transition = 'opacity 0.5s ease';
                        itemToRemove.style.opacity = '0';
                        setTimeout(() => {
                            itemToRemove.remove();
                            alert('Mod deleted successfully. (Simulation)');
                        }, 500);
                    }
                }
            });
        });
    }

}); // End DOMContentLoaded