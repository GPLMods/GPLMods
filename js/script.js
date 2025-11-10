/* ===================================================================
   TABLE OF CONTENTS
   ===================================================================
   1.  Global DOMContentLoaded Wrapper
   2.  Mobile Menu & Sidebar Accordion
   3.  Animated Search Bar Placeholder (COLOR CYCLE FIXED)
   4.  Back to Top Button & Conditional Banner
   5.  Advanced Tab Navigation (Homepage & Mod Pages)
   6.  Login/Sign-Up Modal Logic
   7.  FORM SIMULATIONS & HELPERS
       - Form Submissions (Login, Signup, Profile, etc.)
       - Live Avatar Preview
       - Upload Page Dynamic Categories & File Name Display
       - Delete Item Confirmation
       - Download Button Tab Link
   8.  FAQ Accordion
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

    // --- 3. Animated Search Bar Placeholder (DEFINITIVE FIX) ---
    const searchInput = document.getElementById('animated-search');
    if (searchInput) {
        const searchTerms = ["Kinemaster...", "Roblox...", "Minecraft...", "Spotify...", "Elementor..."];
        const themeColors = ["var(--gold)", "var(--silver)"]; // Gold and Silver colors
        let termIndex = 0;
        let letterIndex = 0;
        let currentTerm = '';
        let isDeleting = false;
        let typingTimeout;

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
                // THIS LINE FIXES THE COLOR CYCLING
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
                searchInput.placeholder = ""; // Clear it before restarting
                clearTimeout(typingTimeout); // Ensure no old timer is running
                letterIndex = 0;
                isDeleting = false;
                termIndex = 0; // Reset index to start from the beginning
                 searchInput.style.setProperty('--placeholder-color', themeColors[0]);
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
        backToTopButton.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
    }

    // --- 5. Advanced Tab Navigation (Homepage & Mod Pages) ---
    function initializeTabs(navElement, highlightElement, isMainTabs) {
        if (!navElement || !highlightElement) return;

        const tabButtons = navElement.querySelectorAll('.tab-button');
        
        function moveHighlight(targetTab) {
            if (!targetTab) return;
            const navRect = navElement.getBoundingClientRect();
            const targetRect = targetTab.getBoundingClientRect();
            
            requestAnimationFrame(() => {
                highlightElement.style.width = `${targetRect.width}px`;
                highlightElement.style.transform = `translateX(${targetRect.left - navRect.left + navElement.scrollLeft}px)`;
            });
        }

        const initialActiveTab = navElement.querySelector('.tab-button.active');
        if (initialActiveTab) {
            setTimeout(() => moveHighlight(initialActiveTab), 150);
        }

        tabButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                e.preventDefault();
                const targetTabId = button.dataset.tab;
                
                button.scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' });
                
                tabButtons.forEach(btn => btn.classList.remove('active'));
                button.classList.add('active');
                moveHighlight(button);
                
                document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

                if (isMainTabs) {
                    const iosSubTabsContainer = document.getElementById('ios-sub-tabs-container');
                    if (targetTabId === 'ios') {
                        if(iosSubTabsContainer) iosSubTabsContainer.style.display = 'block';
                        const firstSubTabButton = document.querySelector('#ios-tabs-nav .tab-button');
                        if (firstSubTabButton) firstSubTabButton.click();
                        else document.getElementById('ios-jailed-mods')?.classList.add('active');
                    } else {
                       if(iosSubTabsContainer) iosSubTabsContainer.style.display = 'none';
                       document.getElementById(targetTabId + '-mods')?.classList.add('active');
                    }
                } else {
                     document.getElementById(targetTabId + '-mods')?.classList.add('active');
                    if (targetTabId.startsWith('ios-')) {
                        const mainIosTab = document.querySelector('#main-tabs-nav .tab-button[data-tab="ios"]');
                        if (mainIosTab && !mainIosTab.classList.contains('active')) {
                             document.querySelectorAll('#main-tabs-nav .tab-button').forEach(btn => btn.classList.remove('active'));
                             mainIosTab.classList.add('active');
                             moveHighlight(mainIosTab);
                        }
                    }
                }
            });
        });
        window.addEventListener('resize', () => {
            const activeTab = navElement.querySelector('.tab-button.active');
            if (activeTab) moveHighlight(activeTab);
        });
    }

    initializeTabs(document.getElementById('main-tabs-nav'), document.getElementById('main-tab-highlight'), true);
    initializeTabs(document.getElementById('ios-tabs-nav'), document.getElementById('ios-tab-highlight'), false);
    
    // For mod detail pages
    const detailTabsNav = document.querySelector('.details-panel .tabs-nav');
    if (detailTabsNav) {
        const detailTabButtons = detailTabsNav.querySelectorAll('.tab-button');
        detailTabButtons.forEach(button => {
            button.addEventListener('click', () => {
                const targetTabId = button.getAttribute('data-tab');
                detailTabButtons.forEach(btn => btn.classList.remove('active'));
                document.querySelectorAll('.details-panel .tab-content').forEach(content => content.classList.remove('active'));
                button.classList.add('active');
                document.getElementById(targetTabId).classList.add('active');
            });
        });
    }


    // --- 6. Login/Sign-Up Modal Logic ---
    const loginModal = document.getElementById('loginModal');
    const signupModal = document.getElementById('signupModal');
    const showModal = (modal) => modal && modal.classList.add('visible');
    const hideModal = (modal) => modal && modal.classList.remove('visible');
    document.querySelectorAll('#loginBtnHeader, #loginBtnMobile').forEach(btn => btn.addEventListener('click', (e) => { e.preventDefault(); showModal(loginModal); }));
    document.querySelectorAll('#signupBtnHeader, #signupBtnMobile').forEach(btn => btn.addEventListener('click', (e) => { e.preventDefault(); showModal(signupModal); }));
    document.querySelectorAll('#loginModalClose, #signupModalClose').forEach(btn => btn.addEventListener('click', () => { hideModal(loginModal); hideModal(signupModal); }));
    [loginModal, signupModal].forEach(modal => { if(modal) modal.addEventListener('click', (e) => { if (e.target === modal) hideModal(modal); }); });
    const switchToSignup = document.getElementById('switchToSignup');
    const switchToLogin = document.getElementById('switchToLogin');
    if (switchToSignup) switchToSignup.addEventListener('click', (e) => { e.preventDefault(); hideModal(loginModal); showModal(signupModal); });
    if (switchToLogin) switchToLogin.addEventListener('click', (e) => { e.preventDefault(); hideModal(signupModal); showModal(loginModal); });

    // --- 7. FORM SIMULATIONS & HELPERS ---
    const loginForm = document.getElementById('login-form') || document.getElementById('loginForm');
    if(loginForm) loginForm.addEventListener('submit', (e) => { e.preventDefault(); alert('Login successful! (Simulation)'); if(loginModal) {hideModal(loginModal); loginForm.reset();} else { window.location.href = 'index.html'; }});
    const signupForm = document.getElementById('signup-form') || document.getElementById('signupForm');
    if(signupForm) signupForm.addEventListener('submit', (e) => { e.preventDefault(); alert('Account created! (Simulation)'); if(signupModal) {hideModal(signupModal); signupForm.reset();} else { window.location.href = 'login.html'; }});
    const profileDetailsForm = document.getElementById('profile-details-form');
    if(profileDetailsForm) profileDetailsForm.addEventListener('submit', (e) => { e.preventDefault(); alert('Profile details updated successfully!'); });
    const passwordChangeForm = document.getElementById('password-change-form');
    if(passwordChangeForm) passwordChangeForm.addEventListener('submit', (e) => { e.preventDefault(); alert('Password changed successfully!'); e.target.reset(); });
    const deleteAccountBtn = document.getElementById('delete-account-btn');
    if(deleteAccountBtn) deleteAccountBtn.addEventListener('click', () => { if (confirm('Are you absolutely sure you want to delete your account? This is permanent.')) { if(confirm('FINAL WARNING: All data will be erased.')) { alert('Account deleted.'); } } });
    
    const modForm = document.getElementById('modForm');
    if (modForm) {
        modForm.addEventListener('submit', function(event) {
            event.preventDefault();
            alert('Thank you! Your mod has been submitted for review.');
            modForm.reset();
            document.getElementById('modFileName').textContent = 'No file selected';
            document.getElementById('imageFileName').textContent = 'No file selected';
            document.getElementById('modCategory').innerHTML = '<option value="" disabled selected>Select a platform first...</option>';
            document.getElementById('modCategory').disabled = true;
        });
    }

    const avatarInput = document.getElementById('avatar-input');
    const avatarPreview = document.getElementById('avatar-preview');
    if(avatarInput && avatarPreview) {
        avatarInput.addEventListener('change', function() {
            if (this.files && this.files[0]) {
                const reader = new FileReader();
                reader.onload = (e) => { avatarPreview.src = e.target.result; }
                reader.readAsDataURL(this.files[0]);
            }
        });
    }
    
    const platformSelect = document.getElementById('modPlatform');
    const categorySelect = document.getElementById('modCategory');
    if(platformSelect && categorySelect) {
        const categoriesByPlatform = { android: ['Game - Action', 'Game - Adventure', 'App - Productivity', 'App - Tools'], 'ios-jailed': ['Game', 'App', 'Social', 'Other'], 'ios-jailbroken': ['Tweak', 'Theme', 'Utility', 'Widget'], windows: ['Game', 'Software', 'Utility'], wordpress: ['Plugin', 'Theme'] };
        platformSelect.addEventListener('change', function() {
            const categories = categoriesByPlatform[this.value] || [];
            categorySelect.innerHTML = '<option value="" disabled selected>Select a platform first...</option>';
            categorySelect.disabled = true;
            if (categories.length > 0) {
                categorySelect.disabled = false;
                categorySelect.innerHTML = '<option value="" disabled selected>Select a category...</option>';
                categories.forEach(cat => categorySelect.add(new Option(cat, cat.toLowerCase().replace(/ /g, '-'))));
            }
        });
    }
    
    function setupFileInput(inputId, displayId) { const input = document.getElementById(inputId); const display = document.getElementById(displayId); if (input && display) input.addEventListener('change', function() { display.textContent = this.files.length > 0 ? this.files[0].name : 'No file selected'; }); }
    setupFileInput('modFile', 'modFileName');
    setupFileInput('imageFile', 'imageFileName');

    const deleteButtons = document.querySelectorAll('.delete-btn');
    deleteButtons.forEach(button => { button.addEventListener('click', function(event) { event.preventDefault(); if (confirm('Are you sure you want to delete this mod?')) { const item = this.closest('.upload-item'); item.style.opacity = '0'; setTimeout(() => item.remove(), 500); } }); });

    const downloadButtonTab = document.querySelector('.download-button[href="#versions"]');
    if (downloadButtonTab) {
        downloadButtonTab.addEventListener('click', function(e) {
            e.preventDefault();
            const versionsTabButton = document.querySelector('.tab-button[data-tab="versions"]');
            if (versionsTabButton) versionsTabButton.click();
            document.querySelector('.details-panel')?.scrollIntoView({ behavior: 'smooth' });
        });
    }

    // --- 8. FAQ Accordion ---
    const faqItems = document.querySelectorAll('.faq-item');
    faqItems.forEach(item => {
        const question = item.querySelector('.faq-question');
        if (question) {
            question.addEventListener('click', () => {
                const isAlreadyActive = item.classList.contains('active');
                faqItems.forEach(i => i.classList.remove('active'));
                if (!isAlreadyActive) item.classList.add('active');
            });
        }
    });

    // Countdown timer for coming-soon.html
    const daysEl = document.getElementById('days');
    if (daysEl) {
        const countDownDate = new Date();
        countDownDate.setDate(countDownDate.getDate() + 30);
        const timer = setInterval(() => {
            const distance = countDownDate - new Date().getTime();
            if (distance < 0) { clearInterval(timer); document.getElementById('countdown').innerHTML = "<h2>We're Live!</h2>"; return; }
            document.getElementById('days').textContent = String(Math.floor(distance / (1000 * 60 * 60 * 24))).padStart(2, '0');
            document.getElementById('hours').textContent = String(Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60))).padStart(2, '0');
            document.getElementById('minutes').textContent = String(Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60))).padStart(2, '0');
            document.getElementById('seconds').textContent = String(Math.floor((distance % (1000 * 60)) / 1000)).padStart(2, '0');
        }, 1000);
    }
    const notifyForm = document.getElementById('notify-form');
    if (notifyForm) {
        notifyForm.addEventListener('submit', (e) => {
            e.preventDefault();
            alert('Thank you! You will be notified on launch.');
            notifyForm.reset();
        });
    }
});