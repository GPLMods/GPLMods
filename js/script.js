/* ===================================================================
   TABLE OF CONTENTS
   ===================================================================
   1.  Global DOMContentLoaded Wrapper
   2.  Mobile Menu & Sidebar Accordion
   3.  Animated Search Bar Placeholder
   4.  Back to Top Button & Conditional Banner
   5.  Advanced Tab Navigation (Homepage & Mod Pages)
   6.  Login/Sign-Up Modal Logic
   7.  FORM FUNCTIONALITY & HELPERS
       - Form Submissions (Simulations for Login, Profile, etc.)
       - **NEW:** Real Mod Upload Form Logic (Async/Fetch)
       - Live Avatar Preview
       - Upload Page Dynamic Categories & File Name Display
       - Delete Item Confirmation
       - Download Button Tab Link
   8.  FAQ Accordion
   9.  Special Page Scripts (Countdown Timer)
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
                isDeleting = true; typeSpeed = 1500;
            } else if (isDeleting && letterIndex === 0) {
                isDeleting = false;
                termIndex = (termIndex + 1) % searchTerms.length;
                searchInput.style.setProperty('--placeholder-color', themeColors[termIndex % themeColors.length]);
                typeSpeed = 300;
            }
            typingTimeout = setTimeout(typeAnimation, typeSpeed);
        }
        typeAnimation();

        searchInput.addEventListener('focus', () => { clearTimeout(typingTimeout); searchInput.placeholder = "Search for mods..."; });
        searchInput.addEventListener('blur', () => { if (searchInput.value === '') { searchInput.placeholder = ""; letterIndex = 0; isDeleting = false; typeAnimation(); } });
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
    function initializeTabs(navElement, highlightElement) {
        if (!navElement || !highlightElement) return;
        const tabButtons = navElement.querySelectorAll('.tab-button');
        const moveHighlight = (targetTab) => {
            if (!targetTab) return;
            const navRect = navElement.getBoundingClientRect();
            const targetRect = targetTab.getBoundingClientRect();
            highlightElement.style.width = `${targetRect.width}px`;
            highlightElement.style.transform = `translateX(${targetRect.left - navRect.left + navElement.scrollLeft}px)`;
        };
        tabButtons.forEach(button => {
            button.addEventListener('click', () => moveHighlight(button));
        });
        window.addEventListener('resize', () => moveHighlight(navElement.querySelector('.tab-button.active')));
        const activeTab = navElement.querySelector('.tab-button.active');
        if (activeTab) setTimeout(() => moveHighlight(activeTab), 150);
    }
    const mainTabNav = document.getElementById('main-tabs-nav');
    const mainTabHighlight = document.getElementById('main-tab-highlight');
    if (mainTabNav) {
        initializeTabs(mainTabNav, mainTabHighlight);
        mainTabNav.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', () => {
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                const targetTabId = button.dataset.tab;
                const iosSubTabs = document.getElementById('ios-sub-tabs-container');
                if (targetTabId === 'ios') {
                    if (iosSubTabs) {
                        iosSubTabs.style.display = 'block';
                        document.querySelector('#ios-tabs-nav .tab-button')?.click();
                    }
                } else {
                    if (iosSubTabs) iosSubTabs.style.display = 'none';
                    document.getElementById(targetTabId + '-mods')?.classList.add('active');
                }
            });
        });
    }
    const iosTabNav = document.getElementById('ios-tabs-nav');
    const iosTabHighlight = document.getElementById('ios-tab-highlight');
    if (iosTabNav) {
        initializeTabs(iosTabNav, iosTabHighlight);
        iosTabNav.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', () => {
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                document.getElementById(button.dataset.tab + '-mods')?.classList.add('active');
            });
        });
    }
    
    // For mod detail pages
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

    // --- 6. Login/Sign-Up Modal Logic ---
    const loginModal = document.getElementById('loginModal');
    const signupModal = document.getElementById('signupModal');
    const showModal = (modal) => modal?.classList.add('visible');
    const hideModal = (modal) => modal?.classList.remove('visible');
    document.querySelectorAll('#loginBtnHeader, #loginBtnMobile').forEach(btn => btn.addEventListener('click', (e) => { e.preventDefault(); showModal(loginModal); }));
    document.querySelectorAll('#signupBtnHeader, #signupBtnMobile').forEach(btn => btn.addEventListener('click', (e) => { e.preventDefault(); showModal(signupModal); }));
    document.querySelectorAll('#loginModalClose, #signupModalClose').forEach(btn => btn.addEventListener('click', () => { hideModal(loginModal); hideModal(signupModal); }));
    [loginModal, signupModal].forEach(modal => modal?.addEventListener('click', (e) => { if (e.target === modal) hideModal(modal); }));
    document.getElementById('switchToSignup')?.addEventListener('click', (e) => { e.preventDefault(); hideModal(loginModal); showModal(signupModal); });
    document.getElementById('switchToLogin')?.addEventListener('click', (e) => { e.preventDefault(); hideModal(signupModal); showModal(loginModal); });

    // --- 7. FORM FUNCTIONALITY & HELPERS ---
    const loginForm = document.getElementById('login-form') || document.getElementById('loginForm');
    if (loginForm) loginForm.addEventListener('submit', (e) => { e.preventDefault(); alert('Login successful! (Simulation)'); if(loginModal) {hideModal(loginModal); loginForm.reset();} else { window.location.href = 'index.html'; } });
    
    const signupForm = document.getElementById('signup-form') || document.getElementById('signupForm');
    if (signupForm) signupForm.addEventListener('submit', (e) => { e.preventDefault(); alert('Account created successfully!'); if(signupModal) {hideModal(signupModal); signupForm.reset();} else { window.location.href = 'login.html'; } });
    
    document.getElementById('profile-details-form')?.addEventListener('submit', (e) => { e.preventDefault(); alert('Profile details updated successfully!'); });
    document.getElementById('password-change-form')?.addEventListener('submit', (e) => { e.preventDefault(); alert('Password changed successfully!'); e.target.reset(); });
    document.getElementById('delete-account-btn')?.addEventListener('click', () => { if (confirm('Are you sure you want to permanently delete your account?')) alert('Account deleted.'); });
    
    // --- **NEW** Mod Upload Page Form Logic ---
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
            // Example of adding other form data:
            // formData.append('modName', document.getElementById('modName').value);
            try {
                // IMPORTANT: '/scan-file' is a placeholder. You need a real server endpoint here.
                const response = await fetch('/scan-file', { method: 'POST', body: formData });
                const result = await response.json();
                if (!response.ok) {
                    alert(`Error: ${result.message}`);
                } else {
                    alert(`Success: ${result.message}`);
                    modForm.reset();
                    // Reset UI elements after successful upload
                    document.getElementById('modFileName').textContent = 'No file selected';
                    document.getElementById('imageFileName').textContent = 'No file selected';
                    const categorySelect = document.getElementById('modCategory');
                    if (categorySelect) {
                       categorySelect.innerHTML = '<option value="" disabled selected>Select a platform first...</option>';
                       categorySelect.disabled = true;
                    }
                }
            } catch (error) {
                console.error('Upload failed:', error);
                alert('File upload failed. This is a frontend demonstration. Please check the console for details.');
            }
        });
    }

    const avatarInput = document.getElementById('avatar-input');
    const avatarPreview = document.getElementById('avatar-preview');
    if (avatarInput) {
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
    if (platformSelect && categorySelect) {
        const categoriesByPlatform = { android: ['Game', 'App', 'Tools'], 'ios-jailed': ['Game', 'App'], 'ios-jailbroken': ['Tweak', 'Theme', 'Utility'], windows: ['Game', 'Software'], wordpress: ['Plugin', 'Theme'] };
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
            input.addEventListener('change', function() { display.textContent = this.files.length > 0 ? this.files[0].name : 'No file selected'; });
        }
    }
    setupFileInput('modFile', 'modFileName');
    setupFileInput('imageFile', 'imageFileName');

    const deleteButtons = document.querySelectorAll('.delete-btn');
    deleteButtons.forEach(button => { button.addEventListener('click', function(event) { event.preventDefault(); if (confirm('Are you sure you want to delete this?')) { this.closest('.upload-item')?.remove(); alert('Item deleted.'); } }); });
    
    document.querySelector('.download-button[href="#versions"]')?.addEventListener('click', (e) => { e.preventDefault(); document.querySelector('.tab-button[data-tab="versions"]')?.click(); document.querySelector('.details-panel')?.scrollIntoView({ behavior: 'smooth' }); });

    // --- 8. FAQ Accordion ---
    const faqItems = document.querySelectorAll('.faq-item');
    faqItems.forEach(item => { item.querySelector('.faq-question')?.addEventListener('click', () => { const active = item.classList.contains('active'); faqItems.forEach(i => i.classList.remove('active')); if (!active) item.classList.add('active'); }); });
    
    // --- 9. Special Page Scripts (Countdown) ---
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
    document.getElementById('notify-form')?.addEventListener('submit', (e) => { e.preventDefault(); alert('Thank you! You will be notified on launch.'); e.target.reset(); });
});