import re

with open('c:/Users/bhatn/GPLMods/public/css/style.css', 'r', encoding='utf-8') as f:
    css = f.read()

pattern = re.compile(r'/\* --- Responsive Layout Adjustments --- \*/.*?/\* --- Optimized Sidebar Navigation --- \*/', re.DOTALL)
replacement = '''/* --- Responsive Layout Adjustments --- */
@media (max-width: 992px) {
    /* Tablet & Mobile View */
    .header-content {
        grid-template-columns: 1fr auto;
        grid-template-areas: 
            "logo actions"
            "search search";
    }
    
    .logo { grid-area: logo; }
    .header-right-actions { grid-area: actions; justify-content: flex-end; order: 3; flex-shrink: 0; }
    
    .search-bar { 
        grid-area: search; 
        max-width: 100%;
    }

    .policy-banner { flex-direction: row; justify-content: center; }
    .policy-buttons { margin-left: 20px; }
}

@media (min-width: 1024px) {
    /* Desktop View */
    .search-bar { flex-grow: 1; max-width: 500px; margin: 0 20px; }
    
    /* Reveal the text buttons next to the hamburger menu */
    .desktop-text-buttons {
        display: flex;
        align-items: center;
        gap: 10px;
    }
}

/* Add near .hamburger-menu rules */
.hamburger-menu.open {
  color: var(--gold);
  border: none !important;
  outline: none !important;
  background: transparent !important;
  box-shadow: none !important;
  transform: none !important;
  transition: color 0.2s ease;
}

/* --- New Header Mobile Actions --- */
.header-mobile-actions { display: flex; align-items: center; gap: 12px; order: 2; }

/* FIX: Strict sizing for the avatar to prevent blowout */
.avatar-placeholder {
    display: block; 
    width: 35px !important;
    height: 35px !important;
    min-width: 35px;
    min-height: 35px; 
    border: 2px solid var(--silver);
    background-color: var(--black);
    border-radius: 50%; 
    cursor: pointer; 
    text-decoration: none;
    overflow: hidden;
}

/* FIX: Ensure the image perfectly fills the container */
.avatar-placeholder img {
    width: 100% !important;
    height: 100% !important;
    object-fit: cover !important;
    display: block;
}

/* --- Optimized Sidebar Navigation --- */'''

css = pattern.sub(replacement, css)
with open('c:/Users/bhatn/GPLMods/public/css/style.css', 'w', encoding='utf-8') as f:
    f.write(css)
print('Fixed duplicate CSS!')
