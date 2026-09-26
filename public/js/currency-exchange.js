/**
 * GPL Mods - Global Dynamic Currency Exchange Engine
 * Supports INR (Base), USD, EUR, GBP, AED, CAD, AUD, JPY
 * Persists selection via localStorage ('gpl_currency')
 * Automatically converts all elements with [data-inr-price] or [data-base-inr]
 */
(function() {
    const RATES = {
        INR: 1.0,
        USD: 0.012,       // ~83.33 INR
        EUR: 0.011,       // ~90.90 INR
        GBP: 0.0094,      // ~106.38 INR
        AED: 0.044,       // ~22.72 INR
        CAD: 0.0163,      // ~61.34 INR
        AUD: 0.0182,      // ~54.94 INR
        JPY: 1.78         // ~0.56 INR
    };

    const SYMBOLS = {
        INR: '₹',
        USD: '$',
        EUR: '€',
        GBP: '£',
        AED: 'AED ',
        CAD: 'CA$',
        AUD: 'AU$',
        JPY: '¥'
    };

    const FORMATTERS = {
        INR: (val) => '₹' + Math.round(val).toLocaleString('en-IN'),
        USD: (val) => '$' + (val >= 10 ? Math.round(val) : val.toFixed(2)),
        EUR: (val) => '€' + (val >= 10 ? Math.round(val) : val.toFixed(2)),
        GBP: (val) => '£' + (val >= 10 ? Math.round(val) : val.toFixed(2)),
        AED: (val) => 'AED ' + Math.round(val).toLocaleString(),
        CAD: (val) => 'CA$' + (val >= 10 ? Math.round(val) : val.toFixed(2)),
        AUD: (val) => 'AU$' + (val >= 10 ? Math.round(val) : val.toFixed(2)),
        JPY: (val) => '¥' + Math.round(val).toLocaleString()
    };

    function getSavedCurrency() {
        try {
            return localStorage.getItem('gpl_currency') || 'INR';
        } catch (_) {
            return 'INR';
        }
    }

    function setSavedCurrency(code) {
        if (!RATES[code]) code = 'INR';
        try {
            localStorage.setItem('gpl_currency', code);
        } catch (_) {}
        updateUI(code);
        updatePagePrices(code);
        window.dispatchEvent(new CustomEvent('gplCurrencyChange', {
            detail: { currency: code, rate: RATES[code], symbol: SYMBOLS[code] }
        }));
    }

    function convertFromINR(inrAmount, targetCurrency) {
        const rate = RATES[targetCurrency] || 1.0;
        return inrAmount * rate;
    }

    function formatPrice(inrAmount, targetCurrency) {
        targetCurrency = targetCurrency || getSavedCurrency();
        const converted = convertFromINR(inrAmount, targetCurrency);
        const fmt = FORMATTERS[targetCurrency] || FORMATTERS.INR;
        return fmt(converted);
    }

    function updateUI(code) {
        const label = document.getElementById('active-currency-code');
        if (label) label.textContent = code;

        // Highlight active currency pills on payment pages
        document.querySelectorAll('.cur-pill-btn').forEach(btn => {
            if (btn.getAttribute('data-cur') === code) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });

        // Highlight active currency item in menu (if any)
        const menuItems = document.querySelectorAll('#currency-menu a[data-currency]');
        menuItems.forEach(item => {
            if (item.getAttribute('data-currency') === code) {
                item.style.backgroundColor = 'rgba(255, 215, 0, 0.15)';
                item.style.fontWeight = 'bold';
            } else {
                item.style.backgroundColor = 'transparent';
                item.style.fontWeight = 'normal';
            }
        });
    }

    function updatePagePrices(code) {
        const targetCurrency = code || getSavedCurrency();
        
        // Find all elements with data-inr-price
        document.querySelectorAll('[data-inr-price]').forEach(el => {
            const inr = parseFloat(el.getAttribute('data-inr-price'));
            if (isNaN(inr)) return;

            const formatted = formatPrice(inr, targetCurrency);
            el.textContent = formatted;
        });

        // Also check elements with class .currency-convertible
        document.querySelectorAll('.currency-convertible').forEach(el => {
            const inr = parseFloat(el.getAttribute('data-base-inr'));
            if (isNaN(inr)) return;
            el.textContent = formatPrice(inr, targetCurrency);
        });

        // Toggle or update USD secondary indicator if on non-INR currency
        document.querySelectorAll('.item-usd-sub').forEach(el => {
            if (targetCurrency !== 'INR') {
                el.style.display = 'none';
            } else {
                el.style.display = '';
            }
        });
    }

    function initCurrencySystem() {
        // Automatically bind click handlers for in-page currency pill buttons
        document.querySelectorAll('.cur-pill-btn[data-cur]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const selected = btn.getAttribute('data-cur');
                if (selected) setSavedCurrency(selected);
            });
        });

        const btn = document.getElementById('currency-btn');
        const menu = document.getElementById('currency-menu');

        if (btn && menu) {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                // Close lang menu if open
                const langMenu = document.getElementById('lang-menu');
                if (langMenu) langMenu.classList.remove('show');
                menu.classList.toggle('show');
            });

            document.addEventListener('click', (e) => {
                if (!btn.contains(e.target) && !menu.contains(e.target)) {
                    menu.classList.remove('show');
                }
            });

            menu.querySelectorAll('a[data-currency]').forEach(opt => {
                opt.addEventListener('click', (e) => {
                    e.preventDefault();
                    const selected = opt.getAttribute('data-currency');
                    setSavedCurrency(selected);
                    menu.classList.remove('show');
                });
            });
        }

        const active = getSavedCurrency();
        updateUI(active);
        updatePagePrices(active);
    }

    // Expose Global Helper
    window.GPLCurrency = {
        rates: RATES,
        symbols: SYMBOLS,
        convert: convertFromINR,
        format: formatPrice,
        getCurrency: getSavedCurrency,
        setCurrency: setSavedCurrency,
        updatePage: () => updatePagePrices(getSavedCurrency())
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initCurrencySystem);
    } else {
        initCurrencySystem();
    }
})();
