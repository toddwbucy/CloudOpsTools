/**
 * CloudOpsTools Theme Switcher
 * Handles light/dark theme toggle with localStorage persistence
 */
(function() {
    'use strict';

    // Constants
    const THEME_KEY = 'cloudopstools-theme';
    const DARK_THEME = 'dark';
    const LIGHT_THEME = 'light';

    /**
     * Get the saved theme from localStorage or default to dark
     * @returns {string} The theme name ('dark' or 'light')
     */
    function getSavedTheme() {
        const savedTheme = localStorage.getItem(THEME_KEY);
        if (savedTheme === LIGHT_THEME || savedTheme === DARK_THEME) {
            return savedTheme;
        }
        // Default to dark theme if no preference or invalid value
        return DARK_THEME;
    }

    /**
     * Save theme to localStorage
     * @param {string} theme - The theme to save ('dark' or 'light')
     */
    function saveTheme(theme) {
        localStorage.setItem(THEME_KEY, theme);
    }

    /**
     * Apply the theme to the document
     * @param {string} theme - The theme to apply ('dark' or 'light')
     */
    function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        updateToggleButton(theme);
    }

    /**
     * Update the toggle button appearance based on current theme
     * @param {string} theme - The current theme ('dark' or 'light')
     */
    function updateToggleButton(theme) {
        const toggleButton = document.getElementById('theme-toggle');
        const themeIcon = document.getElementById('theme-icon');
        const themeText = toggleButton ? toggleButton.querySelector('.theme-text') : null;

        if (!toggleButton || !themeIcon) {
            return;
        }

        if (theme === DARK_THEME) {
            // Currently dark, show option to switch to light
            themeIcon.className = 'bi bi-moon-stars-fill';
            if (themeText) {
                themeText.textContent = 'Light Mode';
            }
            toggleButton.setAttribute('aria-checked', 'true');
            toggleButton.setAttribute('aria-label', 'Toggle theme, currently Dark Mode');
        } else {
            // Currently light, show option to switch to dark
            themeIcon.className = 'bi bi-sun-fill';
            if (themeText) {
                themeText.textContent = 'Dark Mode';
            }
            toggleButton.setAttribute('aria-checked', 'false');
            toggleButton.setAttribute('aria-label', 'Toggle theme, currently Light Mode');
        }
    }

    /**
     * Toggle between light and dark themes
     */
    function toggleTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme') || DARK_THEME;
        const newTheme = currentTheme === DARK_THEME ? LIGHT_THEME : DARK_THEME;

        applyTheme(newTheme);
        saveTheme(newTheme);
    }

    /**
     * Initialize the theme switcher
     */
    function init() {
        // Apply saved theme immediately
        const savedTheme = getSavedTheme();
        applyTheme(savedTheme);

        // Set up event listener for theme toggle button
        const toggleButton = document.getElementById('theme-toggle');
        if (toggleButton) {
            toggleButton.addEventListener('click', function(e) {
                e.preventDefault();
                toggleTheme();
            });
        }
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
