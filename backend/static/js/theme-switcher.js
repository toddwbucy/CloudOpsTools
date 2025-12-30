/**
 * PCM-Ops Tools Theme Switcher
 * 
 * Handles light/dark theme switching with localStorage persistence
 * Professional Fusion Dark Mode as default theme
 */

class ThemeSwitcher {
    constructor() {
        this.currentTheme = this.getStoredTheme() || 'dark'; // Default to dark mode
        this.init();
    }

    init() {
        this.applyTheme(this.currentTheme);
        this.setupEventListeners();
        this.updateThemeToggleIcon();
    }

    getStoredTheme() {
        try {
            return localStorage.getItem('pcm-ops-theme');
        } catch (error) {
            console.warn('localStorage not available, using default theme');
            return null;
        }
    }

    setStoredTheme(theme) {
        try {
            localStorage.setItem('pcm-ops-theme', theme);
        } catch (error) {
            console.warn('localStorage not available, theme preference not saved');
        }
    }

    applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        this.currentTheme = theme;
        this.setStoredTheme(theme);
        
        // Add fade-in animation to body for smooth transition
        document.body.classList.add('fade-in-theme');
        setTimeout(() => {
            document.body.classList.remove('fade-in-theme');
        }, 300);

        // Dispatch custom event for other components to listen
        document.dispatchEvent(new CustomEvent('themeChanged', {
            detail: { theme }
        }));
    }

    toggleTheme() {
        const newTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
        this.applyTheme(newTheme);
        this.updateThemeToggleIcon();
    }

    updateThemeToggleIcon() {
        const toggleButton = document.getElementById('theme-toggle');
        if (toggleButton) {
            const icon = toggleButton.querySelector('#theme-icon');
            const text = toggleButton.querySelector('.theme-text');
            
            if (icon && text) {
                if (this.currentTheme === 'dark') {
                    // Currently dark theme, show light mode option
                    icon.className = 'bi bi-sun-fill';
                    text.textContent = 'Light Mode';
                    toggleButton.title = 'Switch to light mode';
                    toggleButton.setAttribute('aria-label', 'Toggle theme, currently Dark Mode');
                    toggleButton.setAttribute('aria-checked', 'true');
                } else {
                    // Currently light theme, show dark mode option
                    icon.className = 'bi bi-moon-stars-fill';
                    text.textContent = 'Dark Mode';
                    toggleButton.title = 'Switch to dark mode';
                    toggleButton.setAttribute('aria-label', 'Toggle theme, currently Light Mode');
                    toggleButton.setAttribute('aria-checked', 'false');
                }
            }
        }
    }

    setupEventListeners() {
        // Theme toggle button click handler
        document.addEventListener('click', (e) => {
            if (e.target.closest('#theme-toggle')) {
                e.preventDefault();
                this.toggleTheme();
            }
        });

        // Listen for system theme changes (optional feature)
        if (window.matchMedia) {
            const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
            mediaQuery.addListener((e) => {
                // Only auto-switch if user hasn't manually set a preference
                if (!this.getStoredTheme()) {
                    this.applyTheme(e.matches ? 'dark' : 'light');
                    this.updateThemeToggleIcon();
                }
            });
        }

        // Keyboard shortcut (Ctrl/Cmd + Shift + T)
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'T') {
                e.preventDefault();
                this.toggleTheme();
            }
        });
    }

    getCurrentTheme() {
        return this.currentTheme;
    }

    // Method to set theme programmatically
    setTheme(theme) {
        if (['light', 'dark'].includes(theme)) {
            this.applyTheme(theme);
            this.updateThemeToggleIcon();
        }
    }
}

// Theme-aware utility functions
const ThemeUtils = {
    // Get theme-appropriate color value
    getThemeColor(lightColor, darkColor) {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
        return currentTheme === 'dark' ? darkColor : lightColor;
    },

    // Check if current theme is dark
    isDarkTheme() {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
        return currentTheme === 'dark';
    },

    // Apply theme-specific styling to dynamic elements
    applyThemeToElement(element, darkStyles = {}, lightStyles = {}) {
        const isDark = this.isDarkTheme();
        const styles = isDark ? darkStyles : lightStyles;
        
        Object.keys(styles).forEach(property => {
            element.style[property] = styles[property];
        });
    }
};

// Initialize theme switcher when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.themeSwitcher = new ThemeSwitcher();
    
    // Add smooth transitions to all elements
    document.body.style.transition = 'background-color 0.3s ease, color 0.3s ease';
    
    // Initialize theme-aware components
    initializeThemeAwareComponents();
});

// Initialize components that need theme awareness
function initializeThemeAwareComponents() {
    // Update chart colors if charts exist
    document.addEventListener('themeChanged', function(e) {
        const theme = e.detail.theme;
        
        // Update any existing charts or dynamic components
        updateChartsTheme(theme);
        updateStatusIndicators(theme);
        updateToastThemes(theme);
    });
}

// Update chart themes (for future chart implementations)
function updateChartsTheme(theme) {
    // Placeholder for chart theme updates
    console.log(`Charts updated for ${theme} theme`);
}

// Update status indicators
function updateStatusIndicators(theme) {
    const statusElements = document.querySelectorAll('.status-indicator, .status-item');
    statusElements.forEach(element => {
        element.classList.add('fade-in-theme');
        setTimeout(() => {
            element.classList.remove('fade-in-theme');
        }, 200);
    });
}

// Update toast themes
function updateToastThemes(theme) {
    const toasts = document.querySelectorAll('.toast');
    toasts.forEach(toast => {
        // Toast styling is handled by CSS variables, this just triggers animations
        toast.classList.add('fade-in-theme');
        setTimeout(() => {
            toast.classList.remove('fade-in-theme');
        }, 200);
    });
}

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { ThemeSwitcher, ThemeUtils };
}

// Global theme utilities for inline scripts
window.ThemeUtils = ThemeUtils;