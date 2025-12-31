/**
 * Shared JavaScript Utilities
 * Common functions used across multiple scripts in the application
 */

/**
 * Escape HTML special characters to prevent XSS
 * @param {string} text - The text to escape
 * @returns {string} Escaped HTML text
 */
function escapeHtml(text) {
    if (typeof text !== 'string') {
        return '';
    }
    
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Get a cookie value by name with proper decoding
 * @param {string} name - The cookie name to look for
 * @returns {string|null} Cookie value or null if not found
 */
function getCookieValue(name) {
    const nameEQ = name + "=";
    const ca = document.cookie.split(';');
    for(let i = 0; i < ca.length; i++) {
        let c = ca[i];
        while (c.charAt(0) === ' ') {
            c = c.substring(1, c.length);
        }
        if (c.indexOf(nameEQ) === 0) {
            return decodeURIComponent(c.substring(nameEQ.length, c.length));
        }
    }
    return null;
}

/**
 * Robust CSRF token retrieval with multiple fallback methods
 * @returns {string|null} CSRF token or null if not found
 */
function getCsrfToken() {
    // Common CSRF token cookie/field names to check
    const tokenNames = ['csrftoken', 'csrf_token', 'csrf-token', 'csrfToken', 'csrf'];
    
    // Try to get from meta tag first
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    if (metaTag) {
        return metaTag.content;
    }
    
    // Try to get from cookies using helper function
    for (let tokenName of tokenNames) {
        const value = getCookieValue(tokenName);
        if (value) return value;
    }
    
    // Try to get from form input fields as fallback
    const inputSelectors = [
        'input[name="csrfmiddlewaretoken"]',
        'input[name="csrf_token"]',
        'input[name="csrf-token"]',
        'input[name="csrfToken"]',
        'input[name="csrf"]'
    ];
    
    for (let selector of inputSelectors) {
        const input = document.querySelector(selector);
        if (input && input.value) {
            return input.value;
        }
    }
    
    return null;
}

/**
 * Build CSRF headers for HTTP requests
 * @returns {Object} Headers object with CSRF token if available
 */
function buildCsrfHeaders() {
    const csrfToken = getCsrfToken();
    if (csrfToken) {
        return { 'X-CSRFToken': csrfToken };
    }
    return {};
}

/**
 * Enhanced input sanitization and validation
 * @param {string} value - The value to sanitize
 * @param {string} type - The type of validation to apply
 * @param {number} maxLength - Maximum length (default 100)
 * @returns {string} Sanitized value
 * @throws {Error} If validation fails
 */
function sanitizeInput(value, type, maxLength = 100) {
    if (typeof value !== 'string') {
        value = String(value);
    }
    
    // Remove control characters and trim
    value = value.replace(/[\x00-\x1F\x7F]/g, '').trim();
    
    // Apply length limit
    if (value.length > maxLength) {
        value = value.substring(0, maxLength);
    }
    
    // Type-specific validation
    switch(type) {
        case 'instance_id':
            // AWS instance IDs: i-xxxxxxxx or i-xxxxxxxxxxxxxxxxx (canonicalized to lowercase)
            if (!/^i-[a-fA-F0-9]{8,17}$/.test(value)) {
                throw new Error('Invalid instance ID format (expected i-xxxxxxxx or i-xxxxxxxxxxxxxxxxx)');
            }
            value = value.toLowerCase();
            break;
            
        case 'account_id':
            // AWS account IDs: 12 digits
            if (!/^\d{12}$/.test(value)) {
                throw new Error('Invalid account ID (must be 12 digits)');
            }
            break;
            
        case 'region':
            // AWS regions: us-east-1, eu-west-2, us-gov-east-1, us-iso-east-1, etc.
            value = value.toLowerCase().trim();
            
            // More specific validation for AWS region format
            // Standard regions: us-east-1, eu-west-2
            // Special regions: us-gov-west-1, us-iso-east-1, us-isob-east-1
            if (!/^(?:[a-z]{2,}-[a-z]+-\d+|[a-z]{2,}-[a-z]+-[a-z]+-\d+)$/.test(value)) {
                throw new Error('Invalid AWS region format');
            }
            break;
            
        case 'platform':
            // Platform: limited set of values
            const validPlatforms = ['windows', 'linux', 'amazon-linux', 'ubuntu', 'rhel', 'centos'];
            if (!validPlatforms.includes(value.toLowerCase())) {
                throw new Error('Invalid platform');
            }
            value = value.toLowerCase();
            break;
            
        case 'change_number':
            // Change number: alphanumeric with dashes/underscores
            if (!/^[A-Za-z0-9_-]{1,50}$/.test(value)) {
                throw new Error('Invalid change number format');
            }
            break;
    }
    
    return value;
}

/**
 * Create a polling function with exponential backoff
 * @param {Function} pollFunction - The function to call for each poll
 * @param {Object} options - Polling configuration options
 * @returns {Object} Object with start() and stop() methods
 */
function createPolling(pollFunction, options = {}) {
    const config = {
        initialInterval: options.initialInterval || 5000,  // Start with 5 seconds
        maxInterval: options.maxInterval || 30000,        // Max 30 seconds
        backoffMultiplier: options.backoffMultiplier || 1.5,
        maxPolls: options.maxPolls || 120,                // Max polls before giving up
        ...options
    };
    
    let currentInterval = config.initialInterval;
    let pollCount = 0;
    let timeoutId = null;
    let isRunning = false;
    
    const resetInterval = () => {
        currentInterval = config.initialInterval;
    };
    
    const increaseInterval = () => {
        currentInterval = Math.min(currentInterval * config.backoffMultiplier, config.maxInterval);
    };
    
    const executePoll = async () => {
        if (!isRunning) return;
        
        pollCount++;
        
        try {
            const result = await pollFunction(pollCount);
            
            // Check if polling should continue
            if (result && result.continue === false) {
                stop();
                return;
            }
            
            // Check max polls limit
            if (pollCount >= config.maxPolls) {
                stop();
                if (config.onMaxPollsReached) {
                    config.onMaxPollsReached();
                }
                return;
            }
            
            // Schedule next poll
            if (isRunning) {
                // Reset interval on success, increase on continuation
                if (result && result.completed) {
                    resetInterval();
                } else {
                    increaseInterval();
                }
                
                timeoutId = setTimeout(executePoll, currentInterval);
            }
            
        } catch (error) {
            console.error('Polling error:', error);
            
            // Increase interval on error and continue if under limit
            if (pollCount < config.maxPolls && isRunning) {
                increaseInterval();
                timeoutId = setTimeout(executePoll, currentInterval);
            } else {
                stop();
                if (config.onError) {
                    config.onError(error);
                }
            }
        }
    };
    
    const start = () => {
        if (isRunning) return;
        
        isRunning = true;
        pollCount = 0;
        currentInterval = config.initialInterval;
        timeoutId = setTimeout(executePoll, currentInterval);
    };
    
    const stop = () => {
        isRunning = false;
        if (timeoutId) {
            clearTimeout(timeoutId);
            timeoutId = null;
        }
    };
    
    return {
        start,
        stop,
        isRunning: () => isRunning,
        getPollCount: () => pollCount,
        getCurrentInterval: () => currentInterval
    };
}

/**
 * Show a toast notification (assumes showToast function is available globally)
 * @param {string} message - The message to display
 * @param {string} type - The type of toast (success, danger, warning, info)
 */
function showToastSafe(message, type = 'info') {
    if (typeof window.showToast === 'function') {
        window.showToast(message, type);
    } else {
        console.log(`[${type.toUpperCase()}] ${message}`);
    }
}

// Export functions for module systems or global scope
if (typeof module !== 'undefined' && module.exports) {
    // Node.js/CommonJS
    module.exports = {
        escapeHtml,
        getCookieValue,
        getCsrfToken,
        buildCsrfHeaders,
        sanitizeInput,
        createPolling,
        showToastSafe
    };
} else {
    // Browser global scope
    window.Utils = {
        escapeHtml,
        getCookieValue,
        getCsrfToken,
        buildCsrfHeaders,
        sanitizeInput,
        createPolling,
        showToastSafe
    };
}