/**
 * Instance list event handlers
 * 
 * This module manages event handlers for the instance list partial
 * to comply with Content Security Policy by avoiding inline handlers
 */

// Initialize event handlers when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    initializeInstanceListHandlers();
});

// Also initialize when HTMX loads new content
document.addEventListener('htmx:afterSwap', function(event) {
    // Only initialize if the swapped content contains instance list elements
    if (event.detail.target.querySelector('#select-all-btn') || 
        event.detail.target.querySelector('#deselect-all-btn') ||
        event.detail.target.querySelector('#select-all-checkbox')) {
        initializeInstanceListHandlers();
    }
});

function initializeInstanceListHandlers() {
    // Select All button
    const selectAllBtn = document.getElementById('select-all-btn');
    if (selectAllBtn) {
        selectAllBtn.removeEventListener('click', handleSelectAll); // Remove any existing listener
        selectAllBtn.addEventListener('click', handleSelectAll);
    }
    
    // Deselect All button
    const deselectAllBtn = document.getElementById('deselect-all-btn');
    if (deselectAllBtn) {
        deselectAllBtn.removeEventListener('click', handleDeselectAll); // Remove any existing listener
        deselectAllBtn.addEventListener('click', handleDeselectAll);
    }
    
    // Select all checkbox
    const selectAllCheckbox = document.getElementById('select-all-checkbox');
    if (selectAllCheckbox) {
        selectAllCheckbox.removeEventListener('change', handleSelectAllCheckbox); // Remove any existing listener
        selectAllCheckbox.addEventListener('change', handleSelectAllCheckbox);
    }
}

function handleSelectAll(event) {
    event.preventDefault();
    if (typeof selectAllInstances === 'function') {
        selectAllInstances();
    }
}

function handleDeselectAll(event) {
    event.preventDefault();
    if (typeof deselectAllInstances === 'function') {
        deselectAllInstances();
    }
}

function handleSelectAllCheckbox(event) {
    if (event.target.checked) {
        if (typeof selectAllInstances === 'function') {
            selectAllInstances();
        }
    } else {
        if (typeof deselectAllInstances === 'function') {
            deselectAllInstances();
        }
    }
}