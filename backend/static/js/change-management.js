// Change Management JavaScript Module
(function() {
    'use strict';

    // Constants
    const RELOAD_DELAY_MS = 500; // Delay before page reload for UI updates

    // Region to environment mapping
    const REGION_ENVIRONMENT_MAP = {
        // US GovCloud regions
        'us-gov-east-1': 'gov',
        'us-gov-west-1': 'gov',
        // Default to checking if region contains 'gov' as fallback
        // All other regions default to 'com'
    };

    // Helper function to determine environment from region
    function getEnvironmentFromRegion(region) {
        const normalizedRegion = region.toLowerCase().trim();
        
        // Check explicit mapping first
        if (REGION_ENVIRONMENT_MAP[normalizedRegion]) {
            return REGION_ENVIRONMENT_MAP[normalizedRegion];
        }
        
        // Fallback: check if region contains 'gov', 'iso', or 'isob'
        // These all use the 'gov' environment for authentication
        if (normalizedRegion.includes('gov') || 
            normalizedRegion.includes('iso') || 
            normalizedRegion.includes('isob')) {
            return 'gov';
        }
        
        // Default to commercial environment
        return 'com';
    }

    // Track manually added instances
    let manualInstances = [];

    // Tool-specific endpoint base URL (will be set by init function)
    let toolEndpoint = '/aws/script-runner'; // Default fallback

    // Use shared utilities (escapeHtml, getCsrfToken, buildCsrfHeaders)
    // These are available from utils.js via window.Utils

    // Initialize the module with tool-specific endpoint
    function initChangeManagement(endpoint) {
        if (endpoint) {
            toolEndpoint = endpoint;
        }
    }

    // Load selected change from dropdown
    async function loadSelectedChange() {
        const changeId = document.getElementById('change-select').value;
        if (!changeId) {
            showToast('Please select a change first', 'warning');
            return;
        }
        
        await loadChange(changeId);
    }

    // Load a change
    async function loadChange(changeId) {
        if (!changeId) return;
        
        try {
            const headers = window.Utils.buildCsrfHeaders();
            // Add cache-busting parameter
            const cacheBuster = `?t=${Date.now()}`;
            
            const response = await fetch(`${toolEndpoint}/load-change/${changeId}${cacheBuster}`, {
                method: 'POST',
                headers: headers,
                credentials: 'same-origin',
                cache: 'no-cache'
            });
            
            if (response.ok) {
                showToast('Change loaded successfully', 'success');
                // Refresh change list instead of full page reload
                await refreshChangeList();
                
                // Reload page to refresh the UI with the loaded change
                // This is needed for tools that haven't implemented partial updates
                setTimeout(() => {
                    window.location.reload();
                }, RELOAD_DELAY_MS);
            } else {
                showToast('Failed to load change', 'danger');
            }
        } catch (error) {
            console.error('Error loading change:', error);
            showToast('Error loading change', 'danger');
        }
    }

    // Refresh change list
    async function refreshChangeList() {
        try {
            // Add cache-busting parameter
            const cacheBuster = `?t=${Date.now()}`;
            const response = await fetch(`${toolEndpoint}/list-changes${cacheBuster}`, {
                credentials: 'same-origin',
                cache: 'no-cache'
            });
            
            if (response.ok) {
                const changes = await response.json();
                const select = document.getElementById('change-select');
                select.innerHTML = '<option value="">Select a change...</option>';
                
                changes.forEach(change => {
                    const option = document.createElement('option');
                    option.value = change.id;
                    option.textContent = `${change.change_number} - ${change.instance_count} instances`;
                    select.appendChild(option);
                });
                
                showToast('Change list refreshed', 'success');
            }
        } catch (error) {
            console.error('Error refreshing changes:', error);
            showToast('Error refreshing change list', 'danger');
        }
    }

    // Use shared sanitizeInput from utils.js

    // Add manual instance
    function addManualInstance() {
        const changeNumber = document.getElementById('manual-change-number').value.trim();
        const instanceId = document.getElementById('manual-instance-id').value.trim();
        const accountId = document.getElementById('manual-account-id').value.trim();
        const region = document.getElementById('manual-region').value;
        const platform = document.getElementById('manual-platform').value;
        
        // Validation
        if (!changeNumber) {
            showToast('Please enter a change number first', 'warning');
            return;
        }
        
        if (!instanceId || !accountId || !region || !platform) {
            showToast('Please fill all instance fields', 'warning');
            return;
        }
        
        try {
            // Sanitize and validate all inputs
            const sanitizedChangeNumber = window.Utils.sanitizeInput(changeNumber, 'change_number');
            const sanitizedInstanceId = window.Utils.sanitizeInput(instanceId, 'instance_id');
            const sanitizedAccountId = window.Utils.sanitizeInput(accountId, 'account_id');
            const sanitizedRegion = window.Utils.sanitizeInput(region, 'region');
            const sanitizedPlatform = window.Utils.sanitizeInput(platform, 'platform');
            
            // Add to array with sanitized values
            manualInstances.push({
                instance_id: sanitizedInstanceId,
                account_id: sanitizedAccountId,
                region: sanitizedRegion,
                platform: sanitizedPlatform,
                environment: getEnvironmentFromRegion(sanitizedRegion)
            });
        } catch (error) {
            showToast('Validation error: ' + error.message, 'danger');
            return;
        }
        
        // Clear instance fields
        document.getElementById('manual-instance-id').value = '';
        document.getElementById('manual-account-id').value = '';
        document.getElementById('manual-region').value = '';
        document.getElementById('manual-platform').value = '';
        
        // Update preview
        updateManualInstancesPreview();
        
        // Enable save button
        document.getElementById('save-manual-change-btn').disabled = false;
    }

    // Update manual instances preview
    function updateManualInstancesPreview() {
        const preview = document.getElementById('manual-instances-preview');
        const list = document.getElementById('manual-instances-list');
        
        if (manualInstances.length === 0) {
            preview.style.display = 'none';
            return;
        }
        
        preview.style.display = 'block';
        list.innerHTML = manualInstances.map((inst, idx) => `
            <div class="list-group-item d-flex justify-content-between align-items-center py-1">
                <div>
                    <small>
                        <strong>${window.Utils.escapeHtml(inst.instance_id)}</strong><br>
                        ${window.Utils.escapeHtml(inst.account_id)} | ${window.Utils.escapeHtml(inst.region)} | ${window.Utils.escapeHtml(inst.platform)}
                    </small>
                </div>
                <button type="button" class="btn btn-sm btn-danger" onclick="removeManualInstance(${idx})">
                    <i class="bi bi-x"></i>
                </button>
            </div>
        `).join('');
    }

    // Remove manual instance
    function removeManualInstance(index) {
        manualInstances.splice(index, 1);
        updateManualInstancesPreview();
        if (manualInstances.length === 0) {
            document.getElementById('save-manual-change-btn').disabled = true;
        }
    }

    // Save manual change
    async function saveManualChange() {
        const changeNumber = document.getElementById('manual-change-number').value.trim();
        const description = document.getElementById('manual-change-description').value.trim();
        
        if (!changeNumber || manualInstances.length === 0) {
            showToast('Please enter change number and add instances', 'warning');
            return;
        }
        
        try {
            const formData = new FormData();
            formData.append('change_number', changeNumber);
            formData.append('description', description);
            formData.append('instances', JSON.stringify(manualInstances));
            
            const headers = window.Utils.buildCsrfHeaders();
            
            const response = await fetch(`${toolEndpoint}/save-change-with-instances`, {
                method: 'POST',
                headers: headers,
                body: formData,
                credentials: 'same-origin'
            });
            
            if (response.ok) {
                try {
                    // Parse response JSON once and handle any JSON errors
                    const responseData = await response.json();
                    
                    // Clear form
                    document.getElementById('manual-change-number').value = '';
                    document.getElementById('manual-change-description').value = '';
                    manualInstances = [];
                    updateManualInstancesPreview();
                    document.getElementById('save-manual-change-btn').disabled = true;
                    
                    showToast('Change saved successfully', 'success');
                    
                    // Refresh the change list instead of reloading the page
                    await refreshChangeList();
                    
                    // Auto-select the newly created change
                    if (responseData.change_id) {
                        const select = document.getElementById('change-select');
                        if (select) {
                            select.value = responseData.change_id;
                            // Trigger change event to update any dependent UI
                            select.dispatchEvent(new Event('change', { bubbles: true }));
                        }
                        
                        // Since the change is automatically loaded on the backend,
                        // show confirmation message but don't auto-reload
                        showToast('Change saved and loaded! Refresh the page to see updated UI.', 'success');
                    }
                } catch (jsonError) {
                    console.error('Error parsing save response:', jsonError);
                    showToast('Change may have been saved, but there was an error processing the response', 'warning');
                    // Still refresh the change list in case the save worked
                    await refreshChangeList();
                }
            } else {
                // Handle non-OK response
                try {
                    const errorData = await response.json();
                    showToast('Failed to save change: ' + (errorData.detail || response.statusText), 'danger');
                } catch (jsonError) {
                    showToast('Failed to save change: ' + response.statusText, 'danger');
                }
            }
        } catch (error) {
            showToast('Error saving change: ' + error.message, 'danger');
        }
    }

    // Clear change
    async function clearChange() {
        if (!confirm('Clear the current change?')) return;
        
        try {
            const headers = window.Utils.buildCsrfHeaders();
            
            const response = await fetch(`${toolEndpoint}/clear-change`, {
                method: 'POST',
                headers: headers,
                credentials: 'same-origin'
            });
            
            if (response.ok) {
                showToast('Change cleared', 'info');
                setTimeout(() => {
                    window.location.reload();
                }, RELOAD_DELAY_MS);
            }
        } catch (error) {
            showToast('Error clearing change: ' + error.message, 'danger');
        }
    }

    // CSV file validation function
    function validateCSVFile(file) {
        // Validate file type
        if (!file.name.toLowerCase().endsWith('.csv')) {
            return { valid: false, error: 'Please select a CSV file (must end with .csv)' };
        }
        
        // Validate file size (10MB limit)
        const maxSize = 10 * 1024 * 1024; // 10MB
        if (file.size > maxSize) {
            return { valid: false, error: 'File size exceeds 10MB limit' };
        }
        
        // Validate minimum file size (should have at least a header)
        if (file.size < 10) {
            return { valid: false, error: 'File appears to be empty or too small' };
        }
        
        return { valid: true };
    }

    // Initialize CSV upload handler
    function initCSVUpload() {
        const uploadForm = document.getElementById('change-csv-upload-form');
        if (uploadForm) {
            uploadForm.addEventListener('submit', async function(e) {
                e.preventDefault();
                
                const fileInput = document.getElementById('change-csv-file');
                const file = fileInput.files[0];
                
                // Validate file before uploading
                if (!file) {
                    showToast('Please select a file to upload', 'warning');
                    return;
                }
                
                const validation = validateCSVFile(file);
                if (!validation.valid) {
                    showToast(validation.error, 'danger');
                    return;
                }
                
                const formData = new FormData(this);
                
                // Store original button text before try block
                const submitBtn = uploadForm.querySelector('button[type="submit"]');
                const originalText = submitBtn ? submitBtn.textContent : 'Upload CSV';
                
                try {
                    // Show uploading indicator
                    if (submitBtn) {
                        submitBtn.textContent = 'Uploading...';
                        submitBtn.disabled = true;
                    }
                    
                    // For file uploads, don't set Content-Type - let browser set it with boundary
                    const csrfToken = window.Utils.getCsrfToken();
                    const headers = csrfToken ? {'X-CSRFToken': csrfToken} : {};
                    
                    const response = await fetch(`${toolEndpoint}/upload-change-csv`, {
                        method: 'POST',
                        headers: headers,
                        body: formData,
                        credentials: 'same-origin'
                    });
                    
                    if (response.ok) {
                        try {
                            // Parse response JSON once and handle any JSON errors
                            const responseData = await response.json();
                            
                            // Clear the file input
                            document.getElementById('change-csv-file').value = '';
                            showToast('CSV uploaded successfully', 'success');
                            
                            // Refresh change list and auto-select the uploaded change
                            await refreshChangeList();
                            
                            if (responseData.change_id) {
                                const select = document.getElementById('change-select');
                                if (select) {
                                    select.value = responseData.change_id;
                                }
                                
                                // Since the change is automatically loaded on the backend,
                                // reload the page to show the loaded change in the UI
                                showToast('CSV uploaded and change loaded successfully!', 'success');
                                setTimeout(() => {
                                    window.location.reload();
                                }, RELOAD_DELAY_MS);
                            }
                        } catch (jsonError) {
                            console.error('Error parsing CSV upload response:', jsonError);
                            showToast('CSV may have been uploaded, but there was an error processing the response', 'warning');
                            // Still refresh the change list in case the upload worked
                            await refreshChangeList();
                        }
                    } else {
                        let errorMsg = `HTTP ${response.status} ${response.statusText}`;
                        try {
                            const contentType = response.headers.get('content-type');
                            if (contentType && contentType.includes('application/json')) {
                                const error = await response.json();
                                errorMsg = error.detail || errorMsg;
                            } else {
                                const text = await response.text();
                                if (text) {
                                    errorMsg = text;
                                }
                            }
                        } catch (parseError) {
                            // Keep the default HTTP status message
                        }
                        showToast('Failed to upload CSV: ' + errorMsg, 'danger');
                    }
                } catch (error) {
                    showToast('Error uploading CSV: ' + error.message, 'danger');
                } finally {
                    // Reset submit button
                    const submitBtn = uploadForm.querySelector('button[type="submit"]');
                    if (submitBtn) {
                        submitBtn.textContent = originalText || 'Upload CSV';
                        submitBtn.disabled = false;
                    }
                }
            });
        }
    }

    // Show toast helper (using existing showToast if available)
    function showToast(message, type) {
        if (typeof window.showToast === 'function') {
            window.showToast(message, type);
        } else {
            console.log(`[${type}] ${message}`);
        }
    }

    // Initialize on DOM ready
    document.addEventListener('DOMContentLoaded', function() {
        initCSVUpload();
        // Initialize change list on load
        refreshChangeList();
    });

    // Export functions to global scope for onclick handlers
    window.initChangeManagement = initChangeManagement;
    window.loadSelectedChange = loadSelectedChange;
    window.loadChange = loadChange;
    window.refreshChangeList = refreshChangeList;
    window.addManualInstance = addManualInstance;
    window.updateManualInstancesPreview = updateManualInstancesPreview;
    window.removeManualInstance = removeManualInstance;
    window.saveManualChange = saveManualChange;
    window.clearChange = clearChange;

})();