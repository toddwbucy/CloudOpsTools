// Linux QC Patching Prep Tool JavaScript
(function() {
    'use strict';
    
    // Module-scoped variables
    let currentChange = null;
    let selectedInstances = new Set();
    let kernelGroups = {};
    let executionStatusInterval = null;
    let manualInstances = [];

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    // Check credentials status on page load
    checkCredentials();
    if (window.currentChangeData) {
        currentChange = window.currentChangeData;
        updateInstanceList();
        // Check for existing Step 1 results and populate Step 2 if available
        checkForExistingStep1Results();
    }
    
    // Note: CSV upload is now handled by the shared change-management.js module
    // which is included via the change_management.html template
});

// Check for existing Step 1 results
async function checkForExistingStep1Results() {
    try {
        // Add cache-busting parameter to ensure fresh data
        const cacheBuster = `?t=${Date.now()}`;
        const response = await fetch(`/aws/linux-qc-patching-prep/latest-step1-results${cacheBuster}`, {
            credentials: 'same-origin',
            cache: 'no-cache'
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log('Existing Step 1 results:', data);
            
            if (data.status === 'success' && data.kernel_groups && Object.keys(data.kernel_groups).length > 0) {
                console.log('Found kernel groups, preparing to populate Step 2');
                kernelGroups = data.kernel_groups;
                
                // Store the batch_id for Step 2
                if (data.batch_id) {
                    window.step1BatchId = data.batch_id;
                    console.log('Stored Step 1 batch_id:', data.batch_id);
                }
                
                // Function to populate Step 2
                const populateStep2 = () => {
                    if (typeof window.populateStep2KernelGroups === 'function') {
                        console.log('Calling populateStep2KernelGroups with:', data.kernel_groups);
                        window.populateStep2KernelGroups(data.kernel_groups);
                        
                        // Make Step 2 section visible if it was hidden
                        const step2Section = document.getElementById('step2');
                        if (step2Section) {
                            step2Section.style.display = 'block';
                        }
                        return true;
                    }
                    return false;
                };
                
                // Try to populate immediately
                if (!populateStep2()) {
                    console.warn('Step 2 script not loaded yet, waiting...');
                    // If not ready, wait for it to load
                    let retries = 0;
                    const maxRetries = 20; // 10 seconds max
                    const retryInterval = setInterval(() => {
                        retries++;
                        if (populateStep2()) {
                            console.log('Successfully populated Step 2 after', retries, 'retries');
                            clearInterval(retryInterval);
                        } else if (retries >= maxRetries) {
                            console.error('Failed to load Step 2 script after', maxRetries, 'retries');
                            clearInterval(retryInterval);
                        }
                    }, 500);
                }
            } else {
                console.log('No kernel groups found in Step 1 results');
            }
        }
    } catch (error) {
        console.error('Error checking for existing Step 1 results:', error);
    }
}

// Load selected change from dropdown (tool-specific version)
async function loadSelectedChange() {
    console.log('linux-qc-patching-prep.js loadSelectedChange called');
    const changeId = document.getElementById('change-select').value;
    console.log('Selected change ID:', changeId);
    
    if (!changeId) {
        showToast('Please select a change first', 'warning');
        return;
    }
    
    await loadChange(changeId);
}

// Export loadSelectedChange to global scope (loadChange will be exported after it's defined)
window.loadSelectedChange = loadSelectedChange;

// Debug session state - call from browser console: debugSession()
async function debugSession() {
    try {
        const response = await fetch('/aws/linux-qc-patching-prep/debug-session', {
            method: 'POST',
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log('=== SESSION DEBUG INFO ===');
            console.log('Session Keys:', data.session_keys);
            console.log('Current Change:', data.current_change);
            console.log('Session Size:', data.session_size);
            console.log('Change Manually Cleared:', data.change_manually_cleared);
            console.log('=== END SESSION DEBUG ===');
            return data;
        } else {
            console.error('Failed to get session debug info:', response.status);
        }
    } catch (error) {
        console.error('Error debugging session:', error);
    }
}

// Clear session state - call from browser console: clearSession()
async function clearSession() {
    try {
        const headers = window.Utils ? window.Utils.buildCsrfHeaders() : {};
        
        const response = await fetch('/aws/linux-qc-patching-prep/clear-change', {
            method: 'POST',
            headers: headers,
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            console.log('Session cleared successfully');
            showToast('Session cleared', 'success');
            return true;
        } else {
            console.error('Failed to clear session:', response.status);
            return false;
        }
    } catch (error) {
        console.error('Error clearing session:', error);
        return false;
    }
}

// Export debug functions to global scope
window.debugSession = debugSession;
window.clearSession = clearSession;

// Load a change (tool-specific version)
async function loadChange(changeId) {
    console.log('linux-qc-patching-prep.js loadChange called with ID:', changeId);
    if (!changeId) return;
    
    try {
        // Add cache-busting parameter
        const cacheBuster = `?t=${Date.now()}`;
        const url = `/aws/linux-qc-patching-prep/load-change/${changeId}${cacheBuster}`;
        console.log('Fetching:', url);
        
        const headers = window.Utils ? window.Utils.buildCsrfHeaders() : {};
        
        const response = await fetch(url, {
            method: 'POST',
            headers: headers,
            credentials: 'same-origin',
            cache: 'no-cache'
        });
        
        console.log('Response status:', response.status);
        
        if (response.ok) {
            const data = await response.json();
            console.log('Response data:', data);
            
            if (data.change) {
                currentChange = data.change;
                selectedInstances = new Set(currentChange.selected_instances);
                updateInstanceList();
                showToast('Change loaded successfully', 'success');
                
                // Check for existing Step 1 results
                await checkForExistingStep1Results();
                
                // Reload page to ensure UI is fully updated with the loaded change
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            } else {
                console.error('No change data in response:', data);
                showToast('Invalid response from server', 'danger');
            }
            
        } else {
            const errorText = await response.text();
            console.error('Load change failed:', response.status, errorText);
            showToast('Failed to load change: ' + response.status, 'danger');
        }
    } catch (error) {
        console.error('Error loading change:', error);
        showToast('Error loading change: ' + error.message, 'danger');
    }
}

// Export loadChange to global scope
window.loadChange = loadChange;

// Refresh the change list dropdown
async function refreshChangeList() {
    try {
        const cacheBuster = `?t=${Date.now()}`;
        const response = await fetch(`/aws/linux-qc-patching-prep/list-changes${cacheBuster}`, {
            credentials: 'same-origin',
            cache: 'no-cache'
        });
        
        if (response.ok) {
            const changes = await response.json();
            const select = document.getElementById('change-select');
            if (select) {
                // Store current selection
                const currentValue = select.value;
                
                // Clear existing options except the first one
                while (select.children.length > 1) {
                    select.removeChild(select.lastChild);
                }
                
                // Add new options
                changes.forEach(change => {
                    const option = document.createElement('option');
                    option.value = change.id;
                    option.textContent = `${change.change_number} (${change.instance_count} instances)`;
                    select.appendChild(option);
                });
                
                // Restore selection if it still exists
                if (currentValue) {
                    select.value = currentValue;
                }
            }
        }
    } catch (error) {
        console.error('Error refreshing change list:', error);
    }
}

// Test Connectivity for all instances
async function testConnectivity() {
    if (!currentChange || !currentChange.instances || currentChange.instances.length === 0) {
        showToast('No change loaded or no instances in change', 'warning');
        return;
    }
    
    const resultsDiv = document.getElementById('connectivity-results');
    const testBtn = document.getElementById('test-connectivity-btn');
    
    // Disable button and show loading
    testBtn.disabled = true;
    testBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Confirming...';
    resultsDiv.className = 'alert alert-info';
    resultsDiv.innerHTML = '<i class="bi bi-hourglass-split me-1"></i>Confirming connectivity to all instances...';
    
    try {
        const response = await fetch('/aws/linux-qc-patching-prep/test-connectivity', {
            method: 'POST',
            headers: Object.assign(
                {'Content-Type': 'application/json'},
                (window.Utils && window.Utils.getCsrfToken()) ? {'X-CSRFToken': window.Utils.getCsrfToken()} : {}
            ),
            body: JSON.stringify({
                instance_ids: currentChange.instances.map(i => i.instance_id)
            }),
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            let data;
            try {
                data = await response.json();
            } catch (parseError) {
                console.error('Failed to parse JSON response:', parseError);
                resultsDiv.className = 'alert alert-danger';
                // Create icon element
                const icon = document.createElement('i');
                icon.className = 'bi bi-x-circle me-1';
                // Safely set error message text
                const textNode = document.createTextNode('Error: Invalid response format from server');
                // Clear and append safely
                resultsDiv.innerHTML = '';
                resultsDiv.appendChild(icon);
                resultsDiv.appendChild(textNode);
                return;
            }
            displayConnectivityResults(data.results);
        } else {
            let error;
            try {
                error = await response.json();
            } catch (parseError) {
                console.error('Failed to parse error JSON:', parseError);
                error = { detail: 'Failed to test connectivity (invalid error response)' };
            }
            resultsDiv.className = 'alert alert-danger';
            // Create icon element
            const icon = document.createElement('i');
            icon.className = 'bi bi-x-circle me-1';
            // Safely set error message text
            const message = error.detail || 'Failed to test connectivity';
            const textNode = document.createTextNode(`Error: ${message}`);
            // Clear and append safely
            resultsDiv.innerHTML = '';
            resultsDiv.appendChild(icon);
            resultsDiv.appendChild(textNode);
        }
    } catch (error) {
        resultsDiv.className = 'alert alert-danger';
        // Create icon element
        const icon = document.createElement('i');
        icon.className = 'bi bi-x-circle me-1';
        // Safely set error message text
        const textNode = document.createTextNode(`Error: ${error.message}`);
        // Clear and append safely
        resultsDiv.innerHTML = '';
        resultsDiv.appendChild(icon);
        resultsDiv.appendChild(textNode);
    } finally {
        // Re-enable button
        testBtn.disabled = false;
        testBtn.innerHTML = '<i class="bi bi-wifi me-2"></i>Confirm Connectivity';
    }
}

// Display connectivity test results
function displayConnectivityResults(results) {
    const resultsDiv = document.getElementById('connectivity-results');
    
    // Count status
    const accessible = results.filter(r => r.accessible).length;
    const total = results.length;
    
    // Determine overall status
    let alertClass = 'alert-success';
    let iconClass = 'bi-check-circle';
    if (accessible === 0) {
        alertClass = 'alert-danger';
        iconClass = 'bi-x-circle';
    } else if (accessible < total) {
        alertClass = 'alert-warning';
        iconClass = 'bi-exclamation-triangle';
    }
    
    // Build results HTML
    let html = `<div class="mb-2">
        <i class="bi ${iconClass} me-1"></i>
        <strong>${accessible} of ${total} instances accessible</strong>
    </div>`;
    
    // Add details for each instance
    if (results.length > 0) {
        html += '<div class="small">';
        results.forEach(result => {
            const icon = result.accessible ? '✅' : '❌';
            const statusText = result.accessible ? 'Accessible' : (result.error || 'Not accessible');
            html += `<div>${icon} ${result.instance_id}: ${statusText}</div>`;
        });
        html += '</div>';
    }
    
    resultsDiv.className = `alert ${alertClass}`;
    resultsDiv.innerHTML = html;
}

// Execute QC Step
async function executeQCStep(step) {
    // Always execute on all instances in the current change
    if (!currentChange || !currentChange.instances || currentChange.instances.length === 0) {
        showToast('No change loaded or no instances in change', 'warning');
        return;
    }
    
    // Get kernel version for step 2
    let kernelVersion = '';
    if (step === 'step2_kernel_staging') {
        kernelVersion = document.getElementById('kernel-version').value.trim();
        if (!kernelVersion) {
            showToast('Please enter a kernel version', 'warning');
            return;
        }
    }
    
    // Show execution status
    showExecutionStatus(`Executing ${step.replace(/_/g, ' ')}...`, 'info');
    
    try {
        const response = await fetch('/aws/linux-qc-patching-prep/execute-qc-step', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                step: step,
                kernel_version: kernelVersion
            }),
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            const data = await response.json();
            showToast(`QC step started: ${data.execution_count} instances`, 'success');
            
            // Start polling for results
            pollExecutionStatus(data.batch_id, step);
        } else {
            const error = await response.json();
            showToast(`Failed to execute: ${error.detail}`, 'danger');
        }
    } catch (error) {
        console.error('Error executing QC step:', error);
        showToast('Error executing QC step', 'danger');
    }
}

// Poll for execution status with exponential backoff
function pollExecutionStatus(batchId, step) {
    if (executionStatusInterval && executionStatusInterval.stop) {
        executionStatusInterval.stop();
        executionStatusInterval = null;
    }
    
    // Create polling with exponential backoff
    const polling = window.Utils.createPolling(async (pollCount) => {
        try {
            const response = await fetch(`/aws/linux-qc-patching-prep/qc-results/${batchId}`, {
                credentials: 'same-origin'
            });
            
            if (response.ok) {
                const data = await response.json();
                
                // Update results display
                displayStepResults(step, data);
                
                // Check if completed
                if (data.completed === data.total) {
                    showExecutionStatus('Execution completed', 'success');
                    showToast('QC step completed', 'success');
                    
                    // If step 1, store kernel groups and populate Step 2
                    if (step === 'step1_initial_qc') {
                        // Store the batch_id for Step 2
                        window.step1BatchId = batchId;
                        console.log('Stored Step 1 batch_id:', batchId);
                        
                        if (data.kernel_groups) {
                            console.log('Kernel groups received:', data.kernel_groups);
                            kernelGroups = data.kernel_groups;
                            // The groups will be displayed in displayStepResults
                            // Also populate Step 2 kernel selection
                            if (typeof window.populateStep2KernelGroups === 'function') {
                                console.log('Calling populateStep2KernelGroups with:', data.kernel_groups);
                                window.populateStep2KernelGroups(data.kernel_groups);
                                
                                // Make Step 2 section visible if it was hidden
                                const step2Section = document.getElementById('step2');
                                if (step2Section) {
                                    step2Section.style.display = 'block';
                                    // Scroll to Step 2 to show the user it's ready
                                    step2Section.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                                }
                            } else {
                                console.error('populateStep2KernelGroups function not found!');
                                // Try again after a short delay in case the script is still loading
                                setTimeout(() => {
                                    if (typeof window.populateStep2KernelGroups === 'function') {
                                        console.log('Retrying populateStep2KernelGroups after delay');
                                        window.populateStep2KernelGroups(data.kernel_groups);
                                        
                                        const step2Section = document.getElementById('step2');
                                        if (step2Section) {
                                            step2Section.style.display = 'block';
                                            step2Section.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
                                        }
                                    }
                                }, 500);
                            }
                        } else {
                            console.log('No kernel groups in response. Data:', data);
                        }
                    }
                    
                    return { continue: false, completed: true };
                }
                
                // Continue polling if not completed
                return { continue: true, completed: false };
            } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        } catch (error) {
            console.error('Error polling status:', error);
            // Let the polling system handle retries with backoff
            throw error;
        }
    }, {
        initialInterval: 5000,      // Start with 5 seconds
        maxInterval: 30000,         // Max 30 seconds
        backoffMultiplier: 1.5,     // Increase by 1.5x
        maxPolls: 120,              // 10 minutes max
        onMaxPollsReached: () => {
            showExecutionStatus('Execution timed out', 'warning');
            showToast('Execution timed out after 10 minutes', 'warning');
        },
        onError: (error) => {
            showExecutionStatus('Polling failed', 'danger');
            showToast('Failed to check execution status', 'danger');
        }
    });
    
    // Store reference for cleanup
    executionStatusInterval = polling;
    
    // Start polling
    polling.start();
}

// Display step results
function displayStepResults(step, data) {
    const resultsDiv = document.getElementById(`${step.replace(/_.*/, '')}-results`);
    if (!resultsDiv) return;
    
    let html = `
        <div class="alert alert-info">
            <strong>Progress:</strong> ${data.completed} / ${data.total} instances completed
        </div>
    `;
    
    // Note: Kernel groups are now handled in Step 2, not displayed here in Step 1
    
    // Regular results table
    if (data.results && data.results.length > 0) {
        html += '<div class="table-responsive"><table class="table table-sm">';
        
        // New headers for step 1 - removed hostname, added three test columns
        if (step === 'step1_initial_qc') {
            html += '<thead><tr><th>Instance</th><th>Status</th><th>Distro</th><th>Running Kernel</th><th>Repo Check</th><th>Disk Space</th><th>CrowdStrike</th><th>Output</th></tr></thead><tbody>';
        } else {
            html += '<thead><tr><th>Instance</th><th>Hostname</th><th>Status</th><th>Output</th></tr></thead><tbody>';
        }
        
        for (const result of data.results) {
            const statusClass = result.status === 'completed' ? 'text-success' : 
                              result.status === 'failed' ? 'text-danger' : 'text-warning';
            
            if (step === 'step1_initial_qc') {
                // Parse test results from output for step 1
                let repoCheckPassed = false;
                let diskSpacePassed = false;
                
                if (result.output) {
                    // Look for test results in the output
                    repoCheckPassed = result.output.includes('(Test Repositories Result): PASSED');
                    diskSpacePassed = result.output.includes('(Disk Space Check Result): PASSED');
                }
                
                html += `
                    <tr>
                        <td>${window.Utils.escapeHtml(result.instance_id)}</td>
                        <td class="${statusClass}">${window.Utils.escapeHtml(result.status)}</td>
                        <td>${result.parsed_info?.distro ? window.Utils.escapeHtml(result.parsed_info.distro) : '-'}</td>
                        <td><small>${result.parsed_info?.current_kernel ? window.Utils.escapeHtml(result.parsed_info.current_kernel) : '-'}</small></td>
                        <td>${repoCheckPassed ? 
                            '<span class="badge bg-success">Pass</span>' : 
                            '<span class="badge bg-danger">Fail</span>'}</td>
                        <td>${diskSpacePassed ? 
                            '<span class="badge bg-success">Pass</span>' : 
                            '<span class="badge bg-danger">Fail</span>'}</td>
                        <td>${result.parsed_info?.crowdstrike_running ? 
                            '<span class="badge bg-success">Pass</span>' : 
                            '<span class="badge bg-danger">Fail</span>'}</td>
                        <td>
                            ${result.output ? 
                                `<details><summary>View</summary><pre class="bg-dark text-white p-2" style="max-height: 300px; overflow-y: auto;">${window.Utils.escapeHtml(result.output)}</pre></details>` : 
                                '<span class="text-muted">-</span>'}
                        </td>
                    </tr>
                `;
            } else {
                // For other steps, keep the original format with hostname
                html += `
                    <tr>
                        <td>${window.Utils.escapeHtml(result.instance_id)}</td>
                        <td>${result.parsed_info?.hostname ? window.Utils.escapeHtml(result.parsed_info.hostname) : '-'}</td>
                        <td class="${statusClass}">${window.Utils.escapeHtml(result.status)}</td>
                        <td>
                            ${result.output ? 
                                `<details><summary>View Output</summary><pre class="bg-dark text-white p-2" style="max-height: 300px; overflow-y: auto;">${window.Utils.escapeHtml(result.output)}</pre></details>` : 
                                '<span class="text-muted">No output yet</span>'}
                        </td>
                    </tr>
                `;
            }
        }
        
        html += '</tbody></table></div>';
    }
    
    resultsDiv.innerHTML = html;
}

// Note: Kernel groups display has been moved to Step 2 (linux-patcher-step2.js)
// The functions displayKernelGroups and selectKernelForGroup are now handled in Step 2


// Update instance list display
function updateInstanceList() {
    const tbody = document.getElementById('instance-list');
    if (!tbody || !currentChange) return;
    
    let html = '';
    for (const instance of currentChange.instances) {
        const checked = selectedInstances.has(instance.instance_id) ? 'checked' : '';
        html += `
            <tr>
                <td><input type="checkbox" value="${instance.instance_id}" ${checked} onchange="toggleInstance(this)"></td>
                <td>${window.Utils.escapeHtml(instance.instance_id)}</td>
                <td>${window.Utils.escapeHtml(instance.name || '-')}</td>
                <td>${window.Utils.escapeHtml(instance.account_id)}</td>
                <td>${window.Utils.escapeHtml(instance.region)}</td>
                <td class="kernel-info" data-instance="${instance.instance_id}">-</td>
            </tr>
        `;
    }
    
    tbody.innerHTML = html;
}

// Toggle instance selection
function toggleInstance(checkbox) {
    if (checkbox.checked) {
        selectedInstances.add(checkbox.value);
    } else {
        selectedInstances.delete(checkbox.value);
    }
}

// Select all instances
function selectAllInstances() {
    if (!currentChange) return;
    selectedInstances = new Set(currentChange.instances.map(i => i.instance_id));
    updateInstanceList();
}

// Deselect all instances
function deselectAllInstances() {
    selectedInstances.clear();
    updateInstanceList();
}

// Show execution status
function showExecutionStatus(message, type) {
    const statusDiv = document.getElementById('execution-status');
    if (!statusDiv) return;
    
    const alertClass = type === 'success' ? 'alert-success' : 
                      type === 'warning' ? 'alert-warning' : 
                      type === 'danger' ? 'alert-danger' : 'alert-info';
    
    statusDiv.innerHTML = `
        <div class="alert ${alertClass}">
            ${type === 'info' ? '<div class="spinner-border spinner-border-sm me-2"></div>' : ''}
            ${window.Utils.escapeHtml(message)}
        </div>
    `;
}

// Download reports
async function downloadReports() {
    // Download QC execution results for the current change
    window.location.href = '/aws/linux-qc-patching-prep/download-reports';
}

// Download final reports (Step 3 only - abbreviated)
async function downloadFinalReports() {
    // Download abbreviated final QC report for the current change
    window.location.href = '/aws/linux-qc-patching-prep/download-final-report';
}

// CSV upload form is initialized in the main DOMContentLoaded event listener above

// Redirect to AWS auth page for credential management
function showCredentialsModal(env) {
    // This function is kept for backward compatibility but now redirects to AWS auth page
    window.location.href = '/aws';
}

// Check credentials status
async function checkCredentials() {
    // The credentials are stored in session by /aws/authenticate
    // We need to check the session state, not validate through API
    // For now, just check if the elements exist
    const comStatus = document.getElementById('com-creds-status');
    const govStatus = document.getElementById('gov-creds-status');
    
    if (comStatus && govStatus) {
        // Check if we have a success message from authentication
        // This is a temporary solution - credentials are managed via /aws page
        console.log('Credential status badges found, user should set credentials via AWS page');
    }
}

// Refresh change list (local version for Linux QC Patching Prep) 
async function refreshChangeListLocal() {
    try {
        const response = await fetch('/aws/linux-qc-patching-prep/list-changes', {
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            const changes = await response.json();
            const select = document.getElementById('change-select');
            if (select) {
                const currentValue = select.value;
                select.innerHTML = '<option value="">Select a change...</option>';
                changes.forEach(change => {
                    const option = document.createElement('option');
                    option.value = change.id;
                    option.textContent = `${change.change_number || change.number} - ${change.instance_count} instances`;
                    if (option.value === currentValue) {
                        option.selected = true;
                    }
                    select.appendChild(option);
                });
                showToast('Change list refreshed', 'info');
            }
        }
    } catch (error) {
        console.error('Error refreshing changes:', error);
        showToast('Failed to refresh change list', 'danger');
    }
}

// Clear current change
async function clearChange() {
    if (!confirm('Clear the current change?')) return;
    
    try {
        const headers = window.Utils ? window.Utils.buildCsrfHeaders() : {};
        
        const response = await fetch('/aws/linux-qc-patching-prep/clear-change', {
            method: 'POST',
            headers: headers,
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            currentChange = null;
            selectedInstances.clear();
            updateInstanceList();
            showToast('Change cleared', 'success');
            
            // Reload page to reset state
            setTimeout(() => {
                window.location.reload();
            }, 1000);
        }
    } catch (error) {
        console.error('Error clearing change:', error);
        showToast('Failed to clear change', 'danger');
    }
}

// Note: Manual change functions are now handled by the shared change_management.html template
// The functions createQuickChange, addManualInstance, updateManualInstancesList, 
// removeManualInstance, and saveManualChange have been moved there

// Show toast notification using the global showToast from base template
function showToast(message, type) {
    // Use the global showToast function if available (from base.html)
    if (window.showToast && window.showToast !== showToast) {
        window.showToast(message, type);
    } else {
        // Fallback to execution status area if global toast not available
        console.log(`[${type}] ${message}`);
        const statusDiv = document.getElementById('execution-status');
        if (statusDiv) {
            const alertClass = type === 'success' ? 'alert-success' : 
                              type === 'warning' ? 'alert-warning' : 
                              type === 'danger' ? 'alert-danger' : 'alert-info';
            statusDiv.innerHTML = `
                <div class="alert ${alertClass} alert-dismissible fade show" role="alert">
                    ${window.Utils.escapeHtml(message)}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                </div>
            `;
        }
    }
}

// Use shared escapeHtml from utils.js

// Export functions to global scope
window.loadSelectedChange = loadSelectedChange;
window.loadChange = loadChange;
window.testConnectivity = testConnectivity;
window.executeQCStep = executeQCStep;
window.pollExecutionStatus = pollExecutionStatus;  // Added for use in step2
window.checkForExistingStep1Results = checkForExistingStep1Results;
// selectKernelForGroup is now handled in linux-patcher-step2.js
window.selectAllInstances = selectAllInstances;
window.deselectAllInstances = deselectAllInstances;
window.toggleInstance = toggleInstance;
window.downloadReports = downloadReports;
window.downloadFinalReports = downloadFinalReports;
window.showCredentialsModal = showCredentialsModal;
window.checkCredentials = checkCredentials;
// Do not override shared function; use local version instead
window.refreshChangeListLocal = refreshChangeListLocal;
window.clearChange = clearChange;
// Manual change functions are handled by change_management.html
window.showToast = showToast;

// Export getter/setter for currentChange to maintain scope
Object.defineProperty(window, 'currentChange', {
    get: function() { return currentChange; },
    set: function(value) { currentChange = value; }
});

})(); // End of IIFE