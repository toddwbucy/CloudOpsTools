// AWS Script Execution Module
// Uses shared utilities from utils.js for escapeHtml and other common functions

// Execution state
let executionInProgress = false;
let executionStatusInterval = null;

// Execute script with status tracking
window.executeScript = async function() {
    if (!ScriptRunnerState.currentChange || !ScriptRunnerState.currentScript || ScriptRunnerState.selectedInstances.size === 0) {
        showToast('Please select a change, script, and instances', 'warning');
        return;
    }
    
    // Prevent duplicate executions
    const executeBtn = document.getElementById('execute-btn') || document.getElementById('execute-script-btn');
    if (executionInProgress) {
        showToast('Execution already in progress', 'info');
        return;
    }
    
    // Update UI to show execution starting
    executionInProgress = true;
    if (executeBtn) {
        executeBtn.disabled = true;
        executeBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Executing...';
    }
    
    // Show execution status
    showExecutionStatus('Starting execution...', 'info');
    
    const data = {
        change_id: ScriptRunnerState.currentChange.id,
        script_id: ScriptRunnerState.currentScript,
        instance_ids: Array.from(ScriptRunnerState.selectedInstances)
    };
    
    try {
        const response = await fetch('/aws/script-runner/execute', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(data),
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            showExecutionStatus('Execution in progress...', 'primary');
            showToast('Execution started successfully', 'success');
            
            // Start polling for status updates
            startExecutionStatusPolling();
            
            // Refresh results after initial delay
            setTimeout(refreshResults, 2000);
        } else {
            const errorData = await response.json().catch(() => ({}));
            showExecutionStatus('Execution failed', 'danger');
            showToast(`Execution failed: ${errorData.detail || 'Unknown error'}`, 'danger');
            resetExecuteButton();
        }
    } catch (error) {
        console.error('Error executing script:', error);
        showExecutionStatus('Execution error', 'danger');
        showToast('Error executing script. Please check your configuration and try again.', 'danger');
        resetExecuteButton();
    }
}

// Show execution status message
function showExecutionStatus(message, type = 'info') {
    const statusContainer = document.getElementById('execution-status');
    if (!statusContainer) {
        // Create status container if it doesn't exist
        const resultsTab = document.querySelector('#results-tab-pane');
        if (resultsTab) {
            const statusDiv = document.createElement('div');
            statusDiv.id = 'execution-status';
            statusDiv.className = 'mb-3';
            resultsTab.insertBefore(statusDiv, resultsTab.firstChild);
        }
    }
    
    const statusEl = document.getElementById('execution-status');
    if (statusEl) {
        statusEl.innerHTML = `
            <div class="alert alert-${type} d-flex align-items-center" role="alert">
                ${type === 'primary' ? '<div class="spinner-border spinner-border-sm me-2" role="status"></div>' : ''}
                <div>${message}</div>
            </div>
        `;
    }
}

// Start polling for execution status with exponential backoff
function startExecutionStatusPolling() {
    // Clear any existing polling
    if (executionStatusInterval && executionStatusInterval.stop) {
        executionStatusInterval.stop();
        executionStatusInterval = null;
    }
    
    // Create polling with exponential backoff
    const polling = window.Utils.createPolling(async (pollCount) => {
        try {
            const response = await fetch('/aws/script-runner/execution-status', {
                credentials: 'same-origin'
            });
            
            if (response.ok) {
                const status = await response.json();
                
                if (status.completed) {
                    if (status.success) {
                        showExecutionStatus('Execution completed successfully', 'success');
                        showToast('Execution completed successfully', 'success');
                    } else {
                        showExecutionStatus('Execution completed with errors', 'warning');
                        showToast('Execution completed with some errors', 'warning');
                    }
                    
                    resetExecuteButton();
                    refreshResults();
                    
                    return { continue: false, completed: true };
                }
                
                // Continue polling if not completed
                return { continue: true, completed: false };
            } else {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
        } catch (error) {
            console.error('Error polling execution status:', error);
            // Let the polling system handle retries with backoff
            throw error;
        }
    }, {
        initialInterval: 5000,      // Start with 5 seconds  
        maxInterval: 30000,         // Max 30 seconds
        backoffMultiplier: 1.5,     // Increase by 1.5x
        maxPolls: 60,               // 5 minutes max (adjusted for backoff)
        onMaxPollsReached: () => {
            showExecutionStatus('Execution taking longer than expected', 'warning');
            showToast('Execution timed out after 5 minutes', 'warning');
            resetExecuteButton();
        },
        onError: (error) => {
            showExecutionStatus('Polling failed', 'danger');
            showToast('Failed to check execution status', 'danger');
            resetExecuteButton();
        }
    });
    
    // Store reference for cleanup
    executionStatusInterval = polling;
    
    // Start polling
    polling.start();
}

// Reset execute button to initial state
function resetExecuteButton() {
    executionInProgress = false;
    const executeBtn = document.getElementById('execute-btn') || document.getElementById('execute-script-btn');
    if (executeBtn) {
        executeBtn.disabled = false;
        executeBtn.innerHTML = '<i class="bi bi-play-circle me-2"></i>Execute Script';
    }
}

// Refresh execution results
window.refreshResults = async function() {
    try {
        const response = await fetch('/aws/script-runner/last-execution-results', {
            credentials: 'same-origin'
        });
        if (response.ok) {
            const results = await response.json();
            displayResults(results);
        }
    } catch (error) {
        console.error('Error loading results:', error);
        showToast('Error loading results. Please try again.', 'danger');
    }
}

// Display execution results
window.displayResults = function(results) {
    const resultsDiv = document.getElementById('execution-results');
    if (!results || results.length === 0) {
        resultsDiv.innerHTML = '<p class="text-muted">No execution results yet.</p>';
        return;
    }
    
    // Clear execution status if showing results
    const statusEl = document.getElementById('execution-status');
    if (statusEl && executionInProgress === false) {
        statusEl.innerHTML = '';
    }
    
    // Create a formatted display of results with download button
    let html = `
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h6 class="mb-0">Execution Results</h6>
            <button class="btn btn-sm btn-outline-primary" onclick="downloadResults()">
                <i class="bi bi-download me-1"></i>Download Results
            </button>
        </div>
    `;
    
    // Group results by status (backend sends "Completed", "Failed", "Running")
    const successResults = results.filter(r => r.status === 'Completed');
    const failedResults = results.filter(r => r.status === 'Failed');
    const inProgressResults = results.filter(r => r.status === 'Running' || r.status === 'Pending');
    
    if (successResults.length > 0) {
        html += `
            <div class="alert alert-success">
                <strong>Successful: ${successResults.length} instance(s)</strong>
            </div>
        `;
    }
    
    if (failedResults.length > 0) {
        html += `
            <div class="alert alert-danger">
                <strong>Failed: ${failedResults.length} instance(s)</strong>
            </div>
        `;
    }
    
    if (inProgressResults.length > 0) {
        html += `
            <div class="alert alert-info">
                <strong>In Progress: ${inProgressResults.length} instance(s)</strong>
            </div>
        `;
    }
    
    // Display detailed results in a table format
    html += `
        <div class="table-responsive">
            <table class="table table-sm table-striped">
                <thead>
                    <tr>
                        <th>Instance ID</th>
                        <th>Command ID</th>
                        <th>Status</th>
                        <th>Output</th>
                        <th>Error</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    for (const result of results) {
        const statusClass = result.status === 'Completed' ? 'text-success' : 
                          result.status === 'Failed' ? 'text-danger' : 
                          'text-warning';
        
        html += `
            <tr>
                <td>
                    <small>${window.Utils.escapeHtml(result.instance_id)}</small>
                    ${result.instance_name ? '<br><span class="text-muted">' + window.Utils.escapeHtml(result.instance_name) + '</span>' : ''}
                </td>
                <td><small class="font-monospace">${result.command_id ? window.Utils.escapeHtml(result.command_id) : 'N/A'}</small></td>
                <td><span class="${statusClass}">${window.Utils.escapeHtml(result.status)}</span></td>
                <td>
                    ${result.output ? 
                        '<details><summary>View Output</summary><pre class="bg-dark text-white p-2 mt-2">' + window.Utils.escapeHtml(result.output) + '</pre></details>' : 
                        '<span class="text-muted">No output</span>'}
                </td>
                <td>
                    ${result.error ? 
                        '<span class="text-danger">' + window.Utils.escapeHtml(result.error).substring(0, 100) + (result.error.length > 100 ? '...' : '') + '</span>' : 
                        '<span class="text-muted">-</span>'}
                </td>
            </tr>
        `;
    }
    
    html += `
                </tbody>
            </table>
        </div>
    `;
    
    resultsDiv.innerHTML = html;
}

// Download results as markdown file
window.downloadResults = function() {
    window.location.href = '/aws/script-runner/download-results';
}

// Cleanup function to prevent memory leaks
function cleanupExecutionModule() {
    // Stop any active polling
    if (executionStatusInterval && executionStatusInterval.stop) {
        executionStatusInterval.stop();
        executionStatusInterval = null;
    }
    
    // Reset execution state
    executionInProgress = false;
    
    console.debug('AWS execution module cleaned up');
}

// Initialize execution module
document.addEventListener('DOMContentLoaded', function() {
    // Add execute button to the page if it doesn't exist
    const executeContainer = document.querySelector('.execute-container');
    if (executeContainer && !document.getElementById('execute-script-btn')) {
        const executeBtn = document.createElement('button');
        executeBtn.id = 'execute-script-btn';
        executeBtn.className = 'btn btn-success btn-lg';
        executeBtn.innerHTML = '<i class="bi bi-play-circle me-2"></i>Execute Script';
        executeBtn.onclick = executeScript;
        executeContainer.appendChild(executeBtn);
    }
    
    // Clean up any lingering polling on page load
    cleanupExecutionModule();
});

// Page unload cleanup to prevent memory leaks
window.addEventListener('beforeunload', function() {
    cleanupExecutionModule();
});

// Additional cleanup for SPA navigation (if using)
window.addEventListener('pagehide', function() {
    cleanupExecutionModule();
});

// Visibility change cleanup (tab switching)
document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'hidden') {
        // Pause polling when tab is hidden to save resources
        if (executionStatusInterval && executionStatusInterval.stop && executionInProgress) {
            console.debug('Pausing execution polling - tab hidden');
            executionStatusInterval.stop();
        }
    } else if (document.visibilityState === 'visible' && executionInProgress) {
        // Resume polling when tab becomes visible again
        console.debug('Resuming execution polling - tab visible');
        startExecutionStatusPolling();
    }
});