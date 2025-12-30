// Linux QC Patching Post Tool JavaScript
(function() {
    'use strict';
    
    // Module-scoped variables
    let currentBatchId = null;
    let pollInterval = null;
    let currentChange = window.currentChangeData || null;

    // Initialize when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        console.log('Linux QC Patching Post Tool initialized');
        console.log('Current change data:', currentChange);

        // Set up event handlers
        setupEventHandlers();

        // If we have a current change, update the UI
        if (currentChange) {
            console.log('Updating UI for loaded change:', currentChange.change_number);
            updateUIForLoadedChange();
        } else {
            console.log('No change currently loaded');
        }
    });

    function setupEventHandlers() {
        // Instance selection checkbox
        const selectAllCheckbox = document.getElementById('select-all-instances');
        if (selectAllCheckbox) {
            selectAllCheckbox.addEventListener('change', function() {
                const checkboxes = document.querySelectorAll('.instance-checkbox');
                checkboxes.forEach(cb => cb.checked = this.checked);
            });
        }
    }

    function updateUIForLoadedChange() {
        // Enable specific buttons when change is loaded
        if (currentChange && currentChange.instances && currentChange.instances.length > 0) {
            console.log(`Enabling buttons for ${currentChange.instances.length} instances`);

            // Enable connectivity test button
            const connectivityBtn = document.getElementById('test-connectivity-btn');
            if (connectivityBtn) {
                connectivityBtn.disabled = false;
                console.log('Enabled connectivity test button');
            }

            // Enable validation execution button
            const validationBtn = document.getElementById('execute-validation-btn');
            if (validationBtn) {
                validationBtn.disabled = false;
                console.log('Enabled validation execution button');
            }
        } else {
            console.log('No instances in current change, buttons remain disabled');
        }
    }

    // Test connectivity to all instances
    window.testConnectivity = async function() {
        if (!currentChange || !currentChange.instances) {
            alert('Please load a change first');
            return;
        }

        const btn = document.getElementById('test-connectivity-btn');
        const resultsDiv = document.getElementById('connectivity-results');
        
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Testing...';
        
        try {
            const instanceIds = currentChange.instances.map(i => i.instance_id);
            
            // Get CSRF token (assuming change-management.js is loaded)
            const csrfToken = typeof getCsrfToken === 'function' ? getCsrfToken() : null;
            const headers = {'Content-Type': 'application/json'};
            if (csrfToken) {
                headers['X-CSRFToken'] = csrfToken;
            }
        const response = await fetch('/aws/linux-qc-patching-post/test-connectivity', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({instance_ids: instanceIds})
        });

            const data = await response.json();
            
            if (data.status === 'success') {
                const results = data.results;
                const accessible = results.filter(r => r.accessible).length;
                const total = results.length;
                
                if (accessible === total) {
                    resultsDiv.className = 'alert alert-success';
                    resultsDiv.innerHTML = `<i class="bi bi-check-circle me-1"></i>All ${total} instances are online and accessible`;
                } else if (accessible > 0) {
                    resultsDiv.className = 'alert alert-warning';
                    resultsDiv.innerHTML = `<i class="bi bi-exclamation-triangle me-1"></i>${accessible} of ${total} instances are accessible`;
                    
                    // Show details of inaccessible instances
                    const inaccessible = results.filter(r => !r.accessible);
                    let details = '<ul class="mb-0 mt-2">';
                    inaccessible.forEach(inst => {
                        details += `<li>${window.Utils.escapeHtml(inst.instance_id)}: ${window.Utils.escapeHtml(inst.error)}</li>`;
                    });
                    details += '</ul>';
                    resultsDiv.innerHTML += details;
                } else {
                    resultsDiv.className = 'alert alert-danger';
                    resultsDiv.innerHTML = `<i class="bi bi-x-circle me-1"></i>No instances are accessible`;
                }
            } else {
                throw new Error(data.detail || 'Failed to test connectivity');
            }
        } catch (error) {
            console.error('Error testing connectivity:', error);
            resultsDiv.className = 'alert alert-danger';
            resultsDiv.innerHTML = `<i class="bi bi-x-circle me-1"></i>Error: ${error.message}`;
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-wifi me-2"></i>Confirm Connectivity';
        }
    };

    // Execute post-patch validation
    window.executePostValidation = async function() {
        if (!currentChange || !currentChange.instances) {
            alert('Please load a change first');
            return;
        }

        const btn = document.getElementById('execute-validation-btn');
        const resultsDiv = document.getElementById('validation-results');
        
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Executing...';
        
        try {
            const instanceIds = currentChange.instances.map(i => i.instance_id);

            // Get CSRF token (assuming change-management.js is loaded)
            const csrfToken = typeof getCsrfToken === 'function' ? getCsrfToken() : null;
            const headers = {'Content-Type': 'application/json'};
            if (csrfToken) {
                headers['X-CSRFToken'] = csrfToken;
            }

            const response = await fetch('/aws/linux-qc-patching-post/execute-post-validation', {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({instance_ids: instanceIds})
            });

            const data = await response.json();
            
            if (data.status === 'success') {
                currentBatchId = data.batch_id;
                
                // Show initial status
                resultsDiv.innerHTML = `
                    <div class="alert alert-info">
                        <i class="bi bi-hourglass-split me-2"></i>
                        Validation started for ${data.execution_count} instances
                        <div class="mt-2">
                            <strong>Batch ID:</strong> ${data.batch_id}
                        </div>
                    </div>
                    <div id="validation-progress" class="mt-3"></div>
                `;
                
                // Start polling for results
                startPollingResults();
            } else {
                throw new Error(data.detail || 'Failed to start validation');
            }
        } catch (error) {
            console.error('Error executing validation:', error);
            resultsDiv.innerHTML = `
                <div class="alert alert-danger">
                    <i class="bi bi-x-circle me-1"></i>Error: ${error.message}
                </div>
            `;
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-play-circle me-2"></i>Run Validation';
        }
    };

    // Poll for validation results
    function startPollingResults() {
        if (pollInterval) {
            clearInterval(pollInterval);
        }

        // Initial poll
        pollResults();

        // Poll every 3 seconds
        pollInterval = setInterval(pollResults, 3000);
    }

    async function pollResults() {
        if (!currentBatchId) return;

        try {
            const response = await fetch(`/aws/linux-qc-patching-post/validation-results/${currentBatchId}`);
            const data = await response.json();

            if (data.status === 'success') {
                updateValidationResults(data);

                // Stop polling if all executions are complete
                if (data.completed === data.total) {
                    clearInterval(pollInterval);
                    pollInterval = null;
                }
            }
        } catch (error) {
            console.error('Error polling results:', error);
        }
    }

    function updateValidationResults(data) {
        const progressDiv = document.getElementById('validation-progress');
        if (!progressDiv) return;

        const percentComplete = data.total > 0 ? Math.round((data.completed / data.total) * 100) : 0;
        
        let html = `
            <div class="progress mb-3">
                <div class="progress-bar ${percentComplete === 100 ? 'bg-success' : 'bg-primary'}" 
                     role="progressbar" style="width: ${percentComplete}%">
                    ${data.completed} / ${data.total} (${percentComplete}%)
                </div>
            </div>
        `;

        // Show summary
        if (data.completed > 0) {
            html += `
                <div class="row mb-3">
                    <div class="col-md-6">
                        <div class="alert alert-success">
                            <h6><i class="bi bi-check-circle me-2"></i>Passed Validation</h6>
                            <strong>${data.passed_count}</strong> instances
                        </div>
                    </div>
                    <div class="col-md-6">
                        <div class="alert alert-danger">
                            <h6><i class="bi bi-x-circle me-2"></i>Failed Validation</h6>
                            <strong>${data.failed_count}</strong> instances
                        </div>
                    </div>
                </div>
            `;
        }

        // Show passed instances
        if (data.passed_instances && data.passed_instances.length > 0) {
            html += `
                <div class="card mb-3">
                    <div class="card-header bg-success text-white">
                        <h6 class="mb-0">Passed Instances</h6>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Instance ID</th>
                                        <th>Hostname</th>
                                        <th>Current Kernel</th>
                                        <th>Patch Date</th>
                                    </tr>
                                </thead>
                                <tbody>
            `;

            data.passed_instances.forEach(inst => {
                html += `
                    <tr>
                        <td>${inst.instance_id}</td>
                        <td>${inst.hostname || '-'}</td>
                        <td>${inst.current_kernel || '-'}</td>
                        <td>${inst.date || '-'}</td>
                    </tr>
                `;
            });

            html += `
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            `;
        }

        // Show failed instances
        if (data.failed_instances && data.failed_instances.length > 0) {
            html += `
                <div class="card mb-3">
                    <div class="card-header bg-danger text-white">
                        <h6 class="mb-0">Failed Instances</h6>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Instance ID</th>
                                        <th>Hostname</th>
                                        <th>Reason</th>
                                    </tr>
                                </thead>
                                <tbody>
            `;

            data.failed_instances.forEach(inst => {
                html += `
                    <tr>
                        <td>${inst.instance_id}</td>
                        <td>${inst.hostname || '-'}</td>
                        <td class="text-danger">${inst.error_reason}</td>
                    </tr>
                `;
            });

            html += `
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            `;
        }

        // Show raw output for debugging (collapsible)
        if (data.results && data.results.length > 0) {
            html += `
                <div class="card">
                    <div class="card-header">
                        <h6 class="mb-0">
                            <a data-bs-toggle="collapse" href="#raw-output" role="button">
                                <i class="bi bi-terminal me-2"></i>Raw Output (Click to expand)
                            </a>
                        </h6>
                    </div>
                    <div class="collapse" id="raw-output">
                        <div class="card-body">
            `;

            data.results.forEach(result => {
                const statusClass = result.status === 'completed' ? 'success' : 
                                  result.status === 'failed' ? 'danger' : 'warning';
                html += `
                    <div class="mb-3">
                        <h6>
                            <span class="badge bg-${statusClass}">${result.instance_id}</span>
                            ${result.instance_name ? `<small class="text-muted ms-2">${result.instance_name}</small>` : ''}
                        </h6>
                        <pre class="bg-dark text-white p-2 rounded" style="max-height: 300px; overflow-y: auto;">${window.Utils.escapeHtml(result.output || result.error || 'No output')}</pre>
                    </div>
                `;
            });

            html += `
                        </div>
                    </div>
                </div>
            `;
        }

        progressDiv.innerHTML = html;
    }

    // Use shared escapeHtml from utils.js

})();