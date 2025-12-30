// AWS SFT Fixer Tool JavaScript
(function() {
    'use strict';
    
    // Module-scoped variables
    let currentBatchId = null;
    let pollInterval = null;
    let instanceConfig = null;
    let sftStatus = null;

    // Initialize when DOM is ready
    document.addEventListener('DOMContentLoaded', function() {
        console.log('AWS SFT Fixer Tool initialized');
        
        // Set up event handlers
        setupEventHandlers();
    });

    function setupEventHandlers() {
        // Form validation
        const instanceIdInput = document.getElementById('instance-id');
        const accountNumberInput = document.getElementById('account-number');
        
        if (instanceIdInput) {
            instanceIdInput.addEventListener('input', validateInstanceId);
        }
        
        if (accountNumberInput) {
            accountNumberInput.addEventListener('input', validateAccountNumber);
        }
    }

    function validateInstanceId() {
        const input = document.getElementById('instance-id');
        const value = input.value.trim();
        
        if (value && !value.match(/^i-[0-9a-fA-F]{8,17}$/)) {
            input.setCustomValidity('Instance ID must start with "i-" followed by 8-17 hex characters');
        } else {
            input.setCustomValidity('');
        }
    }

    function validateAccountNumber() {
        const input = document.getElementById('account-number');
        const value = input.value.trim();
        
        if (value && !value.match(/^[0-9]{12}$/)) {
            input.setCustomValidity('Account number must be exactly 12 digits');
        } else {
            input.setCustomValidity('');
        }
    }

    // Validate instance configuration and test SSM connectivity
    window.validateInstance = async function() {
        const osType = document.getElementById('os-type').value;
        const instanceId = document.getElementById('instance-id').value.trim();
        const region = document.getElementById('region').value;
        const accountNumber = document.getElementById('account-number').value.trim();
        
        const btn = document.getElementById('validate-btn');
        const resultsDiv = document.getElementById('validation-results');
        const operationsDiv = document.getElementById('sft-operations');
        
        // Validate form inputs
        if (!osType || !instanceId || !region || !accountNumber) {
            showAlert(resultsDiv, 'danger', 'Please fill in all required fields');
            return;
        }

        if (!instanceId.match(/^i-[0-9a-fA-F]{8,17}$/)) {
            showAlert(resultsDiv, 'danger', 'Invalid Instance ID format');
            return;
        }

        if (!accountNumber.match(/^[0-9]{12}$/)) {
            showAlert(resultsDiv, 'danger', 'Account number must be exactly 12 digits');
            return;
        }

        // Store instance configuration
        instanceConfig = {
            os_type: osType,
            instance_id: instanceId,
            region: region,
            account_number: accountNumber
        };

        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Validating...';
        
        try {
            // Get CSRF token if available
            const csrfToken = typeof getCsrfToken === 'function' ? getCsrfToken() : null;
            const headers = {'Content-Type': 'application/json'};
            if (csrfToken) {
                headers['X-CSRFToken'] = csrfToken;
            }

            const response = await fetch('/aws/sft-fixer/validate-instance', {
                method: 'POST',
                headers: headers,
                body: JSON.stringify(instanceConfig)
            });

            const data = await response.json();
            
            if (data.status === 'success') {
                showAlert(resultsDiv, 'success', `✓ SSM connectivity confirmed for instance ${instanceId}`);
                operationsDiv.style.display = 'block';
                
                // Scroll to operations section
                operationsDiv.scrollIntoView({ behavior: 'smooth', block: 'start' });
            } else {
                showAlert(resultsDiv, 'danger', `✗ SSM connectivity failed: ${data.detail || 'Unknown error'}`);
                operationsDiv.style.display = 'none';
            }
        } catch (error) {
            console.error('Validation error:', error);
            showAlert(resultsDiv, 'danger', 'Failed to validate instance connectivity');
            operationsDiv.style.display = 'none';
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-wifi me-2"></i>Validate SSM Connectivity';
        }
    };

    // Run SFT detection
    window.runDetection = async function() {
        if (!instanceConfig) {
            alert('Please validate instance configuration first');
            return;
        }

        const btn = document.getElementById('detect-btn');
        const statusDiv = document.getElementById('operation-status');
        
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Detecting...';
        
        try {
            const scriptType = instanceConfig.os_type === 'windows' ? 'detect_windows' : 'detect';
            await executeScript(scriptType, 'SFT Detection', statusDiv);
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-play-circle me-1"></i>Run Detection';
        }
    };

    // Run SFT installation
    window.runInstallation = async function() {
        if (!instanceConfig) {
            alert('Please validate instance configuration first');
            return;
        }

        // Confirm before installation
        if (!confirm('This will install ScaleFT on the target instance. Continue?')) {
            return;
        }

        const btn = document.getElementById('install-btn');
        const statusDiv = document.getElementById('operation-status');
        
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Installing...';
        
        try {
            let scriptType;
            if (instanceConfig.os_type === 'windows') {
                scriptType = 'install_windows';
            } else {
                // For Linux, we need to detect the distribution first
                // For now, default to Ubuntu - in a real implementation you'd detect this
                scriptType = 'install_ubuntu'; // Could be install_rhel based on detection
            }
            await executeScript(scriptType, 'SFT Installation', statusDiv);
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-cloud-download me-1"></i>Install SFT';
        }
    };

    // Run SFT reset
    window.runReset = async function() {
        if (!instanceConfig) {
            alert('Please validate instance configuration first');
            return;
        }

        // Confirm before reset
        if (!confirm('This will reset the ScaleFT configuration and tokens. Continue?')) {
            return;
        }

        const btn = document.getElementById('reset-btn');
        const statusDiv = document.getElementById('operation-status');
        
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Resetting...';
        
        try {
            const scriptType = instanceConfig.os_type === 'windows' ? 'reset_windows' : 'reset_linux';
            await executeScript(scriptType, 'SFT Reset', statusDiv);
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-arrow-repeat me-1"></i>Reset SFT';
        }
    };

    // Execute a script on the instance
    async function executeScript(scriptType, operationName, statusDiv) {
        showAlert(statusDiv, 'info', `Starting ${operationName}...`);
        
        try {
            // Get CSRF token if available
            const csrfToken = typeof getCsrfToken === 'function' ? getCsrfToken() : null;
            const headers = {'Content-Type': 'application/json'};
            if (csrfToken) {
                headers['X-CSRFToken'] = csrfToken;
            }

            const response = await fetch('/aws/sft-fixer/execute-script', {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({
                    instance_config: instanceConfig,
                    script_type: scriptType
                })
            });

            const data = await response.json();
            
            if (data.status === 'success') {
                currentBatchId = data.batch_id;
                showAlert(statusDiv, 'info', `${operationName} started. Monitoring execution...`);
                
                // Start polling for results
                startPolling();
            } else {
                throw new Error(data.detail || 'Failed to execute script');
            }
        } catch (error) {
            console.error('Script execution error:', error);
            showAlert(statusDiv, 'danger', `Failed to start ${operationName}: ${error.message}`);
        }
    }

    // Start polling for execution results
    function startPolling() {
        if (pollInterval) {
            clearInterval(pollInterval);
        }
        
        pollInterval = setInterval(pollResults, 3000); // Poll every 3 seconds
        pollResults(); // Initial poll
    }

    // Stop polling
    function stopPolling() {
        if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
        }
    }

    // Poll for execution results
    async function pollResults() {
        if (!currentBatchId) {
            stopPolling();
            return;
        }

        try {
            const response = await fetch(`/aws/sft-fixer/batch-status/${currentBatchId}`);
            const data = await response.json();
            
            if (data.status === 'success') {
                updateExecutionResults(data.batch_status);
                
                // Stop polling if execution is complete
                if (data.batch_status.status === 'completed' || data.batch_status.status === 'failed') {
                    stopPolling();
                    
                    // Update button states based on results if this was a detection
                    if (data.batch_status.results && data.batch_status.results.length > 0) {
                        updateButtonStates(data.batch_status.results[0]);
                    }
                }
            }
        } catch (error) {
            console.error('Polling error:', error);
            stopPolling();
        }
    }

    // Update execution results display
    function updateExecutionResults(batchStatus) {
        const statusDiv = document.getElementById('execution-status');
        const resultsDiv = document.getElementById('execution-results');
        
        // Update status
        let statusClass = 'info';
        if (batchStatus.status === 'completed') statusClass = 'success';
        if (batchStatus.status === 'failed') statusClass = 'danger';
        
        statusDiv.innerHTML = `<div class="alert alert-${statusClass}">
            <strong>Status:</strong> ${batchStatus.status.toUpperCase()}
            ${batchStatus.completed_count > 0 ? `(${batchStatus.completed_count} completed)` : ''}
        </div>`;
        
        // Update results
        if (batchStatus.results && batchStatus.results.length > 0) {
            let resultsHtml = '<div class="mt-3">';
            
            batchStatus.results.forEach((result, index) => {
                const success = result.status === 'success';
                const alertClass = success ? 'alert-success' : 'alert-danger';
                
                resultsHtml += `<div class="alert ${alertClass}">
                    <h6><i class="bi bi-${success ? 'check-circle' : 'x-circle'} me-2"></i>
                    Instance: ${window.Utils ? window.Utils.escapeHtml(result.instance_id) : result.instance_id}</h6>
                    <pre class="mb-0" style="white-space: pre-wrap;">${window.Utils ? window.Utils.escapeHtml(result.output) : result.output}</pre>
                </div>`;
            });
            
            resultsHtml += '</div>';
            resultsDiv.innerHTML = resultsHtml;
        }
    }

    // Update button states based on detection results
    function updateButtonStates(result) {
        const installBtn = document.getElementById('install-btn');
        const resetBtn = document.getElementById('reset-btn');
        
        if (result && result.output) {
            const output = result.output;
            
            // Check if SFT is installed
            const sftInstalled = output.includes('SFT_INSTALLED=true');
            
            // Update button states
            installBtn.disabled = sftInstalled;
            resetBtn.disabled = !sftInstalled;
            
            // Store SFT status for future reference
            sftStatus = {
                installed: sftInstalled,
                running: output.includes('SFT_STATUS=running'),
                hasEnrollmentToken: output.includes('SFT_ENROLLMENT_TOKEN=exists'),
                hasDeviceToken: output.includes('SFT_DEVICE_TOKEN=exists'),
                hasConfig: output.includes('SFT_CONFIG=exists')
            };
        }
    }

    // Utility function to show alerts
    function showAlert(element, type, message) {
        element.className = `alert alert-${type}`;
        element.innerHTML = `<i class="bi bi-${getAlertIcon(type)} me-2"></i>${message}`;
    }

    // Get appropriate icon for alert type
    function getAlertIcon(type) {
        switch(type) {
            case 'success': return 'check-circle';
            case 'danger': return 'x-circle';
            case 'warning': return 'exclamation-triangle';
            case 'info': return 'info-circle';
            default: return 'info-circle';
        }
    }

    // Clean up on page unload
    window.addEventListener('beforeunload', function() {
        stopPolling();
    });
})();