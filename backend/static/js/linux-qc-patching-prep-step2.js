// Additional functions for Step 2 kernel staging

// Populate Step 2 with kernel selection interface
function populateStep2KernelGroups(kernelGroups) {
    console.log('populateStep2KernelGroups called with:', kernelGroups);
    const container = document.getElementById('step2-kernel-groups');
    const executeSection = document.getElementById('step2-execute-section');
    
    console.log('Container element:', container);
    console.log('Execute section element:', executeSection);
    
    if (!container) {
        console.error('step2-kernel-groups element not found! Waiting for DOM...');
        // Try again after DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                populateStep2KernelGroups(kernelGroups);
            });
            return;
        }
        // If still not found, there's a real problem
        console.error('Cannot find step2-kernel-groups element in the DOM');
        return;
    }
    
    // All instances in kernel groups have already passed QC (filtered on server side)
    const passedGroups = kernelGroups;
    
    if (Object.keys(passedGroups).length === 0) {
        container.innerHTML = `
            <div class="alert alert-warning">
                <i class="bi bi-exclamation-triangle me-2"></i>
                No instances passed all QC tests. Cannot proceed with kernel staging.
                <br><small>Instances must pass Repository Check, Disk Space Check, and have CrowdStrike running to proceed to Step 2.</small>
            </div>
        `;
        return;
    }
    
    // All instances in kernel groups have already passed QC
    const totalFailed = 0;
    
    // First show the kernel groups card (moved from Step 1)
    let html = '';
    
    // Show warning if some instances failed QC
    if (totalFailed > 0) {
        html += `
            <div class="alert alert-info mb-3">
                <i class="bi bi-info-circle me-2"></i>
                <strong>${totalFailed} instance(s) excluded from Step 2</strong> due to failing one or more QC checks 
                (Repository Check, Disk Space Check, or CrowdStrike not running).
            </div>
        `;
    }
    
    html += `
        <div class="card bg-light mb-3">
            <div class="card-header">
                <h6 class="mb-0"><i class="bi bi-cpu me-2"></i>Kernel Groups Detected</h6>
            </div>
            <div class="card-body">
                <p class="text-muted mb-3">Servers are grouped by distribution and current kernel version. Only instances that passed all QC checks are shown.</p>
                <div class="row">
    `;
    
    for (const [groupKey, groupData] of Object.entries(passedGroups)) {
        const instanceCount = groupData.instances.length;
        const passedCount = groupData.instances.length;  // All instances already passed QC
        const availableKernels = groupData.available_kernels || [];
        
        html += `
            <div class="col-md-6 mb-3">
                <div class="card border-primary">
                    <div class="card-header bg-primary text-white">
                        <strong>${escapeHtml(groupKey)}</strong>
                    </div>
                    <div class="card-body">
                        <p class="mb-2">
                            <strong>Instances:</strong> ${instanceCount}<br>
                            <strong>Tests Passed:</strong> ${passedCount}/${instanceCount}
                        </p>
                        
                        ${availableKernels.length > 0 ? `
                            <div class="mb-2">
                                <label class="form-label small">Available Kernels:</label>
                                <select class="form-select form-select-sm kernel-select" data-group="${escapeHtml(groupKey)}">
                                    <option value="">Select kernel...</option>
                                    ${availableKernels.map(k => 
                                        `<option value="${escapeHtml(k)}">${escapeHtml(k)}</option>`
                                    ).join('')}
                                </select>
                            </div>
                        ` : '<p class="text-muted small">No kernel updates available</p>'}
                        
                        <button class="btn btn-sm btn-primary w-100" 
                                data-group-key="${escapeHtml(groupKey)}"
                                onclick="selectGroupForStaging(event, this.dataset.groupKey)">
                            <i class="bi bi-check2-square me-1"></i>Select Group
                        </button>
                        
                        <details class="mt-2">
                            <summary class="small">View Instances</summary>
                            <ul class="list-unstyled small mt-2">
                                ${groupData.instances.map(i => `
                                    <li>
                                        ${escapeHtml(i.instance_id)}
                                        <span class="badge bg-success ms-1">Ready</span>
                                    </li>
                                `).join('')}
                            </ul>
                        </details>
                    </div>
                </div>
            </div>
        `;
    }
    
    html += `
                </div>
            </div>
        </div>
    `;
    
    // Store kernel groups for later reference
    window.step2KernelGroups = passedGroups;
    
    container.innerHTML = html;
    executeSection.style.display = 'block';
}

// New function to handle group selection in Step 2
function selectGroupForStaging(event, groupKey) {
    // Accept event as first parameter
    const selectElement = document.querySelector(`.kernel-select[data-group="${groupKey}"]`);
    if (!selectElement) {
        console.error(`Kernel select element not found for group: ${groupKey}`);
        showToast('Internal error: Kernel selection element not found', 'danger');
        return;
    }
    const selectedKernel = selectElement ? selectElement.value : '';
    if (!selectedKernel) {
        showToast('Please select a kernel version first', 'warning');
        return;
    }
    
    // Update the UI to show this group is selected
    // Use event.currentTarget as fallback if event.target is not the button
    const button = event.currentTarget || event.target;
    if (button && button.classList) {
        if (button.classList.contains('btn-primary')) {
            button.classList.remove('btn-primary');
            button.classList.add('btn-success');
            button.innerHTML = '<i class="bi bi-check-circle-fill me-1"></i>Group Selected';
        }
    }
    
    showToast(`Group "${groupKey}" selected with kernel ${selectedKernel}`, 'success');
}

// Toggle instance list visibility
function toggleInstanceList(groupId) {
    const div = document.getElementById(`instances-${groupId}`);
    if (div) {
        div.style.display = div.style.display === 'none' ? 'block' : 'none';
    }
}

// Execute Step 2 for all groups with selected kernels
async function executeStep2AllGroups() {
    // Get all kernel select dropdowns from the kernel groups cards
    const selects = document.querySelectorAll('.kernel-select');
    const kernelGroups = [];
    
    selects.forEach(select => {
        const groupKey = select.dataset.group;
        const selectedKernel = select.value;
        
        if (selectedKernel && window.step2KernelGroups && window.step2KernelGroups[groupKey]) {
            // Get instance IDs for this group
            const instanceIds = window.step2KernelGroups[groupKey].instances.map(i => i.instance_id);
            
            kernelGroups.push({
                group: groupKey,
                kernel: selectedKernel,
                instances: instanceIds
            });
        }
    });
    
    if (kernelGroups.length === 0) {
        showToast('Please select kernel versions for at least one group', 'warning');
        return;
    }
    
    // Disable the button
    const btn = document.getElementById('step2-execute-btn');
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Executing...';
    }
    
    try {
        // Get CSRF token (using Utils function if available)
        const csrfToken = (window.Utils && typeof window.Utils.getCsrfToken === 'function') 
            ? window.Utils.getCsrfToken() 
            : null;
        const headers = {'Content-Type': 'application/json'};
        if (csrfToken) {
            headers['X-CSRFToken'] = csrfToken;
        }

        // Use the new multi-kernel endpoint that handles grouping by account/region/kernel
        const response = await fetch('/aws/linux-qc-patching-prep/execute-step2-multi-kernel', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify({
                kernel_groups: kernelGroups
            }),
            credentials: 'same-origin'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(`Step 2 kernel staging started: ${data.execution_count} instances across ${data.execution_groups} execution group(s)`, 'success');
            
            // Show results
            const resultsDiv = document.getElementById('step2-results');
            if (resultsDiv) {
                let groupsHtml = '';
                if (data.groups && data.groups.length > 0) {
                    groupsHtml = '<div class="mt-3"><h6>Execution Groups:</h6><ul class="small">';
                    data.groups.forEach(g => {
                        groupsHtml += `<li>Account ${g.account}, Region ${g.region}: ${g.instances} instance(s) → kernel ${escapeHtml(g.kernel)}</li>`;
                    });
                    groupsHtml += '</ul></div>';
                }
                
                resultsDiv.innerHTML = `
                    <div class="alert alert-success">
                        <h6><i class="bi bi-check-circle me-2"></i>Kernel Staging Started</h6>
                        <p>Master Batch ID: <code>${data.master_batch_id}</code></p>
                        <p>Total instances: ${data.execution_count}</p>
                        <p>Execution groups: ${data.execution_groups} (grouped by account/region/kernel)</p>
                        ${groupsHtml}
                        <div class="mt-2">
                            <small class="text-muted">
                                <i class="bi bi-info-circle me-1"></i>
                                Instances in the same account/region with the same kernel are executed together for efficiency.
                            </small>
                        </div>
                    </div>
                `;
            }
            
            // Start polling for results using the master batch ID
            if (data.master_batch_id) {
                // Poll for the master batch status
                pollExecutionStatus(data.master_batch_id, 'step2_kernel_staging');
            }
        } else {
            showToast(data.detail || 'Failed to start kernel staging', 'danger');
            
            // Show error details
            const resultsDiv = document.getElementById('step2-results');
            if (resultsDiv) {
                resultsDiv.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="bi bi-x-circle me-2"></i>
                        ${escapeHtml(data.detail || 'Failed to start kernel staging')}
                    </div>
                `;
            }
        }
    } catch (error) {
        console.error('Error executing Step 2:', error);
        showToast('Failed to execute Step 2: ' + error.message, 'danger');
    } finally {
        // Re-enable the button
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-gear-wide-connected me-2"></i>Stage All Groups';
        }
    }
}

// Use shared escapeHtml function from utils.js
function escapeHtml(unsafe) {
    if (window.Utils && typeof window.Utils.escapeHtml === 'function') {
        return window.Utils.escapeHtml(unsafe);
    }
    // Fallback if Utils not loaded
    if (unsafe == null) return '';
    return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Export functions to window scope
window.populateStep2KernelGroups = populateStep2KernelGroups;
window.toggleInstanceList = toggleInstanceList;
window.executeStep2AllGroups = executeStep2AllGroups;
window.selectGroupForStaging = selectGroupForStaging;