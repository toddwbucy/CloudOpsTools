// AWS Change Management Module
// Uses shared utilities from utils.js for escapeHtml and other common functions

// Load existing changes into dropdown
window.loadExistingChanges = async function() {
    try {
        const response = await fetch('/aws/script-runner/list-changes', {
            credentials: 'same-origin'
        });
        if (response.ok) {
            const changes = await response.json();
            const select = document.getElementById('existing-change-select');
            if (select) {
                select.innerHTML = '<option value="">Select a change...</option>';
                changes.forEach(change => {
                    const option = document.createElement('option');
                    option.value = change.id;
                    option.textContent = `${change.number} - ${change.instance_count} instances`;
                    select.appendChild(option);
                });
            }
        }
    } catch (error) {
        console.error('Error loading changes:', error);
        showToast('Error loading changes. Please refresh the page.', 'danger');
    }
}

// Load a specific change
window.loadChange = async function() {
    const changeId = document.getElementById('existing-change-select').value;
    if (!changeId) {
        showToast('Please select a change', 'warning');
        return;
    }
    
    try {
        const response = await fetch(`/aws/script-runner/load-change/${changeId}`, {
            method: 'POST',
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            const data = await response.json();
            console.log('Change data received:', data);
            
            if (data.status === 'success') {
                updateChangeDisplay(data);
                showToast('Change loaded successfully', 'success');
            } else {
                showToast('Failed to load change: ' + (data.detail || 'Unknown error'), 'danger');
            }
        } else {
            showToast('Failed to load change', 'danger');
        }
    } catch (error) {
        console.error('Error loading change:', error);
        showToast('Error loading change. Please try again.', 'danger');
    }
}

// Update change display
window.updateChangeDisplay = function(data) {
    ScriptRunnerState.currentChange = data.change;
    
    if (!ScriptRunnerState.currentChange) {
        const instanceList = document.getElementById('instance-list');
        if (instanceList) {
            instanceList.innerHTML = '<p class="text-muted text-center">No instances loaded</p>';
        }
        return;
    }
    
    // Update header badge
    const changeBadge = document.getElementById('current-change-badge');
    if (changeBadge) {
        changeBadge.innerHTML = `
            <span class="badge bg-success fs-5">
                <i class="bi bi-file-earmark-check me-1"></i>
                Change: ${ScriptRunnerState.currentChange.number || 'None'}
            </span>
        `;
    }
    
    // Update instance list
    updateInstanceList(data.instances || []);
    
    // Update selected instances set
    if (data.selected_instances) {
        // Convert array of instance objects to Set of instance IDs
        if (data.selected_instances.length > 0 && typeof data.selected_instances[0] === 'object') {
            ScriptRunnerState.selectedInstances = new Set(
                data.selected_instances.map(inst => inst.instance_id)
            );
        } else {
            ScriptRunnerState.selectedInstances = new Set(data.selected_instances);
        }
    }
    
    // Show scripts and execution sections
    const sections = ['scripts-section', 'execution-section', 'results-section'];
    sections.forEach(sectionId => {
        const section = document.getElementById(sectionId);
        if (section) section.style.display = 'block';
    });
    
    // Update scripts if they're included in the response
    if (data.scripts && data.scripts.length > 0) {
        updateScriptList(data.scripts);
    } else {
        // Always load scripts for this change
        loadScripts();
    }
}

// Update instance list display
window.updateInstanceList = function(instances) {
    const listDiv = document.getElementById('instance-list');
    const countBadge = document.getElementById('instance-count');
    
    if (countBadge) countBadge.textContent = instances.length;
    
    if (!listDiv) return;
    
    if (instances.length === 0) {
        listDiv.innerHTML = '<p class="text-muted text-center">No instances in this change</p>';
        return;
    }
    
    let html = `
        <div class="mb-2">
            <div class="input-group mb-2">
                <span class="input-group-text"><i class="bi bi-search"></i></span>
                <input type="text" class="form-control" id="instance-search" placeholder="Search instances..." 
                       onkeyup="filterInstances()">
            </div>
            <button class="btn btn-sm btn-outline-primary me-2" onclick="selectAllInstances()">
                <i class="bi bi-check-square me-1"></i>Select All
            </button>
            <button class="btn btn-sm btn-outline-secondary" onclick="deselectAllInstances()">
                <i class="bi bi-square me-1"></i>Deselect All
            </button>
        </div>
        <div class="table-responsive">
            <table class="table table-sm">
                <thead>
                    <tr>
                        <th style="width: 40px;">
                            <input type="checkbox" class="form-check-input" id="select-all-checkbox" 
                                   onchange="toggleAllInstances(this)">
                        </th>
                        <th>Instance ID</th>
                        <th>Name</th>
                        <th>State</th>
                        <th>Account</th>
                        <th>Region</th>
                    </tr>
                </thead>
                <tbody id="instance-tbody">
    `;
    
    instances.forEach((instance, index) => {
        const instanceId = instance.instance_id || instance.InstanceId;
        const name = instance.name || instance.Name || '-';
        const state = instance.state || instance.State || 'unknown';
        const account = instance.account_alias || instance.account_id || '-';
        const region = instance.region || '-';
        const isChecked = ScriptRunnerState.selectedInstances.has(instanceId) ? 'checked' : '';
        
        const stateClass = state === 'running' ? 'text-success' : 
                          state === 'stopped' ? 'text-danger' : 'text-warning';
        
        html += `
            <tr class="instance-row" data-instance-id="${window.Utils.escapeHtml(instanceId)}">
                <td>
                    <input type="checkbox" class="form-check-input instance-checkbox" 
                           value="${window.Utils.escapeHtml(instanceId)}" ${isChecked}
                           onchange="toggleInstance('${window.Utils.escapeHtml(instanceId)}')">
                </td>
                <td><code>${window.Utils.escapeHtml(instanceId)}</code></td>
                <td>${window.Utils.escapeHtml(name)}</td>
                <td><span class="${stateClass}">${window.Utils.escapeHtml(state)}</span></td>
                <td>${window.Utils.escapeHtml(account)}</td>
                <td>${window.Utils.escapeHtml(region)}</td>
            </tr>
        `;
    });
    
    html += `
                </tbody>
            </table>
        </div>
    `;
    
    listDiv.innerHTML = html;
}

// Toggle instance selection
window.toggleInstance = function(instanceId) {
    if (ScriptRunnerState.selectedInstances.has(instanceId)) {
        ScriptRunnerState.selectedInstances.delete(instanceId);
    } else {
        ScriptRunnerState.selectedInstances.add(instanceId);
    }
    updateSelectedCount();
}

// Toggle all instances
window.toggleAllInstances = function(checkbox) {
    const checkboxes = document.querySelectorAll('.instance-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = checkbox.checked;
        const instanceId = cb.value;
        if (checkbox.checked) {
            ScriptRunnerState.selectedInstances.add(instanceId);
        } else {
            ScriptRunnerState.selectedInstances.delete(instanceId);
        }
    });
    updateSelectedCount();
}

// Select all visible instances
window.selectAllInstances = function() {
    const checkboxes = document.querySelectorAll('.instance-row:not([style*="display: none"]) .instance-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = true;
        ScriptRunnerState.selectedInstances.add(cb.value);
    });
    updateSelectedCount();
}

// Deselect all visible instances
window.deselectAllInstances = function() {
    const checkboxes = document.querySelectorAll('.instance-row:not([style*="display: none"]) .instance-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = false;
        ScriptRunnerState.selectedInstances.delete(cb.value);
    });
    updateSelectedCount();
}

// Filter instances based on search
window.filterInstances = function() {
    const searchTerm = document.getElementById('instance-search').value.toLowerCase();
    const rows = document.querySelectorAll('.instance-row');
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(searchTerm) ? '' : 'none';
    });
}

// Update selected instance count
window.updateSelectedCount = function() {
    const selectedCount = ScriptRunnerState.selectedInstances.size;
    const badge = document.getElementById('selected-count');
    if (badge) {
        badge.textContent = selectedCount;
    }
}

// Upload CSV file
window.uploadCSV = async function(event) {
    event.preventDefault();
    
    const fileInput = document.getElementById('csv-file');
    if (!fileInput.files[0]) {
        showToast('Please select a CSV file', 'warning');
        return;
    }
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    
    try {
        const response = await fetch('/aws/script-runner/upload-csv', {
            method: 'POST',
            body: formData,
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            const data = await response.json();
            updateChangeDisplay(data);
            showToast('CSV uploaded successfully', 'success');
            fileInput.value = '';
        } else {
            const error = await response.json();
            showToast('Upload failed: ' + (error.detail || 'Unknown error'), 'danger');
        }
    } catch (error) {
        console.error('Error uploading CSV:', error);
        showToast('Error uploading CSV. Please try again.', 'danger');
    }
}

// Save manual change
window.saveManualChange = async function(event) {
    event.preventDefault();
    
    const changeNumber = document.getElementById('manual-change-number').value;
    const instanceIds = document.getElementById('manual-instance-ids').value
        .split(/[\n,]/)
        .map(id => id.trim())
        .filter(id => id);
    
    if (!changeNumber || instanceIds.length === 0) {
        showToast('Please enter change number and at least one instance ID', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/aws/script-runner/save-manual-change', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                change_number: changeNumber,
                instance_ids: instanceIds
            }),
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            const data = await response.json();
            updateChangeDisplay(data);
            showToast('Change saved successfully', 'success');
            document.getElementById('manual-change-form').reset();
        } else {
            const error = await response.json();
            showToast('Save failed: ' + (error.detail || 'Unknown error'), 'danger');
        }
    } catch (error) {
        console.error('Error saving change:', error);
        showToast('Error saving change. Please try again.', 'danger');
    }
}

// Initialize change management
document.addEventListener('DOMContentLoaded', async function() {
    // Load existing changes for dropdown
    loadExistingChanges();
    
    // Check if we have a current change in session
    try {
        const response = await fetch('/aws/script-runner/get-current-change', {
            credentials: 'same-origin'
        });
        if (response.ok) {
            const data = await response.json();
            if (data.change && data.change.number) {
                updateChangeDisplay(data);
            } else {
                // No change in session, show placeholder
                const changeBadge = document.getElementById('current-change-badge');
                if (changeBadge) {
                    changeBadge.innerHTML = `
                        <span class="badge bg-secondary fs-5">
                            <i class="bi bi-file-earmark me-1"></i>
                            Change: None
                        </span>
                    `;
                }
            }
        }
    } catch (error) {
        console.error('Error checking session:', error);
    }
    
    // Initialize form handlers
    const csvForm = document.getElementById('csv-upload-form');
    const manualForm = document.getElementById('manual-change-form');
    
    if (csvForm) {
        csvForm.addEventListener('submit', uploadCSV);
    }
    
    if (manualForm) {
        manualForm.addEventListener('submit', saveManualChange);
    }
});