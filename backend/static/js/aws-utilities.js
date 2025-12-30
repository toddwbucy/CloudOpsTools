// AWS Script Runner Utility Functions

// Show toast notification with safe content insertion
window.showToast = function(message, type = 'info') {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show position-fixed top-0 end-0 m-3`;
    alertDiv.style.zIndex = '9999';
    
    // Safely set the message text
    const messageSpan = document.createElement('span');
    messageSpan.textContent = message;
    alertDiv.appendChild(messageSpan);
    
    // Add close button
    const closeButton = document.createElement('button');
    closeButton.type = 'button';
    closeButton.className = 'btn-close';
    closeButton.setAttribute('data-bs-dismiss', 'alert');
    alertDiv.appendChild(closeButton);
    
    document.body.appendChild(alertDiv);
    setTimeout(() => alertDiv.remove(), 5000);
}

// Toggle input method for credential forms
window.toggleInputMethod = function(env) {
    const singleInput = document.getElementById(`${env}-single-input`);
    const individualFields = document.getElementById(`${env}-individual-fields`);
    const singleRadio = document.getElementById(`${env}-single-radio`);
    
    if (singleRadio && singleRadio.checked) {
        if (singleInput) singleInput.style.display = 'block';
        if (individualFields) individualFields.style.display = 'none';
    } else {
        if (singleInput) singleInput.style.display = 'none';
        if (individualFields) individualFields.style.display = 'block';
    }
}

// Manual instance management
window.addManualInstance = function() {
    const instanceId = document.getElementById('manual-instance-id').value;
    const accountId = document.getElementById('manual-account-id').value;
    const region = document.getElementById('manual-region').value;
    const platform = document.getElementById('manual-platform').value;
    
    if (!instanceId || !accountId || !region || !platform) {
        showToast('Please fill all instance fields', 'warning');
        return;
    }
    
    // Add defensive checks for ScriptRunnerState
    if (typeof ScriptRunnerState === 'undefined') {
        showToast('Script runner state not initialized', 'danger');
        return;
    }
    
    // Initialize manualInstances if it doesn't exist
    if (!ScriptRunnerState.manualInstances) {
        ScriptRunnerState.manualInstances = [];
    }
    
    // Check for duplicate instance ID
    const isDuplicate = ScriptRunnerState.manualInstances.some(
        instance => instance.instance_id === instanceId
    );
    
    if (isDuplicate) {
        showToast('Instance ID already exists in the list', 'warning');
        return;
    }
    
    ScriptRunnerState.manualInstances.push({
        instance_id: instanceId,
        account_id: accountId,
        region: region,
        platform: platform,
        environment: region.includes('gov') ? 'gov' : 'com'
    });
    
    showToast('Instance added', 'success');
    
    // Clear fields
    document.getElementById('manual-instance-id').value = '';
    document.getElementById('manual-account-id').value = '';
    document.getElementById('manual-region').value = '';
    document.getElementById('manual-platform').value = '';
    
    // Update preview
    updateManualInstancesPreview();
    
    // Enable save button
    const saveBtn = document.getElementById('save-change-btn');
    if (saveBtn) saveBtn.disabled = false;
}

// Update manual instances preview
window.updateManualInstancesPreview = function() {
    const preview = document.getElementById('manual-instances-preview');
    const list = document.getElementById('manual-instances-list');
    
    if (!preview || !list) return;
    
    if (ScriptRunnerState.manualInstances.length === 0) {
        preview.style.display = 'none';
        return;
    }
    
    preview.style.display = 'block';
    list.innerHTML = ScriptRunnerState.manualInstances.map((inst, idx) => `
        <div class="mb-2 p-2 bg-light rounded">
            <div class="d-flex justify-content-between align-items-center">
                <div>
                    <strong>${inst.instance_id}</strong><br>
                    <small class="text-muted">${inst.account_id} | ${inst.region} | ${inst.platform}</small>
                </div>
                <button type="button" class="btn btn-sm btn-danger" onclick="removeManualInstance(${idx})">
                    <i class="bi bi-x"></i>
                </button>
            </div>
        </div>
    `).join('');
}

// Remove manual instance
window.removeManualInstance = function(index) {
    ScriptRunnerState.manualInstances.splice(index, 1);
    updateManualInstancesPreview();
    
    if (ScriptRunnerState.manualInstances.length === 0) {
        const saveBtn = document.getElementById('save-change-btn');
        if (saveBtn) saveBtn.disabled = true;
    }
}

// Initialize utilities
document.addEventListener('DOMContentLoaded', function() {
    // Any initialization code for utilities can go here
});