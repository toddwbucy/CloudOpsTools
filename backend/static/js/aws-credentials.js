// AWS Credentials Management Module
// Uses shared utilities from utils.js for escapeHtml and other common functions

// Clear sensitive data from memory
function clearSensitiveData(formElements) {
    if (formElements.accessKey) formElements.accessKey.value = '';
    if (formElements.secretKey) formElements.secretKey.value = '';
    if (formElements.sessionToken) formElements.sessionToken.value = '';
}

// Toggle credential form visibility
window.toggleCredentialForm = function(env) {
    console.log(`Toggling credential form for ${env}`);
    
    const collapseEl = document.getElementById(`${env}-credential-collapse`);
    const chevron = document.getElementById(`${env}-chevron`);
    
    if (!collapseEl) {
        console.error(`Collapse element not found for ${env}`);
        return;
    }
    
    // Check if Bootstrap is available
    if (typeof bootstrap !== 'undefined' && bootstrap.Collapse) {
        try {
            const bsCollapse = bootstrap.Collapse.getInstance(collapseEl) || new bootstrap.Collapse(collapseEl, {toggle: false});
            bsCollapse.toggle();
            
            // Update chevron
            if (collapseEl.classList.contains('show')) {
                chevron.classList.remove('bi-chevron-up');
                chevron.classList.add('bi-chevron-down');
            } else {
                chevron.classList.remove('bi-chevron-down');
                chevron.classList.add('bi-chevron-up');
            }
        } catch (e) {
            console.error('Bootstrap error:', e);
            manualToggle();
        }
    } else if (typeof $ !== 'undefined') {
        // Try jQuery
        try {
            $(collapseEl).collapse('toggle');
            
            // Update chevron based on state after a short delay
            setTimeout(() => {
                if ($(collapseEl).hasClass('show')) {
                    chevron.classList.remove('bi-chevron-down');
                    chevron.classList.add('bi-chevron-up');
                } else {
                    chevron.classList.remove('bi-chevron-up');
                    chevron.classList.add('bi-chevron-down');
                }
            }, 350);
        } catch (e) {
            console.error('jQuery error:', e);
            manualToggle();
        }
    } else {
        manualToggle();
    }
    
    function manualToggle() {
        // Manual toggle as last resort
        if (collapseEl.classList.contains('show')) {
            collapseEl.classList.remove('show');
            collapseEl.style.display = 'none';
            chevron.classList.remove('bi-chevron-up');
            chevron.classList.add('bi-chevron-down');
        } else {
            collapseEl.classList.add('show');
            collapseEl.style.display = 'block';
            chevron.classList.remove('bi-chevron-down');
            chevron.classList.add('bi-chevron-up');
        }
    }
}

// Helper function to parse JSON credentials
function parseJSON(text) {
    try {
        const data = JSON.parse(text);
        return {
            accessKey: data.AccessKeyId || data.aws_access_key_id || data.accessKeyId || '',
            secretKey: data.SecretAccessKey || data.aws_secret_access_key || data.secretAccessKey || '',
            sessionToken: data.SessionToken || data.aws_session_token || data.sessionToken || ''
        };
    } catch (e) {
        return null;
    }
}

// Helper function to parse INI/config format credentials
function parseINI(text) {
    const result = { accessKey: '', secretKey: '', sessionToken: '' };
    const lines = text.split('\n');
    
    for (const line of lines) {
        const cleanLine = line.trim();
        if (cleanLine.includes('aws_access_key_id') || cleanLine.includes('AccessKeyId')) {
            result.accessKey = cleanLine.split('=')[1]?.trim() || '';
        } else if (cleanLine.includes('aws_secret_access_key') || cleanLine.includes('SecretAccessKey')) {
            result.secretKey = cleanLine.split('=')[1]?.trim() || '';
        } else if (cleanLine.includes('aws_session_token') || cleanLine.includes('SessionToken')) {
            result.sessionToken = cleanLine.split('=')[1]?.trim() || '';
        }
    }
    
    return result;
}

// Helper function to parse space/line separated credentials
function parseSpaceSeparated(text) {
    const parts = text.replace(/\s+/g, ' ').trim().split(/[\s\n]+/);
    const result = { accessKey: '', secretKey: '', sessionToken: '' };
    
    // Look for AWS access key pattern (starts with ASIA or AKIA)
    let accessKeyIndex = -1;
    for (let i = 0; i < parts.length; i++) {
        if (parts[i].match(/^(ASIA|AKIA)[A-Z0-9]{16}$/)) {
            accessKeyIndex = i;
            result.accessKey = parts[i];
            break;
        }
    }
    
    if (accessKeyIndex >= 0 && parts.length >= accessKeyIndex + 2) {
        result.secretKey = parts[accessKeyIndex + 1];
        if (parts.length > accessKeyIndex + 2) {
            // Join remaining parts for session token
            result.sessionToken = parts.slice(accessKeyIndex + 2).join('');
        }
    } else {
        // Fallback: take first 3 non-empty parts
        const nonEmptyParts = parts.filter(p => p.length > 0);
        if (nonEmptyParts.length >= 2) {
            result.accessKey = nonEmptyParts[0];
            result.secretKey = nonEmptyParts[1];
            if (nonEmptyParts.length >= 3) {
                result.sessionToken = nonEmptyParts.slice(2).join('');
            }
        }
    }
    
    return result;
}

// Parse credentials with enhanced security and refactored logic
function parseCredentials(env) {
    const singleTextElement = document.getElementById(`${env}-single-credentials`);
    if (!singleTextElement) {
        showToast('Credential input element not found', 'warning');
        return;
    }
    
    const singleText = singleTextElement.value.trim();
    if (!singleText) {
        showToast('Please paste some credentials first', 'warning');
        return;
    }
    
    let accessKey = '';
    let secretKey = '';
    let sessionToken = '';
    
    try {
        let credentials = null;
        
        // Try parsing as JSON first (no need to sanitize before JSON.parse)
        if (singleText.trim().startsWith('{') || (singleText.trim().startsWith('[') && singleText.includes('{'))) {
            credentials = parseJSON(singleText);
        }
        
        // Try INI/config format if JSON failed
        if (!credentials && (singleText.includes('aws_access_key_id') || singleText.includes('AccessKeyId'))) {
            credentials = parseINI(singleText);
        }
        
        // Try space/line separated format as fallback
        if (!credentials) {
            credentials = parseSpaceSeparated(singleText);
        }
        
        if (!credentials || (!credentials.accessKey && !credentials.secretKey)) {
            showToast('Could not parse credentials. Please check the format.', 'warning');
            return;
        }
        
        // Sanitize the extracted values before using them
        accessKey = window.Utils.sanitizeInput(credentials.accessKey);
        secretKey = window.Utils.sanitizeInput(credentials.secretKey);
        sessionToken = window.Utils.sanitizeInput(credentials.sessionToken);
        
        // Fill the individual fields
        const accessKeyEl = document.getElementById(`${env}-access-key`);
        const secretKeyEl = document.getElementById(`${env}-secret-key`);
        const sessionTokenEl = document.getElementById(`${env}-session-token`);
        
        if (accessKey && accessKeyEl) accessKeyEl.value = accessKey;
        if (secretKey && secretKeyEl) secretKeyEl.value = secretKey;
        if (sessionToken && sessionTokenEl) sessionTokenEl.value = sessionToken;
        
        // Switch to individual fields view
        const individualFieldsEl = document.getElementById(`${env}-individual-fields`);
        if (individualFieldsEl) {
            individualFieldsEl.checked = true;
            toggleInputMethod(env);
        }
        
        // Clear the original input for security
        singleTextElement.value = '';
        
        if (accessKey && secretKey && sessionToken) {
            showToast('Credentials parsed successfully!', 'success');
        } else {
            showToast('Could not parse all required fields', 'warning');
        }
    } catch (error) {
        // Don't expose sensitive error details
        console.error('Credential parsing error');
        showToast('Error parsing credentials. Please check the format.', 'danger');
    }
}

// Parse COM credentials
window.parseComCredentials = function() {
    parseCredentials('com');
}

// Parse GOV credentials
window.parseGovCredentials = function() {
    parseCredentials('gov');
}

// Update credentials
window.updateCredentials = async function(env, form) {
    try {
        // Always parse the single input first
        parseCredentials(env);
        
        // Get form data
        const formData = new FormData(form);
        
        // Add single credential block (already sanitized)
        const singleTextEl = document.getElementById(`${env}-single-credentials`);
        if (singleTextEl) {
            formData.append(`${env}_credentials_block`, ''); // Already cleared after parsing
        }
        
        // Submit AWS credentials to the accounts endpoint with CSRF protection
        const csrfHeaders = window.Utils.buildCsrfHeaders();
        const response = await fetch('/aws/script-runner/accounts', {
            method: 'POST',
            headers: csrfHeaders,
            body: formData,
            credentials: 'same-origin'
        });
        
        // Clear sensitive form data
        const accessKeyEl = document.getElementById(`${env}-access-key`);
        const secretKeyEl = document.getElementById(`${env}-secret-key`);
        const sessionTokenEl = document.getElementById(`${env}-session-token`);
        clearSensitiveData({
            accessKey: accessKeyEl,
            secretKey: secretKeyEl,
            sessionToken: sessionTokenEl
        });
        
        if (response.ok) {
            showToast(`${env.toUpperCase()} credentials updated successfully!`, 'success');
            // Reload page to reflect new credential status
            setTimeout(() => location.reload(), 1000);
        } else {
            const data = await response.json();
            // Don't expose sensitive error details
            showToast(`Failed to update ${env.toUpperCase()} credentials`, 'danger');
        }
    } catch (error) {
        // Don't expose sensitive error details
        console.error('Credential update error');
        showToast(`Error updating credentials`, 'danger');
    }
}

// Initialize credential management
document.addEventListener('DOMContentLoaded', function() {
    // Setup chevron rotation for collapse events
    const comCollapse = document.getElementById('com-credential-collapse');
    const govCollapse = document.getElementById('gov-credential-collapse');
    const comChevron = document.getElementById('com-chevron');
    const govChevron = document.getElementById('gov-chevron');
    
    if (comCollapse && comChevron) {
        comCollapse.addEventListener('show.bs.collapse', function () {
            comChevron.classList.remove('bi-chevron-down');
            comChevron.classList.add('bi-chevron-up');
        });
        comCollapse.addEventListener('hide.bs.collapse', function () {
            comChevron.classList.remove('bi-chevron-up');
            comChevron.classList.add('bi-chevron-down');
        });
    }
    
    if (govCollapse && govChevron) {
        govCollapse.addEventListener('show.bs.collapse', function () {
            govChevron.classList.remove('bi-chevron-down');
            govChevron.classList.add('bi-chevron-up');
        });
        govCollapse.addEventListener('hide.bs.collapse', function () {
            govChevron.classList.remove('bi-chevron-up');
            govChevron.classList.add('bi-chevron-down');
        });
    }
    
    // Bind form handlers
    const comForm = document.getElementById('com-update-form');
    const govForm = document.getElementById('gov-update-form');
    
    if (comForm) {
        comForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            await updateCredentials('com', comForm);
        });
    }
    
    if (govForm) {
        govForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            await updateCredentials('gov', govForm);
        });
    }
});