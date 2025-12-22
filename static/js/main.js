// Helper to get CSRF token
function getCsrfToken() {
    return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
}

// Service control functions
function updateServiceCard(card, data, enabled) {
    // Update Badge
    const badge = card.querySelector('.status-badge');
    badge.className = 'status-badge'; // Reset classes
    if (enabled) {
        badge.classList.add('status-online');
        badge.textContent = 'ONLINE';
    } else {
        badge.classList.add('status-offline');
        badge.textContent = 'OFFLINE';
    }

    // Update URL Row
    const urlRow = card.querySelector('.current-url-row');
    const urlLink = card.querySelector('.url-link');
    if (enabled && data.url) {
        urlLink.href = data.url;
        urlLink.textContent = data.url;
        urlRow.style.display = 'flex';
    } else {
        urlRow.style.display = 'none';
    }

    // Update Regex Row
    const regexRow = card.querySelector('.regex-row');
    if (regexRow) {
        const regexCode = card.querySelector('.regex-pattern');
        if (enabled && data.regex) {
            regexCode.dataset.regex = data.regex;
            regexCode.textContent = data.regex;
            regexRow.style.display = 'flex';
        } else {
            regexRow.style.display = 'none';
        }
    }

    // Update Actions
    const actions = card.querySelector('.service-actions');
    actions.style.display = enabled ? 'flex' : 'none';
}

function updateServiceHealthUI(serviceId, isHealthy, isOnline) {
    const card = document.querySelector(`.service-card[data-service-id="${serviceId}"]`);
    if (!card) return;

    const badge = card.querySelector('.status-badge');
    const slider = card.querySelector('.slider');

    if (isOnline) {
        if (isHealthy) {
            badge.className = 'status-badge status-online';
            badge.textContent = 'ONLINE';
            slider.classList.remove('slider-error');
        } else {
            badge.className = 'status-badge status-error';
            badge.textContent = 'UNHEALTHY';
            slider.classList.add('slider-error');
        }
    } else {
        badge.className = 'status-badge status-offline';
        badge.textContent = 'OFFLINE';
        slider.classList.remove('slider-error');
    }
}

async function toggleService(serviceId, enable, event) {
    const action = enable ? 'on' : 'off';
    
    const switchInput = event.target;
    switchInput.disabled = true;
    
    // Find the parent service card to show a loading state
    const serviceCard = switchInput.closest('.service-card');
    serviceCard.classList.add('loading-state');
    
    try {
        const response = await fetch(`/api/services/${serviceId}/${action}`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': getCsrfToken()
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(data.message, 'success');
            updateServiceCard(serviceCard, data, enable);
            switchInput.disabled = false;
            
            // Refresh firewall and health status in the UI
            if (window.refreshStatus) {
                window.refreshStatus();
            }
        } else {
            showToast('Error: ' + (data.error || 'Unknown error occurred'), 'error');
            // Revert the switch state on failure
            switchInput.checked = !enable;
            switchInput.disabled = false;
        }
    } catch (error) {
        showToast('Error: ' + error.message, 'error');
        // Revert the switch state on failure
        switchInput.checked = !enable;
        switchInput.disabled = false;
    } finally {
        serviceCard.classList.remove('loading-state');
    }
}

async function rotateService(serviceId, event) {
    const btn = event.target;
    const originalText = btn.textContent; // Save original text
    btn.disabled = true;
    btn.textContent = '⏳ Rotating...';
    
    // Find service card
    const serviceCard = btn.closest('.service-card');
    
    try {
        const response = await fetch(`/api/services/${serviceId}/rotate`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': getCsrfToken()
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(data.message, 'success');
            updateServiceCard(serviceCard, data, true);
        } else {
            showToast('Error: ' + (data.error || 'Unknown error occurred'), 'error');
        }
    } catch (error) {
        showToast('Error: ' + error.message, 'error');
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function deleteService(serviceId, serviceName) {
    const confirmMsg = `Are you sure you want to delete "${serviceName}"?\n\nThis action cannot be undone.`;
    if (!confirm(confirmMsg)) return;
    
    try {
        const response = await fetch(`/api/services/${serviceId}`, {
            method: 'DELETE',
            headers: {
                'X-CSRFToken': getCsrfToken()
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(data.message, 'success');
            // Reload after a short delay to show the toast
            setTimeout(() => window.location.reload(), 1000);
        } else {
            showToast('Error: ' + (data.error || 'Unknown error occurred'), 'error');
        }
    } catch (error) {
        showToast('Error: ' + error.message, 'error');
    }
}

async function diagnoseService(serviceId, event) {
    const btn = event.target;
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = '🔍 Checking...';
    
    try {
        const response = await fetch(`/api/services/${serviceId}/diagnose`, {
            method: 'GET'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showDiagnosticsModal(data);
        } else {
            showToast('Error: ' + (data.error || 'Unknown error occurred'), 'error');
        }
        
        btn.disabled = false;
        btn.textContent = originalText;
    } catch (error) {
        showToast('Error: ' + error.message, 'error');
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function repairService(serviceId) {
    try {
        const response = await fetch(`/api/services/${serviceId}/repair`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': getCsrfToken()
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showToast(data.message, 'success');
            // Close modal and reload after a short delay
            setTimeout(() => {
                closeDiagnosticsModal();
                window.location.reload();
            }, 1500);
        } else {
            showToast('Error: ' + (data.error || 'Unknown error occurred'), 'error');
        }
    } catch (error) {
        showToast('Error: ' + error.message, 'error');
    }
}



function showDiagnosticsModal(diagnostics) {
    const modal = document.getElementById('diagnosticsModal');
    const content = document.getElementById('diagnosticsContent');
    
    let html = `<div class="diagnostics-service-info">
        <h4>${diagnostics.service.name}</h4>
        <p><strong>Status:</strong> ${diagnostics.service.enabled ? 'Enabled' : 'Disabled'}</p>
    </div>`;
    
    html += '<div class="diagnostics-checks">';
    
    for (const [checkName, checkData] of Object.entries(diagnostics.checks)) {
        const statusClass = checkData.status === 'ok' ? 'check-ok' : 
                          checkData.status === 'warning' ? 'check-warning' : 
                          checkData.status === 'fail' ? 'check-fail' : 'check-info';
        
        const statusIcon = checkData.status === 'ok' ? '✅' : 
                         checkData.status === 'warning' ? '⚠️' : 
                         checkData.status === 'fail' ? '❌' : 'ℹ️';
        
        html += `<div class="diagnostic-check ${statusClass}">
            <div class="check-header">
                <span class="check-icon">${statusIcon}</span>
                <strong>${checkName.replace(/_/g, ' ').toUpperCase()}</strong>
            </div>
            <div class="check-message">${checkData.message}</div>`;
        
        // Show additional details if available
        if (checkData.expected || checkData.actual || checkData.port || checkData.hostname || checkData.target_url || checkData.target || checkData.status_code || checkData.error) {
            html += '<div class="check-details">';
            if (checkData.expected) html += `<div>Expected: <code>${checkData.expected}</code></div>`;
            if (checkData.actual) html += `<div>Actual: <code>${checkData.actual}</code></div>`;
            if (checkData.port) html += `<div>Port: <code>${checkData.port}</code></div>`;
            if (checkData.hostname) html += `<div>Hostname: <code>${checkData.hostname}</code></div>`;
            if (checkData.target_url) html += `<div>Target: <code>${checkData.target_url}</code></div>`;
            if (checkData.target) html += `<div>Backend URL: <code>${checkData.target}</code></div>`;
            if (checkData.status_code) html += `<div>Status Code: <code>${checkData.status_code}</code></div>`;
            if (checkData.error) html += `<div>Error: <code>${checkData.error}</code></div>`;
            html += '</div>';
        }
        
        html += '</div>';
    }
    
    html += '</div>';
    
    // Add repair button if there are any warnings or failures
    const hasIssues = Object.values(diagnostics.checks).some(c => c.status === 'warning' || c.status === 'fail');
    if (hasIssues && diagnostics.service.enabled) {
        html += `<div class="diagnostics-actions">
            <button class="btn btn-primary" onclick="repairService(${diagnostics.service.id})">
                🔧 Repair Configuration
            </button>
        </div>`;
    }
    
    content.innerHTML = html;
    modal.style.display = 'block';
}

function closeDiagnosticsModal() {
    document.getElementById('diagnosticsModal').style.display = 'none';
}

// Auto-hide alerts after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });
    
    // Attach event listeners to HA settings buttons
    document.querySelectorAll('.btn-icon[data-service-id]').forEach(button => {
        button.addEventListener('click', function(event) {
            event.preventDefault();
            showHassModal(this.dataset.serviceId, this.dataset.serviceName);
        });
    });
    
    // Attach event listeners to regex patterns
    document.querySelectorAll('.regex-pattern[data-regex]').forEach(element => {
        // Populate the visible text from data attribute to avoid duplication
        element.textContent = element.dataset.regex;
        
        element.addEventListener('click', function(event) {
            event.preventDefault();
            copyToClipboard(this.dataset.regex, 'Regex pattern copied to clipboard!');
        });
    });
    
    // Attach event listener to modal close button
    const modalCloseBtn = document.getElementById('modal-close-btn');
    if (modalCloseBtn) {
        modalCloseBtn.addEventListener('click', closeHassModal);
    }
    
    // Attach event listener to copy button in modal
    const copyHassConfigBtn = document.getElementById('copy-hass-config-btn');
    if (copyHassConfigBtn) {
        copyHassConfigBtn.addEventListener('click', copyHassConfig);
    }
    
    // Attach event listener to Base URL input
    const hassBaseUrlInput = document.getElementById('hass-base-url');
    if (hassBaseUrlInput) {
        hassBaseUrlInput.addEventListener('input', updateHassConfig);
    }
    
    // Attach event listener to API Key Select
    const hassApiKeySelect = document.getElementById('hass-api-key-select');
    if (hassApiKeySelect) {
        hassApiKeySelect.addEventListener('change', function() {
            // Reset authorization when selection changes
            window.authorizedApiKey = null;
            updateHassConfig();
        });
    }
});

// Home Assistant Modal functions
function showHassModal(serviceId, serviceName) {
    const modal = document.getElementById('hassModal');
    
    // Store context in modal dataset
    modal.dataset.serviceId = serviceId;
    modal.dataset.serviceName = serviceName;
    
    // Reset Authorized Key
    window.authorizedApiKey = null;
    const keySelect = document.getElementById('hass-api-key-select');
    if (keySelect) keySelect.value = "";
    
    // Set default Base URL if empty
    const baseUrlInput = document.getElementById('hass-base-url');
    if (!baseUrlInput.value) {
        baseUrlInput.value = window.location.origin;
    }
    
    updateHassConfig();
    
    modal.style.display = 'block';
}

async function saveHassBaseUrl() {
    const baseUrl = document.getElementById('hass-base-url').value.trim();
    if (!baseUrl) {
        showToast('Base URL cannot be empty', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/api/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({
                key: 'HASS_BASE_URL',
                value: baseUrl
            })
        });
        
        const data = await response.json();
        if (response.ok) {
            showToast('Base URL saved as default', 'success');
            updateHassConfig();
        } else {
            showToast('Error: ' + data.error, 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

function updateHassConfig() {
    const modal = document.getElementById('hassModal');
    const serviceId = modal.dataset.serviceId;
    const serviceName = modal.dataset.serviceName;
    const baseUrl = document.getElementById('hass-base-url').value.replace(/\/$/, ''); // Remove trailing slash
    
    // Determine API Key placeholder
    let apiKeyPlaceholder = 'your-api-key-here';
    if (window.authorizedApiKey) {
        // Since we can't retrieve the actual key, we use the name with a clear indicator
        apiKeyPlaceholder = `<${window.authorizedApiKey}>`;
    }
    
    // Sanitize service name for YAML - remove special characters and normalize spaces
    const serviceNameSlug = serviceName.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');
    const safeServiceName = serviceName.replace(/['"]/g, ''); // Remove quotes from display name
    
    // Generate the Home Assistant YAML configuration
    const jinjaOpen = '{{';
    const jinjaClose = '}}';
    
    // Note: serviceId is always numeric (INTEGER PRIMARY KEY from database)
    const hassConfig = `- switch:
    command_on: "curl -X POST -s -H 'X-API-Key: ${apiKeyPlaceholder}' ${baseUrl}/api/services/${serviceId}/on"
    command_off: "curl -X POST -s -H 'X-API-Key: ${apiKeyPlaceholder}' ${baseUrl}/api/services/${serviceId}/off"
    command_state: "curl -s -H 'X-API-Key: ${apiKeyPlaceholder}' ${baseUrl}/api/services/${serviceId}/status"
    value_template: "${jinjaOpen} value_json.status == 'ONLINE' ${jinjaClose}"
    unique_id: "traefik_${serviceNameSlug}"
    name: "traefik ${safeServiceName}"`;
    
    document.getElementById('hassConfig').textContent = hassConfig;
}

function closeHassModal() {
    document.getElementById('hassModal').style.display = 'none';
}

function copyHassConfig() {
    const config = document.getElementById('hassConfig').textContent;
    copyToClipboard(config, 'Configuration copied to clipboard!');
}

// Close modal when clicking outside
window.addEventListener('click', function(event) {
    const hassModal = document.getElementById('hassModal');
    const diagnosticsModal = document.getElementById('diagnosticsModal');
    
    if (event.target === hassModal) {
        closeHassModal();
    }
    
    if (event.target === diagnosticsModal) {
        closeDiagnosticsModal();
    }
});

// Copy to clipboard function
function copyToClipboard(text, successMessage) {
    // Modern clipboard API
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            showToast(successMessage, 'success');
        }).catch(err => {
            showToast('Failed to copy: ' + err, 'error');
        });
    } else {
        // Fallback for older browsers or non-HTTPS contexts
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        document.body.appendChild(textArea);
        textArea.select();
        
        try {
            document.execCommand('copy');
            showToast(successMessage, 'success');
        } catch (err) {
            showToast('Failed to copy: ' + err, 'error');
        } finally {
            document.body.removeChild(textArea);
        }
    }
}

// Re-auth and API Key functions
function authorizeApiKey() {
    const select = document.getElementById('hass-api-key-select');
    const selectedKey = select.value;
    
    if (!selectedKey) {
        showToast('Please select an API Key first', 'warning');
        return;
    }
    
    // Open re-auth modal
    document.getElementById('reauth-password').value = '';
    document.getElementById('reauthModal').style.display = 'flex';
    document.getElementById('reauth-password').focus();
}

function closeReauthModal() {
    document.getElementById('reauthModal').style.display = 'none';
}

async function confirmReauth() {
    const password = document.getElementById('reauth-password').value;
    if (!password) return;
    
    try {
        const response = await fetch('/api/auth/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ password: password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Success
            const select = document.getElementById('hass-api-key-select');
            window.authorizedApiKey = select.value;
            updateHassConfig();
            closeReauthModal();
            showToast('Identity verified. Key placeholder updated.', 'success');
            
            // Add a note about hidden values
            setTimeout(() => {
                showToast('Note: Actual key values are hidden for security.', 'info');
            }, 2000);
        } else {
            showToast('Error: ' + (data.error || 'Verification failed'), 'error');
        }
    } catch (e) {
        showToast('Error: ' + e.message, 'error');
    }
}

// Allow Enter key in re-auth modal
document.addEventListener('DOMContentLoaded', function() {
    const reauthPwd = document.getElementById('reauth-password');
    if (reauthPwd) {
        reauthPwd.addEventListener('keyup', function(event) {
            if (event.key === 'Enter') {
                confirmReauth();
            }
        });
    }
});
