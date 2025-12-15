// Service control functions
async function toggleService(serviceId, enable, event) {
    const action = enable ? 'on' : 'off';
    
    const switchInput = event.target;
    switchInput.disabled = true;
    
    // Find the parent service card to show a loading state
    const serviceCard = switchInput.closest('.service-card');
    serviceCard.classList.add('loading-state');
    
    try {
        const response = await fetch(`/api/services/${serviceId}/${action}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification(data.message, 'success');
            setTimeout(() => window.location.reload(), 1000);
        } else {
            showNotification('Error: ' + (data.error || 'Unknown error occurred'), 'error');
            // Revert the switch state on failure
            switchInput.checked = !enable;
            switchInput.disabled = false;
            serviceCard.classList.remove('loading-state');
        }
    } catch (error) {
        showNotification('Error: ' + error.message, 'error');
        // Revert the switch state on failure
        switchInput.checked = !enable;
        switchInput.disabled = false;
        serviceCard.classList.remove('loading-state');
    }
}

async function rotateService(serviceId, event) {
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = '⏳ Rotating...';
    
    try {
        const response = await fetch(`/api/services/${serviceId}/rotate`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification(data.message, 'success');
            // Reload after a short delay to show the toast
            setTimeout(() => window.location.reload(), 1000);
        } else {
            showNotification('Error: ' + (data.error || 'Unknown error occurred'), 'error');
            btn.disabled = false;
            btn.textContent = '🔄 Rotate URL';
        }
    } catch (error) {
        showNotification('Error: ' + error.message, 'error');
        btn.disabled = false;
        btn.textContent = '🔄 Rotate URL';
    }
}

async function deleteService(serviceId, serviceName) {
    const confirmMsg = `Are you sure you want to delete "${serviceName}"?\n\nThis action cannot be undone.`;
    if (!confirm(confirmMsg)) return;
    
    try {
        const response = await fetch(`/api/services/${serviceId}`, {
            method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification(data.message, 'success');
            // Reload after a short delay to show the toast
            setTimeout(() => window.location.reload(), 1000);
        } else {
            showNotification('Error: ' + (data.error || 'Unknown error occurred'), 'error');
        }
    } catch (error) {
        showNotification('Error: ' + error.message, 'error');
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
            showNotification('Error: ' + (data.error || 'Unknown error occurred'), 'error');
        }
        
        btn.disabled = false;
        btn.textContent = originalText;
    } catch (error) {
        showNotification('Error: ' + error.message, 'error');
        btn.disabled = false;
        btn.textContent = originalText;
    }
}

async function repairService(serviceId) {
    try {
        const response = await fetch(`/api/services/${serviceId}/repair`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showNotification(data.message, 'success');
            // Close modal and reload after a short delay
            setTimeout(() => {
                closeDiagnosticsModal();
                window.location.reload();
            }, 1500);
        } else {
            showNotification('Error: ' + (data.error || 'Unknown error occurred'), 'error');
        }
    } catch (error) {
        showNotification('Error: ' + error.message, 'error');
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
});

// Show temporary notification
function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type}`;
    notification.textContent = message;
    notification.style.position = 'fixed';
    notification.style.top = '20px';
    notification.style.right = '20px';
    notification.style.zIndex = '10000';
    notification.style.minWidth = '250px';
    notification.style.animation = 'slideIn 0.3s ease-out';
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Home Assistant Modal functions
function showHassModal(serviceId, serviceName) {
    // Sanitize service name for YAML - remove special characters and normalize spaces
    const serviceNameSlug = serviceName.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');
    const safeServiceName = serviceName.replace(/['"]/g, ''); // Remove quotes from display name
    
    // Get the base URL from window location
    const baseUrl = window.location.origin;
    
    // Generate the Home Assistant YAML configuration
    // Build the Jinja2 template string by concatenating parts to avoid template literal interpretation
    const jinjaOpen = '{{';
    const jinjaClose = '}}';
    
    // Note: serviceId is always numeric (INTEGER PRIMARY KEY from database)
    const hassConfig = `- switch:
    command_on: "curl -X POST -s -H 'X-API-Key: your-api-key-here' ${baseUrl}/api/services/${serviceId}/on"
    command_off: "curl -X POST -s -H 'X-API-Key: your-api-key-here' ${baseUrl}/api/services/${serviceId}/off"
    command_state: "curl -s -H 'X-API-Key: your-api-key-here' ${baseUrl}/api/services/${serviceId}/status"
    value_template: "${jinjaOpen} value_json.status == 'ONLINE' ${jinjaClose}"
    unique_id: "traefik_${serviceNameSlug}"
    name: "traefik ${safeServiceName}"`;
    
    document.getElementById('hassConfig').textContent = hassConfig;
    document.getElementById('hassModal').style.display = 'block';
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
            showNotification(successMessage, 'success');
        }).catch(err => {
            showNotification('Failed to copy: ' + err, 'error');
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
            showNotification(successMessage, 'success');
        } catch (err) {
            showNotification('Failed to copy: ' + err, 'error');
        } finally {
            document.body.removeChild(textArea);
        }
    }
}
