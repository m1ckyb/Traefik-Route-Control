// Service control functions
async function toggleService(serviceId, enable, event) {
    const action = enable ? 'on' : 'off';
    
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = enable ? '⏳ Enabling...' : '⏳ Disabling...';
    
    try {
        const response = await fetch(`/api/services/${serviceId}/${action}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Show success toast notification
            showNotification(data.message, 'success');
            // Reload after a short delay to show the toast
            setTimeout(() => window.location.reload(), 1000);
        } else {
            showNotification('Error: ' + (data.error || 'Unknown error occurred'), 'error');
            btn.disabled = false;
            btn.textContent = enable ? '🚀 Turn On' : '🛑 Turn Off';
        }
    } catch (error) {
        showNotification('Error: ' + error.message, 'error');
        btn.disabled = false;
        btn.textContent = enable ? '🚀 Turn On' : '🛑 Turn Off';
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
    const modal = document.getElementById('hassModal');
    if (event.target === modal) {
        closeHassModal();
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
