// Service control functions
async function toggleService(serviceId, enable, event) {
    const action = enable ? 'on' : 'off';
    const confirmMsg = enable 
        ? 'Turn on this service and create a new rotating URL?' 
        : 'Turn off this service and close its route?';
    
    if (!confirm(confirmMsg)) return;
    
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = enable ? '⏳ Enabling...' : '⏳ Disabling...';
    
    try {
        const response = await fetch(`/api/services/${serviceId}/${action}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Show success message and reload
            alert(data.message);
            window.location.reload();
        } else {
            alert('Error: ' + (data.error || 'Unknown error occurred'));
            btn.disabled = false;
            btn.textContent = enable ? '🚀 Turn On' : '🛑 Turn Off';
        }
    } catch (error) {
        alert('Error: ' + error.message);
        btn.disabled = false;
        btn.textContent = enable ? '🚀 Turn On' : '🛑 Turn Off';
    }
}

async function rotateService(serviceId, event) {
    if (!confirm('Generate a new rotating URL for this service?')) return;
    
    const btn = event.target;
    btn.disabled = true;
    btn.textContent = '⏳ Rotating...';
    
    try {
        const response = await fetch(`/api/services/${serviceId}/rotate`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            alert(data.message);
            window.location.reload();
        } else {
            alert('Error: ' + (data.error || 'Unknown error occurred'));
            btn.disabled = false;
            btn.textContent = '🔄 Rotate URL';
        }
    } catch (error) {
        alert('Error: ' + error.message);
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
            alert(data.message);
            window.location.reload();
        } else {
            alert('Error: ' + (data.error || 'Unknown error occurred'));
        }
    } catch (error) {
        alert('Error: ' + error.message);
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
        notification.style.opacity = '0';
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
    
    const hassConfig = `switch:
  - platform: command_line
    switches:
      traefik_${serviceNameSlug}:
        command_on: "curl -X POST -s ${baseUrl}/api/services/${serviceId}/on"
        command_off: "curl -X POST -s ${baseUrl}/api/services/${serviceId}/off"
        command_state: "curl -s ${baseUrl}/api/status"
        value_template: "${jinjaOpen} value_json.active_services | selectattr('id', 'equalto', ${serviceId}) | list | length > 0 ${jinjaClose}"
        friendly_name: "Traefik ${safeServiceName}"`;
    
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
    navigator.clipboard.writeText(text).then(() => {
        showNotification(successMessage, 'success');
    }).catch(err => {
        showNotification('Failed to copy: ' + err, 'error');
    });
}
