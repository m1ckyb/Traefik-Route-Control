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
});

// Home Assistant Modal functions
function showHassModal(serviceId, event) {
    event.preventDefault();
    
    // Get the service card to extract information
    const serviceCard = document.querySelector(`[data-service-id="${serviceId}"]`);
    const serviceName = serviceCard.querySelector('h3').textContent;
    const serviceNameSlug = serviceName.toLowerCase().replace(/\s+/g, '_');
    
    // Get the base URL from window location
    const baseUrl = window.location.origin;
    
    // Generate the Home Assistant YAML configuration
    const hassConfig = `switch:
  - platform: command_line
    switches:
      traefik_${serviceNameSlug}:
        command_on: "curl -X POST -s ${baseUrl}/api/services/${serviceId}/on"
        command_off: "curl -X POST -s ${baseUrl}/api/services/${serviceId}/off"
        command_state: "curl -s ${baseUrl}/api/status"
        value_template: "{{ value_json.active_services | selectattr('id', 'equalto', ${serviceId}) | list | length > 0 }}"
        friendly_name: "Traefik ${serviceName}"`;
    
    document.getElementById('hassConfig').textContent = hassConfig;
    document.getElementById('hassModal').style.display = 'block';
}

function closeHassModal() {
    document.getElementById('hassModal').style.display = 'none';
}

function copyHassConfig() {
    const config = document.getElementById('hassConfig').textContent;
    navigator.clipboard.writeText(config).then(() => {
        alert('Configuration copied to clipboard!');
    }).catch(err => {
        alert('Failed to copy: ' + err);
    });
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('hassModal');
    if (event.target === modal) {
        closeHassModal();
    }
}

// Copy to clipboard function for regex pattern
function copyToClipboard(text, event) {
    event.preventDefault();
    navigator.clipboard.writeText(text).then(() => {
        alert('Regex pattern copied to clipboard!');
    }).catch(err => {
        alert('Failed to copy: ' + err);
    });
}
