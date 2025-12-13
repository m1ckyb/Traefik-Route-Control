#!/usr/bin/env python3
import redis
import requests
import random
import string
import os
import sys
import argparse
import urllib3
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash
import database as db

# Suppress InsecureRequestWarning for UniFi self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIGURATION =================
script_dir = os.path.dirname(os.path.abspath(__file__))

# Initialize database
db.init_db()

# Try to load from .env file if exists (for migration)
env_path = os.path.join(script_dir, ".env")
if os.path.exists(env_path):
    load_dotenv(env_path)
    # Migrate settings from .env to database
    migrate_env_to_db()

def migrate_env_to_db():
    """Migrate settings from .env file to database (one-time)."""
    env_keys = [
        "CF_API_TOKEN", "CF_ZONE_ID", "DOMAIN_ROOT", "ORIGIN_RULE_NAME",
        "REDIS_HOST", "REDIS_PORT", "REDIS_PASS",
        "HASS_URL", "HASS_ENTITY_ID", "HASS_TOKEN",
        "UNIFI_HOST", "UNIFI_USER", "UNIFI_PASS", "UNIFI_RULE_NAME"
    ]
    
    migrated = False
    for key in env_keys:
        value = os.getenv(key)
        if value and not db.get_setting(key):
            db.set_setting(key, value)
            migrated = True
    
    # Migrate single service to database if env vars exist
    router_name = os.getenv("ROUTER_NAME")
    service_name = os.getenv("SERVICE_NAME")
    target_url = os.getenv("TARGET_INT_URL")
    
    if router_name and service_name and target_url:
        services = db.get_all_services()
        if not services:
            # Create default service from env
            db.add_service(
                name="Jellyfin",
                router_name=router_name,
                service_name=service_name,
                target_url=target_url,
                subdomain_prefix="jf"
            )
            migrated = True
    
    if migrated:
        print("✅ Migrated settings from .env to database")

def get_setting(key, required=True):
    """Get a setting from database."""
    value = db.get_setting(key)
    if not value and required:
        print(f"❌ Configuration Error: '{key}' is missing from settings")
        if key in ["CF_API_TOKEN", "CF_ZONE_ID", "DOMAIN_ROOT", "REDIS_HOST", 
                   "UNIFI_HOST", "UNIFI_USER", "UNIFI_PASS", "UNIFI_RULE_NAME"]:
            print(f"   Please configure settings via the web UI at /settings")
            return None
    return value

# API Settings
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 5000))

# ================= HELPER FUNCTIONS =================
def get_redis():
    try:
        redis_host = get_setting("REDIS_HOST")
        redis_port = int(get_setting("REDIS_PORT", required=False) or "6379")
        redis_pass = get_setting("REDIS_PASS", required=False)
        
        return redis.Redis(
            host=redis_host, 
            port=redis_port, 
            password=redis_pass if redis_pass else None, 
            decode_responses=True
        )
    except Exception as e:
        print(f"❌ Redis Connection Error: {e}")
        return None

def get_public_ip():
    try:
        return requests.get("https://api.ipify.org", timeout=5).text
    except:
        return "Unknown"

def count_active_routers():
    """Counts how many Traefik routers are currently active in Redis."""
    r = get_redis()
    keys = r.keys("traefik/http/routers/*/rule")
    return len(keys)

def cf_request(method, endpoint, data=None):
    cf_token = get_setting("CF_API_TOKEN")
    cf_zone_id = get_setting("CF_ZONE_ID")
    
    if not cf_token or not cf_zone_id:
        print(f"❌ Cloudflare settings not configured")
        return None
    
    headers = {
        "Authorization": f"Bearer {cf_token}",
        "Content-Type": "application/json"
    }
    url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/{endpoint}"
    response = requests.request(method, url, headers=headers, json=data)
    if not response.ok:
        print(f"❌ Cloudflare Error ({endpoint}): {response.text}")
        return None
    return response.json()

def update_hass(state, service_name="Service"):
    hass_url = get_setting("HASS_URL", required=False)
    hass_entity = get_setting("HASS_ENTITY_ID", required=False)
    hass_token = get_setting("HASS_TOKEN", required=False)
    
    if not hass_url or not hass_entity or not hass_token:
        return  # HA integration disabled
    
    headers = {"Authorization": f"Bearer {hass_token}", "Content-Type": "application/json"}
    try:
        response = requests.post(
            f"{hass_url}/api/states/{hass_entity}",
            headers=headers,
            json={"state": state, "attributes": {"service": service_name}},
            timeout=5
        )
        if response.status_code not in [200, 201]:
            print(f"❌ Failed to update HA (Status {response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ HA Connection Failed: {e}")

# ================= UNIFI LOGIC =================

def check_unifi_rule():
    """Reads the current status of the UniFi Port Forward rule."""
    unifi_host = get_setting("UNIFI_HOST", required=False)
    unifi_user = get_setting("UNIFI_USER", required=False)
    unifi_pass = get_setting("UNIFI_PASS", required=False)
    unifi_rule_name = get_setting("UNIFI_RULE_NAME", required=False)
    
    if not all([unifi_host, unifi_user, unifi_pass, unifi_rule_name]):
        return None
    
    base_url = f"https://{unifi_host}"
    session = requests.Session()
    session.verify = False

    try:
        # Login
        login_data = {"username": unifi_user, "password": unifi_pass}
        resp = session.post(f"{base_url}/api/auth/login", json=login_data, timeout=5)
        if resp.status_code != 200:
            return None # Login failed

        # Fetch Rules
        pf_url = f"{base_url}/proxy/network/api/s/default/rest/portforward"
        resp = session.get(pf_url, timeout=5)
        rules = resp.json().get("data", [])
        
        target_rule = next((r for r in rules if r.get("name") == unifi_rule_name), None)
        if target_rule:
            return target_rule["enabled"] # Returns True or False
        return None # Rule not found
        
    except Exception:
        return None # Connection error

def toggle_unifi(enable_rule):
    """Logs into UDM Pro and toggles the Port Forwarding Rule"""
    unifi_host = get_setting("UNIFI_HOST", required=False)
    unifi_user = get_setting("UNIFI_USER", required=False)
    unifi_pass = get_setting("UNIFI_PASS", required=False)
    unifi_rule_name = get_setting("UNIFI_RULE_NAME", required=False)
    
    if not all([unifi_host, unifi_user, unifi_pass, unifi_rule_name]):
        print("⚠️ UniFi settings not configured, skipping firewall control")
        return True
    
    base_url = f"https://{unifi_host}"
    session = requests.Session()
    session.verify = False 

    print(f"🔹 Connecting to UniFi Controller ({unifi_host})...")

    try:
        login_data = {"username": unifi_user, "password": unifi_pass}
        resp = session.post(f"{base_url}/api/auth/login", json=login_data, timeout=10)
        
        if resp.status_code != 200:
            print(f"❌ UniFi Login Failed: HTTP {resp.status_code}")
            return False
            
        csrf_token = resp.headers.get("x-csrf-token")
        headers = {"X-CSRF-Token": csrf_token} if csrf_token else {}

    except Exception as e:
        print(f"❌ UniFi Connection Error: {e}")
        return False

    pf_url = f"{base_url}/proxy/network/api/s/default/rest/portforward"
    
    try:
        resp = session.get(pf_url, timeout=10)
        rules = resp.json().get("data", [])
    except Exception as e:
        print(f"❌ Error fetching rules: {e}")
        return False

    target_rule = next((r for r in rules if r.get("name") == unifi_rule_name), None)

    if not target_rule:
        print(f"❌ Error: UniFi Rule '{unifi_rule_name}' not found!")
        return False

    if target_rule["enabled"] == enable_rule:
        print(f"   UniFi rule is already {'ENABLED' if enable_rule else 'DISABLED'}.")
        return True

    target_rule["enabled"] = enable_rule
    try:
        rule_id = target_rule["_id"]
        resp = session.put(f"{pf_url}/{rule_id}", json=target_rule, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            print(f"✅ UniFi Rule '{unifi_rule_name}' set to {'ENABLED' if enable_rule else 'DISABLED'}.")
            return True
        else:
            print(f"❌ Failed to update rule: {resp.text}")
            return False
    except Exception as e:
        print(f"❌ Error updating rule: {e}")
        return False

# ================= CORE LOGIC =================
def get_status():
    """Get overall system status"""
    r = get_redis()
    if not r:
        return {"error": "Redis connection failed"}
    
    # Check UniFi Status
    firewall_status = "UNKNOWN"
    is_open = check_unifi_rule()
    if is_open is True:
        firewall_status = "OPEN"
    elif is_open is False:
        firewall_status = "CLOSED"
    
    # Get all services and their status
    services = db.get_all_services()
    active_services = []
    
    for service in services:
        current_rule = r.get(f"traefik/http/routers/{service['router_name']}/rule")
        if current_rule:
            host = current_rule.replace("Host(`", "").replace("`)", "")
            active_services.append({
                "id": service['id'],
                "name": service['name'],
                "hostname": f"https://{host}",
                "status": "ONLINE"
            })
    
    return {
        "firewall": firewall_status,
        "active_services": active_services,
        "total_services": len(services),
        "active_count": len(active_services),
        "public_ip": get_public_ip()
    }

def get_service_status(service_id):
    """Get status of a specific service"""
    service = db.get_service(service_id)
    if not service:
        return None
    
    r = get_redis()
    if not r:
        return {"error": "Redis connection failed"}
    
    current_rule = r.get(f"traefik/http/routers/{service['router_name']}/rule")
    
    if current_rule:
        host = current_rule.replace("Host(`", "").replace("`)", "")
        return {
            "status": "ONLINE",
            "hostname": host,
            "full_url": f"https://{host}",
            "service": service
        }
    else:
        return {
            "status": "OFFLINE",
            "service": service
        }

def turn_off_service(service_id):
    """Turn off a specific service"""
    service = db.get_service(service_id)
    if not service:
        return {"error": "Service not found"}
    
    print(f"\n🛑 === SHUTTING DOWN {service['name']} ===")
    r = get_redis()
    if not r:
        return {"error": "Redis connection failed"}

    router_name = service['router_name']
    service_name = service['service_name']
    subdomain_prefix = service['subdomain_prefix']
    
    print("🔹 Removing Traefik Router...")
    r.delete(f"traefik/http/routers/{router_name}/rule")
    r.delete(f"traefik/http/routers/{router_name}/service")
    r.delete(f"traefik/http/routers/{router_name}/entryPoints/0")
    r.delete(f"traefik/http/routers/{router_name}/tls/certResolver")
    r.delete(f"traefik/http/services/{service_name}/loadbalancer/servers/0/url")

    remaining_count = count_active_routers()
    print(f"   Active routers remaining: {remaining_count}")

    if remaining_count == 0:
        print("   No other services active. Closing firewall...")
        toggle_unifi(False)
    else:
        print("   ⚠️ Other services are still active. Firewall will remain OPEN.")

    print("🔹 Cleaning up DNS records...")
    records = cf_request("GET", f"dns_records?type=A&name_contains={subdomain_prefix}-")
    if records:
        count = 0
        for record in records.get('result', []):
            print(f"   Deleting: {record['name']}")
            cf_request("DELETE", f"dns_records/{record['id']}")
            count += 1
        
        if count == 0:
            print("   No DNS records found to clean.")

    print("🔹 Updating Home Assistant...")
    update_hass("Disabled", service['name'])
    
    # Update database
    db.update_service_status(service_id, False, None)
    
    print(f"✅ {service['name']} ACCESS DISABLED.\n")
    return {"message": f"{service['name']} disabled successfully"}

def turn_on_service(service_id):
    """Turn on a specific service"""
    service = db.get_service(service_id)
    if not service:
        return {"error": "Service not found"}
    
    print(f"\n🚀 === ENABLING {service['name']} ===")
    
    if not toggle_unifi(True):
        print("⚠️ Warning: UniFi update failed, but proceeding with other steps...")

    domain_root = get_setting("DOMAIN_ROOT")
    if not domain_root:
        return {"error": "DOMAIN_ROOT not configured"}
    
    random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    new_subdomain = f"{service['subdomain_prefix']}-{random_part}"
    full_hostname = f"{new_subdomain}.{domain_root}"
    public_ip = get_public_ip()
    
    print(f"   Service: {service['name']}")
    print(f"   Target:  {full_hostname}")
    print(f"   IP:      {public_ip}")

    print("🔹 Creating DNS Record...")
    dns_data = {"type": "A", "name": new_subdomain, "content": public_ip, "ttl": 1, "proxied": True}
    result = cf_request("POST", "dns_records", dns_data)
    if not result:
        return {"error": "Failed to create DNS record"}

    print("🔹 Updating Origin Rule...")
    origin_rule_name = get_setting("ORIGIN_RULE_NAME", required=False) or "Service Rotation"
    ruleset_data = cf_request("GET", "rulesets/phases/http_request_origin/entrypoint")
    
    if ruleset_data:
        rules = ruleset_data.get('result', {}).get('rules', [])
        target_rule = next((r for r in rules if r.get('description') == origin_rule_name), None)
        ruleset_id = ruleset_data.get('result', {}).get('id')

        if target_rule:
            update_data = {
                "expression": f"http.host eq \"{full_hostname}\"",
                "description": origin_rule_name,
                "action": target_rule['action'],
                "action_parameters": target_rule['action_parameters'],
                "enabled": True
            }
            cf_request("PATCH", f"rulesets/{ruleset_id}/rules/{target_rule['id']}", update_data)
        else:
            print("⚠️ Warning: Origin Rule not found, skipping...")

    print("🔹 Cleaning old DNS for this service...")
    records = cf_request("GET", f"dns_records?type=A&name_contains={service['subdomain_prefix']}-")
    if records:
        for record in records.get('result', []):
            if record['name'] != full_hostname:
                cf_request("DELETE", f"dns_records/{record['id']}")

    print("🔹 Updating Traefik...")
    r = get_redis()
    if not r:
        return {"error": "Redis connection failed"}
    
    router_name = service['router_name']
    service_name = service['service_name']
    target_url = service['target_url']
    
    r.set(f"traefik/http/routers/{router_name}/rule", f"Host(`{full_hostname}`)")
    r.set(f"traefik/http/routers/{router_name}/service", service_name)
    r.set(f"traefik/http/routers/{router_name}/entryPoints/0", "https")
    r.set(f"traefik/http/routers/{router_name}/tls/certResolver", "main")
    r.set(f"traefik/http/services/{service_name}/loadbalancer/servers/0/url", target_url)

    print("🔹 Updating Home Assistant...")
    update_hass(f"https://{full_hostname}", service['name'])
    
    # Update database
    db.update_service_status(service_id, True, full_hostname)

    print(f"✅ SUCCESS! {service['name']} live at: https://{full_hostname}\n")
    return {"message": f"{service['name']} enabled successfully", "url": f"https://{full_hostname}"}

def rotate_service(service_id):
    """Rotate URL for a service (turn off then on)"""
    service = db.get_service(service_id)
    if not service:
        return {"error": "Service not found"}
    
    if not service['enabled']:
        return {"error": "Service is not currently enabled"}
    
    print(f"\n🔄 === ROTATING {service['name']} ===")
    turn_off_service(service_id)
    return turn_on_service(service_id)

# Legacy functions for backward compatibility with CLI
def cmd_off():
    """Turn off all services (legacy CLI command)"""
    services = db.get_all_services()
    for service in services:
        if service['enabled']:
            turn_off_service(service['id'])

def cmd_on():
    """Turn on first service (legacy CLI command)"""
    services = db.get_all_services()
    if services:
        turn_on_service(services[0]['id'])
    else:
        print("❌ No services configured")

# ================= API / MAIN =================
app = Flask(__name__)
app.secret_key = os.urandom(24)

# Web UI Routes
@app.route('/')
def index():
    services = db.get_all_services()
    return render_template('index.html', services=services)

@app.route('/services/new', methods=['GET', 'POST'])
def new_service():
    if request.method == 'POST':
        try:
            db.add_service(
                name=request.form['name'],
                router_name=request.form['router_name'],
                service_name=request.form['service_name'],
                target_url=request.form['target_url'],
                subdomain_prefix=request.form['subdomain_prefix']
            )
            flash('Service added successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('service_form.html', service=None)

@app.route('/services/<int:service_id>/edit', methods=['GET', 'POST'])
def edit_service(service_id):
    service = db.get_service(service_id)
    if not service:
        flash('Service not found', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        try:
            db.update_service(
                service_id,
                name=request.form['name'],
                router_name=request.form['router_name'],
                service_name=request.form['service_name'],
                target_url=request.form['target_url'],
                subdomain_prefix=request.form['subdomain_prefix']
            )
            flash('Service updated successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('service_form.html', service=service)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if request.method == 'POST':
        try:
            # Save all settings
            for key in request.form:
                db.set_setting(key, request.form[key])
            flash('Settings saved successfully!', 'success')
            return redirect(url_for('settings'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    settings = db.get_all_settings()
    return render_template('settings.html', settings=settings)

# API Routes
@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify(get_status())

@app.route('/api/firewall-status', methods=['GET'])
def api_firewall_status():
    firewall_status = "UNKNOWN"
    is_open = check_unifi_rule()
    if is_open is True:
        firewall_status = "OPEN"
    elif is_open is False:
        firewall_status = "CLOSED"
    return jsonify({"status": firewall_status})

@app.route('/api/services/<int:service_id>/on', methods=['POST'])
def api_turn_on(service_id):
    result = turn_on_service(service_id)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/services/<int:service_id>/off', methods=['POST'])
def api_turn_off(service_id):
    result = turn_off_service(service_id)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/services/<int:service_id>/rotate', methods=['POST'])
def api_rotate(service_id):
    result = rotate_service(service_id)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/services/<int:service_id>', methods=['DELETE'])
def api_delete_service(service_id):
    service = db.get_service(service_id)
    if not service:
        return jsonify({"error": "Service not found"}), 404
    
    # If service is enabled, turn it off first
    if service['enabled']:
        turn_off_service(service_id)
    
    db.delete_service(service_id)
    return jsonify({"message": "Service deleted successfully"})

# Legacy API endpoints for backward compatibility
@app.route('/api/turn_on', methods=['POST'])
def api_legacy_turn_on():
    services = db.get_all_services()
    if not services:
        return jsonify({"error": "No services configured"}), 400
    result = turn_on_service(services[0]['id'])
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/turn_off', methods=['POST'])
def api_legacy_turn_off():
    services = db.get_all_services()
    if not services:
        return jsonify({"error": "No services configured"}), 400
    result = turn_off_service(services[0]['id'])
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Control Traefik Route Rotation")
    parser.add_argument("action", choices=["on", "off", "status", "rotate", "serve"], 
                        help="Action to perform", default="serve", nargs="?")
    args = parser.parse_args()

    if args.action == "status":
        s = get_status()
        print(f"\n📊 SYSTEM STATUS")
        print(f"🔥 Firewall: {s.get('firewall', 'UNKNOWN')}")
        print(f"📡 Public IP: {s.get('public_ip', 'Unknown')}")
        print(f"🚦 Active Services: {s.get('active_count', 0)}/{s.get('total_services', 0)}")
        if s.get('active_services'):
            print("\n🌐 Active Services:")
            for svc in s['active_services']:
                print(f"   • {svc['name']}: {svc['hostname']}")
    elif args.action == "off":
        cmd_off()
    elif args.action == "on" or args.action == "rotate":
        cmd_on()
    elif args.action == "serve":
        print(f"🚀 Starting Web UI on http://{API_HOST}:{API_PORT}")
        print(f"   Configure settings and services at http://{API_HOST}:{API_PORT}/settings")
        app.run(host=API_HOST, port=API_PORT, debug=False)

