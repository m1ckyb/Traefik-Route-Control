#!/usr/bin/env python3
import redis
import requests
import random
import string
import os
import sys
import argparse
import urllib3
import json
import secrets
import time
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    AuthenticatorAttachment,
    ResidentKeyRequirement,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
import database as db

# Import DATA_DIR for secret key storage
from database import DATA_DIR

# Suppress InsecureRequestWarning for UniFi self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIGURATION =================
script_dir = os.path.dirname(os.path.abspath(__file__))

# Initialize database
db.init_db()

# Constants
REQUIRED_SETTINGS = [
    "CF_API_TOKEN", "CF_ZONE_ID", "DOMAIN_ROOT", "REDIS_HOST",
    "UNIFI_HOST", "UNIFI_USER", "UNIFI_PASS", "UNIFI_RULE_NAME"
]

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

# Try to load from .env file if exists (for migration)
env_path = os.path.join(script_dir, ".env")
if os.path.exists(env_path):
    load_dotenv(env_path)
    # Migrate settings from .env to database
    migrate_env_to_db()

def get_setting(key, required=True):
    """Get a setting from database."""
    value = db.get_setting(key)
    if not value and required:
        print(f"❌ Configuration Error: '{key}' is missing from settings")
        if key in REQUIRED_SETTINGS:
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

def update_hass(state, service_name="Service", hass_entity_id=None):
    hass_url = get_setting("HASS_URL", required=False)
    hass_token = get_setting("HASS_TOKEN", required=False)
    
    # Use provided entity ID or fall back to global setting (for backward compatibility)
    if not hass_entity_id:
        hass_entity_id = get_setting("HASS_ENTITY_ID", required=False)
    
    if not hass_url or not hass_entity_id or not hass_token:
        return  # HA integration disabled
    
    headers = {"Authorization": f"Bearer {hass_token}", "Content-Type": "application/json"}
    try:
        response = requests.post(
            f"{hass_url}/api/states/{hass_entity_id}",
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
    update_hass("Disabled", service['name'], service.get('hass_entity_id'))
    
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
    update_hass(f"https://{full_hostname}", service['name'], service.get('hass_entity_id'))
    
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

# Use persistent secret key from environment or generate one and store it
SECRET_KEY_FILE = os.path.join(DATA_DIR, '.secret_key')
if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE, 'rb') as f:
        app.secret_key = f.read()
else:
    app.secret_key = os.urandom(24)
    with open(SECRET_KEY_FILE, 'wb') as f:
        f.write(app.secret_key)

# Track application startup time for initial setup window
STARTUP_TIME = time.time()
# Parse and validate SETUP_WINDOW_SECONDS (default 5 minutes, min 60s, max 1 hour)
try:
    SETUP_WINDOW_SECONDS = int(os.environ.get('SETUP_WINDOW_SECONDS', '300'))
    if SETUP_WINDOW_SECONDS < 60 or SETUP_WINDOW_SECONDS > 3600:
        print(f"⚠️ SETUP_WINDOW_SECONDS={SETUP_WINDOW_SECONDS} is outside recommended range (60-3600). Using default 300.")
        SETUP_WINDOW_SECONDS = 300
except ValueError:
    print(f"⚠️ Invalid SETUP_WINDOW_SECONDS value. Using default 300.")
    SETUP_WINDOW_SECONDS = 300

def is_in_setup_window():
    """Check if we're still in the setup window after startup."""
    return (time.time() - STARTUP_TIME) < SETUP_WINDOW_SECONDS

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Custom unauthorized handler
@login_manager.unauthorized_handler
def unauthorized():
    # During setup window with no users, redirect to login without message
    if db.count_users() == 0 and is_in_setup_window():
        return redirect(url_for('login'))
    # Otherwise show the default message
    flash('Please log in to access this page.', 'warning')
    return redirect(url_for('login'))

class User(UserMixin):
    def __init__(self, user_id, username):
        self.id = user_id
        self.username = username

@login_manager.user_loader
def load_user(user_id):
    user = db.get_user(int(user_id))
    if user:
        return User(user['id'], user['username'])
    return None

# RP (Relying Party) settings for WebAuthn
RP_ID = os.environ.get('RP_ID', 'localhost')
RP_NAME = "Traefik Route Control"
ORIGIN = os.environ.get('ORIGIN', f'http://localhost:5000')

def get_expected_origin():
    """
    Get the expected origin for WebAuthn operations.
    For development, dynamically determine based on request to support localhost/127.0.0.1/0.0.0.0.
    For production with RP_ID set, use the configured ORIGIN.
    """
    # If ORIGIN is explicitly set via environment variable (not default), use it
    if 'ORIGIN' in os.environ:
        return ORIGIN
    
    # For development (default config), dynamically determine origin from request
    # This allows localhost, 127.0.0.1, and other local addresses to work
    if request:
        scheme = request.scheme  # http or https
        host = request.host      # includes hostname and port
        return f"{scheme}://{host}"
    
    # Fallback to configured ORIGIN
    return ORIGIN

def get_expected_rp_id():
    """
    Get the expected RP ID for WebAuthn operations.
    For development with localhost-like addresses, use the hostname without port.
    """
    # If RP_ID is explicitly set via environment variable (not default), use it
    if 'RP_ID' in os.environ:
        return RP_ID
    
    # For development (default config), extract hostname from request
    # This supports localhost, 127.0.0.1, etc.
    if request:
        host = request.host
        # Remove port if present
        hostname = host.split(':')[0]
        # For development, accept localhost-like addresses
        # WebAuthn treats localhost, 127.0.0.1, and [::1] as secure contexts
        return hostname
    
    # Fallback to configured RP_ID
    return RP_ID

# Web UI Routes
@app.route('/login', methods=['GET'])
def login():
    # Check if this is initial setup (no users exist)
    is_setup = db.count_users() == 0
    
    # Check if we're in the setup window
    in_setup_window = is_in_setup_window() if is_setup else False
    
    # If setup required but window expired, show warning
    setup_expired = is_setup and not in_setup_window
    
    return render_template('login.html', 
                          is_setup=is_setup, 
                          in_setup_window=in_setup_window,
                          setup_expired=setup_expired)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# WebAuthn routes
@app.route('/auth/register/begin', methods=['POST'])
def register_begin():
    # Only allow registration during setup window if no users exist
    if db.count_users() == 0 and not is_in_setup_window():
        return jsonify({"error": "Setup window expired. Please restart the application."}), 410
    
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"error": "Username required"}), 400
    
    # Check if user already exists
    existing_user = db.get_user_by_username(username)
    if existing_user:
        return jsonify({"error": "Username already exists"}), 400
    
    # Generate temporary user ID for this registration attempt
    # We'll create the actual user only after successful verification
    temp_user_id = random.randint(1000000, 9999999)
    user_id_bytes = temp_user_id.to_bytes(4, byteorder='big')
    
    # Get dynamic RP_ID and origin for this request
    rp_id = get_expected_rp_id()
    origin = get_expected_origin()
    
    # Generate registration options
    registration_options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=user_id_bytes,
        user_name=username,
        user_display_name=username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.PREFERRED
        ),
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
        ]
    )
    
    # Store challenge, username, and context in session for verification
    session['registration_challenge'] = registration_options.challenge.hex()
    session['registration_username'] = username
    session['registration_rp_id'] = rp_id
    session['registration_origin'] = origin
    
    # Convert to JSON-serializable format
    options_json = options_to_json(registration_options)
    return jsonify(json.loads(options_json))

@app.route('/auth/register/complete', methods=['POST'])
def register_complete():
    data = request.json
    credential = data.get('credential')
    
    if not credential:
        return jsonify({"error": "Credential required"}), 400
    
    challenge = session.get('registration_challenge')
    username = session.get('registration_username')
    rp_id = session.get('registration_rp_id')
    origin = session.get('registration_origin')
    
    if not challenge or not username or not rp_id or not origin:
        return jsonify({"error": "Invalid session"}), 400
    
    try:
        # Verify the registration response
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=bytes.fromhex(challenge),
            expected_rp_id=rp_id,
            expected_origin=origin,
        )
        
        # Create user only after successful verification
        user_id = db.add_user(username)
        
        # Store credential
        db.add_credential(
            user_id=user_id,
            credential_id=verification.credential_id.hex(),
            public_key=verification.credential_public_key.hex()
        )
        
        # Log the user in
        user = db.get_user(user_id)
        login_user(User(user['id'], user['username']))
        
        # Clear session
        session.pop('registration_challenge', None)
        session.pop('registration_username', None)
        session.pop('registration_rp_id', None)
        session.pop('registration_origin', None)
        
        return jsonify({"success": True})
        
    except Exception as e:
        # Clear session on error
        session.pop('registration_challenge', None)
        session.pop('registration_username', None)
        session.pop('registration_rp_id', None)
        session.pop('registration_origin', None)
        return jsonify({"error": str(e)}), 400

@app.route('/auth/login/begin', methods=['POST'])
def login_begin():
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"error": "Username required"}), 400
    
    # Check if user exists
    user = db.get_user_by_username(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Get user credentials
    credentials = db.get_credentials_for_user(user['id'])
    if not credentials:
        return jsonify({"error": "No credentials found"}), 404
    
    # Get dynamic RP_ID and origin for this request
    rp_id = get_expected_rp_id()
    origin = get_expected_origin()
    
    # Generate authentication options
    allow_credentials = [
        PublicKeyCredentialDescriptor(id=bytes.fromhex(cred['credential_id']))
        for cred in credentials
    ]
    
    authentication_options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=allow_credentials,
        user_verification=UserVerificationRequirement.PREFERRED
    )
    
    # Store challenge, user_id, and context in session for verification
    session['authentication_challenge'] = authentication_options.challenge.hex()
    session['authentication_user_id'] = user['id']
    session['authentication_rp_id'] = rp_id
    session['authentication_origin'] = origin
    
    # Convert to JSON-serializable format
    options_json = options_to_json(authentication_options)
    return jsonify(json.loads(options_json))

@app.route('/auth/login/complete', methods=['POST'])
def login_complete():
    data = request.json
    credential = data.get('credential')
    
    if not credential:
        return jsonify({"error": "Credential required"}), 400
    
    challenge = session.get('authentication_challenge')
    user_id = session.get('authentication_user_id')
    rp_id = session.get('authentication_rp_id')
    origin = session.get('authentication_origin')
    
    if not challenge or not user_id or not rp_id or not origin:
        return jsonify({"error": "Invalid session"}), 400
    
    try:
        # Get credential from database
        cred_id = credential.get('id')
        db_credential = db.get_credential_by_id(cred_id)
        
        if not db_credential or db_credential['user_id'] != user_id:
            return jsonify({"error": "Invalid credential"}), 400
        
        # Verify the authentication response
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=bytes.fromhex(challenge),
            expected_rp_id=rp_id,
            expected_origin=origin,
            credential_public_key=bytes.fromhex(db_credential['public_key']),
            credential_current_sign_count=db_credential['sign_count']
        )
        
        # Update sign count
        db.update_credential_sign_count(cred_id, verification.new_sign_count)
        
        # Log the user in
        user = db.get_user(user_id)
        login_user(User(user['id'], user['username']))
        
        # Clear session
        session.pop('authentication_challenge', None)
        session.pop('authentication_user_id', None)
        session.pop('authentication_rp_id', None)
        session.pop('authentication_origin', None)
        
        return jsonify({"success": True})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/')
def index():
    # Allow access during setup window if no users exist
    if db.count_users() == 0 and is_in_setup_window():
        return redirect(url_for('login'))
    
    # Otherwise require login
    if not current_user.is_authenticated:
        return login_manager.unauthorized()
    
    services = db.get_all_services()
    return render_template('index.html', services=services)

@app.route('/services/new', methods=['GET', 'POST'])
@login_required
def new_service():
    if request.method == 'POST':
        try:
            db.add_service(
                name=request.form['name'],
                router_name=request.form['router_name'],
                service_name=request.form['service_name'],
                target_url=request.form['target_url'],
                subdomain_prefix=request.form['subdomain_prefix'],
                hass_entity_id=request.form.get('hass_entity_id') or None
            )
            flash('Service added successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('service_form.html', service=None)

@app.route('/services/<int:service_id>/edit', methods=['GET', 'POST'])
@login_required
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
                subdomain_prefix=request.form['subdomain_prefix'],
                hass_entity_id=request.form.get('hass_entity_id') or None
            )
            flash('Service updated successfully!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
    
    return render_template('service_form.html', service=service)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
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
@login_required
def api_status():
    return jsonify(get_status())

@app.route('/api/firewall-status', methods=['GET'])
@login_required
def api_firewall_status():
    firewall_status = "UNKNOWN"
    is_open = check_unifi_rule()
    if is_open is True:
        firewall_status = "OPEN"
    elif is_open is False:
        firewall_status = "CLOSED"
    return jsonify({"status": firewall_status})

@app.route('/api/services/<int:service_id>/on', methods=['POST'])
@login_required
def api_turn_on(service_id):
    result = turn_on_service(service_id)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/services/<int:service_id>/off', methods=['POST'])
@login_required
def api_turn_off(service_id):
    result = turn_off_service(service_id)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/services/<int:service_id>/rotate', methods=['POST'])
@login_required
def api_rotate(service_id):
    result = rotate_service(service_id)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/services/<int:service_id>', methods=['DELETE'])
@login_required
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
@login_required
def api_legacy_turn_on():
    services = db.get_all_services()
    if not services:
        return jsonify({"error": "No services configured"}), 400
    result = turn_on_service(services[0]['id'])
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/turn_off', methods=['POST'])
@login_required
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

