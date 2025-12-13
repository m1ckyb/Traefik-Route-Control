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
from flask import Flask, jsonify

# Suppress InsecureRequestWarning for UniFi self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIGURATION =================
script_dir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(script_dir, ".env"))

def get_env(key):
    value = os.getenv(key)
    if not value:
        print(f"❌ Configuration Error: '{key}' is missing from .env file")
        sys.exit(1)
    return value

# Cloudflare Settings
CF_API_TOKEN = get_env("CF_API_TOKEN")
CF_ZONE_ID = get_env("CF_ZONE_ID")
DOMAIN_ROOT = get_env("DOMAIN_ROOT")
ORIGIN_RULE_NAME = get_env("ORIGIN_RULE_NAME")

# Traefik / Redis Settings
REDIS_HOST = get_env("REDIS_HOST")
REDIS_PORT = int(get_env("REDIS_PORT"))
REDIS_PASS = os.getenv("REDIS_PASS") 
ROUTER_NAME = get_env("ROUTER_NAME")
SERVICE_NAME = get_env("SERVICE_NAME")
TARGET_INT_URL = get_env("TARGET_INT_URL")

# Home Assistant Settings
HASS_URL = get_env("HASS_URL")
HASS_ENTITY_ID = get_env("HASS_ENTITY_ID")
HASS_TOKEN = get_env("HASS_TOKEN")

# UniFi Settings
UNIFI_HOST = get_env("UNIFI_HOST")
UNIFI_USER = get_env("UNIFI_USER")
UNIFI_PASS = get_env("UNIFI_PASS")
UNIFI_RULE_NAME = get_env("UNIFI_RULE_NAME")

# API Settings
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 5000))

# ================= HELPER FUNCTIONS =================
def get_redis():
    try:
        return redis.Redis(
            host=REDIS_HOST, 
            port=REDIS_PORT, 
            password=REDIS_PASS, 
            decode_responses=True
        )
    except Exception as e:
        print(f"❌ Redis Connection Error: {e}")
        sys.exit(1)

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
    headers = {
        "Authorization": f"Bearer {CF_API_TOKEN}",
        "Content-Type": "application/json"
    }
    url = f"https://api.cloudflare.com/client/v4/zones/{CF_ZONE_ID}/{endpoint}"
    response = requests.request(method, url, headers=headers, json=data)
    if not response.ok:
        print(f"❌ Cloudflare Error ({endpoint}): {response.text}")
        sys.exit(1)
    return response.json()

def update_hass(state):
    headers = {"Authorization": f"Bearer {HASS_TOKEN}", "Content-Type": "application/json"}
    try:
        response = requests.post(
            f"{HASS_URL}/api/states/{HASS_ENTITY_ID}",
            headers=headers,
            json={"state": state},
            timeout=5
        )
        if response.status_code not in [200, 201]:
            print(f"❌ Failed to update HA (Status {response.status_code}): {response.text}")
    except Exception as e:
        print(f"❌ HA Connection Failed: {e}")

# ================= UNIFI LOGIC =================

def check_unifi_rule():
    """Reads the current status of the UniFi Port Forward rule."""
    base_url = f"https://{UNIFI_HOST}"
    session = requests.Session()
    session.verify = False

    try:
        # Login
        login_data = {"username": UNIFI_USER, "password": UNIFI_PASS}
        resp = session.post(f"{base_url}/api/auth/login", json=login_data, timeout=5)
        if resp.status_code != 200:
            return None # Login failed

        # Fetch Rules
        pf_url = f"{base_url}/proxy/network/api/s/default/rest/portforward"
        resp = session.get(pf_url, timeout=5)
        rules = resp.json().get("data", [])
        
        target_rule = next((r for r in rules if r.get("name") == UNIFI_RULE_NAME), None)
        if target_rule:
            return target_rule["enabled"] # Returns True or False
        return None # Rule not found
        
    except Exception:
        return None # Connection error

def toggle_unifi(enable_rule):
    """Logs into UDM Pro and toggles the Port Forwarding Rule"""
    base_url = f"https://{UNIFI_HOST}"
    session = requests.Session()
    session.verify = False 

    print(f"🔹 Connecting to UniFi Controller ({UNIFI_HOST})...")

    try:
        login_data = {"username": UNIFI_USER, "password": UNIFI_PASS}
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

    target_rule = next((r for r in rules if r.get("name") == UNIFI_RULE_NAME), None)

    if not target_rule:
        print(f"❌ Error: UniFi Rule '{UNIFI_RULE_NAME}' not found!")
        return False

    if target_rule["enabled"] == enable_rule:
        print(f"   UniFi rule is already {'ENABLED' if enable_rule else 'DISABLED'}.")
        return True

    target_rule["enabled"] = enable_rule
    try:
        rule_id = target_rule["_id"]
        resp = session.put(f"{pf_url}/{rule_id}", json=target_rule, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            print(f"✅ UniFi Rule '{UNIFI_RULE_NAME}' set to {'ENABLED' if enable_rule else 'DISABLED'}.")
            return True
        else:
            print(f"❌ Failed to update rule: {resp.text}")
            return False
    except Exception as e:
        print(f"❌ Error updating rule: {e}")
        return False

# ================= CORE LOGIC =================
def get_status():
    r = get_redis()
    current_rule = r.get(f"traefik/http/routers/{ROUTER_NAME}/rule")
    
    # Check UniFi Status
    firewall_status = "UNKNOWN"
    is_open = check_unifi_rule()
    if is_open is True:
        firewall_status = "OPEN"
    elif is_open is False:
        firewall_status = "CLOSED"

    if current_rule:
        host = current_rule.replace("Host(`", "").replace("`)", "")
        return {
            "status": "ONLINE",
            "hostname": f"https://{host}",
            "public_ip": get_public_ip(),
            "firewall": firewall_status
        }
    else:
        return {
            "status": "OFFLINE",
            "details": f"Redis key not found",
            "firewall": firewall_status
        }

def cmd_off():
    print("\n🛑 === SHUTTING DOWN JELLYFIN ACCESS ===")
    r = get_redis()

    print("🔹 Removing Traefik Router...")
    r.delete(f"traefik/http/routers/{ROUTER_NAME}/rule")
    r.delete(f"traefik/http/routers/{ROUTER_NAME}/service")
    r.delete(f"traefik/http/routers/{ROUTER_NAME}/tls/certResolver")

    remaining_count = count_active_routers()
    print(f"   Active routers remaining: {remaining_count}")

    if remaining_count == 0:
        print("   No other services active. Closing firewall...")
        toggle_unifi(False)
    else:
        print("   ⚠️ Other services are still active. Firewall will remain OPEN.")

    print("🔹 Cleaning up DNS records...")
    records = cf_request("GET", f"dns_records?type=A&name_contains=jf-")
    count = 0
    for record in records.get('result', []):
        print(f"   Deleting: {record['name']}")
        cf_request("DELETE", f"dns_records/{record['id']}")
        count += 1
    
    if count == 0:
        print("   No DNS records found to clean.")

    print("🔹 Updating Home Assistant...")
    update_hass("Disabled")
    
    print("✅ ACCESS DISABLED.\n")

def cmd_on():
    print("\n🚀 === ROTATING / ENABLING JELLYFIN ACCESS ===")
    
    if not toggle_unifi(True):
        print("⚠️ Warning: UniFi update failed, but proceeding with other steps...")

    random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    new_subdomain = f"jf-{random_part}"
    full_hostname = f"{new_subdomain}.{DOMAIN_ROOT}"
    public_ip = get_public_ip()
    
    print(f"   Target: {full_hostname}")
    print(f"   IP:     {public_ip}")

    print("🔹 Creating DNS Record...")
    dns_data = {"type": "A", "name": new_subdomain, "content": public_ip, "ttl": 1, "proxied": True}
    cf_request("POST", "dns_records", dns_data)

    print("🔹 Updating Origin Rule...")
    ruleset_data = cf_request("GET", "rulesets/phases/http_request_origin/entrypoint")
    rules = ruleset_data.get('result', {}).get('rules', [])
    
    target_rule = next((r for r in rules if r.get('description') == ORIGIN_RULE_NAME), None)
    ruleset_id = ruleset_data.get('result', {}).get('id')

    if target_rule:
        update_data = {
            "expression": f"http.host eq \"{full_hostname}\"",
            "description": ORIGIN_RULE_NAME,
            "action": target_rule['action'],
            "action_parameters": target_rule['action_parameters'],
            "enabled": True
        }
        cf_request("PATCH", f"rulesets/{ruleset_id}/rules/{target_rule['id']}", update_data)
    else:
        print("❌ Error: Origin Rule not found!")
        return

    print("🔹 Cleaning old DNS...")
    records = cf_request("GET", f"dns_records?type=A&name_contains=jf-")
    for record in records.get('result', []):
        if record['name'] != full_hostname:
            cf_request("DELETE", f"dns_records/{record['id']}")

    print("🔹 Updating Traefik...")
    r = get_redis()
    r.set(f"traefik/http/routers/{ROUTER_NAME}/rule", f"Host(`{full_hostname}`)")
    r.set(f"traefik/http/routers/{ROUTER_NAME}/service", SERVICE_NAME)
    r.set(f"traefik/http/routers/{ROUTER_NAME}/entryPoints/0", "https")
    r.set(f"traefik/http/routers/{ROUTER_NAME}/tls/certResolver", "main")
    r.set(f"traefik/http/services/{SERVICE_NAME}/loadbalancer/servers/0/url", TARGET_INT_URL)

    print("🔹 Updating Home Assistant...")
    update_hass(f"https://{full_hostname}")

    print(f"✅ SUCCESS! Live at: https://{full_hostname}\n")

# ================= API / MAIN =================
app = Flask(__name__)

@app.route('/api/status', methods=['GET'])
def api_status():
    return jsonify(get_status())

@app.route('/api/turn_on', methods=['POST'])
def api_turn_on():
    cmd_on()
    return jsonify({"message": "Jellyfin access enabled successfully."})

@app.route('/api/turn_off', methods=['POST'])
def api_turn_off():
    cmd_off()
    return jsonify({"message": "Jellyfin access disabled successfully."})

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Control Jellyfin Traefik Rotation")
    parser.add_argument("action", choices=["on", "off", "status", "rotate", "serve"], 
                        help="Action to perform", default="status", nargs="?")
    args = parser.parse_args()

    if args.action == "status":
        s = get_status()
        print(f"\n📊 STATUS: {s['status']}")
        print(f"🔥 Firewall: {s['firewall']}")
        if s.get('hostname'): print(f"🔗 URL: {s['hostname']}")
    elif args.action == "off":
        cmd_off()
    elif args.action == "on" or args.action == "rotate":
        cmd_on()
    elif args.action == "serve":
        print(f"🚀 Starting API server on http://{API_HOST}:{API_PORT}")
        app.run(host=API_HOST, port=API_PORT)
