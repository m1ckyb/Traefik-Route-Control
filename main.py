#!/usr/bin/env python3
import redis
import requests
import random
import string
import os
import sys
import argparse
from dotenv import load_dotenv
from flask import Flask, jsonify

# ================= CONFIGURATION =================
# Load variables from .env file in the same directory
script_dir = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(script_dir, ".env"))

def get_env(key):
    """Helper to get env var or exit if missing"""
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
REDIS_PASS = os.getenv("REDIS_PASS") # Optional, allows None
ROUTER_NAME = get_env("ROUTER_NAME")
SERVICE_NAME = get_env("SERVICE_NAME")
TARGET_INT_URL = get_env("TARGET_INT_URL")

# Home Assistant Settings
HASS_URL = get_env("HASS_URL")
HASS_ENTITY_ID = get_env("HASS_ENTITY_ID")
HASS_TOKEN = get_env("HASS_TOKEN")

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
        
        # Check if the update actually succeeded (200 OK or 201 Created)
        if response.status_code in [200, 201]:
            print(f"   Home Assistant updated: {state}")
        else:
            print(f"❌ Failed to update HA (Status {response.status_code}): {response.text}")

    except Exception as e:
        print(f"❌ Connection Failed: {e}")

# ================= CORE LOGIC =================
def get_status():
    """Returns a dictionary with the current status."""
    r = get_redis()
    current_rule = r.get(f"traefik/http/routers/{ROUTER_NAME}/rule")
    
    if current_rule:
        host = current_rule.replace("Host(`", "").replace("`)", "")
        return {
            "status": "ONLINE",
            "hostname": f"https://{host}",
            "public_ip": get_public_ip()
        }
    else:
        return {
            "status": "OFFLINE",
            "details": f"Redis key 'traefik/http/routers/{ROUTER_NAME}/rule' not found"
        }

# ================= COMMANDS =================

def cmd_status():
    print("\n📊 === STATUS REPORT ===")
    status_data = get_status()
    if status_data['status'] == 'ONLINE':
        print(f"✅ Status:   ONLINE")
        print(f"🔗 Hostname: {status_data['hostname']}")
        print(f"🌍 Public IP: {status_data['public_ip']}")
    else:
        print(f"⛔ Status:   OFFLINE")
        print(f"   ({status_data['details']})")
    print("========================\n")

def cmd_off():
    print("\n🛑 === SHUTTING DOWN JELLYFIN ACCESS ===")
    r = get_redis()
    
    print("🔹 Removing Traefik Router...")
    r.delete(f"traefik/http/routers/{ROUTER_NAME}/rule")
    r.delete(f"traefik/http/routers/{ROUTER_NAME}/service")
    r.delete(f"traefik/http/routers/{ROUTER_NAME}/tls/certResolver")
    
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
    
    random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    new_subdomain = f"jf-{random_part}"
    full_hostname = f"{new_subdomain}.{DOMAIN_ROOT}"
    public_ip = get_public_ip()
    
    print(f"   Target: {full_hostname}")
    print(f"   IP:     {public_ip}")

    # 1. Cloudflare DNS
    print("🔹 Creating DNS Record...")
    dns_data = {"type": "A", "name": new_subdomain, "content": public_ip, "ttl": 1, "proxied": True}
    cf_request("POST", "dns_records", dns_data)

    # 2. Cloudflare Origin Rule
    print("🔹 Updating Origin Rule...")
    ruleset_data = cf_request("GET", "rulesets/phases/http_request_origin/entrypoint")
    rules = ruleset_data.get('result', {}).get('rules', [])
    
    target_rule = next((r for r in rules if r.get('description') == ORIGIN_RULE_NAME), None)
    ruleset_id = ruleset_data.get('result', {}).get('id')

    if target_rule:
        # Must extract existing action logic to prevent API error 20015
        update_data = {
            "expression": f"http.host eq \"{full_hostname}\"",
            "description": ORIGIN_RULE_NAME,
            "action": target_rule['action'],
            "action_parameters": target_rule['action_parameters'],
            "enabled": True
        }
        cf_request("PATCH", f"rulesets/{ruleset_id}/rules/{target_rule['id']}", update_data)
    else:
        print("❌ Error: Origin Rule not found! Create a rule named 'Jellyfin Rotation' in Cloudflare first.")
        return

    # 3. Clean old DNS
    print("🔹 Cleaning old DNS...")
    records = cf_request("GET", f"dns_records?type=A&name_contains=jf-")
    for record in records.get('result', []):
        if record['name'] != full_hostname:
            cf_request("DELETE", f"dns_records/{record['id']}")

    # 4. Traefik (Redis)
    print("🔹 Updating Traefik...")
    r = get_redis()
    r.set(f"traefik/http/routers/{ROUTER_NAME}/rule", f"Host(`{full_hostname}`)")
    r.set(f"traefik/http/routers/{ROUTER_NAME}/service", SERVICE_NAME)
    r.set(f"traefik/http/routers/{ROUTER_NAME}/entryPoints/0", "https")
    r.set(f"traefik/http/routers/{ROUTER_NAME}/tls/certResolver", "main")
    r.set(f"traefik/http/services/{SERVICE_NAME}/loadbalancer/servers/0/url", TARGET_INT_URL)

    # 5. Home Assistant
    print("🔹 Updating Home Assistant...")
    update_hass(f"https://{full_hostname}")

    print(f"✅ SUCCESS! Live at: https://{full_hostname}\n")

# ================= API DEFINITION =================
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

# ================= ENTRY POINT =================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Control Jellyfin Traefik Rotation")
    parser.add_argument("action", choices=["on", "off", "status", "rotate", "serve"], 
                        help="Action to perform", default="status", nargs="?")
    args = parser.parse_args()

    if args.action == "status":
        cmd_status()
    elif args.action == "off":
        cmd_off()
    elif args.action == "on" or args.action == "rotate":
        cmd_on()
    elif args.action == "serve":
        print(f"🚀 Starting API server on http://{API_HOST}:{API_PORT}")
        app.run(host=API_HOST, port=API_PORT)