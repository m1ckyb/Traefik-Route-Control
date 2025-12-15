#!/usr/bin/env python3
import redis
import requests
import random
import string
import os
import sys
import argparse
import urllib3
from urllib.parse import urlparse
import json
import secrets
import time
import base64
import hashlib
from functools import wraps
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, session, has_request_context
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

# --- LOGGING SETUP ---
class Tee(object):
    def __init__(self, *files):
        self.files = files
    def write(self, obj):
        for f in self.files:
            try:
                f.write(obj)
                f.flush()
            except: pass
    def flush(self):
        for f in self.files:
            try: f.flush()
            except: pass

LOG_FILE = os.path.join(DATA_DIR, 'app.log')
# Truncate log file on startup and redirect stdout/stderr
try:
    with open(LOG_FILE, 'w', encoding='utf-8') as f:
        f.write(f"--- Log Started at {time.ctime()} ---\n")
    
    log_file_handle = open(LOG_FILE, 'a', encoding='utf-8')
    sys.stdout = Tee(sys.stdout, log_file_handle)
    sys.stderr = Tee(sys.stderr, log_file_handle)
except Exception as e:
    print(f"⚠️ Failed to setup logging: {e}")
# ---------------------

# Suppress InsecureRequestWarning for UniFi self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIGURATION =================
script_dir = os.path.dirname(os.path.abspath(__file__))

# Initialize database
db.init_db()

# Constants
# Settings are now stored in database and configured via web UI
# No longer required at startup
REQUIRED_SETTINGS = []

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
    
    # Set defaults for new settings if they don't exist
    if not db.get_setting("FIREWALL_TYPE"):
        # Default to unifi if UNIFI_HOST is set, otherwise none
        if db.get_setting("UNIFI_HOST"):
            db.set_setting("FIREWALL_TYPE", "unifi")
        else:
            db.set_setting("FIREWALL_TYPE", "none")
        migrated = True
    
    if not db.get_setting("HASS_ENABLED"):
        # Default to enabled if HASS_URL is set, otherwise disabled
        if db.get_setting("HASS_URL"):
            db.set_setting("HASS_ENABLED", "1")
        else:
            db.set_setting("HASS_ENABLED", "0")
        migrated = True
    
    if migrated:
        print("✅ Migrated settings from .env to database")

# Try to load from .env file if exists (for migration)
env_path = os.path.join(script_dir, ".env")
if os.path.exists(env_path):
    load_dotenv(env_path)

def get_setting(key, required=True):
    """Get a setting from database.
    
    Args:
        key: The setting key to retrieve
        required: Documentation hint only (no longer enforced at startup).
                  Validation happens at point of use.
    
    Returns:
        The setting value or None if not found
    """
    value = db.get_setting(key)
    # Settings are now optional at startup and configured via web UI
    # No longer print errors for missing settings during startup
    return value

# API Settings
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", 5000))

# ================= HELPER FUNCTIONS =================
def get_redis():
    try:
        redis_host = get_setting("REDIS_HOST")
        if not redis_host:
            print("⚠️ Redis not configured")
            return None
        
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

def check_port_open(port):
    """
    Check if a port is open by verifying the UniFi firewall rule status.
    
    Note: This function checks if the firewall rule is enabled, not if the port
    is actually accessible from the internet. A full external port check would 
    require using third-party services which may have rate limits or reliability issues.
    
    Args:
        port: The port number to check
    
    Returns:
        dict: {"open": bool or None, "error": str or None}
              - open=True: Port confirmed accessible (firewall rule enabled with correct port)
              - open=False: Port not accessible (firewall rule has issues)
              - open=None: Port status unknown (firewall control not configured)
    """
    try:
        # Check if the UniFi rule is enabled with the correct port
        rule_info = check_unifi_rule()
        
        if rule_info is None:
            # Firewall control is disabled or not configured
            # Return unknown status rather than assuming it's open
            return {"open": None, "error": "Firewall control not configured - port status unknown"}
        
        if rule_info.get("enabled") and rule_info.get("port") == port:
            return {"open": True, "error": None}
        else:
            return {"open": False, "error": f"Firewall rule shows port {rule_info.get('port', 'unknown')} instead of {port}"}
    except Exception as e:
        return {"open": False, "error": str(e)}


# List of well-known ports to avoid (from IANA registry)
# https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
RESERVED_PORTS = set([
    # System Ports (1-1023)
    *range(1, 1024),
    # Commonly used registered ports (1024-49151)
    1080, 1194, 1433, 1434, 1521, 1701, 1723, 1883, 1900,
    2049, 2082, 2083, 2086, 2087, 2095, 2096, 2375, 2376, 2377, 2379, 2380,
    3000, 3001, 3002, 3003, 3004, 3005, 3006, 3128, 3268, 3269, 3306, 3389,
    4443, 4444, 4567, 4789, 4822,
    5000, 5001, 5432, 5433, 5555, 5672, 5900, 5901, 5984, 5985, 5986,
    6379, 6443, 6666, 6667, 6697,
    7000, 7001, 7077, 7443, 7474, 7687,
    8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009,
    8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089,
    8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099,
    8123, 8180, 8181, 8200, 8243, 8280, 8281, 8443, 8444, 8530, 8531, 8545, 8554, 8880, 8888, 8889,
    9000, 9001, 9002, 9003, 9009, 9042, 9090, 9091, 9092, 9093, 9094, 9095, 9096, 9100, 9200, 9300, 9418, 9443,
    10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009, 10050, 10051,
    11211, 11371,
    15672,
    16379,
    17500,
    19132, 19133,
    20000,
    25565, 25575,
    27015, 27016, 27017, 27018, 27019,
    28015, 28016, 28017,
    32400,
    33060,
    35197,
    37777,
    50000, 50001, 50002,
])

def generate_random_port():
    """
    Generate a random port between 1024 and 65535, avoiding known assigned ports.
    Returns a port number that is not in the RESERVED_PORTS set.
    
    Note: With ~63,000 available ports (64,535 total - 1,184 reserved), the random
    selection approach is efficient. Even with 100 services running, we have a 
    >99.9% chance of finding a port in the first 1000 attempts.
    """
    # Get active ports once to avoid repeated database queries
    services = db.get_all_services()
    ports_in_use = {s.get('current_port') for s in services 
                    if s.get('enabled') and s.get('current_port') is not None}
    
    max_attempts = 1000
    for _ in range(max_attempts):
        port = random.randint(1024, 65535)
        if port not in RESERVED_PORTS and port not in ports_in_use:
            return port
    
    # Fallback: try to find a port in a safe range that avoids both reserved and in-use ports
    # Using higher port range which has fewer common services
    for _ in range(max_attempts):
        port = random.randint(49152, 65535)  # Dynamic/Private port range
        if port not in RESERVED_PORTS and port not in ports_in_use:
            return port
    
    # Ultimate fallback (should never reach here given 64k port space)
    # Return a port in the dynamic range, even if it might be reserved
    return random.randint(49152, 65535)

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

def should_delete_dns_record(record_name, subdomain_prefix, current_hostname=None):
    """
    Check if a DNS record should be deleted based on subdomain prefix matching.
    
    Args:
        record_name: Full DNS record name (e.g., "jf-abc123.example.com")
        subdomain_prefix: Service subdomain prefix (e.g., "jf")
        current_hostname: Optional current hostname to preserve (won't be deleted)
    
    Returns:
        bool: True if the record should be deleted, False otherwise
    """
    # Don't delete the current hostname
    if current_hostname and record_name == current_hostname:
        return False
    
    # Only delete records that actually start with this service's prefix pattern
    expected_prefix = f"{subdomain_prefix}-"
    # Extract just the subdomain part (without domain)
    subdomain = record_name.split('.')[0] if '.' in record_name else record_name
    
    return subdomain.startswith(expected_prefix)

def update_hass(state, service_name="Service", hass_entity_id=None):
    # Check if Home Assistant integration is enabled
    hass_enabled = get_setting("HASS_ENABLED", required=False)
    if hass_enabled == "0":
        return  # HA integration disabled
    
    hass_url = get_setting("HASS_URL", required=False)
    hass_token = get_setting("HASS_TOKEN", required=False)
    
    # Use provided entity ID or fall back to global setting (for backward compatibility)
    if not hass_entity_id:
        hass_entity_id = get_setting("HASS_ENTITY_ID", required=False)
    
    # Strip whitespace - if result is empty/None, skip HA update
    hass_entity_id = hass_entity_id.strip() if hass_entity_id else None
    
    if not hass_url or not hass_entity_id or not hass_token:
        return  # HA integration disabled or not configured
    
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
    """Reads the current status of the UniFi Port Forward rule.
    
    Returns:
        dict: {"enabled": bool, "port": int or None} or None if not available
              port can be None if 'dst_port' is not set in the rule
    """
    # Check if firewall control is enabled
    firewall_type = get_setting("FIREWALL_TYPE", required=False)
    if firewall_type == "none":
        return None
    
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
            # Convert port to int for consistent comparison, with error handling
            dst_port = target_rule.get("dst_port")
            port = None
            if dst_port:
                try:
                    port = int(dst_port)
                except (ValueError, TypeError):
                    # If conversion fails, log and leave as None
                    print(f"⚠️ Warning: Invalid port value '{dst_port}' in UniFi rule")
            return {
                "enabled": target_rule["enabled"],
                "port": port
            }
        return None # Rule not found
        
    except Exception:
        return None # Connection error

def toggle_unifi(enable_rule, forward_port=None):
    """
    Logs into UDM Pro and toggles the Port Forwarding Rule.
    
    Args:
        enable_rule: Boolean to enable/disable the rule
        forward_port: Optional port number to update in the rule
    """
    # Check if firewall control is enabled
    firewall_type = get_setting("FIREWALL_TYPE", required=False)
    if firewall_type == "none":
        print("⚠️ Firewall control disabled, skipping firewall control")
        return True
    
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

    # Track what changed
    changes = []
    if target_rule["enabled"] != enable_rule:
        changes.append(f"enabled={'ENABLED' if enable_rule else 'DISABLED'}")
    
    # Update the rule
    target_rule["enabled"] = enable_rule
    
    # Update the WAN port if provided
    if forward_port is not None and enable_rule:
        old_port = target_rule.get("dst_port", "unknown")
        if old_port != forward_port:
            target_rule["dst_port"] = str(forward_port)
            changes.append(f"port={forward_port}")
            print(f"   Updating WAN port: {old_port} → {forward_port}")
    
    if not changes:
        print(f"   UniFi rule is already configured correctly.")
        return True

    try:
        rule_id = target_rule["_id"]
        resp = session.put(f"{pf_url}/{rule_id}", json=target_rule, headers=headers, timeout=10)
        
        if resp.status_code == 200:
            print(f"✅ UniFi Rule '{unifi_rule_name}' updated: {', '.join(changes)}.")
            return True
        else:
            print(f"❌ Failed to update rule: {resp.text}")
            return False
    except Exception as e:
        print(f"❌ Error updating rule: {e}")
        return False

# Default Cloudflare Origin Rule action type
DEFAULT_ORIGIN_ACTION = "route"

def get_status():
    """Get overall system status"""
    r = get_redis()
    if not r:
        return {"error": "Redis connection failed"}
    
    # Check UniFi Status
    firewall_status = "UNKNOWN"
    rule_info = check_unifi_rule()
    if rule_info and rule_info["enabled"] is True:
        firewall_status = "OPEN"
    elif rule_info and rule_info["enabled"] is False:
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
        
        # Check actual Redis configuration vs expected
        actual_target_url = r.get(f"traefik/http/services/{service['service_name']}/loadbalancer/servers/0/url")
        expected_target_url = service['target_url']
        
        # Check for configuration mismatch
        config_mismatch = actual_target_url != expected_target_url
        
        result = {
            "status": "ONLINE",
            "hostname": host,
            "full_url": f"https://{host}",
            "service": service,
            "config_mismatch": config_mismatch
        }
        
        # Include diagnostic info if there's a mismatch
        if config_mismatch:
            result["actual_target_url"] = actual_target_url
            result["expected_target_url"] = expected_target_url
        
        # Include port if available
        if service.get('current_port'):
            result['port'] = service['current_port']
        return result
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
            if should_delete_dns_record(record['name'], subdomain_prefix):
                print(f"   Deleting: {record['name']}")
                cf_request("DELETE", f"dns_records/{record['id']}")
                count += 1
        
        if count == 0:
            print("   No DNS records found to clean.")

    print("🔹 Cleaning up Origin Rule...")
    origin_rule_name = get_setting("ORIGIN_RULE_NAME", required=False) or "Service Rotation"
    
    # Get all currently enabled services to build the list of hostnames
    all_services = db.get_all_services()
    # Exclude the service being turned off
    active_hostnames = [s['current_hostname'] for s in all_services if s['enabled'] and s['current_hostname'] and s['id'] != service_id]
    
    ruleset_data = cf_request("GET", "rulesets/phases/http_request_origin/entrypoint")
    if ruleset_data:
        rules = ruleset_data.get('result', {}).get('rules', [])
        target_rule = next((r for r in rules if r.get('description') == origin_rule_name), None)
        ruleset_id = ruleset_data.get('result', {}).get('id')

        if target_rule:
            if active_hostnames:
                # Update the rule with the remaining hostnames
                host_list = " ".join(f'"{h}"' for h in active_hostnames)
                new_expression = f"http.host in {{{host_list}}}"
                
                update_data = {
                    "expression": new_expression,
                    "description": origin_rule_name,
                    "action": target_rule['action'],
                    "action_parameters": target_rule['action_parameters'],
                    "enabled": True
                }
                cf_request("PATCH", f"rulesets/{ruleset_id}/rules/{target_rule['id']}", update_data)
                print(f"   Updated Origin Rule with remaining hosts: {origin_rule_name}")
            else:
                # No active services left, delete the rule
                cf_request("DELETE", f"rulesets/{ruleset_id}/rules/{target_rule['id']}")
                print(f"   Deleted Origin Rule as no services are active: {origin_rule_name}")
        else:
            print(f"   No Origin Rule found to clean up.")

    print("🔹 Updating Home Assistant...")
    update_hass("Disabled", service['name'], service.get('hass_entity_id'))
    
    # Update database - clear hostname and port
    db.update_service_status(service_id, False, None, None)
    
    print(f"✅ {service['name']} ACCESS DISABLED.\n")
    return {"message": f"{service['name']} disabled successfully"}

def turn_on_service(service_id):
    """Turn on a specific service"""
    service = db.get_service(service_id)
    if not service:
        return {"error": "Service not found"}
    
    print(f"\n🚀 === ENABLING {service['name']} ===")
    
    # Check if any other service is already enabled and get its port
    # All active services share the same firewall port
    all_services = db.get_all_services()
    active_service_ports = set()
    active_service_with_port = None
    
    for other_service in all_services:
        if other_service['id'] != service_id and other_service['enabled']:
            port = other_service.get('current_port')
            if port:
                active_service_ports.add(port)
                if active_service_with_port is None:
                    active_service_with_port = other_service
    
    # Validate that all active services are using the same port
    if len(active_service_ports) > 1:
        print(f"⚠️ Warning: Multiple different ports detected across active services: {active_service_ports}")
        print(f"   This may indicate a configuration issue. Using port from {active_service_with_port['name']}")
    
    # Use existing port if available, otherwise generate new one
    if active_service_with_port:
        active_service_port = active_service_with_port['current_port']
        print(f"   Reusing existing port from {active_service_with_port['name']}: {active_service_port}")
        # Firewall is already open with the existing port
        print(f"   Firewall already open on port {active_service_port}")
    else:
        active_service_port = generate_random_port()
        print(f"   Generated new random port: {active_service_port}")
        # Update UniFi with the new port only if we're generating a new one
        if not toggle_unifi(True, active_service_port):
            print("⚠️ Warning: UniFi update failed, but proceeding with other steps...")
    
    random_port = active_service_port  # Use the shared port

    domain_root = get_setting("DOMAIN_ROOT")
    if not domain_root:
        return {"error": "DOMAIN_ROOT not configured"}
    
    random_part = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    new_subdomain = f"{service['subdomain_prefix']}-{random_part}"
    full_hostname = f"{new_subdomain}.{domain_root}"
    public_ip = get_public_ip()
    
    print(f"   Service: {service['name']}")
    print(f"   Target:  {full_hostname}")
    print(f"   Port:    {random_port}")
    print(f"   IP:      {public_ip}")

    print("🔹 Creating DNS Record...")
    dns_data = {"type": "A", "name": new_subdomain, "content": public_ip, "ttl": 1, "proxied": True}
    result = cf_request("POST", "dns_records", dns_data)
    if not result:
        return {"error": "Failed to create DNS record"}

    print("🔹 Updating Origin Rule...")
    origin_rule_name = get_setting("ORIGIN_RULE_NAME", required=False) or "Service Rotation"
    
    # Get all currently enabled services to build the list of hostnames
    all_services = db.get_all_services()
    active_hostnames = [s['current_hostname'] for s in all_services if s['enabled'] and s['current_hostname']]
    
    # Add the new hostname to the list
    if full_hostname not in active_hostnames:
        active_hostnames.append(full_hostname)
    
    # Format for Cloudflare API
    host_list = " ".join(f'"{h}"' for h in active_hostnames)
    new_expression = f"http.host in {{{host_list}}}"
    
    ruleset_data = cf_request("GET", "rulesets/phases/http_request_origin/entrypoint")
    
    if ruleset_data:
        rules = ruleset_data.get('result', {}).get('rules', [])
        target_rule = next((r for r in rules if r.get('description') == origin_rule_name), None)
        ruleset_id = ruleset_data.get('result', {}).get('id')

        if target_rule:
            # Update existing rule
            update_data = {
                "expression": new_expression,
                "description": origin_rule_name,
                "action": target_rule['action'],
                "action_parameters": target_rule['action_parameters'],
                "enabled": True
            }
            # Also update the port in the action parameters
            if 'origin' not in update_data['action_parameters']:
                update_data['action_parameters']['origin'] = {}
            update_data['action_parameters']['origin']['port'] = random_port

            cf_request("PATCH", f"rulesets/{ruleset_id}/rules/{target_rule['id']}", update_data)
            print(f"   Updated existing Origin Rule: {origin_rule_name}")
        else:
            # Create a new rule
            new_rule_data = {
                "expression": new_expression,
                "description": origin_rule_name,
                "action": "route",
                "action_parameters": {
                    "origin": {
                        "port": random_port
                    }
                },
                "enabled": True
            }
            
            rules_data = {
                "rules": rules + [new_rule_data]
            }
            
            result = cf_request("PUT", f"rulesets/{ruleset_id}", rules_data)
            if result:
                print(f"   Created new Origin Rule: {origin_rule_name}")
            else:
                print(f"   ⚠️ Warning: Failed to create Origin Rule")


    print("🔹 Cleaning old DNS for this service...")
    records = cf_request("GET", f"dns_records?type=A&name_contains={service['subdomain_prefix']}-")
    if records:
        for record in records.get('result', []):
            if should_delete_dns_record(record['name'], service['subdomain_prefix'], full_hostname):
                print(f"   Deleting old DNS record: {record['name']}")
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
    
    # Update database with hostname and port
    db.update_service_status(service_id, True, full_hostname, random_port)

    # Check if port is open (brief delay to allow firewall rule to propagate)
    print("🔹 Verifying port accessibility...")
    time.sleep(1)  # Brief 1-second delay to allow firewall rule to propagate
    port_check = check_port_open(random_port)
    
    port_open = port_check.get("open")
    if port_open is True:
        print(f"✅ Port {random_port} verified as accessible")
        port_status = "verified"
    elif port_open is None:
        error_msg = port_check.get("error", "Unknown error")
        print(f"⚠️ Port status unknown: {error_msg}")
        port_status = "unknown"
    else:
        error_msg = port_check.get("error", "Unknown error")
        print(f"⚠️ Port verification failed: {error_msg}")
        port_status = "unverified"

    print(f"✅ SUCCESS! {service['name']} live at: https://{full_hostname} (Port: {random_port})\n")
    return {
        "message": f"{service['name']} enabled successfully", 
        "url": f"https://{full_hostname}", 
        "port": random_port,
        "port_status": port_status
    }

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

# API Key authentication support
def api_key_or_login_required(f):
    """Decorator that allows either API key or session-based authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for API key in header
        api_key = request.headers.get('X-API-Key')
        if api_key is not None:
            # API key header was provided (even if empty)
            # Strip whitespace and check if non-empty
            api_key = api_key.strip()
            if not api_key:
                # Empty API key
                return jsonify({"error": "Invalid API key"}), 401
            
            # Hash the provided key
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()
            # Check if key exists in database
            key_data = db.get_api_key_by_hash(key_hash)
            if key_data:
                # Update last used timestamp
                db.update_api_key_last_used(key_hash)
                # Continue with the request
                return f(*args, **kwargs)
            else:
                # Invalid API key
                return jsonify({"error": "Invalid API key"}), 401
        
        # No API key, check for session-based authentication
        if current_user.is_authenticated:
            return f(*args, **kwargs)
        
        # Neither authentication method succeeded
        # For API requests (JSON expected), return 401
        # For browser requests, redirect to login
        if request.path.startswith('/api/'):
            return jsonify({"error": "Authentication required. Provide X-API-Key header or log in."}), 401
        else:
            return login_manager.unauthorized()
    
    return decorated_function

# RP (Relying Party) settings for WebAuthn
RP_ID = os.environ.get('RP_ID', 'localhost')
RP_NAME = "Traefik Route Control"
ORIGIN = os.environ.get('ORIGIN', f'http://localhost:5000')

def get_expected_origin():
    """
    Get the expected origin for WebAuthn operations.
    For development, dynamically determine based on request to support localhost/127.0.0.1/0.0.0.0.
    For production with ORIGIN set, use the configured ORIGIN.
    """
    # If ORIGIN is explicitly set via environment variable (not default), use it
    if 'ORIGIN' in os.environ:
        return ORIGIN
    
    # For development (default config), dynamically determine origin from request
    # This allows localhost, 127.0.0.1, and other local addresses to work
    if has_request_context():
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
    if has_request_context():
        host = request.host
        # Use urlparse for robust hostname extraction that handles IPv6
        # request.host includes port, so we need to parse it properly
        # For IPv6: [::1]:5000 -> ::1
        # For IPv4: 127.0.0.1:5000 -> 127.0.0.1
        # For hostname: localhost:5000 -> localhost
        if host.startswith('['):
            # IPv6 address with brackets
            hostname = host.split(']')[0][1:]  # Remove brackets
        else:
            # IPv4 or hostname
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
        # Log what's missing for debugging (server-side only)
        missing = []
        if not challenge: missing.append('challenge')
        if not username: missing.append('username')
        if not rp_id: missing.append('rp_id')
        if not origin: missing.append('origin')
        print(f"⚠️ Registration failed: Missing session data: {', '.join(missing)}")
        # Return generic error to client
        return jsonify({"error": "Invalid or expired session. Please try again."}), 400
    
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
        # Log what's missing for debugging (server-side only)
        missing = []
        if not challenge: missing.append('challenge')
        if not user_id: missing.append('user_id')
        if not rp_id: missing.append('rp_id')
        if not origin: missing.append('origin')
        print(f"⚠️ Authentication failed: Missing session data: {', '.join(missing)}")
        # Return generic error to client
        return jsonify({"error": "Invalid or expired session. Please try again."}), 400
    
    try:
        # Convert credential ID from base64 URL-safe to hex to match database storage
        # The credential['rawId'] is base64 URL-safe encoded
        cred_id_base64 = credential.get('rawId', '')
        # Decode using urlsafe_b64decode which handles padding automatically
        cred_id_bytes = base64.urlsafe_b64decode(cred_id_base64 + '==')  # Add padding for safety
        cred_id_hex = cred_id_bytes.hex()
        
        # Get credential from database
        db_credential = db.get_credential_by_id(cred_id_hex)
        
        if not db_credential or db_credential['user_id'] != user_id:
            print(f"⚠️ Credential lookup failed: cred_id_hex={cred_id_hex}, db_credential={db_credential}")
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
        
        # Update sign count using the hex credential ID
        db.update_credential_sign_count(cred_id_hex, verification.new_sign_count)
        
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
        # Clear session on error
        session.pop('authentication_challenge', None)
        session.pop('authentication_user_id', None)
        session.pop('authentication_rp_id', None)
        session.pop('authentication_origin', None)
        return jsonify({"error": str(e)}), 400

@app.route('/')
def index():
    # Allow access during setup window if no users exist
    if db.count_users() == 0 and is_in_setup_window():
        return redirect(url_for('login'))
    
    # Otherwise require login
    if not current_user.is_authenticated:
        return login_manager.unauthorized()
    
    # Check if user needs onboarding
    user = db.get_user(current_user.id)
    if user and not user.get('onboarding_completed'):
        return redirect(url_for('onboarding'))
    
    services = db.get_all_services()
    settings = db.get_all_settings()
    return render_template('index.html', services=services, settings=settings)

@app.route('/onboarding', methods=['GET'])
@login_required
def onboarding():
    """Show onboarding wizard for new users"""
    user = db.get_user(current_user.id)
    if user and user.get('onboarding_completed'):
        # Already completed onboarding, redirect to home
        return redirect(url_for('index'))
    
    settings = db.get_all_settings()
    return render_template('onboarding.html', settings=settings)

@app.route('/onboarding/complete', methods=['POST'])
@login_required
def onboarding_complete():
    """Complete onboarding and save all settings"""
    try:
        # Save all settings
        for key in request.form:
            db.set_setting(key, request.form[key])
        
        # Mark onboarding as completed
        db.update_user_onboarding_status(current_user.id, True)
        
        flash('Setup completed successfully!', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('onboarding'))

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
@api_key_or_login_required
def api_status():
    return jsonify(get_status())

@app.route('/api/firewall-status', methods=['GET'])
@api_key_or_login_required
def api_firewall_status():
    firewall_status = "UNKNOWN"
    firewall_port = None
    rule_info = check_unifi_rule()
    if rule_info:
        if rule_info["enabled"] is True:
            firewall_status = "OPEN"
        elif rule_info["enabled"] is False:
            firewall_status = "CLOSED"
        firewall_port = rule_info.get("port")
    return jsonify({"status": firewall_status, "port": firewall_port})

@app.route('/api/services/<int:service_id>/on', methods=['POST'])
@api_key_or_login_required
def api_turn_on(service_id):
    result = turn_on_service(service_id)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/services/<int:service_id>/off', methods=['POST'])
@api_key_or_login_required
def api_turn_off(service_id):
    result = turn_off_service(service_id)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/services/<int:service_id>/rotate', methods=['POST'])
@api_key_or_login_required
def api_rotate(service_id):
    result = rotate_service(service_id)
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/services/<int:service_id>/status', methods=['GET'])
@api_key_or_login_required
def api_service_status(service_id):
    result = get_service_status(service_id)
    if result is None:
        return jsonify({"error": "Service not found"}), 404
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/services/<int:service_id>/repair', methods=['POST'])
@api_key_or_login_required
def api_repair_service(service_id):
    """Repair service configuration by syncing database config to Redis/Traefik"""
    service = db.get_service(service_id)
    if not service:
        return jsonify({"error": "Service not found"}), 404
    
    # Only repair enabled services
    if not service['enabled']:
        return jsonify({"error": "Service must be enabled to repair"}), 400
    
    r = get_redis()
    if not r:
        return jsonify({"error": "Redis connection failed"}), 400
    
    # Check what's currently in Redis
    current_rule = r.get(f"traefik/http/routers/{service['router_name']}/rule")
    if not current_rule:
        return jsonify({"error": "Service is not active in Traefik"}), 400
    
    # Get actual vs expected values
    actual_target_url = r.get(f"traefik/http/services/{service['service_name']}/loadbalancer/servers/0/url")
    expected_target_url = service['target_url']
    
    if actual_target_url == expected_target_url:
        return jsonify({"message": "Service configuration is already correct", "target_url": expected_target_url})
    
    # Repair: Update Redis with correct target URL from database
    r.set(f"traefik/http/services/{service['service_name']}/loadbalancer/servers/0/url", expected_target_url)
    
    print(f"🔧 Repaired {service['name']}: {actual_target_url} → {expected_target_url}")
    
    return jsonify({
        "message": "Service configuration repaired successfully",
        "old_target_url": actual_target_url,
        "new_target_url": expected_target_url
    })

@app.route('/api/services/<int:service_id>/diagnose', methods=['GET'])
@api_key_or_login_required
def api_diagnose_service(service_id):
    """Diagnose service configuration and connectivity issues"""
    service = db.get_service(service_id)
    if not service:
        return jsonify({"error": "Service not found"}), 404
    
    diagnostics = {
        "service": service,
        "checks": {}
    }
    
    # Check Redis connection
    r = get_redis()
    if not r:
        diagnostics["checks"]["redis"] = {"status": "fail", "message": "Redis connection failed"}
        return jsonify(diagnostics), 400
    else:
        diagnostics["checks"]["redis"] = {"status": "ok", "message": "Redis connection successful"}
    
    # Check if service is enabled
    if not service['enabled']:
        diagnostics["checks"]["enabled"] = {"status": "info", "message": "Service is disabled"}
        return jsonify(diagnostics)
    
    diagnostics["checks"]["enabled"] = {"status": "ok", "message": "Service is enabled"}
    
    # Check Traefik router configuration
    current_rule = r.get(f"traefik/http/routers/{service['router_name']}/rule")
    if not current_rule:
        diagnostics["checks"]["traefik_router"] = {
            "status": "fail", 
            "message": "Router not found in Traefik/Redis"
        }
    else:
        hostname = current_rule.replace("Host(`", "").replace("`)", "")
        diagnostics["checks"]["traefik_router"] = {
            "status": "ok",
            "message": "Router configured correctly",
            "hostname": hostname
        }
    
    # Check Traefik service configuration
    actual_target_url = r.get(f"traefik/http/services/{service['service_name']}/loadbalancer/servers/0/url")
    expected_target_url = service['target_url']
    
    if not actual_target_url:
        diagnostics["checks"]["traefik_service"] = {
            "status": "fail",
            "message": "Service backend not configured in Traefik"
        }
    elif actual_target_url != expected_target_url:
        diagnostics["checks"]["traefik_service"] = {
            "status": "warning",
            "message": "Service backend URL mismatch",
            "expected": expected_target_url,
            "actual": actual_target_url
        }
    else:
        diagnostics["checks"]["traefik_service"] = {
            "status": "ok",
            "message": "Service backend configured correctly",
            "target_url": actual_target_url
        }
    
    # Check DNS record
    if service.get('current_hostname'):
        domain_root = get_setting("DOMAIN_ROOT", required=False)
        if domain_root:
            records = cf_request("GET", f"dns_records?type=A&name={service['current_hostname']}")
            
            if records and records.get('result'):
                dns_record = records['result'][0]
                diagnostics["checks"]["dns"] = {
                    "status": "ok",
                    "message": "DNS record exists",
                    "name": dns_record['name'],
                    "content": dns_record['content'],
                    "proxied": dns_record['proxied']
                }
            else:
                diagnostics["checks"]["dns"] = {
                    "status": "fail",
                    "message": "DNS record not found in Cloudflare",
                    "expected_name": service['current_hostname']
                }
        else:
            diagnostics["checks"]["dns"] = {
                "status": "info",
                "message": "Cannot check DNS - DOMAIN_ROOT not configured"
            }
    else:
        diagnostics["checks"]["dns"] = {
            "status": "info",
            "message": "No current hostname - service may not have been activated yet"
        }
    
    # Check Cloudflare Origin Rule
    if service.get('current_hostname'):
        origin_rule_name = get_setting("ORIGIN_RULE_NAME", required=False) or "Service Rotation"
        
        ruleset_data = cf_request("GET", "rulesets/phases/http_request_origin/entrypoint")
        if ruleset_data:
            rules = ruleset_data.get('result', {}).get('rules', [])
            target_rule = next((r for r in rules if r.get('description') == origin_rule_name), None)
            
            if target_rule:
                # Check if hostname is in expression
                expression = target_rule.get('expression', '')
                hostname = service['current_hostname']
                
                if f'"{hostname}"' in expression:
                    port = target_rule.get('action_parameters', {}).get('origin', {}).get('port')
                    diagnostics["checks"]["origin_rule"] = {
                        "status": "ok",
                        "message": "Origin rule exists and includes hostname",
                        "port": port,
                        "enabled": target_rule.get('enabled')
                    }
                else:
                    diagnostics["checks"]["origin_rule"] = {
                        "status": "warning",
                        "message": "Origin rule exists but hostname missing from expression",
                        "expression": expression
                    }
            else:
                diagnostics["checks"]["origin_rule"] = {
                    "status": "warning",
                    "message": "Origin rule not found",
                    "expected_description": origin_rule_name
                }
        else:
            diagnostics["checks"]["origin_rule"] = {
                "status": "fail",
                "message": "Cannot retrieve origin rules from Cloudflare"
            }
    
    # Check firewall status
    rule_info = check_unifi_rule()
    if rule_info is None:
        diagnostics["checks"]["firewall"] = {
            "status": "info",
            "message": "Firewall control not configured"
        }
    elif rule_info.get("enabled"):
        diagnostics["checks"]["firewall"] = {
            "status": "ok",
            "message": "Firewall rule is enabled",
            "port": rule_info.get("port")
        }
    else:
        diagnostics["checks"]["firewall"] = {
            "status": "warning",
            "message": "Firewall rule is disabled",
            "port": rule_info.get("port")
        }
    
    # Check backend host connectivity
    target_url = service['target_url']
    try:
        # Parse URL to validate it
        parsed_url = urlparse(target_url)
        
        # Basic SSRF protection: only allow http/https schemes
        # Note: Checking internal IPs (e.g., 192.168.x.x) is the intended use case
        # as this application manages access to internal backend services
        if parsed_url.scheme not in ['http', 'https']:
            diagnostics["checks"]["backend_host"] = {
                "status": "info",
                "message": f"Skipping connectivity check for non-HTTP(S) URL",
                "target": target_url
            }
        else:
            response = requests.get(target_url, timeout=5, allow_redirects=True)
            
            # Categorize responses more accurately
            if 200 <= response.status_code < 300:
                # 2xx: Success - host is responding correctly
                diagnostics["checks"]["backend_host"] = {
                    "status": "ok",
                    "message": "Backend host is responding",
                    "target": target_url,
                    "status_code": response.status_code
                }
            elif 300 <= response.status_code < 400:
                # 3xx: Redirects (kept for clarity, though allow_redirects=True means this won't trigger)
                diagnostics["checks"]["backend_host"] = {
                    "status": "ok",
                    "message": "Backend host is responding (redirect)",
                    "target": target_url,
                    "status_code": response.status_code
                }
            elif 400 <= response.status_code < 500:
                # 4xx: Client errors - host is reachable but may have config issues
                diagnostics["checks"]["backend_host"] = {
                    "status": "warning",
                    "message": f"Backend host returned client error (HTTP {response.status_code})",
                    "target": target_url,
                    "status_code": response.status_code
                }
            else:
                # 5xx: Server errors - host is reachable but has internal errors
                diagnostics["checks"]["backend_host"] = {
                    "status": "warning",
                    "message": f"Backend host returned server error (HTTP {response.status_code})",
                    "target": target_url,
                    "status_code": response.status_code
                }
    except requests.exceptions.Timeout:
        diagnostics["checks"]["backend_host"] = {
            "status": "fail",
            "message": "Backend host connection timed out",
            "target": target_url
        }
    except requests.exceptions.ConnectionError as e:
        diagnostics["checks"]["backend_host"] = {
            "status": "fail",
            "message": "Cannot connect to backend host",
            "target": target_url,
            "error": str(e)
        }
    except Exception as e:
        diagnostics["checks"]["backend_host"] = {
            "status": "fail",
            "message": "Error checking backend host",
            "target": target_url,
            "error": str(e)
        }
    
    return jsonify(diagnostics)

@app.route('/api/services/<int:service_id>', methods=['DELETE'])
@api_key_or_login_required
def api_delete_service(service_id):
    service = db.get_service(service_id)
    if not service:
        return jsonify({"error": "Service not found"}), 404
    
    # If service is enabled, turn it off first
    if service['enabled']:
        turn_off_service(service_id)
    
    db.delete_service(service_id)
    return jsonify({"message": "Service deleted successfully"})

@app.route('/api/logs', methods=['GET'])
@api_key_or_login_required
def api_get_logs():
    try:
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r', encoding='utf-8') as f:
                content = f.read()
            return jsonify({"logs": content})
        return jsonify({"logs": "Log file empty or not found."})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/services/all/on', methods=['POST'])
@api_key_or_login_required
def api_turn_on_all():
    services = db.get_all_services()
    results = []
    for service in services:
        if not service['enabled']:
            result = turn_on_service(service['id'])
            results.append(result)
    return jsonify({"results": results})

@app.route('/api/services/all/off', methods=['POST'])
@api_key_or_login_required
def api_turn_off_all():
    services = db.get_all_services()
    results = []
    for service in services:
        if service['enabled']:
            result = turn_off_service(service['id'])
            results.append(result)
    return jsonify({"results": results})

# Legacy API endpoints for backward compatibility
@app.route('/api/turn_on', methods=['POST'])
@api_key_or_login_required
def api_legacy_turn_on():
    services = db.get_all_services()
    if not services:
        return jsonify({"error": "No services configured"}), 400
    result = turn_on_service(services[0]['id'])
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

@app.route('/api/turn_off', methods=['POST'])
@api_key_or_login_required
def api_legacy_turn_off():
    services = db.get_all_services()
    if not services:
        return jsonify({"error": "No services configured"}), 400
    result = turn_off_service(services[0]['id'])
    if "error" in result:
        return jsonify(result), 400
    return jsonify(result)

# API Key Management Routes
@app.route('/api-keys', methods=['GET'])
@login_required
def api_keys_page():
    """Show API key management page"""
    api_keys = db.get_api_keys_for_user(current_user.id)
    return render_template('api_keys.html', api_keys=api_keys)

@app.route('/api-keys/create', methods=['POST'])
@login_required
def create_api_key():
    """Create a new API key"""
    try:
        name = request.form.get('name', 'API Key')
        
        # Generate a random API key (32 bytes = 64 hex characters)
        api_key = secrets.token_hex(32)
        
        # Hash the key for storage
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Store in database
        db.add_api_key(current_user.id, key_hash, name)
        
        # Store temporarily in session to show on redirect (only shown once)
        session['new_api_key'] = api_key
        
        return redirect(url_for('api_keys_page'))
    except Exception as e:
        flash(f'Error creating API key: {str(e)}', 'error')
        return redirect(url_for('api_keys_page'))

@app.route('/api-keys/<int:key_id>/delete', methods=['POST'])
@login_required
def delete_api_key_route(key_id):
    """Delete an API key"""
    try:
        # Verify the key belongs to the current user
        keys = db.get_api_keys_for_user(current_user.id)
        if not any(k['id'] == key_id for k in keys):
            flash('API key not found', 'error')
            return redirect(url_for('api_keys_page'))
        
        db.delete_api_key(key_id)
        flash('API key deleted successfully', 'success')
        return redirect(url_for('api_keys_page'))
    except Exception as e:
        flash(f'Error deleting API key: {str(e)}', 'error')
        return redirect(url_for('api_keys_page'))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Control Traefik Route Rotation")
    parser.add_argument("action", choices=["on", "off", "status", "rotate", "serve"], 
                        help="Action to perform", default="serve", nargs="?")
    args = parser.parse_args()

    # Ensure environment is migrated/setup before any action
    migrate_env_to_db()

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
