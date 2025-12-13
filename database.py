#!/usr/bin/env python3
import sqlite3
import json
import os
from contextlib import contextmanager

# Use /app/data for Docker volume mounting, fall back to current directory
DATA_DIR = os.environ.get('DATA_DIR', '/app/data' if os.path.exists('/app/data') else os.path.dirname(__file__))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "config.db")

def init_db():
    """Initialize the database schema."""
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                router_name TEXT NOT NULL UNIQUE,
                service_name TEXT NOT NULL,
                target_url TEXT NOT NULL,
                subdomain_prefix TEXT NOT NULL,
                hass_entity_id TEXT,
                enabled INTEGER DEFAULT 0,
                current_hostname TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS webauthn_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                credential_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                sign_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
            )
        """)
        
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Check current schema version
        cursor = conn.execute("SELECT MAX(version) as version FROM schema_version")
        row = cursor.fetchone()
        current_version = row['version'] if row['version'] else 0
        
        # Migration 1: Add hass_entity_id column if not exists
        if current_version < 1:
            cursor = conn.execute("PRAGMA table_info(services)")
            columns = [row[1] for row in cursor.fetchall()]
            if 'hass_entity_id' not in columns:
                conn.execute("ALTER TABLE services ADD COLUMN hass_entity_id TEXT")
            conn.execute("INSERT INTO schema_version (version) VALUES (1)")
        
        conn.commit()

@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# Service CRUD operations
def get_all_services():
    """Get all services."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM services ORDER BY name")
        return [dict(row) for row in cursor.fetchall()]

def get_service(service_id):
    """Get a specific service by ID."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM services WHERE id = ?", (service_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_service_by_router_name(router_name):
    """Get a specific service by router name."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM services WHERE router_name = ?", (router_name,))
        row = cursor.fetchone()
        return dict(row) if row else None

def add_service(name, router_name, service_name, target_url, subdomain_prefix, hass_entity_id=None):
    """Add a new service."""
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO services (name, router_name, service_name, target_url, subdomain_prefix, hass_entity_id)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, router_name, service_name, target_url, subdomain_prefix, hass_entity_id))
        conn.commit()
        return cursor.lastrowid

def update_service(service_id, name, router_name, service_name, target_url, subdomain_prefix, hass_entity_id=None):
    """Update an existing service."""
    with get_db() as conn:
        conn.execute("""
            UPDATE services 
            SET name = ?, router_name = ?, service_name = ?, target_url = ?, 
                subdomain_prefix = ?, hass_entity_id = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (name, router_name, service_name, target_url, subdomain_prefix, hass_entity_id, service_id))
        conn.commit()

def delete_service(service_id):
    """Delete a service."""
    with get_db() as conn:
        conn.execute("DELETE FROM services WHERE id = ?", (service_id,))
        conn.commit()

def update_service_status(service_id, enabled, current_hostname=None):
    """Update service enabled status and current hostname."""
    with get_db() as conn:
        conn.execute("""
            UPDATE services 
            SET enabled = ?, current_hostname = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (1 if enabled else 0, current_hostname, service_id))
        conn.commit()

# Settings CRUD operations
def get_setting(key, default=None):
    """Get a setting value."""
    with get_db() as conn:
        cursor = conn.execute("SELECT value FROM settings WHERE key = ?", (key,))
        row = cursor.fetchone()
        return row['value'] if row else default

def set_setting(key, value):
    """Set a setting value."""
    with get_db() as conn:
        conn.execute("""
            INSERT INTO settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = CURRENT_TIMESTAMP
        """, (key, value, value))
        conn.commit()

def get_all_settings():
    """Get all settings as a dictionary."""
    with get_db() as conn:
        cursor = conn.execute("SELECT key, value FROM settings")
        return {row['key']: row['value'] for row in cursor.fetchall()}

# User CRUD operations
def get_user(user_id):
    """Get a specific user by ID."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_user_by_username(username):
    """Get a specific user by username."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return dict(row) if row else None

def get_all_users():
    """Get all users."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM users ORDER BY username")
        return [dict(row) for row in cursor.fetchall()]

def add_user(username):
    """Add a new user."""
    with get_db() as conn:
        cursor = conn.execute("INSERT INTO users (username) VALUES (?)", (username,))
        conn.commit()
        return cursor.lastrowid

def delete_user(user_id):
    """Delete a user."""
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

def count_users():
    """Count total users."""
    with get_db() as conn:
        cursor = conn.execute("SELECT COUNT(*) FROM users")
        return cursor.fetchone()[0]

# WebAuthn credential operations
def add_credential(user_id, credential_id, public_key):
    """Add a new WebAuthn credential."""
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO webauthn_credentials (user_id, credential_id, public_key)
            VALUES (?, ?, ?)
        """, (user_id, credential_id, public_key))
        conn.commit()
        return cursor.lastrowid

def get_credentials_for_user(user_id):
    """Get all credentials for a user."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM webauthn_credentials WHERE user_id = ?", (user_id,))
        return [dict(row) for row in cursor.fetchall()]

def get_credential_by_id(credential_id):
    """Get a credential by credential_id."""
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM webauthn_credentials WHERE credential_id = ?", (credential_id,))
        row = cursor.fetchone()
        return dict(row) if row else None

def update_credential_sign_count(credential_id, sign_count):
    """Update the sign count for a credential."""
    with get_db() as conn:
        conn.execute("""
            UPDATE webauthn_credentials 
            SET sign_count = ?
            WHERE credential_id = ?
        """, (sign_count, credential_id))
        conn.commit()

def delete_credential(credential_id):
    """Delete a credential."""
    with get_db() as conn:
        conn.execute("DELETE FROM webauthn_credentials WHERE credential_id = ?", (credential_id,))
        conn.commit()
