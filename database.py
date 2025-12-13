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

def add_service(name, router_name, service_name, target_url, subdomain_prefix):
    """Add a new service."""
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO services (name, router_name, service_name, target_url, subdomain_prefix)
            VALUES (?, ?, ?, ?, ?)
        """, (name, router_name, service_name, target_url, subdomain_prefix))
        conn.commit()
        return cursor.lastrowid

def update_service(service_id, name, router_name, service_name, target_url, subdomain_prefix):
    """Update an existing service."""
    with get_db() as conn:
        conn.execute("""
            UPDATE services 
            SET name = ?, router_name = ?, service_name = ?, target_url = ?, 
                subdomain_prefix = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (name, router_name, service_name, target_url, subdomain_prefix, service_id))
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
