import json
import threading
import time
import paho.mqtt.client as mqtt
import database as db

class MQTTHandler:
    def __init__(self, command_callback=None):
        self.client = None
        self.enabled = False
        self.host = None
        self.port = 1883
        self.username = None
        self.password = None
        self.discovery_prefix = "homeassistant"
        self.command_callback = command_callback
        self.running = False
        self._lock = threading.RLock()

    def load_config(self):
        """Load MQTT configuration from database."""
        self.enabled = db.get_setting("MQTT_ENABLED", "0") == "1"
        self.host = db.get_setting("MQTT_HOST")
        self.port = int(db.get_setting("MQTT_PORT", "1883"))
        self.username = db.get_setting("MQTT_USER")
        self.password = db.get_setting("MQTT_PASS")
        self.discovery_prefix = db.get_setting("MQTT_DISCOVERY_PREFIX", "homeassistant")

    def start(self):
        """Start the MQTT client if enabled."""
        with self._lock:
            self.load_config()
            
            if not self.enabled:
                if self.running:
                    self.stop()
                return

            if not self.host:
                print("⚠️ MQTT enabled but no host configured.")
                return

            if self.running:
                # If already running, we might need to reconnect if config changed
                # For simplicity, we can restart
                self.stop()

            try:
                self.client = mqtt.Client()
                if self.username:
                    self.client.username_pw_set(self.username, self.password)
                
                self.client.on_connect = self.on_connect
                self.client.on_message = self.on_message
                self.client.on_disconnect = self.on_disconnect

                print(f"🔹 Connecting to MQTT Broker at {self.host}:{self.port}...")
                self.client.connect_async(self.host, self.port, 60)
                self.client.loop_start()
                self.running = True
                
            except Exception as e:
                print(f"❌ Failed to start MQTT client: {e}")
                self.running = False

    def stop(self):
        """Stop the MQTT client."""
        with self._lock:
            if self.client:
                print("🔹 Stopping MQTT client...")
                self.client.loop_stop()
                self.client.disconnect()
                self.client = None
            self.running = False

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            print("✅ Connected to MQTT Broker")
            self.publish_all_discovery()
            # Subscribe to all service command topics
            self.subscribe_all()
        else:
            print(f"❌ MQTT Connection failed with code {rc}")

    def on_disconnect(self, client, userdata, rc):
        if rc != 0:
            print("⚠️ MQTT Unexpected disconnection. Auto-reconnect should handle this.")
        else:
            print("🔹 MQTT Disconnected")

    def on_message(self, client, userdata, msg):
        try:
            # Topic format: routeghost/service/<service_id>/set
            # We expect the topic structure to be consistent
            parts = msg.topic.split('/')
            if len(parts) >= 4 and parts[0] == "routeghost" and parts[1] == "service" and parts[3] == "set":
                service_id = int(parts[2])
                payload = msg.payload.decode().upper()
                
                if self.command_callback:
                    if payload == "ON":
                        print(f"🔹 MQTT Command: Turn ON Service {service_id}")
                        self.command_callback(service_id, True)
                    elif payload == "OFF":
                        print(f"🔹 MQTT Command: Turn OFF Service {service_id}")
                        self.command_callback(service_id, False)
        except Exception as e:
            print(f"❌ Error handling MQTT message: {e}")

    def subscribe_all(self):
        """Subscribe to command topics for all services."""
        if not self.client or not self.client.is_connected():
            return
            
        services = db.get_all_services()
        for service in services:
            topic = f"routeghost/service/{service['id']}/set"
            self.client.subscribe(topic)

    def publish_discovery(self, service):
        """Publish Home Assistant Discovery config for a service."""
        if not self.client or not self.client.is_connected():
            return

        service_id = service['id']
        safe_name = service['name'].lower().replace(" ", "_")
        unique_id = f"routeghost_service_{service_id}"
        
        topic = f"{self.discovery_prefix}/switch/routeghost/{service_id}/config"
        
        payload = {
            "name": f"RouteGhost {service['name']}",
            "unique_id": unique_id,
            "command_topic": f"routeghost/service/{service_id}/set",
            "state_topic": f"routeghost/service/{service_id}/state",
            "availability_topic": "routeghost/status",
            "device": {
                "identifiers": ["routeghost_main"],
                "name": "RouteGhost Manager",
                "manufacturer": "RouteGhost",
                "model": "RouteGhost Gateway",
                "sw_version": "0.1.0" 
            }
        }
        
        self.client.publish(topic, json.dumps(payload), retain=True)
        
        # Publish current state immediately
        is_active = service['enabled'] == 1
        self.publish_state(service, is_active)

    def publish_all_discovery(self):
        """Publish discovery for all services and availability."""
        if not self.client or not self.client.is_connected():
            return
            
        # Publish availability
        self.client.publish("routeghost/status", "online", retain=True)
        
        services = db.get_all_services()
        for service in services:
            self.publish_discovery(service)

    def publish_state(self, service_dict_or_id, is_active):
        """Publish state update for a service."""
        if not self.client or not self.client.is_connected():
            return

        if isinstance(service_dict_or_id, dict):
            service_id = service_dict_or_id['id']
        else:
            service_id = service_dict_or_id

        topic = f"routeghost/service/{service_id}/state"
        state = "ON" if is_active else "OFF"
        self.client.publish(topic, state, retain=True)

    def reload(self):
        """Reload configuration and restart."""
        self.start()

# Global instance
mqtt_manager = MQTTHandler()
