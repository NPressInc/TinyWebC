#!/usr/bin/env python3
"""
Simple Relay Server for TinyWeb Node Discovery

This server maintains a mapping of public keys to IP:port addresses.
Nodes can:
- POST /register: Register/update their public key with current IP:port
- GET /lookup/<public_key_hex>: Get IP:port for a public key

Usage:
    python3 simple_relay_server.py

Nodes register with:
    curl -X POST http://relay-server:5050/register \
         -H "Content-Type: application/json" \
         -d '{"public_key": "hex_key_here", "ip": "192.168.1.100", "port": 8080}'

Nodes lookup peers with:
    curl http://relay-server:5050/lookup/hex_public_key_here
"""

import json
import threading
import time
from flask import Flask, request, jsonify
from datetime import datetime, timedelta

app = Flask(__name__)

# In-memory storage: public_key_hex -> {"ip": str, "port": int, "last_seen": datetime}
node_registry = {}

# Thread lock for thread-safe access
registry_lock = threading.Lock()

# Clean up stale entries (older than 5 minutes)
def cleanup_stale_entries():
    while True:
        time.sleep(60)  # Check every minute
        cutoff_time = datetime.now() - timedelta(minutes=5)

        with registry_lock:
            stale_keys = []
            for pubkey, data in node_registry.items():
                if data['last_seen'] < cutoff_time:
                    stale_keys.append(pubkey)

            for key in stale_keys:
                print(f"Removing stale entry for {key[:16]}...")
                del node_registry[key]

# Start cleanup thread
cleanup_thread = threading.Thread(target=cleanup_stale_entries, daemon=True)
cleanup_thread.start()

def validate_public_key(pubkey_hex):
    """Validate that the public key is proper hex and correct length"""
    try:
        # Ed25519 public keys are 32 bytes = 64 hex chars
        if len(pubkey_hex) != 64:
            return False
        int(pubkey_hex, 16)  # Validate hex
        return True
    except ValueError:
        return False

@app.route('/register', methods=['POST'])
def register_node():
    """Register or update a node's IP:port"""
    try:
        data = request.get_json()

        if not data or 'public_key' not in data or 'ip' not in data or 'port' not in data:
            return jsonify({"error": "Missing required fields: public_key, ip, port"}), 400

        pubkey = data['public_key'].lower()  # Normalize to lowercase
        ip = data['ip']
        port = int(data['port'])

        # Validate inputs
        if not validate_public_key(pubkey):
            return jsonify({"error": "Invalid public key format"}), 400

        if port < 1 or port > 65535:
            return jsonify({"error": "Invalid port number"}), 400

        # Update registry
        with registry_lock:
            node_registry[pubkey] = {
                'ip': ip,
                'port': port,
                'last_seen': datetime.now()
            }

        print(f"Registered node {pubkey[:16]}... at {ip}:{port}")
        return jsonify({"status": "registered", "public_key": pubkey})

    except Exception as e:
        print(f"Registration error: {e}")
        return jsonify({"error": "Registration failed"}), 500

@app.route('/lookup/<pubkey_hex>', methods=['GET'])
def lookup_node(pubkey_hex):
    """Lookup a node's IP:port by public key"""
    pubkey = pubkey_hex.lower()  # Normalize to lowercase

    if not validate_public_key(pubkey):
        return jsonify({"error": "Invalid public key format"}), 400

    with registry_lock:
        if pubkey in node_registry:
            data = node_registry[pubkey]
            # Check if entry is not too stale (max 10 minutes)
            if datetime.now() - data['last_seen'] < timedelta(minutes=10):
                return jsonify({
                    "ip": data['ip'],
                    "port": data['port'],
                    "last_seen": data['last_seen'].isoformat()
                })

    return jsonify({"error": "Node not found or stale"}), 404

@app.route('/status', methods=['GET'])
def get_status():
    """Get server status and registry info"""
    with registry_lock:
        active_nodes = len(node_registry)
        return jsonify({
            "status": "running",
            "active_nodes": active_nodes,
            "nodes": list(node_registry.keys())  # Just keys for privacy
        })

@app.route('/health', methods=['GET'])
def health_check():
    """Simple health check endpoint"""
    return jsonify({"status": "healthy"})

if __name__ == '__main__':
    print("Starting TinyWeb Relay Server on port 5050...")
    print("Endpoints:")
    print("  POST /register - Register node")
    print("  GET /lookup/<pubkey> - Lookup node")
    print("  GET /status - Server status")
    print("  GET /health - Health check")
    app.run(host='0.0.0.0', port=5050, debug=True)
