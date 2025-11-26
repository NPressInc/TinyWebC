#!/usr/bin/env python3
"""
Docker Config Generator for TinyWeb

Generates node-specific configurations and Docker setup files from a master config.
"""

import json
import os
import sys
import argparse
import subprocess
import re
import shutil
from pathlib import Path
from typing import Dict, List, Any

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    print("Warning: PyYAML not installed. Install with: pip install pyyaml", file=sys.stderr)


def extract_node_index(node_id):
    """Extract numeric index from node_id (e.g., 'node_01' -> 1, 'node_22' -> 22)."""
    match = re.match(r'^node_(\d+)$', node_id)
    if not match:
        raise ValueError(f"Invalid node_id format: {node_id}. Expected 'node_XX' where XX is 01-99")
    return int(match.group(1))


def format_node_index(index):
    """Format index as 2-digit zero-padded string (e.g., 1 -> '01', 22 -> '22')."""
    if index < 1 or index > 99:
        raise ValueError(f"Node index must be between 1 and 99, got {index}")
    return f"{index:02d}"


def generate_hostname(node_id, discovery_config, node_config=None):
    """
    Generate hostname based on discovery mode.
    
    Args:
        node_id: Node ID (e.g., 'node_01')
        discovery_config: Discovery configuration from docker.discovery
        node_config: Optional node-specific config (for static mode)
    
    Returns:
        Generated hostname string
    """
    index = extract_node_index(node_id)
    index_str = format_node_index(index)
    mode = discovery_config.get('mode', 'tailscale')
    hostname_prefix = discovery_config.get('hostname_prefix', 'tw_node')
    
    if mode == 'tailscale':
        # Short hostname: {prefix}{index} (e.g., tw_node01)
        return f"{hostname_prefix}{index_str}"
    
    elif mode == 'dns_pattern':
        # Full domain: {prefix}{index}.{domain}
        dns_pattern = discovery_config.get('dns_pattern', {})
        domain = dns_pattern.get('domain')
        if not domain:
            raise ValueError("dns_pattern mode requires 'docker.discovery.dns_pattern.domain' in config")
        return f"{hostname_prefix}{index_str}.{domain}"
    
    elif mode == 'static':
        # Use hostname from node config
        if not node_config or 'hostname' not in node_config:
            raise ValueError(f"Static mode requires 'hostname' field in node config for {node_id}")
        return node_config['hostname']
    
    else:
        raise ValueError(f"Unknown discovery mode: {mode}")


def generate_node_config(node, discovery_config, docker_mode):
    """
    Generate node-specific network_config.json.
    
    Args:
        node: Node object from master config
        discovery_config: Discovery configuration from docker.discovery
        docker_mode: 'production' or 'test'
    
    Returns:
        Dictionary representing the node-specific config
    """
    node_id = node['id']
    discovery_mode = discovery_config.get('mode', 'tailscale')
    
    # Generate hostname
    hostname = generate_hostname(node_id, discovery_config, node)
    
    # Build config
    config = {
        'id': node_id,
        'name': node['name'],
        'hostname': hostname,
        'gossip_port': 9000,
        'api_port': 8000,
        'discovery_mode': discovery_mode
    }
    
    # Add peers based on discovery mode
    if discovery_mode == 'static':
        # Static mode: use peers from node config
        config['peers'] = node.get('peers', [])
    else:
        # Tailscale/DNS pattern: empty peers (dynamic discovery)
        config['peers'] = []
    
    # Add DNS pattern info if in dns_pattern mode
    if discovery_mode == 'dns_pattern':
        dns_pattern = discovery_config.get('dns_pattern', {})
        if 'domain' in dns_pattern:
            config['dns_domain'] = dns_pattern['domain']
        if 'hostname_prefix' in discovery_config:
            config['hostname_prefix'] = discovery_config['hostname_prefix']
    
    # Add hostname_prefix for tailscale mode
    if discovery_mode == 'tailscale' and 'hostname_prefix' in discovery_config:
        config['hostname_prefix'] = discovery_config['hostname_prefix']
    
    return config


def validate_master_config(config):
    """Validate master config structure and constraints."""
    # Check required fields
    if 'nodes' not in config:
        raise ValueError("Master config must contain 'nodes' array")
    
    if 'docker' not in config:
        raise ValueError("Master config must contain 'docker' section")
    
    docker_config = config['docker']
    if 'mode' not in docker_config:
        raise ValueError("docker.mode is required")
    
    if 'discovery' not in docker_config:
        raise ValueError("docker.discovery is required")
    
    discovery = docker_config['discovery']
    if 'mode' not in discovery:
        raise ValueError("docker.discovery.mode is required")
    
    if discovery['mode'] != 'static' and 'hostname_prefix' not in discovery:
        raise ValueError("docker.discovery.hostname_prefix is required for non-static modes")
    
    # Validate node count (max 99)
    nodes = config['nodes']
    if len(nodes) > 99:
        raise ValueError(f"Maximum 99 nodes allowed, got {len(nodes)}")
    
    # Validate node IDs
    node_ids = set()
    for node in nodes:
        node_id = node.get('id')
        if not node_id:
            raise ValueError("Each node must have an 'id' field")
        
        if not re.match(r'^node_\d{2}$', node_id):
            raise ValueError(f"Invalid node_id format: {node_id}. Expected 'node_XX' where XX is 01-99")
        
        if node_id in node_ids:
            raise ValueError(f"Duplicate node_id: {node_id}")
        
        node_ids.add(node_id)
        
        # Validate static mode requirements
        if discovery['mode'] == 'static':
            if 'hostname' not in node:
                raise ValueError(f"Static mode requires 'hostname' field for node {node_id}")
    
    # Validate extensions if present
    if 'extensions' in config:
        if not isinstance(config['extensions'], list):
            raise ValueError("extensions must be an array")
        
        # Validate extension structure matches schema
        for ext in config['extensions']:
            if not isinstance(ext, dict):
                raise ValueError("Each extension must be an object")
            
            required_fields = ['id', 'name', 'docker_image']
            for field in required_fields:
                if field not in ext:
                    raise ValueError(f"Extension missing required field: {field}")
            
            # Validate field types
            if not isinstance(ext['id'], str) or len(ext['id']) == 0:
                raise ValueError("Extension 'id' must be a non-empty string")
            if not isinstance(ext['name'], str) or len(ext['name']) == 0:
                raise ValueError("Extension 'name' must be a non-empty string")
            if not isinstance(ext['docker_image'], str) or len(ext['docker_image']) == 0:
                raise ValueError("Extension 'docker_image' must be a non-empty string")
            
            # Validate optional fields if present
            if 'ports' in ext and not isinstance(ext['ports'], list):
                raise ValueError("Extension 'ports' must be an array")
            if 'bridge_endpoint' in ext and not isinstance(ext['bridge_endpoint'], str):
                raise ValueError("Extension 'bridge_endpoint' must be a string")
            if 'enabled' in ext and not isinstance(ext['enabled'], bool):
                raise ValueError("Extension 'enabled' must be a boolean")
    
    return True


def generate_docker_compose(master_config: Dict, nodes: List[Dict], discovery_config: Dict, 
                           docker_mode: str, output_dir: Path, compose_mode: str) -> Dict:
    """
    Generate docker-compose configuration.
    
    Args:
        master_config: Master network configuration
        nodes: List of node configurations
        discovery_config: Discovery configuration from docker.discovery
        docker_mode: 'production' or 'test'
        output_dir: Output directory for configs
        compose_mode: 'production' or 'test' (for compose file type)
    
    Returns:
        Dictionary representing docker-compose configuration
    """
    discovery_mode = discovery_config.get('mode', 'tailscale')
    hostname_prefix = discovery_config.get('hostname_prefix', 'tw_node')
    
    compose = {
        'version': '3.8',
        'services': {},
        'volumes': {}
    }
    
    # Generate Tailscale sidecar services if in tailscale mode
    if discovery_mode == 'tailscale':
        for node in nodes:
            node_id = node['id']
            index = extract_node_index(node_id)
            hostname = generate_hostname(node_id, discovery_config, node)
            
            tailscale_service_name = f'tailscale_{node_id}'
            compose['services'][tailscale_service_name] = {
                'image': 'tailscale/tailscale:latest',
                'environment': {
                    'TS_AUTHKEY': '${TS_AUTHKEY}',
                    'TS_HOSTNAME': hostname,
                    'TS_STATE_DIR': '/var/lib/tailscale'
                },
                'volumes': [
                    f'{tailscale_service_name}_state:/var/lib/tailscale'
                ],
                'cap_add': ['NET_ADMIN'],
                'healthcheck': {
                    'test': ['CMD', 'tailscale', 'status', '--json'],
                    'interval': '10s',
                    'timeout': '5s',
                    'retries': '3',
                    'start_period': '30s'
                },
                'restart': 'unless-stopped' if compose_mode == 'production' else 'no'
            }
            
            # Add volume definition
            compose['volumes'][f'{tailscale_service_name}_state'] = {}
    
    # Generate node services
    for node in nodes:
        node_id = node['id']
        index = extract_node_index(node_id)
        node_service_name = f'node_{node_id}'
        
        # Base service configuration
        service = {
            'build': {
                'context': '.',
                'dockerfile': 'scripts/Dockerfile.node'
            },
            'environment': {
                'TINYWEB_NODE_ID': str(index)
            },
            'volumes': [
                f'{str(output_dir / node_id / "state")}:/app/state'
            ],
            'healthcheck': {
                'test': ['CMD', 'curl', '-f', 'http://localhost:8000/health'] if discovery_mode != 'tailscale' else ['CMD-SHELL', 'curl -f http://localhost:8000/health || exit 1'],
                'interval': '30s',
                'timeout': '10s',
                'retries': '3',
                'start_period': '40s'
            },
            'restart': 'unless-stopped' if compose_mode == 'production' else 'no'
        }
        
        # Add discovery mode to environment (optional, can be read from config)
        if discovery_mode:
            service['environment']['TINYWEB_DISCOVERY_MODE'] = discovery_mode
        
        # Configure based on discovery mode
        if discovery_mode == 'tailscale':
            # Tailscale mode: share network with Tailscale sidecar
            tailscale_service_name = f'tailscale_{node_id}'
            service['network_mode'] = f'service:{tailscale_service_name}'
            service['depends_on'] = {
                tailscale_service_name: {
                    'condition': 'service_healthy'
                }
            }
            # Optional: expose API port on host (8000 + index)
            if compose_mode == 'production':
                service['ports'] = [f'{8000 + index}:8000']
        
        elif discovery_mode == 'dns_pattern':
            # DNS pattern mode: use bridge network
            service['network_mode'] = 'bridge'
            # Ports depend on user's tunnel/port forwarding setup
            # For now, don't expose ports (user will configure)
        
        elif discovery_mode == 'static':
            # Static mode: use bridge network, expose ports directly
            # Note: For docker-compose with multiple nodes on same host, we use different
            # host ports (8000+index) to avoid conflicts. If deploying one node per host,
            # you can use 8000:8000 directly (user configures port forwarding on router)
            service['network_mode'] = 'bridge'
            service['ports'] = [
                '9000:9000/udp',  # Gossip UDP (same port for all nodes - user configures forwarding)
                f'{8000 + index}:8000'  # API TCP (different host port per node to avoid conflicts)
            ]
        
        compose['services'][node_service_name] = service
    
    # Parse and validate extensions (reserved for future dashboard integration)
    # Extensions are already validated in validate_master_config(), so we just log them here
    if 'extensions' in master_config:
        extensions = master_config['extensions']
        if isinstance(extensions, list) and len(extensions) > 0:
            print(f"  Note: Found {len(extensions)} extension(s) in config (reserved for dashboard)")
            # Don't generate extension services yet - reserved for dashboard
    
    return compose


def main():
    parser = argparse.ArgumentParser(description='Generate Docker configs for TinyWeb nodes')
    parser.add_argument('--master-config', required=True,
                       help='Path to master network config JSON file')
    parser.add_argument('--mode', choices=['production', 'test'], default='production',
                       help='Docker deployment mode (default: production)')
    parser.add_argument('--output-dir', default='docker_configs',
                       help='Output directory for generated configs (default: docker_configs)')
    parser.add_argument('--skip-init', action='store_true',
                       help='Skip running init_tool (for testing config generation only)')
    
    args = parser.parse_args()
    
    # Load master config
    master_config_path = Path(args.master_config)
    if not master_config_path.exists():
        print(f"Error: Master config not found: {master_config_path}", file=sys.stderr)
        sys.exit(1)
    
    with open(master_config_path, 'r') as f:
        master_config = json.load(f)
    
    # Validate config
    try:
        validate_master_config(master_config)
    except ValueError as e:
        print(f"Error: Invalid master config: {e}", file=sys.stderr)
        sys.exit(1)
    
    docker_config = master_config['docker']
    discovery_config = docker_config['discovery']
    nodes = master_config['nodes']
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Generating configs for {len(nodes)} nodes...")
    print(f"Discovery mode: {discovery_config['mode']}")
    print(f"Output directory: {output_dir}")
    
    # Generate configs for each node
    for node in nodes:
        node_id = node['id']
        node_dir = output_dir / node_id
        state_dir = node_dir / 'state'
        state_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate node-specific config
        node_config = generate_node_config(node, discovery_config, args.mode)
        
        # Save node-specific network_config.json
        config_path = node_dir / 'network_config.json'
        with open(config_path, 'w') as f:
            json.dump(node_config, f, indent=2)
        
        print(f"  Generated config for {node_id}: {config_path}")
        print(f"    Hostname: {node_config['hostname']}")
        
        # Run init_tool for each node (Task 3.3)
        if not args.skip_init:
            print(f"    Initializing state for {node_id}...")
            
            # Build init_tool command
            # init_tool will:
            # 1. Initialize state directory (database, keys, etc.) in state_dir
            # 2. Save network_config.json to state_dir/network_config.json
            # init_tool expects master config (with nodes array), not node-specific config
            # It filters to the specified node using --node-id
            # Find init_tool - check build directory first (most common location)
            init_tool_path = Path('build/init_tool')
            if not init_tool_path.exists():
                init_tool_path = Path('init_tool')  # Try current directory
            if not init_tool_path.exists():
                init_tool_path = Path('scripts/init_tool')  # Try scripts directory
            
            init_cmd = [
                str(init_tool_path),
                '--config', str(master_config_path),  # Use master config (init_tool filters by --node-id)
                '--node-id', node_id,
                '--state-dir', str(state_dir)  # Initialize state in this directory
            ]
            
            # Run init_tool from project root
            # init_tool will save network_config.json to state_dir/network_config.json
            try:
                result = subprocess.run(
                    init_cmd,
                    cwd=Path.cwd(),  # Run from project root
                    capture_output=True,
                    text=True,
                    check=False
                )
                
                if result.returncode != 0:
                    print(f"    Warning: init_tool failed for {node_id}:", file=sys.stderr)
                    print(result.stderr, file=sys.stderr)
                    print(f"    Continuing anyway...")
                else:
                    print(f"    ✓ Initialized state for {node_id}")
            except FileNotFoundError:
                print(f"    Error: init_tool not found. Make sure it's built and in PATH", file=sys.stderr)
                print(f"    Run: make init_tool", file=sys.stderr)
                if not args.skip_init:
                    sys.exit(1)
            except Exception as e:
                print(f"    Error running init_tool: {e}", file=sys.stderr)
                if not args.skip_init:
                    sys.exit(1)
    
    # Generate docker-compose files (Task 3.5)
    print(f"\nGenerating docker-compose files...")
    if not HAS_YAML:
        print("  Error: PyYAML required for docker-compose generation. Install with: pip install pyyaml", file=sys.stderr)
        print("  Skipping docker-compose generation...", file=sys.stderr)
    else:
        compose_prod = generate_docker_compose(master_config, nodes, discovery_config, args.mode, output_dir, 'production')
        compose_test = generate_docker_compose(master_config, nodes, discovery_config, args.mode, output_dir, 'test')
        
        # Write docker-compose.yml (production) - YAML format
        compose_prod_path = output_dir / 'docker-compose.yml'
        with open(compose_prod_path, 'w') as f:
            yaml.dump(compose_prod, f, default_flow_style=False, sort_keys=False)
        print(f"  Generated: {compose_prod_path}")
        
        # Write docker-compose.test.yml (test) - YAML format
        compose_test_path = output_dir / 'docker-compose.test.yml'
        with open(compose_test_path, 'w') as f:
            yaml.dump(compose_test, f, default_flow_style=False, sort_keys=False)
        print(f"  Generated: {compose_test_path}")
    
    print(f"\nConfig generation complete!")
    print(f"Next steps:")
    print(f"  1. Build tinyweb binary: cmake -S . -B build && cmake --build build")
    print(f"  2. Build Docker image: docker build -f scripts/Dockerfile.node -t tinyweb-node .")
    print(f"  3. Set TS_AUTHKEY environment variable (for Tailscale mode)")
    print(f"  4. Start services: docker-compose -f {compose_prod_path} up -d")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

