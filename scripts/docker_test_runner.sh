#!/bin/bash
# Docker Test Runner for TinyWeb
# Orchestrates Docker-based integration tests

set -e

# Export TS_AUTHKEY if it's set (needed for Tailscale services)
# Docker Compose will automatically pick up exported environment variables
if [[ -n "$TS_AUTHKEY" ]]; then
    export TS_AUTHKEY
fi

# TS_AUTHKEY is already exported above for Docker Compose
# It will also be used for Tailscale Admin API cleanup

# Default values
CONFIG_FILE="scripts/configs/network_config.json"
TEST_SCRIPT=""
COMPOSE_FILE="docker_configs/docker-compose.test.yml"
TIMEOUT=120  # seconds
POLL_INTERVAL=2  # seconds

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --test-script)
            TEST_SCRIPT="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--config <config.json>] [--test-script <script.sh>]"
            echo ""
            echo "Options:"
            echo "  --config <file>      Master network config file (default: scripts/configs/network_config.json)"
            echo "  --test-script <file> Optional test script to run after containers are healthy"
            echo "  --help, -h           Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Check if config file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo -e "${RED}Error: Config file not found: $CONFIG_FILE${NC}" >&2
    exit 1
fi

# Global variable to store discovery mode
DISCOVERY_MODE=""

# Function to cleanup Tailscale devices
cleanup_tailscale_devices() {
    echo "  Cleaning up Tailscale devices..."
    
    # Extract hostname prefix from config
    HOSTNAME_PREFIX=$(grep -o '"hostname_prefix"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" 2>/dev/null | \
        sed -n 's/.*"hostname_prefix"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
    
    # Replace underscores with hyphens (same as we do in hostname generation)
    HOSTNAME_PREFIX=$(echo "$HOSTNAME_PREFIX" | tr '_' '-')
    
    if [[ -n "$HOSTNAME_PREFIX" ]]; then
        # Tailscale API requires an API access token (not auth key) and tailnet name
        # Check for TS_API_KEY (API access token) or TS_TAILNET_API_KEY
        API_KEY="${TS_API_KEY:-${TS_TAILNET_API_KEY:-}}"
        TAILNET="${TS_TAILNET:-}"
        
        if [[ -z "$API_KEY" ]]; then
            echo "    ⚠️  TS_API_KEY or TS_TAILNET_API_KEY not set."
            echo "    To enable automatic cleanup, set:"
            echo "      export TS_API_KEY='tskey-api-...'  # API access token from Tailscale Admin"
            echo "      export TS_TAILNET='-'  # Simplest: use '-' for your default tailnet"
            echo "      OR export TS_TAILNET='your-org.com'  # Your organization's domain"
            echo "    Devices with hostname pattern '${HOSTNAME_PREFIX}*' may need manual removal."
            echo "    Generate API tokens at: https://login.tailscale.com/admin/settings/keys"
            return 0
        fi
        
        if [[ -z "$TAILNET" ]]; then
            echo "    ⚠️  TS_TAILNET not set."
            echo "    Set your tailnet name: export TS_TAILNET='your-org.com' (or use '-' for default)"
            echo "    The tailnet name is your organization's domain (e.g., 'example.com')"
            echo "    or your email address for personal accounts (e.g., 'user@gmail.com')"
            echo "    You can also use '-' as shorthand for your default tailnet."
            echo "    Find it at: https://login.tailscale.com/admin/settings/general"
            echo "    Devices with hostname pattern '${HOSTNAME_PREFIX}*' may need manual removal."
            return 0
        fi
        
        # Use '-' as shorthand for default tailnet if user set it
        if [[ "$TAILNET" == "-" ]]; then
            TAILNET="-"
        fi
        
        echo "    Using Tailscale Admin API to remove devices..."
        echo "    API endpoint: /api/v2/tailnet/${TAILNET}/devices"
        # Correct endpoint: /api/v2/tailnet/{tailnet}/devices
        # Use verbose curl to see what's happening, but capture output
        DEVICES_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}\nHTTP_STATUS:%{http_code}" -u "${API_KEY}:" "https://api.tailscale.com/api/v2/tailnet/${TAILNET}/devices" 2>&1)
        HTTP_CODE=$(echo "$DEVICES_RESPONSE" | grep "^HTTP_CODE:" | cut -d: -f2 | tr -d ' ')
        DEVICES=$(echo "$DEVICES_RESPONSE" | grep -v "^HTTP_CODE:" | grep -v "^HTTP_STATUS:")
        
        if [[ -z "$HTTP_CODE" ]]; then
            echo "    ✗ Could not determine HTTP status code"
            echo "    Full response: ${DEVICES_RESPONSE:0:500}"
        elif [[ "$HTTP_CODE" != "200" ]]; then
            echo "    ✗ API call failed with HTTP code: ${HTTP_CODE}"
            echo "    Response body: ${DEVICES:0:500}"
            if [[ "$HTTP_CODE" == "401" ]]; then
                echo "    Note: Authentication failed. Check that TS_API_KEY is a valid API access token (tskey-api-...)"
            elif [[ "$HTTP_CODE" == "404" ]]; then
                echo "    Note: Tailnet '${TAILNET}' not found. Try:"
                echo "      - Use your organization domain: export TS_TAILNET='your-org.com'"
                echo "      - Use your email: export TS_TAILNET='user@gmail.com'"
                echo "      - Find it at: https://login.tailscale.com/admin/settings/general"
            fi
            echo "    Generate API tokens at: https://login.tailscale.com/admin/settings/keys"
        elif [[ -z "$DEVICES" ]]; then
            echo "    ✗ API call returned empty response (HTTP ${HTTP_CODE})"
            echo "    This might indicate the tailnet has no devices or the API key lacks permissions."
        elif ! echo "$DEVICES" | grep -q "devices"; then
            echo "    ✗ API response did not contain 'devices' field"
            echo "    HTTP code: ${HTTP_CODE}"
            echo "    Response preview (first 500 chars):"
            echo "${DEVICES:0:500}" | sed 's/^/      /'
        else
            # Extract device IDs for devices matching our hostname pattern
            # Pass API_KEY and HOSTNAME_PREFIX via environment to Python
            echo "$DEVICES" | TS_API_KEY_VALUE="${API_KEY}" HOSTNAME_PREFIX_VALUE="${HOSTNAME_PREFIX}" python3 <<'PYTHON_SCRIPT' 2>&1
import sys, json, base64, os
try:
    input_data = sys.stdin.read()
    if not input_data or not input_data.strip():
        print('    ✗ Error: Received empty response from API', file=sys.stderr)
        sys.exit(1)
    data = json.loads(input_data)
    devices = data.get('devices', [])
    removed = 0
    api_key = os.environ.get('TS_API_KEY_VALUE', '')
    hostname_prefix = os.environ.get('HOSTNAME_PREFIX_VALUE', '')
    if not api_key:
        print('    ✗ Error: TS_API_KEY_VALUE not found in environment', file=sys.stderr)
        sys.exit(1)
    if not hostname_prefix:
        print('    ✗ Error: HOSTNAME_PREFIX_VALUE not found in environment', file=sys.stderr)
        sys.exit(1)
    # Create Basic Auth header
    auth_string = base64.b64encode(f'{api_key}:'.encode()).decode()
    
    for device in devices:
        # Tailscale API uses 'name' field, not 'hostname'
        device_name = device.get('name', '')
        if device_name.startswith(hostname_prefix):
            device_id = device.get('id', '')
            if device_id:
                import urllib.request, urllib.error
                req = urllib.request.Request(
                    f'https://api.tailscale.com/api/v2/device/{device_id}',
                    method='DELETE',
                    headers={'Authorization': f'Basic {auth_string}'}
                )
                try:
                    with urllib.request.urlopen(req) as f:
                        print(f'    ✓ Removed device: {device_name}')
                        removed += 1
                except urllib.error.HTTPError as e:
                    error_body = e.read().decode() if e.fp else 'unknown error'
                    print(f'    ✗ Failed to remove {device_name}: HTTP {e.code}', file=sys.stderr)
                    print(f'    Error details: {error_body}', file=sys.stderr)
                except Exception as e:
                    print(f'    ✗ Failed to remove {device_name}: {e}', file=sys.stderr)
    if removed == 0:
        print('    No matching devices found to remove (or already removed)')
except json.JSONDecodeError as e:
    print(f'    ✗ Error parsing API response: {e}', file=sys.stderr)
    print(f'    Raw response (first 500 chars): {sys.stdin.read()[:500] if hasattr(sys.stdin, "read") else "N/A"}', file=sys.stderr)
    print('    Note: Devices may need manual removal from Tailscale Admin', file=sys.stderr)
except Exception as e:
    import traceback
    print(f'    ✗ Unexpected error: {e}', file=sys.stderr)
    print(f'    Traceback:', file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    print('    Note: Devices may need manual removal from Tailscale Admin', file=sys.stderr)
PYTHON_SCRIPT
        fi
    else
        echo "    Could not determine hostname prefix from config"
    fi
}

# Check if discovery mode is Tailscale and warn about ephemeral keys
check_tailscale_ephemeral_key() {
    # Try to extract discovery mode using a simple grep/sed approach (no Python dependency)
    DISCOVERY_MODE=$(grep -o '"mode"[[:space:]]*:[[:space:]]*"[^"]*"' "$CONFIG_FILE" 2>/dev/null | \
        grep -A 5 '"discovery"' | grep '"mode"' | \
        sed -n 's/.*"mode"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
    
    # Fallback to Python if grep doesn't work
    if [[ -z "$DISCOVERY_MODE" ]] && command -v python3 &> /dev/null; then
        DISCOVERY_MODE=$(python3 -c "import json; c=json.load(open('$CONFIG_FILE')); print(c.get('docker', {}).get('discovery', {}).get('mode', ''))" 2>/dev/null || echo "")
    fi
    
    if [[ "$DISCOVERY_MODE" == "tailscale" ]]; then
        if [[ -z "$TS_AUTHKEY" ]]; then
            echo -e "${RED}Error: TS_AUTHKEY not set. Required for Tailscale discovery mode.${NC}" >&2
            echo -e "${YELLOW}   Set it with: export TS_AUTHKEY='your-key-here'${NC}" >&2
            echo -e "${YELLOW}   For multi-container testing, use a REUSABLE key (not ephemeral).${NC}" >&2
            echo -e "${YELLOW}   Create keys in: Tailscale Admin → Settings → Keys${NC}" >&2
            exit 1
        else
            # Export TS_AUTHKEY to ensure it's available to docker compose
            export TS_AUTHKEY
            
            # Check how many nodes we're testing
            NODE_COUNT=$(grep -c '"id"' "$CONFIG_FILE" 2>/dev/null || echo "0")
            if [[ "$NODE_COUNT" -gt 1 ]]; then
                echo -e "${YELLOW}⚠️  IMPORTANT: Multi-container Tailscale testing${NC}"
                echo -e "${YELLOW}   Using ${NODE_COUNT} containers. Ephemeral keys are SINGLE-USE only.${NC}"
                echo -e "${YELLOW}   For multi-container tests, use a REUSABLE auth key (uncheck 'Ephemeral').${NC}"
                echo -e "${YELLOW}   Ephemeral keys will only work for the first container.${NC}"
                echo -e "${YELLOW}   Create reusable keys in: Tailscale Admin → Settings → Keys → Uncheck 'Ephemeral'${NC}"
                echo ""
                echo -e "${YELLOW}   💡 TIP: TS_AUTHKEY will be used for automatic device cleanup after tests${NC}"
            else
                echo -e "${YELLOW}⚠️  IMPORTANT: Using Tailscale discovery mode${NC}"
                echo -e "${YELLOW}   For single-container testing, EPHEMERAL keys are recommended.${NC}"
                echo -e "${YELLOW}   Ephemeral keys auto-delete devices when containers disconnect.${NC}"
                echo -e "${YELLOW}   Create ephemeral keys in: Tailscale Admin → Settings → Keys → Check 'Ephemeral'${NC}"
            fi
            echo ""
        fi
    fi
}

# Function to check if all services are healthy
check_health() {
    local compose_file="$1"
    if [[ ! -f "$compose_file" ]]; then
        return 1
    fi
    
    # Get health status of all services
    local unhealthy=$(docker compose -f "$compose_file" ps --format json 2>/dev/null | \
        python3 -c "import sys, json; services = [json.loads(line) for line in sys.stdin if line.strip()]; \
        unhealthy = [s for s in services if s.get('Health', '') not in ['healthy', ''] and s.get('State', '') == 'running']; \
        print(len(unhealthy))" 2>/dev/null || echo "1")
    
    if [[ "$unhealthy" == "0" ]]; then
        return 0  # All healthy
    else
        return 1  # Some unhealthy
    fi
}

# Function to wait for health checks
wait_for_health() {
    local compose_file="$1"
    local elapsed=0
    
    echo "Waiting for all services to become healthy..."
    
    while [[ $elapsed -lt $TIMEOUT ]]; do
        if check_health "$compose_file"; then
            echo -e "${GREEN}✓ All services are healthy!${NC}"
            return 0
        fi
        
        sleep $POLL_INTERVAL
        elapsed=$((elapsed + POLL_INTERVAL))
        echo -n "."
    done
    
    echo ""
    echo -e "${RED}Timeout: Services did not become healthy within ${TIMEOUT} seconds${NC}"
    echo "Current status:"
    docker compose -f "$compose_file" ps
    return 1
}

# Main execution
echo "=========================================="
echo "TinyWeb Docker Test Runner"
echo "=========================================="
echo ""

# Check for Tailscale ephemeral key warning
check_tailscale_ephemeral_key

# Step 1: Generate configs
echo "Step 1: Generating Docker configs..."
if ! ./build/docker_config_generator --master-config "$CONFIG_FILE" --mode test; then
    echo -e "${RED}Error: Config generation failed${NC}" >&2
    exit 1
fi
echo ""

# Step 2: Build tinyweb binary (required for Docker image)
echo "Step 2: Building tinyweb binary..."
if [[ ! -f "build/tinyweb" ]]; then
    echo "  Binary not found, building..."
    if ! cmake -S . -B build; then
        echo -e "${RED}Error: CMake configuration failed${NC}" >&2
        exit 1
    fi
    if ! cmake --build build --target tinyweb; then
        echo -e "${RED}Error: Build failed${NC}" >&2
        exit 1
    fi
    echo -e "${GREEN}✓ Binary built${NC}"
else
    echo -e "${GREEN}✓ Binary already exists${NC}"
fi
echo ""

# Step 3: Build Docker images
echo "Step 3: Building Docker images..."
if ! docker compose -f "$COMPOSE_FILE" build; then
    echo -e "${RED}Error: Docker build failed${NC}" >&2
    exit 1
fi
echo ""

# Step 4: Start containers
echo "Step 4: Starting containers..."
# Ensure TS_AUTHKEY is exported for Tailscale services (if needed)
# Docker Compose will automatically pick up exported environment variables
if ! docker compose -f "$COMPOSE_FILE" up -d; then
    echo -e "${RED}Error: Failed to start containers${NC}" >&2
    echo ""
    echo "Showing logs for failed containers..."
    echo "=========================================="
    # Show logs for all Tailscale containers
    for service in $(docker compose -f "$COMPOSE_FILE" ps --services 2>/dev/null | grep tailscale || true); do
        echo ""
        echo -e "${YELLOW}=== Logs for $service ===${NC}"
        docker compose -f "$COMPOSE_FILE" logs --tail=50 "$service" 2>&1 || true
    done
    echo ""
    echo -e "${YELLOW}=== All container status ===${NC}"
    docker compose -f "$COMPOSE_FILE" ps -a
    
    # Cleanup Tailscale devices even on failure
    if [[ "$DISCOVERY_MODE" == "tailscale" ]]; then
        echo ""
        echo "Cleaning up Tailscale devices..."
        cleanup_tailscale_devices
    fi
    
    exit 1
fi
echo ""

# Step 5: Wait for health checks
if ! wait_for_health "$COMPOSE_FILE"; then
    echo -e "${RED}Error: Health checks failed${NC}" >&2
    echo "Cleaning up..."
    docker compose -f "$COMPOSE_FILE" down -v
    
    # Cleanup Tailscale devices even on failure
    if [[ "$DISCOVERY_MODE" == "tailscale" ]]; then
        cleanup_tailscale_devices
    fi
    
    exit 1
fi
echo ""

# Step 6: Run test script if provided
if [[ -n "$TEST_SCRIPT" ]]; then
    if [[ ! -f "$TEST_SCRIPT" ]]; then
        echo -e "${RED}Error: Test script not found: $TEST_SCRIPT${NC}" >&2
        docker compose -f "$COMPOSE_FILE" down -v
        if [[ "$DISCOVERY_MODE" == "tailscale" ]]; then
            cleanup_tailscale_devices
        fi
        exit 1
    fi
    
    echo "Step 6: Running test script: $TEST_SCRIPT"
    if bash "$TEST_SCRIPT"; then
        echo -e "${GREEN}✓ Test script passed${NC}"
    else
        echo -e "${RED}✗ Test script failed${NC}" >&2
        docker compose -f "$COMPOSE_FILE" down -v
        if [[ "$DISCOVERY_MODE" == "tailscale" ]]; then
            cleanup_tailscale_devices
        fi
        exit 1
    fi
    echo ""
else
    echo "Step 6: No test script provided, verifying services are running..."
    docker compose -f "$COMPOSE_FILE" ps
    echo ""
fi

# Step 7: Cleanup
echo "Step 7: Cleaning up..."
echo "  Stopping and removing containers..."
docker compose -f "$COMPOSE_FILE" down -v
echo -e "${GREEN}✓ Docker cleanup complete${NC}"

# Cleanup Tailscale devices if in Tailscale mode
if [[ "$DISCOVERY_MODE" == "tailscale" ]]; then
    cleanup_tailscale_devices
fi

echo ""

echo -e "${GREEN}=========================================="
echo "All tests completed successfully!"
echo "==========================================${NC}"

