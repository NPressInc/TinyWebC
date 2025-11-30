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

# Function to generate ephemeral auth keys via Tailscale API
generate_ephemeral_auth_keys() {
    local num_keys=$1
    echo "  Generating ${num_keys} ephemeral auth key(s) via Tailscale API..."
    
    # Check for API access token
    API_KEY="${TS_API_KEY:-${TS_TAILNET_API_KEY:-}}"
    TAILNET="${TS_TAILNET:-}"
    
    if [[ -z "$API_KEY" ]]; then
        echo -e "    ${RED}✗ TS_API_KEY or TS_TAILNET_API_KEY not set.${NC}"
        echo "    To enable automatic ephemeral key generation, set:"
        echo "      export TS_API_KEY='tskey-api-...'  # API access token from Tailscale Admin"
        echo "      export TS_TAILNET='your-org.com'  # Your organization's domain"
        echo "    Generate API tokens at: https://login.tailscale.com/admin/settings/keys"
        return 1
    fi
    
    if [[ -z "$TAILNET" ]]; then
        echo -e "    ${RED}✗ TS_TAILNET not set.${NC}"
        echo "    Set your tailnet name: export TS_TAILNET='your-org.com'"
        echo "    Find it at: https://login.tailscale.com/admin/settings/general"
        return 1
    fi
    
    # Use '-' as shorthand for default tailnet
    if [[ "$TAILNET" == "-" ]]; then
        TAILNET="-"
    fi
    
    # Generate keys and store in environment variables
    local keys_generated=0
    for i in $(seq 1 $num_keys); do
        local key_index=$(printf "%02d" $i)
        local env_var="TS_AUTHKEY_${key_index}"
        
        echo -n "    Generating key ${i}/${num_keys}... "
        
        # Create ephemeral, non-reusable, preauthorized auth key
        # Expires in 24 hours (86400 seconds) - should be plenty for tests
        local response=$(curl -s -w "\n__HTTP_CODE__:%{http_code}" \
            -X POST \
            -H "Authorization: Bearer ${API_KEY}" \
            -H "Content-Type: application/json" \
            -d "{\"capabilities\":{\"devices\":{\"create\":{\"reusable\":false,\"ephemeral\":true,\"preauthorized\":true}}},\"expirySeconds\":86400}" \
            "https://api.tailscale.com/api/v2/tailnet/${TAILNET}/keys" 2>&1)
        
        local http_code=$(echo "$response" | grep -o "__HTTP_CODE__:[0-9]*" | cut -d: -f2)
        local body=$(echo "$response" | sed '/__HTTP_CODE__:/d')
        
        if [[ -z "$http_code" ]] || [[ "$http_code" != "200" ]]; then
            echo -e "${RED}✗ Failed (HTTP ${http_code})${NC}"
            echo "    Response: ${body:0:200}"
            if [[ "$http_code" == "401" ]]; then
                echo "    Note: Check that TS_API_KEY is a valid API access token (tskey-api-...)"
            fi
            return 1
        fi
        
        # Extract key from JSON response and verify it's ephemeral
        local auth_key=$(echo "$body" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('key', ''))" 2>/dev/null)
        local is_ephemeral=$(echo "$body" | python3 -c "import sys, json; d=json.load(sys.stdin); caps=d.get('capabilities', {}); dev_caps=caps.get('devices', {}); create_caps=dev_caps.get('create', {}); print('true' if create_caps.get('ephemeral') else 'false')" 2>/dev/null)
        
        if [[ -z "$auth_key" ]]; then
            echo -e "${RED}✗ Failed to extract key from response${NC}"
            echo "    Response: ${body:0:200}"
            return 1
        fi
        
        if [[ "$is_ephemeral" != "true" ]]; then
            echo -e "${YELLOW}⚠ Warning: Generated key may not be ephemeral${NC}"
        fi
        
        # Export the key as an environment variable
        export "${env_var}=${auth_key}"
        echo -e "${GREEN}✓${NC}"
        keys_generated=$((keys_generated + 1))
    done
    
    echo -e "    ${GREEN}✓ Generated ${keys_generated}/${num_keys} ephemeral auth keys${NC}"
    
    # Debug: Verify keys are exported (don't print actual key values for security)
    echo "    Verifying exported keys..."
    for i in $(seq 1 $num_keys); do
        local key_index=$(printf "%02d" $i)
        local env_var="TS_AUTHKEY_${key_index}"
        local key_value="${!env_var}"
        if [[ -n "$key_value" ]]; then
            local key_len=${#key_value}
            echo "      ✓ ${env_var} is set (length: ${key_len} chars)"
        else
            echo -e "      ${RED}✗ ${env_var} is not set${NC}"
            return 1
        fi
    done
    
    return 0
}

# Function to cleanup Tailscale devices (simplified - ephemeral keys auto-cleanup)
cleanup_tailscale_devices() {
    echo "  Cleaning up Tailscale devices..."
    echo "    ℹ️  Using ephemeral auth keys - devices should auto-cleanup when containers stop"
    echo "    ℹ️  If devices persist, they will be removed automatically when they go offline"
    echo "    ℹ️  No manual cleanup needed with ephemeral keys"
}

# Check if discovery mode is Tailscale and generate ephemeral keys
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
        # Count how many nodes we're testing (only count node IDs, not user IDs)
        NODE_COUNT=$(python3 -c "import json; c=json.load(open('$CONFIG_FILE')); print(len(c.get('nodes', [])))" 2>/dev/null || \
            grep -o '"nodes".*\[.*\]' "$CONFIG_FILE" 2>/dev/null | grep -o '"id"' | wc -l || echo "0")
        
        if [[ "$NODE_COUNT" -eq 0 ]]; then
            echo -e "${RED}Error: No nodes found in config file${NC}" >&2
            exit 1
        fi
        
        echo -e "${YELLOW}⚠️  Using Tailscale discovery mode with ${NODE_COUNT} container(s)${NC}"
        
        # Try to generate ephemeral keys via API (preferred method)
        if generate_ephemeral_auth_keys "$NODE_COUNT"; then
            echo -e "${GREEN}✓ Using programmatically generated ephemeral auth keys${NC}"
            echo -e "${GREEN}  Devices will auto-cleanup when containers stop${NC}"
            echo ""
        else
            # Fallback to manual TS_AUTHKEY if API key generation fails
            if [[ -z "$TS_AUTHKEY" ]]; then
                echo -e "${RED}Error: Cannot generate ephemeral keys and TS_AUTHKEY not set.${NC}" >&2
                echo -e "${YELLOW}   Either set TS_API_KEY and TS_TAILNET for automatic key generation,${NC}" >&2
                echo -e "${YELLOW}   OR set TS_AUTHKEY manually (use REUSABLE key for multi-container tests).${NC}" >&2
                echo -e "${YELLOW}   Create keys at: https://login.tailscale.com/admin/settings/keys${NC}" >&2
                exit 1
            else
                echo -e "${YELLOW}⚠️  Falling back to manual TS_AUTHKEY (not recommended for multi-container tests)${NC}"
                if [[ "$NODE_COUNT" -gt 1 ]]; then
                    echo -e "${YELLOW}   WARNING: Single auth key with ${NODE_COUNT} containers may cause issues.${NC}"
                    echo -e "${YELLOW}   Use a REUSABLE key (uncheck 'Ephemeral') for multi-container tests.${NC}"
                fi
                export TS_AUTHKEY
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
# Note: If using ephemeral keys, docker_config_generator must be rebuilt to use per-container keys
if ! ./build/docker_config_generator --master-config "$CONFIG_FILE" --mode test; then
    echo -e "${RED}Error: Config generation failed${NC}" >&2
    exit 1
fi

# Verify compose file uses per-container keys if ephemeral keys were generated
if [[ "$DISCOVERY_MODE" == "tailscale" ]] && [[ -n "$TS_API_KEY" ]]; then
    if grep -q 'TS_AUTHKEY:.*\${TS_AUTHKEY}' "$COMPOSE_FILE" 2>/dev/null && ! grep -q 'TS_AUTHKEY:.*\${TS_AUTHKEY_[0-9]' "$COMPOSE_FILE" 2>/dev/null; then
        echo -e "    ${YELLOW}⚠️  WARNING: Compose file appears to use old format${NC}"
        echo -e "    ${YELLOW}   Rebuild docker_config_generator: cmake --build build --target docker_config_generator${NC}"
        echo -e "    ${YELLOW}   Then re-run this script${NC}"
    fi
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

# If using ephemeral keys, verify they're set before building
if [[ "$DISCOVERY_MODE" == "tailscale" ]] && [[ -n "$TS_API_KEY" ]]; then
    echo "  Verifying ephemeral keys are available for docker-compose..."
    NODE_COUNT=$(python3 -c "import json; c=json.load(open('$CONFIG_FILE')); print(len(c.get('nodes', [])))" 2>/dev/null || \
        grep -o '"nodes".*\[.*\]' "$CONFIG_FILE" 2>/dev/null | grep -o '"id"' | wc -l || echo "0")
    missing_keys=0
    for i in $(seq 1 $NODE_COUNT); do
        key_index=$(printf "%02d" $i)
        env_var="TS_AUTHKEY_${key_index}"
        if [[ -z "${!env_var}" ]]; then
            echo -e "    ${RED}✗ ${env_var} is not set${NC}"
            missing_keys=$((missing_keys + 1))
        fi
    done
    if [[ $missing_keys -gt 0 ]]; then
        echo -e "    ${RED}Error: ${missing_keys} ephemeral key(s) missing. Regenerating...${NC}"
        if ! generate_ephemeral_auth_keys "$NODE_COUNT"; then
            echo -e "    ${RED}Failed to regenerate keys. Exiting.${NC}" >&2
            exit 1
        fi
    else
        echo -e "    ${GREEN}✓ All ephemeral keys are set${NC}"
    fi
fi

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

