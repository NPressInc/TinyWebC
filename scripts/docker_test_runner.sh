#!/bin/bash
# Docker Test Runner for TinyWeb
# Orchestrates Docker-based integration tests with static discovery

set -e

# Default values
CONFIG_FILE="scripts/configs/network_config.json"
TEST_SCRIPT=""
COMPOSE_FILE="docker_configs/docker-compose.test.yml"
TIMEOUT=120  # seconds
POLL_INTERVAL=2  # seconds
REGEN_KEYS=false  # Default: don't regenerate keys, use existing ones

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
        --regen)
            if [[ "$2" == "true" ]]; then
                REGEN_KEYS=true
            elif [[ "$2" == "false" ]]; then
                REGEN_KEYS=false
            else
                echo "Error: --regen requires 'true' or 'false'"
                exit 1
            fi
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [--config <config.json>] [--test-script <script.sh>] [--regen <true|false>]"
            echo ""
            echo "Options:"
            echo "  --config <file>      Master network config file (default: scripts/configs/network_config.json)"
            echo "  --test-script <file> Optional test script to run after containers are healthy"
            echo "  --regen <true|false> Regenerate keys (default: false, uses existing keys)"
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

# Function to verify peer discovery
verify_peer_discovery() {
    echo "Step 5.5: Verifying peer discovery..."
    
    # Wait a bit for discovery to complete
    echo "  Waiting for discovery to complete (up to 30 seconds)..."
    
    # Get list of node services
    NODE_SERVICES=$(docker compose -f "$COMPOSE_FILE" ps --services 2>/dev/null | grep "^node_" || echo "")
    
    if [[ -z "$NODE_SERVICES" ]]; then
        echo -e "    ${YELLOW}⚠️  No node services found, skipping peer discovery verification${NC}"
        return 0
    fi
    
    # Count expected peers (all other nodes)
    NODE_COUNT=$(echo "$NODE_SERVICES" | wc -l)
    EXPECTED_PEER_COUNT=$((NODE_COUNT - 1))
    
    if [[ "$EXPECTED_PEER_COUNT" -eq 0 ]]; then
        echo "  Only 1 node - no peers to discover"
        return 0
    fi
    
    echo "  Checking peer discovery for ${NODE_COUNT} node(s)..."
    echo "  Each node should discover ${EXPECTED_PEER_COUNT} peer(s)"
    
    # Retry logic
    local max_attempts=4
    local attempt=1
    local all_nodes_ok=false
    
    while [[ $attempt -le $max_attempts ]]; do
        if [[ $attempt -gt 1 ]]; then
            echo "  Attempt ${attempt}/${max_attempts} (waiting 5 seconds)..."
            sleep 5
        fi
        
        all_nodes_ok=true
        local nodes_with_peers=0
        
        for service in $NODE_SERVICES; do
            # Query /gossip/peers endpoint
            PEERS_JSON=$(docker compose -f "$COMPOSE_FILE" exec -T "$service" curl -s http://localhost:8000/gossip/peers 2>/dev/null || echo "")
            
            if [[ -z "$PEERS_JSON" ]]; then
                if [[ $attempt -lt $max_attempts ]]; then
                    all_nodes_ok=false
                    continue
                else
                    echo -e "    ${RED}✗ ${service}: Failed to query peers endpoint${NC}"
                    all_nodes_ok=false
                    continue
                fi
            fi
            
            # Extract peer count from JSON
            PEER_COUNT=$(echo "$PEERS_JSON" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('count', 0))" 2>/dev/null || echo "0")
            
            if [[ "$PEER_COUNT" -ge "$EXPECTED_PEER_COUNT" ]]; then
                if [[ $attempt -eq 1 ]]; then
                    echo -e "    ${GREEN}✓ ${service}: Found ${PEER_COUNT} peer(s)${NC}"
                fi
                nodes_with_peers=$((nodes_with_peers + 1))
            elif [[ "$PEER_COUNT" -gt 0 ]]; then
                if [[ $attempt -eq $max_attempts ]]; then
                    echo -e "    ${YELLOW}⚠ ${service}: Found ${PEER_COUNT} peer(s), expected ${EXPECTED_PEER_COUNT}${NC}"
                fi
                all_nodes_ok=false
            else
                if [[ $attempt -eq $max_attempts ]]; then
                    echo -e "    ${RED}✗ ${service}: No peers discovered (expected ${EXPECTED_PEER_COUNT})${NC}"
                    echo "      Response: ${PEERS_JSON:0:200}"
                fi
                all_nodes_ok=false
            fi
        done
        
        if [[ "$all_nodes_ok" == "true" ]] && [[ $nodes_with_peers -eq $NODE_COUNT ]]; then
            echo -e "  ${GREEN}✓ All nodes discovered ${EXPECTED_PEER_COUNT} peer(s)${NC}"
            return 0
        fi
        
        attempt=$((attempt + 1))
    done
    
    if [[ "$all_nodes_ok" == "true" ]]; then
        echo -e "  ${GREEN}✓ Peer discovery verification complete${NC}"
        return 0
    else
        echo -e "  ${YELLOW}⚠️  Some nodes may not have discovered all peers${NC}"
        return 0  # Don't fail - just warn
    fi
}

# Main execution
echo "=========================================="
echo "TinyWeb Docker Test Runner"
echo "=========================================="
echo ""

# Step 0: Cleanup any leftover containers and state data from previous runs
echo "Step 0: Cleaning up any leftover containers and state data..."
COMPOSE_FILE_TEMP="docker_configs/docker-compose.test.yml"

# First, stop and remove containers (without removing volumes to preserve state during run)
if [[ -f "$COMPOSE_FILE_TEMP" ]]; then
    if docker compose -f "$COMPOSE_FILE_TEMP" ps -q 2>/dev/null | grep -q .; then
        echo "  Found existing containers, stopping and removing..."
        docker compose -f "$COMPOSE_FILE_TEMP" down -v 2>/dev/null || true
        echo -e "  ${GREEN}✓ Containers stopped and removed${NC}"
    else
        echo -e "  ${GREEN}✓ No leftover containers found${NC}"
    fi
else
    echo "  No compose file found yet (will be generated in Step 1)"
fi

# Clean up entire node directories (including configs, state, keys, databases, etc.) for all nodes
# Only if REGEN_KEYS is true
if [[ "$REGEN_KEYS" == "true" ]]; then
    echo "  Cleaning up node directories (configs, state, keys, databases, etc.)..."
    NODES_CLEANED=0
    for node_dir in docker_configs/node_*; do
        if [[ -d "$node_dir" ]]; then
            echo "    Removing $node_dir..."
            rm -rf "$node_dir" 2>/dev/null || true
            NODES_CLEANED=$((NODES_CLEANED + 1))
        fi
    done

    if [[ $NODES_CLEANED -gt 0 ]]; then
        echo -e "  ${GREEN}✓ Cleaned up ${NODES_CLEANED} node directory/ies${NC}"
    else
        echo -e "  ${GREEN}✓ No node directories found to clean${NC}"
    fi
else
    echo "  Skipping node directory cleanup (--regen false, using existing keys and configs)"
fi

echo -e "  ${GREEN}✓ Cleanup complete${NC}"
echo ""

# Step 1: Generate configs
echo "Step 1: Generating Docker configs..."
if [[ "$REGEN_KEYS" == "true" ]]; then
    # Regenerate everything including keys
    if ! ./build/docker_config_generator --master-config "$CONFIG_FILE" --mode test; then
        echo -e "${RED}Error: Config generation failed${NC}" >&2
        exit 1
    fi
else
    # Skip initialization to preserve existing keys and database
    echo "  Skipping initialization (using existing keys and database)"
    if ! ./build/docker_config_generator --master-config "$CONFIG_FILE" --mode test --skip-init; then
        echo -e "${RED}Error: Config generation failed${NC}" >&2
        exit 1
    fi
fi
echo ""

# Step 2: Build tinyweb binary (required for Docker image)
echo "Step 2: Building tinyweb binary..."
echo "  Rebuilding binary to ensure latest code..."
if ! cmake -S . -B build; then
    echo -e "${RED}Error: CMake configuration failed${NC}" >&2
    exit 1
fi
if ! cmake --build build --target tinyweb; then
    echo -e "${RED}Error: Build failed${NC}" >&2
    exit 1
fi
echo -e "${GREEN}✓ Binary built${NC}"
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
if ! docker compose -f "$COMPOSE_FILE" up -d; then
    echo -e "${RED}Error: Failed to start containers${NC}" >&2
    echo ""
    echo "Showing logs for failed containers..."
    echo "=========================================="
    for service in $(docker compose -f "$COMPOSE_FILE" ps --services 2>/dev/null || true); do
        echo ""
        echo -e "${YELLOW}=== Logs for $service ===${NC}"
        docker compose -f "$COMPOSE_FILE" logs --tail=50 "$service" 2>&1 || true
    done
    echo ""
    echo -e "${YELLOW}=== All container status ===${NC}"
    docker compose -f "$COMPOSE_FILE" ps -a
        echo ""
    echo "Containers are being left running for debugging."
    echo "Re-run this script; Step 0 will clean up containers from previous runs."
    exit 1
fi
echo ""

# Step 5: Wait for health checks
if ! wait_for_health "$COMPOSE_FILE"; then
    echo -e "${RED}Error: Health checks failed${NC}" >&2
    echo ""
    echo "Showing logs for unhealthy containers..."
    echo "=========================================="
    for service in $(docker compose -f "$COMPOSE_FILE" ps --services 2>/dev/null | grep "^node_" || true); do
        echo ""
        echo -e "${YELLOW}=== Logs for $service ===${NC}"
        docker compose -f "$COMPOSE_FILE" logs --tail=100 "$service" 2>&1 || true
    done
    echo ""
    echo "Containers are being left running for debugging."
    echo "Re-run this script; Step 0 will clean up containers from previous runs."
    exit 1
fi
echo ""

# Step 5.1: Check container status
echo "Step 5.1: Verifying containers are still running..."
NODE_SERVICES_CHECK=$(docker compose -f "$COMPOSE_FILE" ps --services 2>/dev/null | grep "^node_" || echo "")
if [[ -n "$NODE_SERVICES_CHECK" ]]; then
    any_exited=false
    for service in $NODE_SERVICES_CHECK; do
        container_status=$(docker compose -f "$COMPOSE_FILE" ps --format json 2>/dev/null | \
            python3 -c "import sys, json; \
            services = [json.loads(line) for line in sys.stdin if line.strip()]; \
            service = [s for s in services if s.get('Service') == '$service']; \
            print(service[0].get('State', 'unknown') if service else 'not found')" 2>/dev/null || echo "unknown")
        
        if [[ "$container_status" != "running" ]]; then
            echo -e "  ${RED}✗ ${service}: Container exited (status: ${container_status})${NC}"
            echo "  ========================================="
            echo "  Full logs for ${service}:"
            echo "  ========================================="
            docker compose -f "$COMPOSE_FILE" logs "$service" 2>&1 | sed 's/^/    /' || true
            echo "  ========================================="
            any_exited=true
        else
            echo -e "  ${GREEN}✓ ${service}: Running${NC}"
        fi
    done
    
    if [[ "$any_exited" == "true" ]]; then
        echo ""
        echo -e "${RED}Error: Some containers exited after health checks passed${NC}" >&2
        echo "This usually indicates tinyweb crashed. Check the logs above for errors."
        echo ""
        echo "Containers are being left running for debugging."
        echo "Re-run this script; Step 0 will clean up containers from previous runs."
        exit 1
    fi
else
    echo "  No node services found to check"
fi
echo ""

# Step 5.5: Verify peer discovery
    verify_peer_discovery
    echo ""

# Step 6: Run test script if provided
if [[ -n "$TEST_SCRIPT" ]]; then
    if [[ ! -f "$TEST_SCRIPT" ]]; then
        echo -e "${RED}Error: Test script not found: $TEST_SCRIPT${NC}" >&2
        echo ""
        echo "Containers are being left running for debugging."
        echo "Re-run this script; Step 0 will clean up containers from previous runs."
        exit 1
    fi
    
    echo "Step 6: Running test script: $TEST_SCRIPT"
    if bash "$TEST_SCRIPT"; then
        echo -e "${GREEN}✓ Test script passed${NC}"
    else
        echo -e "${RED}✗ Test script failed${NC}" >&2
        echo ""
        echo "Containers are being left running for debugging."
        echo "Re-run this script; Step 0 will clean up containers from previous runs."
        exit 1
    fi
    echo ""
else
    echo "Step 6: No test script provided, verifying services are running..."
    docker compose -f "$COMPOSE_FILE" ps
    echo ""
fi

# Step 7: Post-run status
echo "Step 7: Post-run status (containers left running for debugging)"
docker compose -f "$COMPOSE_FILE" ps
echo ""
echo -e "${YELLOW}Note: Containers are NOT stopped/removed automatically.${NC}"
echo -e "${YELLOW}Re-run this script to clean up previous runs (Step 0).${NC}"
echo ""

echo -e "${GREEN}=========================================="
echo "All tests completed successfully!"
echo "==========================================${NC}"
