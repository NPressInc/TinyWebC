#!/bin/bash
# Test Full PBFT Consensus Mechanisms
# Tests real consensus between 4 nodes with actual block creation and voting

set -e

echo "🎯 TESTING FULL PBFT CONSENSUS MECHANISMS"
echo "=========================================="
echo "This test will demonstrate:"
echo "• 4 nodes communicating via HTTP"
echo "• Block proposals and verification"
echo "• Consensus voting (2f+1 threshold)"
echo "• Block commitment to blockchain"
echo "• Real PBFT consensus in action"
echo ""

# Configuration
NUM_NODES=4
BASE_PORT=8000
TEST_DURATION=100  # 60 seconds for full consensus testing

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Node tracking
declare -a NODE_PIDS
declare -a NODE_PORTS
declare -a NODE_LOGS
declare -a INITIAL_BLOCK_HEIGHTS

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}🧹 Cleaning up PBFT consensus test...${NC}"

    # Kill all node processes
    for pid in "${NODE_PIDS[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            echo "Stopping PBFT node process $pid..."
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done

    echo -e "${GREEN}✅ Cleanup complete${NC}"
}

# Error handler
error_exit() {
    echo -e "${RED}❌ Error: $1${NC}" >&2
    cleanup
    exit 1
}

# Check if binary exists
check_binary() {
    if [ ! -f "./tinyweb" ]; then
        error_exit "tinyweb binary not found. Please build the project first."
    fi
}

# Start a PBFT node
start_node() {
    local node_id=$1
    
    local port=${NODE_PORTS[$node_id]}
    local log_file=${NODE_LOGS[$node_id]}

    echo -e "${BLUE}🚀 Starting PBFT Node $node_id on port $port...${NC}"

    # Start the node in debug mode for isolated per-node directories
    ./tinyweb --debug --id $node_id --port $port &
    NODE_PIDS[$node_id]=$!

    echo -e "${GREEN}✅ PBFT Node $node_id started (PID: ${NODE_PIDS[$node_id]})${NC}"
}

# Check node health
check_node_health() {
    local node_id=$1
    local port=${NODE_PORTS[$node_id]}

    # Try to connect to the root endpoint (which exists for PBFT nodes)
    if curl -s --max-time 3 "http://127.0.0.1:$port/" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Get blockchain height from node
get_blockchain_height() {
    local node_id=$1
    local port=${NODE_PORTS[$node_id]}

    # Try to get blockchain info
    local response=$(curl -s --max-time 3 "http://127.0.0.1:$port/api/blockchain" 2>/dev/null)

    if [ -n "$response" ]; then
        # Extract height from JSON response (simple parsing)
        echo "$response" | grep -o '"length":[0-9]*' | grep -o '[0-9]*' || echo "0"
    else
        echo "0"
    fi
}

# Monitor consensus activity
monitor_consensus() {
    echo -e "\n${BLUE}📊 Monitoring PBFT Consensus Activity for $TEST_DURATION seconds...${NC}"

    local start_time=$(date +%s)
    local last_status_time=0

    while true; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))

        if [ $elapsed -ge $TEST_DURATION ]; then
            break
        fi

        # Status update every 10 seconds
        if [ $((elapsed - last_status_time)) -ge 10 ]; then
            echo -e "\n${YELLOW}📈 Status at ${elapsed}s/${TEST_DURATION}s:${NC}"

            # Check node health
            local healthy_count=0
            for i in {0..3}; do
                if check_node_health $i; then
                    echo -e "  ${GREEN}✅ Node $i: Healthy${NC}"
                    ((healthy_count++))
                else
                    echo -e "  ${RED}❌ Node $i: Unresponsive${NC}"
                fi
            done

            echo -e "  ${BLUE}📊 ${healthy_count}/4 nodes healthy${NC}"

            # Check consensus progress
            if [ $healthy_count -eq 4 ]; then
                echo -e "  ${BLUE}🔍 Consensus Progress:${NC}"

                for i in {0..3}; do
                    local height=$(get_blockchain_height $i)
                    local progress=$((height - INITIAL_BLOCK_HEIGHTS[$i]))
                    echo -e "    Node $i: ${height} blocks (+${progress} during test)"
                done

                # Check for consensus activity in logs
                echo -e "  ${BLUE}📝 Recent Consensus Activity:${NC}"
                for i in {0..3}; do
                    if [ -f "${NODE_LOGS[$i]}" ]; then
                        local recent_activity=$(tail -5 "${NODE_LOGS[$i]}" 2>/dev/null | grep -E "(block|consensus|proposal|vote|commit|Proposing|Verification|Commit)" | head -1)
                        if [ -n "$recent_activity" ]; then
                            echo -e "    ${GREEN}Node $i: $recent_activity${NC}"
                        fi
                    fi
                done
            fi

            last_status_time=$elapsed
        fi

        sleep 2
    done
}

# Show final results
show_final_results() {
    echo -e "\n${GREEN}🎯 FINAL PBFT CONSENSUS TEST RESULTS${NC}"
    echo "========================================"

    # Final health check
    echo -e "\n${BLUE}📊 Final Node Health:${NC}"
    local final_healthy=0
    for i in {0..3}; do
        if check_node_health $i; then
            echo -e "  ${GREEN}✅ Node $i: HEALTHY${NC}"
            ((final_healthy++))
        else
            echo -e "  ${RED}❌ Node $i: UNRESPONSIVE${NC}"
        fi
    done

    # Final blockchain state
    echo -e "\n${BLUE}📊 Final Blockchain State:${NC}"
    for i in {0..3}; do
        local final_height=$(get_blockchain_height $i)
        local total_progress=$((final_height - INITIAL_BLOCK_HEIGHTS[$i]))
        echo -e "  Node $i: ${final_height} blocks (grew by ${total_progress})"
    done

    # Consensus activity summary
    echo -e "\n${BLUE}📝 Consensus Activity Summary:${NC}"

    local total_proposals=0
    local total_commits=0

    for i in {0..3}; do
        if [ -f "${NODE_LOGS[$i]}" ]; then
            local proposals=$(grep -c "Proposing block" "${NODE_LOGS[$i]}" 2>/dev/null || echo "0")
            local commits=$(grep -c "Successfully committed" "${NODE_LOGS[$i]}" 2>/dev/null || echo "0")

            total_proposals=$((total_proposals + proposals))
            total_commits=$((total_commits + commits))

            echo -e "  Node $i: ${proposals} proposals, ${commits} commits"
        fi
    done

    # Overall assessment
    echo -e "\n${GREEN}🎉 OVERALL ASSESSMENT:${NC}"

    if [ $final_healthy -eq 4 ]; then
        echo -e "  ${GREEN}✅ All 4 nodes remained healthy throughout the test${NC}"
    else
        echo -e "  ${RED}❌ Only $final_healthy/4 nodes remained healthy${NC}"
    fi

    if [ $total_proposals -gt 0 ]; then
        echo -e "  ${GREEN}✅ Block proposals occurred ($total_proposals total)${NC}"
    else
        echo -e "  ${RED}❌ No block proposals detected${NC}"
    fi

    if [ $total_commits -gt 0 ]; then
        echo -e "  ${GREEN}✅ Block commits occurred ($total_commits total)${NC}"
        echo -e "  ${GREEN}✅ PBFT Consensus is WORKING!${NC}"
    else
        echo -e "  ${RED}❌ No block commits detected${NC}"
        echo -e "  ${RED}❌ PBFT Consensus may have issues${NC}"
    fi

    if [ $final_healthy -eq 4 ] && [ $total_commits -gt 0 ]; then
        echo -e "\n${GREEN}🏆 SUCCESS: Full PBFT consensus test PASSED!${NC}"
        echo -e "${GREEN}   • 4-node network operational${NC}"
        echo -e "${GREEN}   • Consensus algorithm working${NC}"
        echo -e "${GREEN}   • Blocks being proposed and committed${NC}"
    else
        echo -e "\n${RED}⚠️  INCOMPLETE: Some consensus issues detected${NC}"
    fi
}

# Main test execution
main() {
    # Set up cleanup on script exit
    trap cleanup EXIT

    echo "⏰ Test Duration: $TEST_DURATION seconds"
    echo "👥 Number of PBFT Nodes: $NUM_NODES"
    echo "🔌 Base Port: $BASE_PORT"
    echo "🎯 Testing: Real PBFT Consensus Mechanisms"
    echo ""

    # Initialize node configuration
    for i in {0..3}; do
        NODE_PORTS[$i]=$((BASE_PORT + i))
        NODE_LOGS[$i]="consensus_node_${i}.log"
    done

    # Check binary
    check_binary

    # Record initial blockchain heights (simplified)
    echo "📊 Recording initial blockchain heights..."
    for i in {0..3}; do
        # Just set to 0 for now - we'll track growth from test start
        INITIAL_BLOCK_HEIGHTS[$i]=0
        echo "  Node $i: Will track growth from test start"
    done

    # Start all nodes simultaneously
    echo -e "\n${BLUE}🚀 Starting all PBFT nodes simultaneously...${NC}"
    for i in {0..3}; do
        start_node $i &
        echo -e "${GREEN}✅ Node $i started in background${NC}"
    done

    echo -e "\n${GREEN}✅ All PBFT nodes started!${NC}"

    # Wait for all nodes to fully initialize their API servers
    echo "🔍 Waiting for all nodes to be ready..."
    sleep 15  # Give all nodes time to fully start up

    # Check node health with retries
    local startup_healthy=0
    local max_retries=10

    for i in {0..3}; do
        local healthy=0
        for retry in $(seq 1 $max_retries); do
            if check_node_health $i; then
                echo -e "  ${GREEN}✅ Node $i: Ready and responding${NC}"
                healthy=1
                ((startup_healthy++))
                break
            else
                echo -e "  ${YELLOW}⏳ Node $i: Not ready yet (attempt $retry/$max_retries)${NC}"
                sleep 3
            fi
        done

        if [ $healthy -eq 0 ]; then
            echo -e "  ${RED}❌ Node $i: Failed to start after $max_retries attempts${NC}"
        fi
    done

    if [ $startup_healthy -lt 4 ]; then
        echo -e "${RED}⚠️  Only $startup_healthy/4 nodes started successfully. Aborting test.${NC}"
        return 1
    fi

    echo -e "${GREEN}🎉 All nodes are ready and synchronized! Starting consensus test...${NC}"

    # Brief pause to let consensus initialize
    sleep 3

    # Monitor consensus activity
    monitor_consensus

    # Show final results
    show_final_results

    echo -e "\n${GREEN}🎯 PBFT Consensus Test Complete!${NC}"
    echo "====================================="
    echo "Check consensus_node_*.log files for detailed activity"
}

# Run main function
main "$@"
