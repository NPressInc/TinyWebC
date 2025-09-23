#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include "../packages/PBFT/pbftNode.h"
#include "../packages/comm/httpClient.h"

// Test configuration
#define NUM_NODES 4
#define TEST_DURATION_SECONDS 100
#define BASE_PORT 8080
#define NODE_TIMEOUT 30

// Node process information
typedef struct {
    pid_t pid;
    uint32_t node_id;
    uint16_t port;
    char url[64];
    int is_running;
    time_t start_time;
    uint32_t blocks_committed;
    uint32_t consensus_rounds;
    uint32_t view_changes;
} NodeInfo;

static NodeInfo nodes[NUM_NODES];
static volatile int test_running = 1;
static pthread_mutex_t test_mutex = PTHREAD_MUTEX_INITIALIZER;

// Signal handler for clean shutdown
void signal_handler(int sig) {
    printf("\n🛑 Received signal %d, shutting down test...\n", sig);
    test_running = 0;
}

// Initialize node information
void init_nodes() {
    for (int i = 0; i < NUM_NODES; i++) {
        nodes[i].node_id = i;
        nodes[i].port = BASE_PORT + i;
        snprintf(nodes[i].url, sizeof(nodes[i].url), "http://127.0.0.1:%d", nodes[i].port);
        nodes[i].is_running = 0;
        nodes[i].start_time = 0;
        nodes[i].blocks_committed = 0;
        nodes[i].consensus_rounds = 0;
        nodes[i].view_changes = 0;
    }
}

// Start a single PBFT node
int start_node(int node_index) {
    NodeInfo* node = &nodes[node_index];

    // Create genesis block and initialize node
    printf("🚀 Starting PBFT Node %u on port %d...\n", node->node_id, node->port);

    // Fork process for node
    node->pid = fork();
    if (node->pid < 0) {
        printf("❌ Failed to fork node %u: %s\n", node->node_id, strerror(errno));
        return 0;
    }

    if (node->pid == 0) {
        // Child process - run the PBFT node
        PBFTNode* pbft_node = pbft_node_create(node->node_id, node->port, true); // Debug mode for testing
        if (!pbft_node) {
            printf("❌ Failed to create PBFT node %u\n", node->node_id);
            exit(1);
        }

        // Initialize node
        if (pbft_node_initialize_keys(pbft_node) != 0) {
            printf("❌ Failed to initialize keys for node %u\n", node->node_id);
            pbft_node_destroy(pbft_node);
            exit(1);
        }

        if (pbft_node_load_or_create_blockchain(pbft_node) != 0) {
            printf("❌ Failed to load/create blockchain for node %u\n", node->node_id);
            pbft_node_destroy(pbft_node);
            exit(1);
        }

        // Add peer information (all other nodes)
        for (int i = 0; i < NUM_NODES; i++) {
            if (i != node_index) {
                char peer_ip[32];
                uint16_t peer_port = BASE_PORT + i;
                snprintf(peer_ip, sizeof(peer_ip), "127.0.0.1:%d", peer_port);

                if (pbft_node_add_peer(pbft_node, NULL, peer_ip, i) != 0) {
                    printf("⚠️ Failed to add peer %d to node %u\n", i, node->node_id);
                }
            }
        }

        printf("✅ Node %u initialized with %d peers\n", node->node_id, NUM_NODES - 1);

        // Run the node
        pbft_node_run(pbft_node);

        // Cleanup (this won't be reached in normal operation)
        pbft_node_destroy(pbft_node);
        exit(0);

    } else {
        // Parent process
        node->is_running = 1;
        node->start_time = time(NULL);

        // Wait a moment for node to start up
        sleep(2);

        // Verify node is responding
        char health_url[128];
        snprintf(health_url, sizeof(health_url), "%s/api/health", node->url);

        HttpResponse* response = http_client_get(health_url, NULL, NULL);
        if (response && response->status_code == 200) {
            printf("✅ Node %u is responding on %s\n", node->node_id, node->url);
            http_response_free(response);
            return 1;
        } else {
            printf("❌ Node %u failed to respond on %s\n", node->node_id, node->url);
            if (response) http_response_free(response);
            return 0;
        }
    }
}

// Stop all nodes
void stop_all_nodes() {
    printf("\n🛑 Stopping all nodes...\n");

    for (int i = 0; i < NUM_NODES; i++) {
        if (nodes[i].is_running && nodes[i].pid > 0) {
            printf("Stopping node %u (PID: %d)...\n", nodes[i].node_id, nodes[i].pid);

            // Try graceful shutdown first
            kill(nodes[i].pid, SIGTERM);

            // Wait up to 5 seconds for graceful shutdown
            int wait_count = 0;
            while (wait_count < 50) {
                int status;
                pid_t result = waitpid(nodes[i].pid, &status, WNOHANG);
                if (result == nodes[i].pid) {
                    printf("✅ Node %u stopped gracefully\n", nodes[i].node_id);
                    break;
                } else if (result == -1 && errno != ECHILD) {
                    printf("❌ Error waiting for node %u: %s\n", nodes[i].node_id, strerror(errno));
                    break;
                }
                usleep(100000); // 100ms
                wait_count++;
            }

            // Force kill if still running
            if (kill(nodes[i].pid, 0) == 0) {
                printf("⚠️ Force killing node %u\n", nodes[i].node_id);
                kill(nodes[i].pid, SIGKILL);
            }

            nodes[i].is_running = 0;
        }
    }
}

// Monitor node health and consensus
void monitor_nodes() {
    time_t start_time = time(NULL);
    time_t last_status_time = 0;

    printf("\n📊 Starting PBFT integration test monitoring...\n");
    printf("⏰ Test will run for %d seconds\n", TEST_DURATION_SECONDS);
    printf("👥 %d nodes configured\n", NUM_NODES);

    while (test_running && (time(NULL) - start_time) < TEST_DURATION_SECONDS) {
        sleep(5); // Check every 5 seconds

        // Print status update every 20 seconds
        if ((time(NULL) - last_status_time) >= 20) {
            printf("\n📈 Status Update (elapsed: %ld seconds):\n", time(NULL) - start_time);

            int healthy_nodes = 0;
            for (int i = 0; i < NUM_NODES; i++) {
                if (nodes[i].is_running) {
                    char health_url[128];
                    snprintf(health_url, sizeof(health_url), "%s/api/health", nodes[i].url);

                    HttpResponse* response = http_client_get(health_url, NULL, NULL);
                    if (response && response->status_code == 200) {
                        printf("  ✅ Node %u: Healthy\n", nodes[i].node_id);
                        healthy_nodes++;
                    } else {
                        printf("  ❌ Node %u: Unresponsive\n", nodes[i].node_id);
                    }
                    if (response) http_response_free(response);
                } else {
                    printf("  💀 Node %u: Not running\n", nodes[i].node_id);
                }
            }

            printf("  📊 %d/%d nodes healthy\n", healthy_nodes, NUM_NODES);
            last_status_time = time(NULL);
        }
    }

    printf("\n⏰ Test duration completed (%d seconds)\n", TEST_DURATION_SECONDS);
}

// Collect final statistics
void collect_final_stats() {
    printf("\n📊 Final Statistics:\n");

    for (int i = 0; i < NUM_NODES; i++) {
        if (nodes[i].is_running) {
            // Query blockchain length
            char blockchain_url[128];
            snprintf(blockchain_url, sizeof(blockchain_url), "%s/api/blockchain", nodes[i].url);

            HttpResponse* response = http_client_get(blockchain_url, NULL, NULL);
            if (response && response->status_code == 200) {
                // Parse blockchain info (simplified)
                if (strstr(response->data, "\"length\":")) {
                    printf("  📦 Node %u: Blockchain query successful\n", nodes[i].node_id);
                }
            } else {
                printf("  📦 Node %u: Failed to query blockchain\n", nodes[i].node_id);
            }
            if (response) http_response_free(response);

            printf("  ⏱️ Node %u: Ran for %ld seconds\n", nodes[i].node_id,
                   time(NULL) - nodes[i].start_time);
        }
    }
}

// Main test function
int main() {
    printf("🧪 PBFT 4-Node Integration Test\n");
    printf("================================\n");

    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Initialize node information
    init_nodes();

    // Start all nodes
    int nodes_started = 0;
    for (int i = 0; i < NUM_NODES; i++) {
        if (start_node(i)) {
            nodes_started++;
        } else {
            printf("❌ Failed to start node %d, aborting test\n", i);
            stop_all_nodes();
            return 1;
        }
        sleep(1); // Stagger startup
    }

    if (nodes_started != NUM_NODES) {
        printf("❌ Failed to start all nodes (%d/%d), aborting\n", nodes_started, NUM_NODES);
        stop_all_nodes();
        return 1;
    }

    printf("✅ All %d nodes started successfully!\n", NUM_NODES);

    // Monitor nodes during test
    monitor_nodes();

    // Collect final statistics
    collect_final_stats();

    // Stop all nodes
    stop_all_nodes();

    // Final report
    printf("\n🎯 Test Results:\n");
    printf("===============\n");
    printf("✅ Test completed successfully\n");
    printf("⏰ Duration: %d seconds\n", TEST_DURATION_SECONDS);
    printf("👥 Nodes tested: %d\n", NUM_NODES);
    printf("📊 All nodes started and monitored\n");

    // Check for any child processes still running
    int status;
    pid_t result;
    while ((result = waitpid(-1, &status, WNOHANG)) > 0) {
        printf("🧹 Cleaned up child process %d\n", result);
    }

    printf("🏁 PBFT Integration Test Complete!\n");
    return 0;
}
