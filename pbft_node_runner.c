#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include "src/features/blockchain/pbft/pbft_node.h"

// Simple PBFT node runner for testing
int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: %s <node_id> <port>\n", argv[0]);
        printf("Example: %s 0 8080\n", argv[0]);
        return 1;
    }

    uint32_t node_id = atoi(argv[1]);
    uint16_t port = atoi(argv[2]);

    printf("🚀 Starting PBFT Node %u on port %d\n", node_id, port);

    // Create PBFT node
    PBFTNode* node = pbft_node_create(node_id, port, false);
    if (!node) {
        printf("❌ Failed to create PBFT node %u\n", node_id);
        return 1;
    }

    // Initialize keys
    if (pbft_node_initialize_keys(node) != 0) {
        printf("❌ Failed to initialize keys for node %u\n", node_id);
        pbft_node_destroy(node);
        return 1;
    }

    // Load or create blockchain
    if (pbft_node_load_or_create_blockchain(node) != 0) {
        printf("❌ Failed to load/create blockchain for node %u\n", node_id);
        pbft_node_destroy(node);
        return 1;
    }

    printf("✅ PBFT Node %u initialized successfully\n", node_id);

    // Configure peers (all other nodes in the 4-node setup)
    for (uint32_t i = 0; i < 4; i++) {
        if (i != node_id) {
            char peer_ip[32];
            uint16_t peer_port = 8080 + i;
            snprintf(peer_ip, sizeof(peer_ip), "127.0.0.1:%d", peer_port);

            if (pbft_node_add_peer(node, NULL, peer_ip, i) != 0) {
                printf("⚠️ Failed to add peer %d to node %u\n", i, node_id);
            } else {
                printf("✅ Added peer %d to node %u\n", i, node_id);
            }
        }
    }

    printf("✅ PBFT Node %u fully configured with %d peers\n", node_id, 3);

    // Set up signal handler for graceful shutdown
    signal(SIGINT, SIG_IGN);  // Ignore SIGINT in child processes
    signal(SIGTERM, SIG_IGN); // Ignore SIGTERM in child processes

    // Run the node
    printf("🎯 PBFT Node %u entering consensus loop...\n", node_id);
    pbft_node_run(node);

    // Cleanup
    printf("🧹 Shutting down PBFT Node %u\n", node_id);
    pbft_node_destroy(node);

    return 0;
}
