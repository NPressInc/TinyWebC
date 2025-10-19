#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sodium.h>
#include "packages/PBFT/pbftNode.h"
#include "packages/comm/pbftApi.h"
#include "packages/sql/database.h"
#include "packages/structures/blockChain/blockchain.h"
#include "packages/fileIO/blockchainPersistence.h"
#include "packages/utils/statePaths.h"

// Global variables
static PBFTNode* g_pbft_node = NULL;
static int g_running = 1;

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down gracefully...\n", sig);
    g_running = 0;
    
    if (g_pbft_node) {
        g_pbft_node->running = 0;
    }
}

// Print usage information
void print_usage(const char* program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("Options:\n");
    printf("  -i, --id <node_id>      Node ID (default: 0)\n");
    printf("  -p, --port <port>       API server port (default: 8000)\n");
    printf("  -d, --debug             Use isolated test directories (test_state/node_X/)\n");
    printf("  -h, --help              Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s --id 1 --port 8001\n", program_name);
    printf("  %s --debug --id 0 --port 8000\n", program_name);
}

// Parse command line arguments
int parse_arguments(int argc, char* argv[], uint32_t* node_id, uint16_t* port, bool* debug_mode) {
    *node_id = 0;     // Default node ID
    *port = 8000;     // Default port (keeping original port)
    *debug_mode = false;  // Default to normal mode

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--id") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --id requires a value\n");
                return -1;
            }
            *node_id = (uint32_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--port") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --port requires a value\n");
                return -1;
            }
            *port = (uint16_t)atoi(argv[++i]);
            if (*port < 1024 || *port > 65535) {
                fprintf(stderr, "Error: Port must be between 1024 and 65535\n");
                return -1;
            }
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            *debug_mode = true;
            printf("🐛 Debug mode enabled - using isolated test directories\n");
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else {
            fprintf(stderr, "Error: Unknown option %s\n", argv[i]);
            return -1;
        }
    }

    return 0;
}

// Initialize system components
int initialize_system(uint32_t node_id, bool debug_mode) {
    printf("Initializing TinyWeb system components for node %u...\n", node_id);
    
    // Initialize sodium for cryptography
    if (sodium_init() < 0) {
        printf("Failed to initialize sodium\n");
        return -1;
    }
    
    // Initialize node-specific state paths
    NodeStatePaths paths;
    if (!state_paths_init(node_id, debug_mode, &paths)) {
        printf("Failed to initialize node state paths\n");
        return -1;
    }
    
    // Initialize message queues
    init_message_queues();
    
    printf("System components initialized successfully for node %u\n", node_id);
    return 0;
}

// Cleanup system components
void cleanup_system(void) {
    printf("Cleaning up system components...\n");
    
    // Cleanup persistence system first
    blockchain_persistence_cleanup();
    
    // Cleanup message queues
    cleanup_message_queues();
    
    // Close database
    if (db_is_initialized()) {
        db_close();
        printf("Database closed\n");
    }
    
    if (g_pbft_node) {
        // Clear the global pbft_node pointer
        extern PBFTNode* pbft_node;
        pbft_node = NULL;
        
        pbft_node_destroy(g_pbft_node);
        g_pbft_node = NULL;
    }
    
    printf("System cleanup completed\n");
}

// Main application thread that monitors the node
void* monitor_thread(void* arg) {
    PBFTNode* node = (PBFTNode*)arg;
    
    printf("TinyWeb monitor thread started\n");
    
    char node_id_str[32];
    snprintf(node_id_str, sizeof(node_id_str), "node_%03u", node->base.id);
    
    while (g_running && node->running) {
        // Monitor node health and performance
        pthread_mutex_lock(&node->state_mutex);
        
        // (heartbeat removed)
        
        // Print periodic status every 100 iterations (~100 seconds)
        if (node->counter % 100 == 0 && node->counter > 0) {
            printf("Node Status - ID: %u, Port: %u, Blockchain Length: %u, Peers: %zu\n",
                   node->base.id, 
                   node->api_port,
                   node->base.blockchain ? node->base.blockchain->length : 0,
                   node->base.peer_count);
        }
        
        pthread_mutex_unlock(&node->state_mutex);
        
        // Sleep for 1 second
        sleep(1);
    }
    
    // (node_status offline marker removed)
    
    printf("TinyWeb monitor thread stopping\n");
    return NULL;
}

int main(int argc, char* argv[]) {
    uint32_t node_id;
    uint16_t port;
    bool debug_mode;
    pthread_t monitor_tid;

    printf("=================================================================\n");
    printf("🚀 Welcome to TinyWeb - Decentralized PBFT Blockchain Node!\n");
    printf("=================================================================\n");

    // Parse command line arguments
    if (parse_arguments(argc, argv, &node_id, &port, &debug_mode) != 0) {
        return 1;
    }
    
    printf("Node Configuration:\n");
    printf("  Node ID: %u\n", node_id);
    printf("  API Port: %u\n", port);
    printf("  Protocol: HTTP + PBFT Consensus\n");
    printf("  Features: Blockchain, Encrypted Transactions\n");
    printf("-----------------------------------------------------------------\n");
    
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize system components
    if (initialize_system(node_id, debug_mode) != 0) {
        fprintf(stderr, "Failed to initialize system components\n");
        return 1;
    }
    
    // Create and initialize PBFT node
    printf("Creating PBFT node...\n");
    g_pbft_node = pbft_node_create(node_id, port, debug_mode);
    if (!g_pbft_node) {
        fprintf(stderr, "Failed to create PBFT node\n");
        cleanup_system();
        return 1;
    }
    
    // Set the global pbft_node pointer for API access
    extern PBFTNode* pbft_node;
    pbft_node = g_pbft_node;
    
    // Initialize node cryptographic keys
    printf("Initializing node keys...\n");
    if (pbft_node_initialize_keys(g_pbft_node) != 0) {
        fprintf(stderr, "Failed to initialize node keys\n");
        cleanup_system();
        return 1;
    }
    
    // Load or create blockchain
    printf("Loading blockchain...\n");
    if (pbft_node_load_or_create_blockchain(g_pbft_node) != 0) {
        fprintf(stderr, "Failed to load/create blockchain\n");
        cleanup_system();
        return 1;
    }
    
    // Load peers from database immediately after blockchain initialization
    printf("Loading peers from database...\n");
    if (pbft_node_load_peers_from_blockchain(g_pbft_node) != 0) {
        printf("⚠️ Warning: Failed to load peers from database, continuing...\n");
    }
    
    // Register this node in the database if it's available
    if (db_is_initialized()) {
        printf("📝 Registering node in database...\n");
        char node_id_str[32];
        snprintf(node_id_str, sizeof(node_id_str), "node_%03u", node_id);
        
        // (node_status registration removed)
        
        printf("✅ Robust persistence system active\n");
    } else {
        printf("⚠️ Database not available - running in file-only mode\n");
    }
    
    // Load peers from blockchain
    if (pbft_node_load_peers_from_blockchain(g_pbft_node) != 0) {
        printf("Warning: Failed to load peers from blockchain (starting in singular mode)\n");
    }
    
    printf("✅ TinyWeb PBFT node initialized successfully\n");
    printf("-----------------------------------------------------------------\n");
    printf("🌐 HTTP API Server: http://localhost:%u\n", port);
    printf("📊 Available Endpoints:\n");
    printf("  • GET  /                          - Node status\n");
    printf("  • GET  /GetBlockChainLength       - Blockchain info\n");
    printf("  • POST /Transaction               - Submit transaction\n");\
    printf("🔧 Press Ctrl+C to shutdown gracefully\n");
    printf("=================================================================\n");
    
    // Start monitor thread
    if (pthread_create(&monitor_tid, NULL, monitor_thread, g_pbft_node) != 0) {
        fprintf(stderr, "Failed to create monitor thread\n");
        cleanup_system();
        return 1;
    }
    
    // Run the PBFT node (this will start both consensus and API server threads)
    // This function blocks until the node shuts down
    pbft_node_run(g_pbft_node);
    
    // Wait for monitor thread to finish
    printf("Waiting for monitor thread to finish...\n");
    pthread_join(monitor_tid, NULL);
    
    // Cleanup and exit
    cleanup_system();
    printf("\n=================================================================\n");
    printf("🛑 TinyWeb PBFT Node shutdown complete - Goodbye!\n");
    printf("=================================================================\n");
    
    return 0;
}