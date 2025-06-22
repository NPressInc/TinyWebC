#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include "pbftNode.h"
#include "packages/comm/pbftApi.h"
#include "packages/utils/jsonUtils.h"

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
    printf("  -p, --port <port>       API server port (default: 5000)\n");
    printf("  -h, --help              Show this help message\n");
    printf("\nExample:\n");
    printf("  %s --id 1 --port 5001\n", program_name);
}

// Parse command line arguments
int parse_arguments(int argc, char* argv[], uint32_t* node_id, uint16_t* port) {
    *node_id = 0;  // Default node ID
    *port = 5000;  // Default port
    
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
int initialize_system(void) {
    printf("Initializing PBFT system components...\n");
    
    // Initialize message queues
    init_message_queues();
    
    printf("System components initialized successfully\n");
    return 0;
}

// Cleanup system components
void cleanup_system(void) {
    printf("Cleaning up system components...\n");
    
    // Cleanup message queues
    cleanup_message_queues();
    
    if (g_pbft_node) {
        pbft_node_destroy(g_pbft_node);
        g_pbft_node = NULL;
    }
    
    printf("System cleanup completed\n");
}

// Main application thread that monitors the node
void* monitor_thread(void* arg) {
    PBFTNode* node = (PBFTNode*)arg;
    
    printf("PBFT monitor thread started\n");
    
    while (g_running && node->running) {
        // Monitor node health and performance
        pthread_mutex_lock(&node->state_mutex);
        
        // Print periodic status
        if (node->counter % 100 == 0) {
            printf("Node Status - ID: %u, Blockchain Length: %u, Peers: %zu\n",
                   node->base.id, 
                   node->base.blockchain ? node->base.blockchain->length : 0,
                   node->base.peer_count);
        }
        
        pthread_mutex_unlock(&node->state_mutex);
        
        // Sleep for 1 second
        sleep(1);
    }
    
    printf("PBFT monitor thread stopping\n");
    return NULL;
}

int main(int argc, char* argv[]) {
    uint32_t node_id;
    uint16_t port;
    pthread_t monitor_tid;
    
    printf("TinyWeb PBFT Node Starting...\n");
    
    // Parse command line arguments
    if (parse_arguments(argc, argv, &node_id, &port) != 0) {
        return 1;
    }
    
    printf("Node Configuration:\n");
    printf("  Node ID: %u\n", node_id);
    printf("  API Port: %u\n", port);
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Initialize system components
    if (initialize_system() != 0) {
        fprintf(stderr, "Failed to initialize system components\n");
        return 1;
    }
    
    // Create and initialize PBFT node
    g_pbft_node = pbft_node_create(node_id, port);
    if (!g_pbft_node) {
        fprintf(stderr, "Failed to create PBFT node\n");
        cleanup_system();
        return 1;
    }
    
    // Initialize node keys
    if (pbft_node_initialize_keys(g_pbft_node) != 0) {
        fprintf(stderr, "Failed to initialize node keys\n");
        cleanup_system();
        return 1;
    }
    
    // Load or create blockchain
    if (pbft_node_load_or_create_blockchain(g_pbft_node) != 0) {
        fprintf(stderr, "Failed to load/create blockchain\n");
        cleanup_system();
        return 1;
    }
    
    // Load peers from blockchain
    if (pbft_node_load_peers_from_blockchain(g_pbft_node) != 0) {
        fprintf(stderr, "Warning: Failed to load peers from blockchain\n");
    }
    
    printf("PBFT node initialized successfully\n");
    
    // Start monitor thread
    if (pthread_create(&monitor_tid, NULL, monitor_thread, g_pbft_node) != 0) {
        fprintf(stderr, "Failed to create monitor thread\n");
        cleanup_system();
        return 1;
    }
    
    // Run the PBFT node (this will start both node logic and API server)
    pbft_node_run(g_pbft_node);
    
    // Wait for monitor thread to finish
    printf("Waiting for monitor thread to finish...\n");
    pthread_join(monitor_tid, NULL);
    
    // Cleanup and exit
    cleanup_system();
    printf("TinyWeb PBFT Node shutdown complete\n");
    
    return 0;
} 