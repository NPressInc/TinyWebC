#ifndef STATE_PATHS_H
#define STATE_PATHS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Maximum path length for state directories
#define MAX_STATE_PATH_LEN 512

/**
 * State path management for node-specific storage
 * 
 * This module provides centralized path management for node-specific state storage.
 * All state data (blockchain, database, keys) is stored under state/node_{id}/
 */

// Structure to hold all node-specific paths
typedef struct {
    uint32_t node_id;
    bool debug_mode;                             // true for debug mode, false for production mode
    char base_dir[MAX_STATE_PATH_LEN];           // state/ (production) or test_state/node_{id} (debug)
    char blockchain_dir[MAX_STATE_PATH_LEN];     // state/blockchain (production) or test_state/node_{id}/blockchain (debug)
    char keys_dir[MAX_STATE_PATH_LEN];           // state/keys (production) or test_state/node_{id}/keys (debug)
    char blockchain_file[MAX_STATE_PATH_LEN];    // state/blockchain/blockchain.dat or test_state/node_{id}/blockchain/blockchain.dat
    char blockchain_json[MAX_STATE_PATH_LEN];    // state/blockchain/blockchain.json or test_state/node_{id}/blockchain/blockchain.json
    char database_file[MAX_STATE_PATH_LEN];      // state/blockchain/blockchain.db or test_state/node_{id}/blockchain/blockchain.db
    char private_key_file[MAX_STATE_PATH_LEN];   // state/keys/node_private.key or test_state/node_{id}/keys/node_private.key
} NodeStatePaths;

/**
 * Initialize node-specific paths for the given node ID
 * Creates all necessary directories if they don't exist
 *
 * @param node_id The node identifier
 * @param debug_mode If true, use isolated test directories; if false, use production directories
 * @param paths Output structure to populate with paths
 * @return true on success, false on failure
 */
bool state_paths_init(uint32_t node_id, bool debug_mode, NodeStatePaths* paths);

/**
 * Ensure all directories exist for the given node paths
 * Creates directories recursively if needed
 * 
 * @param paths The node paths structure
 * @return true on success, false on failure
 */
bool state_paths_ensure_directories(const NodeStatePaths* paths);

/**
 * Get the blockchain directory for a node
 *
 * @param paths The node paths structure containing debug_mode
 * @param buffer Output buffer for the path
 * @param buffer_size Size of the output buffer
 * @return true on success, false on failure
 */
bool state_paths_get_blockchain_dir(const NodeStatePaths* paths, char* buffer, size_t buffer_size);

/**
 * Get the database file path for a node
 *
 * @param paths The node paths structure containing debug_mode
 * @param buffer Output buffer for the path
 * @param buffer_size Size of the output buffer
 * @return true on success, false on failure
 */
bool state_paths_get_database_file(const NodeStatePaths* paths, char* buffer, size_t buffer_size);

/**
 * Get the private key file path for a node
 *
 * @param paths The node paths structure containing debug_mode
 * @param buffer Output buffer for the path
 * @param buffer_size Size of the output buffer
 * @return true on success, false on failure
 */
bool state_paths_get_private_key_file(const NodeStatePaths* paths, char* buffer, size_t buffer_size);

/**
 * Create the base state directory structure
 * Creates state/ directory if it doesn't exist
 * 
 * @return true on success, false on failure
 */
bool state_paths_create_base_directory(void);

#endif // STATE_PATHS_H
