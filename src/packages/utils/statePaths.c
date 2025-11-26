#include "statePaths.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>

// Helper function to ensure directory exists
static bool ensure_directory_exists(const char* path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        // Directory doesn't exist, create it
        #ifdef _WIN32
            if (_mkdir(path) == -1) {
        #else
            if (mkdir(path, 0700) == -1) {
        #endif
                if (errno != EEXIST) {  // Ignore if directory already exists
                    printf("Failed to create directory: %s (error: %s)\n", path, strerror(errno));
                    return false;
                }
            }
    }
    return true;
}

bool state_paths_init(uint32_t node_id, bool debug_mode, NodeStatePaths* paths) {
    if (!paths) {
        return false;
    }

    // Initialize the structure
    memset(paths, 0, sizeof(NodeStatePaths));
    paths->node_id = node_id;
    paths->debug_mode = debug_mode;

    // Always use simple state/ paths - each container/node has isolated state directory
    snprintf(paths->base_dir, sizeof(paths->base_dir), "state");
    snprintf(paths->blockchain_dir, sizeof(paths->blockchain_dir), "state/storage");
    snprintf(paths->keys_dir, sizeof(paths->keys_dir), "state/keys");
    snprintf(paths->blockchain_file, sizeof(paths->blockchain_file), "state/storage/blockchain.dat");
    snprintf(paths->blockchain_json, sizeof(paths->blockchain_json), "state/storage/blockchain.json");
    snprintf(paths->database_file, sizeof(paths->database_file), "state/storage/tinyweb.db");
    snprintf(paths->private_key_file, sizeof(paths->private_key_file), "state/keys/node_private.key");

    // Create all directories
    return state_paths_ensure_directories(paths);
}

bool state_paths_ensure_directories(const NodeStatePaths* paths) {
    if (!paths) {
        return false;
    }
    
    // Create base state directory first
    if (!state_paths_create_base_directory()) {
        return false;
    }
    
    // Create node-specific base directory
    if (!ensure_directory_exists(paths->base_dir)) {
        return false;
    }
    
    // Create storage subdirectory
    if (!ensure_directory_exists(paths->blockchain_dir)) {
        return false;
    }
    
    // Create keys subdirectory
    if (!ensure_directory_exists(paths->keys_dir)) {
        return false;
    }
    
    printf("✓ Created node state directories for node %u\n", paths->node_id);
    return true;
}

bool state_paths_get_blockchain_dir(const NodeStatePaths* paths, char* buffer, size_t buffer_size) {
    if (!paths || !buffer || buffer_size == 0) {
        return false;
    }

    int result = snprintf(buffer, buffer_size, "state/storage");
    return result > 0 && (size_t)result < buffer_size;
}

bool state_paths_get_database_file(const NodeStatePaths* paths, char* buffer, size_t buffer_size) {
    if (!paths || !buffer || buffer_size == 0) {
        return false;
    }

    int result = snprintf(buffer, buffer_size, "state/storage/tinyweb.db");
    return result > 0 && (size_t)result < buffer_size;
}

bool state_paths_get_private_key_file(const NodeStatePaths* paths, char* buffer, size_t buffer_size) {
    if (!paths || !buffer || buffer_size == 0) {
        return false;
    }

    int result = snprintf(buffer, buffer_size, "state/keys/node_private.key");
    return result > 0 && (size_t)result < buffer_size;
}

bool state_paths_create_base_directory(void) {
    return ensure_directory_exists("state");
}

