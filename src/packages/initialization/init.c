#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include "init.h"
#include "packages/keystore/keystore.h"
#include "packages/structures/blockChain/blockchain.h"
#include "packages/structures/blockChain/block.h"
#include "packages/fileIO/blockchainIO.h"
#include "packages/structures/blockChain/transaction_types.h"
#include "packages/encryption/encryption.h"
#include "packages/sql/database.h"
#include "structs/permission/permission.h"

// Helper function to clean up existing blockchain files
static int cleanup_existing_files(const char* blockchain_path, const char* database_path) {
    char filepath[512];
    int success = 1;
    
    // Remove binary blockchain file (.dat)
    snprintf(filepath, sizeof(filepath), "%s/blockchain.dat", blockchain_path);
    if (access(filepath, F_OK) == 0) {
        if (unlink(filepath) != 0) {
            fprintf(stderr, "Warning: Failed to delete %s\n", filepath);
            success = 0;
        } else {
            printf("Removed existing blockchain.dat file\n");
        }
    }
    
    // Remove JSON blockchain file (.json)
    snprintf(filepath, sizeof(filepath), "%s/blockchain.json", blockchain_path);
    if (access(filepath, F_OK) == 0) {
        if (unlink(filepath) != 0) {
            fprintf(stderr, "Warning: Failed to delete %s\n", filepath);
            success = 0;
        } else {
            printf("Removed existing blockchain.json file\n");
        }
    }
    
    // Remove SQLite database files (.db, .db-wal, .db-shm)
    // Use specified database path or default to blockchain_path/blockchain.db
    if (database_path) {
        strncpy(filepath, database_path, sizeof(filepath) - 1);
        filepath[sizeof(filepath) - 1] = '\0';
    } else {
        snprintf(filepath, sizeof(filepath), "%s/blockchain.db", blockchain_path);
    }
    
    if (access(filepath, F_OK) == 0) {
        if (unlink(filepath) != 0) {
            fprintf(stderr, "Warning: Failed to delete %s\n", filepath);
            success = 0;
        } else {
            printf("Removed existing database file: %s\n", filepath);
        }
    }
    
    // Remove WAL file
    snprintf(filepath + strlen(filepath), sizeof(filepath) - strlen(filepath), "-wal");
    if (access(filepath, F_OK) == 0) {
        if (unlink(filepath) != 0) {
            fprintf(stderr, "Warning: Failed to delete %s\n", filepath);
        } else {
            printf("Removed existing WAL file: %s\n", filepath);
        }
    }
    
    // Remove shared memory file
    // Reset filepath to database path and add -shm suffix
    if (database_path) {
        strncpy(filepath, database_path, sizeof(filepath) - 1);
        filepath[sizeof(filepath) - 1] = '\0';
    } else {
        snprintf(filepath, sizeof(filepath), "%s/blockchain.db", blockchain_path);
    }
    snprintf(filepath + strlen(filepath), sizeof(filepath) - strlen(filepath), "-shm");
    if (access(filepath, F_OK) == 0) {
        if (unlink(filepath) != 0) {
            fprintf(stderr, "Warning: Failed to delete %s\n", filepath);
        } else {
            printf("Removed existing SHM file: %s\n", filepath);
        }
    }
    
    return success;
}

// Main initialization function
int initialize_network(const InitConfig* config) {
    if (!config) return -1;

    printf("Starting network initialization...\n");
    
    // Only create and clean production directories in non-debug mode
    if (!config->node_specific_dirs) {
        // Ensure blockchain directory exists
        struct stat st = {0};
        if (stat(config->blockchain_path, &st) == -1) {
            if (mkdir(config->blockchain_path, 0700) == -1) {
                fprintf(stderr, "Error: Failed to create blockchain directory: %s\n", config->blockchain_path);
                return -1;
            }
            printf("Created blockchain directory: %s\n", config->blockchain_path);
        }
        
        // Clean up existing blockchain files
        printf("Cleaning up existing blockchain files...\n");
        if (!cleanup_existing_files(config->blockchain_path, config->database_path)) {
            fprintf(stderr, "Warning: Some existing files could not be removed\n");
        }
    } else {
        printf("Debug mode: Skipping production directory cleanup\n");
    }

    // Initialize all pointers to NULL for proper cleanup
    GeneratedKeys keys = {0};
    TW_BlockChain* blockchain = NULL;
    PeerInfo* peers = NULL;
    char db_path[512];
    
    // Initialize database
    printf("Initializing SQLite database...\n");
    if (config->node_specific_dirs) {
        // For debug mode, use temporary database in test_state
        snprintf(db_path, sizeof(db_path), "test_state/temp_init.db");
        // Create test_state directory if it doesn't exist
        mkdir("test_state", 0700);
    } else {
        if (config->database_path) {
            strncpy(db_path, config->database_path, sizeof(db_path) - 1);
            db_path[sizeof(db_path) - 1] = '\0';
        } else {
            snprintf(db_path, sizeof(db_path), "%s/blockchain.db", config->blockchain_path);
        }
    }
    if (db_init(db_path) != 0) {
        fprintf(stderr, "Error: Failed to initialize database\n");
        return -1;
    }
    printf("Database initialized successfully: %s\n", db_path);

    // 1. Generate keys
    printf("Generating cryptographic keys...\n");
    if (generate_initial_keys(&keys, config) != 0) {
        fprintf(stderr, "Error: Failed to generate initial keys\n");
        db_close();
        return -1;
    }
    printf("Generated keys for %u nodes and %u users\n", keys.node_count, keys.user_count);

    // 2. Save keys to keystore
    printf("Saving keys to keystore...\n");
    if (save_keys_to_keystore_with_config(&keys, config) != 0) {
        fprintf(stderr, "Error: Failed to save keys to keystore\n");
        free_generated_keys(&keys);
        db_close();
        return -1;
    }
    if (config->node_specific_dirs) {
        printf("Keys saved in node-specific directories\n");
    } else {
        printf("Keys saved to keystore: %s\n", config->keystore_path);
    }

    // 3. Create blockchain
    printf("Creating blockchain...\n");
    blockchain = TW_BlockChain_create(keys.node_public_keys[0], NULL, 0);
    if (!blockchain) {
        fprintf(stderr, "Error: Failed to create blockchain\n");
        free_generated_keys(&keys);
        db_close();
        return -1;
    }
    printf("Blockchain created successfully\n");

    // 4. Generate peer list
    printf("Generating peer configuration...\n");
    peers = malloc(sizeof(PeerInfo) * config->node_count);
    if (!peers) {
        fprintf(stderr, "Error: Failed to allocate peer list\n");
        free_generated_keys(&keys);
        TW_BlockChain_destroy(blockchain);
        db_close();
        return -1;
    }

    if (generate_peer_list(peers, &keys, config->base_port) != 0) {
        fprintf(stderr, "Error: Failed to generate peer list\n");
        free(peers);
        free_generated_keys(&keys);
        TW_BlockChain_destroy(blockchain);
        db_close();
        return -1;
    }
    printf("Peer list generated for %u nodes\n", config->node_count);

    // 5. Create initialization block with all setup transactions
    printf("Creating initialization block...\n");
    if (create_initialization_block(&keys, peers, blockchain, config) != 0) {
        fprintf(stderr, "Error: Failed to create initialization block\n");
        free(peers);
        free_generated_keys(&keys);
        TW_BlockChain_destroy(blockchain);
        db_close();
        return -1;
    }
    printf("Initialization block created with %u transactions\n", TW_BlockChain_get_last_block(blockchain)->txn_count);

    // 6. Save the initialized blockchain to file
    printf("Saving blockchain to file...\n");
    
    if (config->node_specific_dirs) {
        // Save blockchain once to a temp location, then copy to each node to ensure identical bytes
        char temp_blockchain_dir[512];
        snprintf(temp_blockchain_dir, sizeof(temp_blockchain_dir), "test_state/temp_blockchain");

        // Create temp directory if needed
        if (mkdir(temp_blockchain_dir, 0700) == -1 && errno != EEXIST) {
            fprintf(stderr, "Error: Failed to create temp blockchain directory: %s\n", temp_blockchain_dir);
            free(peers);
            free_generated_keys(&keys);
            TW_BlockChain_destroy(blockchain);
            db_close();
            return -1;
        }

        // Save blockchain once to temp
        if (!saveBlockChainToFileWithPath(blockchain, temp_blockchain_dir)) {
            fprintf(stderr, "Error: Failed to save temp blockchain\n");
            free(peers);
            free_generated_keys(&keys);
            TW_BlockChain_destroy(blockchain);
            db_close();
            return -1;
        }
        if (!writeBlockChainToJsonWithPath(blockchain, temp_blockchain_dir)) {
            fprintf(stderr, "Warning: Failed to save temp blockchain JSON\n");
        }

        // Copy temp blockchain files to each node directory
        for (uint32_t i = 0; i < config->node_count; i++) {
            char node_blockchain_dir[512];
            char src_path[512];
            char dst_path[512];

            snprintf(node_blockchain_dir, sizeof(node_blockchain_dir), "test_state/node_%u/blockchain", i);

            // Copy blockchain.dat
            snprintf(src_path, sizeof(src_path), "%s/blockchain.dat", temp_blockchain_dir);
            snprintf(dst_path, sizeof(dst_path), "%s/blockchain.dat", node_blockchain_dir);

            FILE* src = fopen(src_path, "rb");
            if (!src) {
                fprintf(stderr, "Error: Failed to open temp blockchain.dat for node %u\n", i);
                free(peers);
                free_generated_keys(&keys);
                TW_BlockChain_destroy(blockchain);
                db_close();
                return -1;
            }
            FILE* dst = fopen(dst_path, "wb");
            if (!dst) {
                fprintf(stderr, "Error: Failed to create blockchain.dat for node %u: %s\n", i, dst_path);
                fclose(src);
                free(peers);
                free_generated_keys(&keys);
                TW_BlockChain_destroy(blockchain);
                db_close();
                return -1;
            }
            char buffer[4096];
            size_t bytes_read;
            while ((bytes_read = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                if (fwrite(buffer, 1, bytes_read, dst) != bytes_read) {
                    fprintf(stderr, "Error: Failed to copy blockchain.dat for node %u\n", i);
                    fclose(src);
                    fclose(dst);
                    free(peers);
                    free_generated_keys(&keys);
                    TW_BlockChain_destroy(blockchain);
                    db_close();
                    return -1;
                }
            }
            fclose(src);
            fclose(dst);

            // Copy blockchain.json (best-effort)
            snprintf(src_path, sizeof(src_path), "%s/blockchain.json", temp_blockchain_dir);
            snprintf(dst_path, sizeof(dst_path), "%s/blockchain.json", node_blockchain_dir);
            FILE* src_json = fopen(src_path, "rb");
            if (src_json) {
                FILE* dst_json = fopen(dst_path, "wb");
                if (dst_json) {
                    while ((bytes_read = fread(buffer, 1, sizeof(buffer), src_json)) > 0) {
                        if (fwrite(buffer, 1, bytes_read, dst_json) != bytes_read) {
                            fprintf(stderr, "Warning: Failed to copy blockchain.json for node %u\n", i);
                            break;
                        }
                    }
                    fclose(dst_json);
                }
                fclose(src_json);
            }

            printf("Blockchain saved for node %u: %s/blockchain.dat\n", i, node_blockchain_dir);
        }

        // Cleanup temp blockchain directory files (optional, keep dir)
        char tmp_path[512];
        snprintf(tmp_path, sizeof(tmp_path), "%s/blockchain.dat", temp_blockchain_dir);
        unlink(tmp_path);
        snprintf(tmp_path, sizeof(tmp_path), "%s/blockchain.json", temp_blockchain_dir);
        unlink(tmp_path);
    } else {
        // Original behavior: save to global directory
        if (!saveBlockChainToFileWithPath(blockchain, config->blockchain_path)) {
            fprintf(stderr, "Error: Failed to save blockchain\n");
            free(peers);
            free_generated_keys(&keys);
            TW_BlockChain_destroy(blockchain);
            db_close();
            return -1;
        }
        printf("Blockchain saved to: %s/blockchain.dat\n", config->blockchain_path);

        // 7. Save blockchain as JSON for human readability
        printf("Saving blockchain as JSON...\n");
        if (!writeBlockChainToJsonWithPath(blockchain, config->blockchain_path)) {
            fprintf(stderr, "Warning: Failed to save blockchain as JSON\n");
            // Don't return error here as the main blockchain file was saved successfully
        } else {
            printf("Blockchain JSON saved to: %s/blockchain.json\n", config->blockchain_path);
        }
    }

    // 8. Load the first node's keypair into keystore for decryption
    printf("Loading node keypair into keystore for database sync...\n");
    keystore_cleanup(); // Clear the temporary keypair
    if (!keystore_load_raw_ed25519_keypair(keys.node_private_keys[0])) {
        fprintf(stderr, "Error: Failed to load node keypair into keystore\n");
        free(peers);
        free_generated_keys(&keys);
        TW_BlockChain_destroy(blockchain);
        db_close();
        return -1;
    }
    printf("Node keypair loaded successfully\n");

    // 9. Synchronize blockchain to database
    printf("Synchronizing blockchain to database...\n");
    if (db_sync_blockchain(blockchain) != 0) {
        fprintf(stderr, "Error: Failed to synchronize blockchain to database\n");
        free(peers);
        free_generated_keys(&keys);
        TW_BlockChain_destroy(blockchain);
        db_close();
        return -1;
    }
    printf("Blockchain synchronized to database successfully\n");

    // 10. Create node-specific databases if in debug mode
    if (config->node_specific_dirs) {
        printf("Creating node-specific databases...\n");

        // Close the temp database
        db_close();

        for (uint32_t i = 0; i < config->node_count; i++) {
            char node_db_path[512];
            snprintf(node_db_path, sizeof(node_db_path), "test_state/node_%u/blockchain/blockchain.db", i);

            // Copy the temp database to the node's directory
            FILE* src = fopen("test_state/temp_init.db", "rb");
            if (!src) {
                fprintf(stderr, "Error: Failed to open temp database for copying to node %u\n", i);
                free(peers);
                free_generated_keys(&keys);
                TW_BlockChain_destroy(blockchain);
                return -1;
            }

            FILE* dst = fopen(node_db_path, "wb");
            if (!dst) {
                fprintf(stderr, "Error: Failed to create database file for node %u: %s\n", i, node_db_path);
                fclose(src);
                free(peers);
                free_generated_keys(&keys);
                TW_BlockChain_destroy(blockchain);
                return -1;
            }

            // Copy file contents
            char buffer[4096];
            size_t bytes_read;
            while ((bytes_read = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                if (fwrite(buffer, 1, bytes_read, dst) != bytes_read) {
                    fprintf(stderr, "Error: Failed to write database file for node %u\n", i);
                    fclose(src);
                    fclose(dst);
                    free(peers);
                    free_generated_keys(&keys);
                    TW_BlockChain_destroy(blockchain);
                    return -1;
                }
            }

            fclose(src);
            fclose(dst);

            printf("Database created for node %u: %s\n", i, node_db_path);
        }

        // Re-open the temp database for cleanup
        if (db_init("test_state/temp_init.db") != 0) {
            fprintf(stderr, "Warning: Failed to re-open temp database for cleanup\n");
        }
    }

    // Cleanup
    free(peers);
    free_generated_keys(&keys);
    TW_BlockChain_destroy(blockchain);
    db_close();

    // Clean up temp database file in debug mode
    if (config->node_specific_dirs) {
        if (unlink("test_state/temp_init.db") != 0) {
            printf("Warning: Failed to clean up temp database file\n");
        }
    }

    printf("Network initialization completed successfully!\n");
    if (config->node_specific_dirs) {
        printf("Files created in node-specific directories:\n");
        for (uint32_t i = 0; i < config->node_count; i++) {
            printf("  Node %u:\n", i);
            printf("    - Blockchain: test_state/node_%u/blockchain/blockchain.dat\n", i);
            printf("    - JSON: test_state/node_%u/blockchain/blockchain.json\n", i);
            printf("    - Database: test_state/node_%u/blockchain/blockchain.db\n", i);
            printf("    - Private Key: test_state/node_%u/keys/node_private.key\n", i);
        }
        printf("  Global user keys: %s/user_*_private.key\n", config->keystore_path);
    } else {
        printf("Files created:\n");
        printf("  - Binary blockchain: %s/blockchain.dat\n", config->blockchain_path);
        printf("  - JSON blockchain: %s/blockchain.json\n", config->blockchain_path);
        printf("  - SQLite database: %s\n", db_path);
        printf("  - Keys: %s\n", config->keystore_path);
    }
    
    return 0;
}

// Key generation functions
int generate_initial_keys(GeneratedKeys* keys, const InitConfig* config) {
    if (!keys || !config) return -1;
    
    // Initialize libsodium
    if (sodium_init() < 0) {
        printf("DEBUG: Failed to initialize libsodium\n");
        return -1;
    }
    
    keys->node_count = config->node_count;
    keys->user_count = config->user_count;
    if (keys->node_count == 0 || keys->user_count == 0) return -1;
    keys->node_private_keys = malloc(sizeof(unsigned char*) * keys->node_count);
    keys->node_public_keys = malloc(sizeof(unsigned char*) * keys->node_count);
    keys->user_private_keys = malloc(sizeof(unsigned char*) * keys->user_count);
    keys->user_public_keys = malloc(sizeof(unsigned char*) * keys->user_count);
    if (!keys->node_private_keys || !keys->node_public_keys || !keys->user_private_keys || !keys->user_public_keys) {
        free_generated_keys(keys);
        return -1;
    }
    for (uint32_t i = 0; i < keys->node_count; i++) {
        keys->node_private_keys[i] = malloc(SIGN_SECRET_SIZE);
        keys->node_public_keys[i] = malloc(PUBKEY_SIZE);
        if (!keys->node_private_keys[i] || !keys->node_public_keys[i]) {
            free_generated_keys(keys);
            return -1;
        }
        
        // Generate Ed25519 keypair directly using libsodium
        unsigned char ed25519_public_key[SIGN_PUBKEY_SIZE];
        if (crypto_sign_keypair(ed25519_public_key, keys->node_private_keys[i]) != 0) {
            free_generated_keys(keys);
            return -1;
        }
        
        // Convert Ed25519 public key to X25519 for encryption
        if (crypto_sign_ed25519_pk_to_curve25519(keys->node_public_keys[i], ed25519_public_key) != 0) {
            free_generated_keys(keys);
            return -1;
        }
    }
    for (uint32_t i = 0; i < keys->user_count; i++) {
        keys->user_private_keys[i] = malloc(SIGN_SECRET_SIZE);
        keys->user_public_keys[i] = malloc(PUBKEY_SIZE);
        if (!keys->user_private_keys[i] || !keys->user_public_keys[i]) {
            free_generated_keys(keys);
            return -1;
        }
        
        // Generate Ed25519 keypair directly using libsodium
        unsigned char ed25519_public_key[SIGN_PUBKEY_SIZE];
        if (crypto_sign_keypair(ed25519_public_key, keys->user_private_keys[i]) != 0) {
            free_generated_keys(keys);
            return -1;
        }
        
        // Convert Ed25519 public key to X25519 for encryption
        if (crypto_sign_ed25519_pk_to_curve25519(keys->user_public_keys[i], ed25519_public_key) != 0) {
            free_generated_keys(keys);
            return -1;
        }
    }
    return 0;
}

int save_keys_to_keystore(const GeneratedKeys* keys, const char* keystore_path, const char* passphrase) {
    if (!keys || !keystore_path || !passphrase) return -1;
    // Save node keys
    for (uint32_t i = 0; i < keys->node_count; i++) {
        char node_key_path[256];
        snprintf(node_key_path, sizeof(node_key_path), "%s/node_%u_private.key", keystore_path, i);
        FILE* f = fopen(node_key_path, "wb");
        if (!f) return -1;
        fwrite(keys->node_private_keys[i], 1, SIGN_SECRET_SIZE, f);
        fclose(f);
    }
    // Save user keys
    for (uint32_t i = 0; i < keys->user_count; i++) {
        char user_key_path[256];
        snprintf(user_key_path, sizeof(user_key_path), "%s/user_%u_private.key", keystore_path, i);
        FILE* f = fopen(user_key_path, "wb");
        if (!f) return -1;
        fwrite(keys->user_private_keys[i], 1, SIGN_SECRET_SIZE, f);
        fclose(f);
    }
    return 0;
}

int save_keys_to_keystore_with_config(const GeneratedKeys* keys, const InitConfig* config) {
    if (!keys || !config) return -1;
    
    if (config->node_specific_dirs) {
        // Create node-specific directories and save keys there (debug layout under test_state/)
        printf("Creating node-specific key directories...\n");
        
        for (uint32_t i = 0; i < keys->node_count; i++) {
            // Create directory structure: test_state/node_X/{keys,blockchain}/
            char node_dir[512];
            char node_keys_dir[512];
            char node_blockchain_dir[512];
            
            snprintf(node_dir, sizeof(node_dir), "test_state/node_%u", i);
            snprintf(node_keys_dir, sizeof(node_keys_dir), "test_state/node_%u/keys", i);
            snprintf(node_blockchain_dir, sizeof(node_blockchain_dir), "test_state/node_%u/blockchain", i);
            
            // Create directories
            if (mkdir(node_dir, 0700) == -1 && errno != EEXIST) {
                fprintf(stderr, "Failed to create node directory: %s\n", node_dir);
                return -1;
            }
            if (mkdir(node_keys_dir, 0700) == -1 && errno != EEXIST) {
                fprintf(stderr, "Failed to create node keys directory: %s\n", node_keys_dir);
                return -1;
            }
            if (mkdir(node_blockchain_dir, 0700) == -1 && errno != EEXIST) {
                fprintf(stderr, "Failed to create node blockchain directory: %s\n", node_blockchain_dir);
                return -1;
            }
            
            // Save node private key
            char node_key_path[512];
            snprintf(node_key_path, sizeof(node_key_path), "%s/node_private.key", node_keys_dir);
            FILE* f = fopen(node_key_path, "wb");
            if (!f) {
                fprintf(stderr, "Failed to create node key file: %s\n", node_key_path);
                return -1;
            }
            fwrite(keys->node_private_keys[i], 1, SIGN_SECRET_SIZE, f);
            fclose(f);
            
            printf("Created node %u key: %s\n", i, node_key_path);
        }
        
        // For debug mode, save user keys in test_state/keys directory
        // Create test_state/keys directory
        char test_keys_dir[] = "test_state/keys";
        if (mkdir(test_keys_dir, 0700) == -1 && errno != EEXIST) {
            fprintf(stderr, "Failed to create test keys directory: %s\n", test_keys_dir);
            return -1;
        }
        
        for (uint32_t i = 0; i < keys->user_count; i++) {
            char user_key_path[512];
            snprintf(user_key_path, sizeof(user_key_path), "%s/user_%u_private.key", test_keys_dir, i);
            FILE* f = fopen(user_key_path, "wb");
            if (!f) {
                fprintf(stderr, "Failed to create user key file: %s\n", user_key_path);
                return -1;
            }
            fwrite(keys->user_private_keys[i], 1, SIGN_SECRET_SIZE, f);
            fclose(f);
            
            printf("Created user %u key: %s\n", i, user_key_path);
        }
    } else {
        // Use the original function for backwards compatibility
        return save_keys_to_keystore(keys, config->keystore_path, config->passphrase);
    }
    
    return 0;
}

// Peer configuration functions
int generate_peer_list(PeerInfo* peers, const GeneratedKeys* keys, uint16_t base_port) {
    if (!peers || !keys) return -1;

    for (uint32_t i = 0; i < keys->node_count; i++) {
        // Set peer ID
        peers[i].id = i + 1;  // Start IDs from 1

        // Copy public key
        memcpy(peers[i].public_key, keys->node_public_keys[i], PUBKEY_SIZE);

        // Set IP:port (localhost for testing)
        snprintf(peers[i].ip_port, sizeof(peers[i].ip_port), "127.0.0.1:%u", base_port + i);

        // Initialize other fields
        peers[i].is_delinquent = 0;
        peers[i].last_seen = time(NULL);
    }

    return 0;
}


// Memory management
void free_generated_keys(GeneratedKeys* keys) {
    if (!keys) return;

    // Free node keys
    if (keys->node_private_keys) {
        for (uint32_t i = 0; i < keys->node_count; i++) {
            free(keys->node_private_keys[i]);
        }
        free(keys->node_private_keys);
    }

    if (keys->node_public_keys) {
        for (uint32_t i = 0; i < keys->node_count; i++) {
            free(keys->node_public_keys[i]);
        }
        free(keys->node_public_keys);
    }

    // Free user keys
    if (keys->user_private_keys) {
        for (uint32_t i = 0; i < keys->user_count; i++) {
            free(keys->user_private_keys[i]);
        }
        free(keys->user_private_keys);
    }

    if (keys->user_public_keys) {
        for (uint32_t i = 0; i < keys->user_count; i++) {
            free(keys->user_public_keys[i]);
        }
        free(keys->user_public_keys);
    }

    // Reset counts
    keys->node_count = 0;
    keys->user_count = 0;
}

// Create initialization block with all setup transactions
int create_initialization_block(const GeneratedKeys* keys, const PeerInfo* peers, TW_BlockChain* blockchain, const InitConfig* config) {
    if (!keys || !peers || !blockchain || !config) return -1;

    printf("Creating initialization block...\n");
    
    // Initialize a keypair in the keystore for encryption operations
    // encrypt_payload_multi requires a keypair to be loaded for ephemeral key generation
    if (!keystore_generate_keypair()) {
        printf("Failed to initialize keystore keypair for encryption\n");
        return -1;
    }
    printf("Initialized keystore keypair for encryption operations\n");

    // Array to collect all initialization transactions
    TW_Transaction** init_transactions = malloc(sizeof(TW_Transaction*) * (keys->user_count + keys->node_count + 2)); // Users + peers + system (removed roles since they're in user registration)
    int txn_count = 0;

    // 1. Create user registration transactions (now includes role assignment)
    printf("Creating user registration transactions...\n");
    for (uint32_t i = 0; i < keys->user_count; i++) {
        TW_Transaction* user_txn = create_user_registration_transaction(keys, i, blockchain->creator_pubkey);
        if (user_txn) {
            init_transactions[txn_count++] = user_txn;
            printf("Created user registration transaction for user %u (includes role assignment)\n", i);
        } else {
            printf("Failed to create user registration transaction for user %u\n", i);
        }
    }

    // 2. Create peer registration transactions
    printf("Creating peer registration transactions...\n");
    for (uint32_t i = 0; i < keys->node_count; i++) {
        TW_Transaction* peer_txn = create_peer_registration_transaction(peers, i, blockchain->creator_pubkey, keys);
        if (peer_txn) {
            init_transactions[txn_count++] = peer_txn;
            printf("Created peer registration transaction for peer %u\n", i);
        } else {
            printf("Failed to create peer registration transaction for peer %u\n", i);
        }
    }

    // 3. Create system configuration transaction
    printf("Creating system configuration transaction...\n");
    TW_Transaction* config_txn = create_system_config_transaction(blockchain->creator_pubkey, keys);
    if (config_txn) {
        init_transactions[txn_count++] = config_txn;
        printf("Created system config transaction\n");
    } else {
        printf("Failed to create system config transaction\n");
    }

    // 4. Create content filter transaction
    printf("Creating content filter transaction...\n");
    TW_Transaction* filter_txn = create_content_filter_transaction(blockchain->creator_pubkey, keys);
    if (filter_txn) {
        init_transactions[txn_count++] = filter_txn;
        printf("Created content filter transaction\n");
    } else {
        printf("Failed to create content filter transaction\n");
    }

    if (txn_count == 0) {
        printf("No transactions created\n");
        free(init_transactions);
        return -1;
    }

    printf("Created %d transactions total\n", txn_count);

    // Get the hash of the last block (genesis block)
    TW_Block* last_block = TW_BlockChain_get_last_block(blockchain);
    unsigned char previous_hash[HASH_SIZE];
    if (last_block) {
        if (TW_Block_getHash(last_block, previous_hash) != 0) {
            printf("Failed to get previous block hash\n");
            return -1;
        }
        printf("Got previous block hash\n");
    } else {
        memset(previous_hash, 0, HASH_SIZE); // All zeros if no previous block
        printf("No previous block, using zero hash\n");
    }

    // Create proposer ID (use first node's public key)
    unsigned char proposer_id[PROP_ID_SIZE];
    memcpy(proposer_id, keys->node_public_keys[0], PROP_ID_SIZE);
    printf("Set proposer ID\n");

    // Create the initialization block
    printf("Creating block with index %u and %d transactions\n", blockchain->length, txn_count);
    TW_Block* init_block = TW_Block_create(
        blockchain->length,  // Block index
        init_transactions,   // Transactions
        txn_count,          // Transaction count
        time(NULL),         // Current timestamp
        previous_hash,      // Previous block hash
        proposer_id         // Proposer ID
    );

    if (!init_block) {
        printf("Failed to create block\n");
        // Clean up transactions if block creation failed
        for (int i = 0; i < txn_count; i++) {
            TW_Transaction_destroy(init_transactions[i]);
        }
        free(init_transactions);
        return -1;
    }

    printf("Block created successfully\n");

    // Build the merkle tree for the initialization block
    TW_Block_buildMerkleTree(init_block);

    // Add the block to the blockchain
    if (TW_BlockChain_add_block(blockchain, init_block) != 0) {
        printf("Failed to add block to blockchain\n");
        TW_Block_destroy(init_block);
        free(init_transactions);
        return -1;
    }

    printf("Block added to blockchain successfully\n");

    free(init_transactions); // The block now owns the transaction pointers
    return 0;
}

// Helper function to create a flat array of all recipients (nodes + users)
unsigned char* create_all_recipients_flat(const GeneratedKeys* keys, uint32_t* total_count) {
    if (!keys || !total_count) return NULL;
    
    *total_count = keys->node_count + keys->user_count;
    unsigned char* all_recipients = malloc(PUBKEY_SIZE * (*total_count));
    if (!all_recipients) return NULL;
    
    // Add all node public keys
    for (uint32_t i = 0; i < keys->node_count; i++) {
        memcpy(all_recipients + (i * PUBKEY_SIZE), keys->node_public_keys[i], PUBKEY_SIZE);
    }
    
    // Add all user public keys
    for (uint32_t i = 0; i < keys->user_count; i++) {
        memcpy(all_recipients + ((keys->node_count + i) * PUBKEY_SIZE), keys->user_public_keys[i], PUBKEY_SIZE);
    }
    
    return all_recipients;
}

// Helper function to create a list of all recipients (nodes + users) as pointers for transaction
unsigned char** create_all_recipients_list(const GeneratedKeys* keys, uint32_t* total_count) {
    if (!keys || !total_count) return NULL;
    
    *total_count = keys->node_count + keys->user_count;
    unsigned char** all_recipients = malloc(sizeof(unsigned char*) * (*total_count));
    if (!all_recipients) return NULL;
    
    // Add all node public keys
    for (uint32_t i = 0; i < keys->node_count; i++) {
        all_recipients[i] = keys->node_public_keys[i];
    }
    
    // Add all user public keys
    for (uint32_t i = 0; i < keys->user_count; i++) {
        all_recipients[keys->node_count + i] = keys->user_public_keys[i];
    }
    
    return all_recipients;
}

// Transaction creation functions
TW_Transaction* create_user_registration_transaction(const GeneratedKeys* keys, uint32_t user_index, const unsigned char* creator_pubkey) {
    if (!keys || user_index >= keys->user_count || !creator_pubkey) {
        return NULL;
    }

    TW_TXN_UserRegistration user_data;
    memset(&user_data, 0, sizeof(user_data));
    
    // Create a simple username based on index
    snprintf(user_data.username, MAX_USERNAME_LENGTH, "user_%u", user_index);
    user_data.age = (user_index == 0) ? 35 : (user_index == 1) ? 32 : (12 + user_index); // Default ages
    
    // Derive Ed25519 signing public key from the user's private key
    if (crypto_sign_ed25519_sk_to_pk(user_data.user_signing_pubkey, keys->user_private_keys[user_index]) != 0) {
        printf("Failed to derive Ed25519 public key for user %u\n", user_index);
        return NULL;
    }
    
    // Assign role based on user index
    if (user_index < 2) {
        // First two users get admin role
        strncpy(user_data.assigned_role, "admin", MAX_ROLE_NAME_LENGTH - 1);
        user_data.permission_set_count = 5;  // Updated to include ADMIN_BASIC
        
        memcpy(&user_data.permission_sets[0], &ADMIN_MESSAGING, sizeof(PermissionSet));
        memcpy(&user_data.permission_sets[1], &ADMIN_GROUP_MANAGEMENT, sizeof(PermissionSet));
        memcpy(&user_data.permission_sets[2], &ADMIN_USER_MANAGEMENT, sizeof(PermissionSet));
        memcpy(&user_data.permission_sets[3], &ADMIN_SYSTEM, sizeof(PermissionSet));
        memcpy(&user_data.permission_sets[4], &ADMIN_BASIC, sizeof(PermissionSet));  // Added ADMIN_BASIC
    } else {
        // Other users get member role
        strncpy(user_data.assigned_role, "member", MAX_ROLE_NAME_LENGTH - 1);
        user_data.permission_set_count = 2;
        
        memcpy(&user_data.permission_sets[0], &MEMBER_MESSAGING, sizeof(PermissionSet));
        memcpy(&user_data.permission_sets[1], &MEMBER_BASIC, sizeof(PermissionSet));
    }

    unsigned char* serialized_buffer = NULL;
    int serialized_size = serialize_user_registration(&user_data, &serialized_buffer);
    if (serialized_size < 0 || !serialized_buffer) {
        return NULL;
    }

    // Create flat array of all recipients (nodes + users)
    uint32_t total_recipients;
    unsigned char* all_recipients_flat = create_all_recipients_flat(keys, &total_recipients);
    if (!all_recipients_flat) {
        free(serialized_buffer);
        return NULL;
    }

    EncryptedPayload* encrypted_payload = encrypt_payload_multi(
        serialized_buffer, 
        serialized_size, 
        all_recipients_flat,
        total_recipients
    );
    free(serialized_buffer);
    free(all_recipients_flat);
    if (!encrypted_payload) {
        return NULL;
    }

    // Create recipients array for transaction
    unsigned char** txn_recipients = create_all_recipients_list(keys, &total_recipients);
    if (!txn_recipients) {
        free_encrypted_payload(encrypted_payload);
        return NULL;
    }

    // Create flat array for transaction (TW_Transaction_create expects flat array)
    unsigned char* txn_recipients_flat = malloc(PUBKEY_SIZE * total_recipients);
    if (!txn_recipients_flat) {
        free(txn_recipients);
        free_encrypted_payload(encrypted_payload);
        return NULL;
    }
    
    // Copy all recipients to flat array for transaction
    for (uint32_t i = 0; i < keys->node_count; i++) {
        memcpy(txn_recipients_flat + (i * PUBKEY_SIZE), keys->node_public_keys[i], PUBKEY_SIZE);
    }
    for (uint32_t i = 0; i < keys->user_count; i++) {
        memcpy(txn_recipients_flat + ((keys->node_count + i) * PUBKEY_SIZE), keys->user_public_keys[i], PUBKEY_SIZE);
    }

    TW_Transaction* txn = TW_Transaction_create(
        TW_TXN_USER_REGISTRATION,
        creator_pubkey,
        txn_recipients_flat,
        total_recipients,
        NULL,
        encrypted_payload,
        NULL
    );
    
    if (txn) {
        TW_Transaction_add_signature(txn);
    } else {
        free_encrypted_payload(encrypted_payload);
    }
    
    free(txn_recipients);
    free(txn_recipients_flat);
    return txn;
}

// Note: Role assignment is now handled within user registration transactions
// The create_role_assignment_transaction function has been removed since roles
// are assigned as part of the user registration process

TW_Transaction* create_peer_registration_transaction(const PeerInfo* peers, uint32_t peer_index, const unsigned char* creator_pubkey, const GeneratedKeys* keys) {
    if (!peers || !creator_pubkey || !keys) return NULL;

    // Create a simple peer registration transaction
    // For now, we'll use a system config transaction to register the peer
    TW_TXN_SystemConfig peer_data;
    memset(&peer_data, 0, sizeof(peer_data));
    peer_data.config_type = 1;  // Peer registration
    peer_data.config_value = peer_index;
    peer_data.config_scope = SCOPE_ORGANIZATION;

    unsigned char* serialized_buffer = NULL;
    int serialized_size = serialize_system_config(&peer_data, &serialized_buffer);
    if (serialized_size < 0 || !serialized_buffer) {
        return NULL;
    }

    // Create flat array of all recipients (nodes + users)
    uint32_t total_recipients;
    unsigned char* all_recipients_flat = create_all_recipients_flat(keys, &total_recipients);
    if (!all_recipients_flat) {
        free(serialized_buffer);
        return NULL;
    }

    EncryptedPayload* encrypted_payload = encrypt_payload_multi(
        serialized_buffer, 
        serialized_size, 
        all_recipients_flat,
        total_recipients
    );
    free(serialized_buffer);
    free(all_recipients_flat);
    if (!encrypted_payload) {
        return NULL;
    }

    // Create flat array for transaction (TW_Transaction_create expects flat array)
    unsigned char* txn_recipients_flat = malloc(PUBKEY_SIZE * total_recipients);
    if (!txn_recipients_flat) {
        free_encrypted_payload(encrypted_payload);
        return NULL;
    }
    
    // Copy all recipients to flat array for transaction
    for (uint32_t i = 0; i < keys->node_count; i++) {
        memcpy(txn_recipients_flat + (i * PUBKEY_SIZE), keys->node_public_keys[i], PUBKEY_SIZE);
    }
    for (uint32_t i = 0; i < keys->user_count; i++) {
        memcpy(txn_recipients_flat + ((keys->node_count + i) * PUBKEY_SIZE), keys->user_public_keys[i], PUBKEY_SIZE);
    }

    TW_Transaction* txn = TW_Transaction_create(
        TW_TXN_SYSTEM_CONFIG,
        creator_pubkey,
        txn_recipients_flat,
        total_recipients,
        NULL,
        encrypted_payload,
        NULL
    );
    
    if (txn) {
        TW_Transaction_add_signature(txn);
    } else {
        free_encrypted_payload(encrypted_payload);
    }
    
    free(txn_recipients_flat);
    return txn;
}

TW_Transaction* create_system_config_transaction(const unsigned char* creator_pubkey, const GeneratedKeys* keys) {
    if (!creator_pubkey || !keys) return NULL;

    TW_TXN_SystemConfig config_data;
    memset(&config_data, 0, sizeof(config_data));
    config_data.config_type = 0;  // Network settings
    config_data.config_value = 1; // Enable basic features
    config_data.config_scope = SCOPE_ORGANIZATION;

    unsigned char* serialized_buffer = NULL;
    int serialized_size = serialize_system_config(&config_data, &serialized_buffer);
    if (serialized_size < 0 || !serialized_buffer) {
        return NULL;
    }

    // Create flat array of all recipients (nodes + users)
    uint32_t total_recipients;
    unsigned char* all_recipients_flat = create_all_recipients_flat(keys, &total_recipients);
    if (!all_recipients_flat) {
        free(serialized_buffer);
        return NULL;
    }

    EncryptedPayload* encrypted_payload = encrypt_payload_multi(
        serialized_buffer, 
        serialized_size, 
        all_recipients_flat,
        total_recipients
    );
    free(serialized_buffer);
    free(all_recipients_flat);
    if (!encrypted_payload) {
        return NULL;
    }

    // Create flat array for transaction (TW_Transaction_create expects flat array)
    unsigned char* txn_recipients_flat = malloc(PUBKEY_SIZE * total_recipients);
    if (!txn_recipients_flat) {
        free_encrypted_payload(encrypted_payload);
        return NULL;
    }
    
    // Copy all recipients to flat array for transaction
    for (uint32_t i = 0; i < keys->node_count; i++) {
        memcpy(txn_recipients_flat + (i * PUBKEY_SIZE), keys->node_public_keys[i], PUBKEY_SIZE);
    }
    for (uint32_t i = 0; i < keys->user_count; i++) {
        memcpy(txn_recipients_flat + ((keys->node_count + i) * PUBKEY_SIZE), keys->user_public_keys[i], PUBKEY_SIZE);
    }

    TW_Transaction* txn = TW_Transaction_create(
        TW_TXN_SYSTEM_CONFIG,
        creator_pubkey,
        txn_recipients_flat,
        total_recipients,
        NULL,
        encrypted_payload,
        NULL
    );
    
    if (txn) {
        TW_Transaction_add_signature(txn);
    } else {
        free_encrypted_payload(encrypted_payload);
    }
    
    free(txn_recipients_flat);
    return txn;
}

TW_Transaction* create_content_filter_transaction(const unsigned char* creator_pubkey, const GeneratedKeys* keys) {
    if (!creator_pubkey || !keys) return NULL;

    TW_TXN_ContentFilter filter_data;
    memset(&filter_data, 0, sizeof(filter_data));
    strncpy(filter_data.rule, "default_safety_rules", MAX_CONTENT_FILTER_RULE_LENGTH - 1);
    filter_data.rule_type = 0;    // Block
    filter_data.rule_action = 1;  // Notify admin
    filter_data.target_scope = SCOPE_ORGANIZATION;

    unsigned char* serialized_buffer = NULL;
    int serialized_size = serialize_content_filter(&filter_data, &serialized_buffer);
    if (serialized_size < 0 || !serialized_buffer) {
        return NULL;
    }

    // Create flat array of all recipients (nodes + users)
    uint32_t total_recipients;
    unsigned char* all_recipients_flat = create_all_recipients_flat(keys, &total_recipients);
    if (!all_recipients_flat) {
        free(serialized_buffer);
        return NULL;
    }

    EncryptedPayload* encrypted_payload = encrypt_payload_multi(
        serialized_buffer, 
        serialized_size, 
        all_recipients_flat,
        total_recipients
    );
    free(serialized_buffer);
    free(all_recipients_flat);
    if (!encrypted_payload) {
        return NULL;
    }

    // Create flat array for transaction (TW_Transaction_create expects flat array)
    unsigned char* txn_recipients_flat = malloc(PUBKEY_SIZE * total_recipients);
    if (!txn_recipients_flat) {
        free_encrypted_payload(encrypted_payload);
        return NULL;
    }
    
    // Copy all recipients to flat array for transaction
    for (uint32_t i = 0; i < keys->node_count; i++) {
        memcpy(txn_recipients_flat + (i * PUBKEY_SIZE), keys->node_public_keys[i], PUBKEY_SIZE);
    }
    for (uint32_t i = 0; i < keys->user_count; i++) {
        memcpy(txn_recipients_flat + ((keys->node_count + i) * PUBKEY_SIZE), keys->user_public_keys[i], PUBKEY_SIZE);
    }

    TW_Transaction* txn = TW_Transaction_create(
        TW_TXN_CONTENT_FILTER,
        creator_pubkey,
        txn_recipients_flat,
        total_recipients,
        NULL,
        encrypted_payload,
        NULL
    );
    
    if (txn) {
        TW_Transaction_add_signature(txn);
    } else {
        free_encrypted_payload(encrypted_payload);
    }
    
    free(txn_recipients_flat);
    return txn;
} 