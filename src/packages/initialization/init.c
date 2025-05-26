#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "init.h"
#include "packages/keystore/keystore.h"
#include "packages/structures/blockChain/blockchain.h"
#include "packages/signing/signing.h"
#include "packages/fileIO/blockchainIO.h"
#include "packages/structures/blockChain/transaction_types.h"
#include "structs/permission/permission.h"

// Main initialization function
int initialize_network(const InitConfig* config) {
    if (!config) return -1;

    // Initialize all pointers to NULL for proper cleanup
    GeneratedKeys keys = {0};
    TW_BlockChain* blockchain = NULL;
    PeerInfo* peers = NULL;

    // 1. Generate keys
    if (generate_initial_keys(&keys, config) != 0) {
        fprintf(stderr, "Error: Failed to generate initial keys\n");
        return -1;
    }

    // 2. Save keys to keystore
    if (save_keys_to_keystore(&keys, config->keystore_path, config->passphrase) != 0) {
        fprintf(stderr, "Error: Failed to save keys to keystore\n");
        free_generated_keys(&keys);
        return -1;
    }

    // 3. Create blockchain
    blockchain = TW_BlockChain_create(keys.node_public_keys[0], NULL, 0);
    if (!blockchain) {
        fprintf(stderr, "Error: Failed to create blockchain\n");
        free_generated_keys(&keys);
        return -1;
    }

    // 4. Generate peer list
    peers = malloc(sizeof(PeerInfo) * config->node_count);
    if (!peers) {
        fprintf(stderr, "Error: Failed to allocate peer list\n");
        free_generated_keys(&keys);
        TW_BlockChain_destroy(blockchain);
        return -1;
    }

    if (generate_peer_list(peers, &keys, config->base_port) != 0) {
        fprintf(stderr, "Error: Failed to generate peer list\n");
        free(peers);
        free_generated_keys(&keys);
        TW_BlockChain_destroy(blockchain);
        return -1;
    }

    // 5. Create peer transactions
    if (create_peer_transactions(peers, blockchain) != 0) {
        fprintf(stderr, "Error: Failed to create peer transactions\n");
        free(peers);
        free_generated_keys(&keys);
        TW_BlockChain_destroy(blockchain);
        return -1;
    }

    // 6. Setup permissions
    if (setup_initial_permissions(&keys, blockchain) != 0) {
        fprintf(stderr, "Error: Failed to setup initial permissions\n");
        free(peers);
        free_generated_keys(&keys);
        TW_BlockChain_destroy(blockchain);
        return -1;
    }

    // 8. Setup network parameters
    if (setup_network_parameters(blockchain) != 0) {
        fprintf(stderr, "Error: Failed to setup network parameters\n");
        free(peers);
        free_generated_keys(&keys);
        TW_BlockChain_destroy(blockchain);
        return -1;
    }

    // Save the initialized blockchain
    if (!saveBlockChainToFile(blockchain)) {
        fprintf(stderr, "Error: Failed to save blockchain\n");
        free(peers);
        free_generated_keys(&keys);
        TW_BlockChain_destroy(blockchain);
        return -1;
    }

    // Save blockchain as JSON for human readability
    if (!writeBlockChainToJson(blockchain)) {
        fprintf(stderr, "Warning: Failed to save blockchain as JSON\n");
        // Don't return error here as the main blockchain file was saved successfully
    }

    // Cleanup
    free(peers);
    free_generated_keys(&keys);
    TW_BlockChain_destroy(blockchain);

    return 0;
}

// Key generation functions
int generate_initial_keys(GeneratedKeys* keys, const InitConfig* config) {
    if (!keys || !config) return -1;
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
        if (!keystore_generate_keypair()) {
            free_generated_keys(keys);
            return -1;
        }
        if (!keystore_get_encryption_public_key(keys->node_public_keys[i]) || !_keystore_get_private_key(keys->node_private_keys[i])) {
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
        if (!keystore_generate_keypair()) {
            free_generated_keys(keys);
            return -1;
        }
        if (!keystore_get_encryption_public_key(keys->user_public_keys[i]) || !_keystore_get_private_key(keys->user_private_keys[i])) {
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
        snprintf(node_key_path, sizeof(node_key_path), "%s/node_%u_key.bin", keystore_path, i);
        FILE* f = fopen(node_key_path, "wb");
        if (!f) return -1;
        fwrite(keys->node_private_keys[i], 1, SIGN_SECRET_SIZE, f);
        fclose(f);
    }
    // Save user keys
    for (uint32_t i = 0; i < keys->user_count; i++) {
        char user_key_path[256];
        snprintf(user_key_path, sizeof(user_key_path), "%s/user_%u_key.bin", keystore_path, i);
        FILE* f = fopen(user_key_path, "wb");
        if (!f) return -1;
        fwrite(keys->user_private_keys[i], 1, SIGN_SECRET_SIZE, f);
        fclose(f);
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

int create_peer_transactions(const PeerInfo* peers, TW_BlockChain* blockchain) {
    if (!peers || !blockchain) return -1;

    // TODO: Create and add transactions for each peer
    // This will depend on your transaction structure and blockchain implementation
    // For now, we'll just return success
    return 0;
}

// Permission setup functions
int setup_initial_permissions(const GeneratedKeys* keys, TW_BlockChain* blockchain) {
    if (!keys || !blockchain) return -1;

    // Create role assignment transactions for each user
    for (uint32_t i = 0; i < keys->user_count; i++) {
        TW_TXN_RoleAssignment role_data;
        memset(&role_data, 0, sizeof(role_data));
        uint64_t permissions = 0;

        if (i == 0) {
            strncpy(role_data.role_name, "parent", MAX_ROLE_NAME_LENGTH - 1);
            permissions = ROLE_PERMISSIONS_PARENT;
        } else {
            strncpy(role_data.role_name, "child", MAX_ROLE_NAME_LENGTH - 1);
            permissions = ROLE_PERMISSIONS_CHILD;
        }
        role_data.permissions = permissions;

        unsigned char* serialized_role_buffer = NULL;
        int serialized_role_size = serialize_role_assignment(&role_data, &serialized_role_buffer);
        if (serialized_role_size < 0 || !serialized_role_buffer) {
            return -1; 
        }

        // Encrypt the serialized role data
        EncryptedPayload* encrypted_payload = encrypt_payload_multi(
            serialized_role_buffer, 
            serialized_role_size, 
            keys->user_public_keys[i], // Sender is the user
            1                          // Only one recipient (the user themselves for now)
        );
        free(serialized_role_buffer); // Free the temporary buffer
        if (!encrypted_payload) {
            return -1;
        }

        TW_Transaction* txn = TW_Transaction_create(
            TW_TXN_ROLE_ASSIGNMENT,
            keys->user_public_keys[i],      // Sender is the user
            keys->user_public_keys[i],      // Recipient is the user (for role assignment)
            1,
            NULL,                           // No group for role assignment
            encrypted_payload,              // Assign the encrypted payload
            NULL                            // Signature will be added later
        );
        
        if (!txn) {
            free_encrypted_payload(encrypted_payload);
            return -1;
        }
        // NOTE: TW_Transaction_create now takes ownership of encrypted_payload if successful,
        // so no need to free it separately if txn is created.

        TW_Transaction_add_signature(txn);

        // Since TW_BlockChain_add_transaction doesn't exist and we don't want it,
        // we'll just destroy the transaction for now to avoid memory leaks
        // TODO: Implement proper block-based transaction handling
        TW_Transaction_destroy(txn);
    }

    return 0;
}

int create_permission_transactions(TW_BlockChain* blockchain) {
    if (!blockchain) return -1;

    // Create initial system configuration transaction
    TW_TXN_SystemConfig config_data;
    memset(&config_data, 0, sizeof(config_data));
    config_data.config_type = 0;  // Network settings
    config_data.config_value = 1; // Enable basic features

    unsigned char* serialized_config_buffer = NULL;
    int serialized_config_size = serialize_system_config(&config_data, &serialized_config_buffer);
    if (serialized_config_size < 0 || !serialized_config_buffer) {
        return -1;
    }

    EncryptedPayload* encrypted_config_payload = encrypt_payload_multi(
        serialized_config_buffer, 
        serialized_config_size, 
        blockchain->creator_pubkey, // Sender is the blockchain creator
        1                           // Recipient is the blockchain creator (or a system key)
    );
    free(serialized_config_buffer);
    if (!encrypted_config_payload) {
        return -1;
    }

    TW_Transaction* txn_config = TW_Transaction_create(
        TW_TXN_SYSTEM_CONFIG,
        blockchain->creator_pubkey,      // Sender
        blockchain->creator_pubkey,      // Recipient
        1,
        NULL,                           // No group
        encrypted_config_payload,
        NULL                            // Signature
    );
    if (!txn_config) {
        free_encrypted_payload(encrypted_config_payload);
        return -1;
    }
    TW_Transaction_add_signature(txn_config);
    // TODO: Add transaction to a block instead of directly to blockchain
    TW_Transaction_destroy(txn_config);

    // Create initial content filter transaction
    TW_TXN_ContentFilter filter_data;
    memset(&filter_data, 0, sizeof(filter_data));
    strncpy(filter_data.rule, "default_safety_rules", MAX_CONTENT_FILTER_RULE_LENGTH - 1);
    filter_data.rule_type = 0;    // Block
    filter_data.rule_action = 1;  // Notify parent

    unsigned char* serialized_filter_buffer = NULL;
    int serialized_filter_size = serialize_content_filter(&filter_data, &serialized_filter_buffer);
    if (serialized_filter_size < 0 || !serialized_filter_buffer) {
        return -1;
    }

    EncryptedPayload* encrypted_filter_payload = encrypt_payload_multi(
        serialized_filter_buffer, 
        serialized_filter_size, 
        blockchain->creator_pubkey, // Sender
        1                           // Recipient
    );
    free(serialized_filter_buffer);
    if (!encrypted_filter_payload) {
        return -1;
    }

    TW_Transaction* txn_filter = TW_Transaction_create(
        TW_TXN_CONTENT_FILTER,
        blockchain->creator_pubkey,      // Sender
        blockchain->creator_pubkey,      // Recipient
        1,
        NULL,                           // No group
        encrypted_filter_payload,
        NULL                            // Signature
    );
    if (!txn_filter) {
        free_encrypted_payload(encrypted_filter_payload);
        return -1;
    }
    TW_Transaction_add_signature(txn_filter);
    // TODO: Add transaction to a block instead of directly to blockchain
    TW_Transaction_destroy(txn_filter);

    return 0;
}

// Helper functions
/*
int create_genesis_block(TW_BlockChain* blockchain) {
    if (!blockchain) return -1;
    
    // Get the creator's public key from the blockchain
    TW_BlockChain_create_genesis_block(blockchain, blockchain->creator_pubkey);
    
    // Verify that the genesis block was created
    if (blockchain->length == 0 || !blockchain->blocks[0]) {
        return -1;
    }
    
    return 0;
}
*/

int setup_network_parameters(TW_BlockChain* blockchain) {
    if (!blockchain) return -1;

    // TODO: Setup network parameters
    // This will depend on your blockchain implementation
    // For now, we'll just return success
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