#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "init.h"
#include "packages/keystore/keystore.h"
#include "packages/structures/blockChain/blockchain.h"
#include "packages/structures/blockChain/block.h"
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

    // 5. Create initialization block with all setup transactions
    if (create_initialization_block(&keys, peers, blockchain, config) != 0) {
        fprintf(stderr, "Error: Failed to create initialization block\n");
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
    // This function is now replaced by create_peer_registration_transaction
    // which is called from create_initialization_block
    return 0;
}

// Permission setup functions
int setup_initial_permissions(const GeneratedKeys* keys, TW_BlockChain* blockchain) {
    // This function is now replaced by create_role_assignment_transaction
    // which is called from create_initialization_block
    return 0;
}

int create_permission_transactions(TW_BlockChain* blockchain) {
    // This function is now replaced by create_system_config_transaction
    // and create_content_filter_transaction which are called from create_initialization_block
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
    // Network parameters are now set via transactions in create_initialization_block
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

    // Array to collect all initialization transactions
    TW_Transaction** init_transactions = malloc(sizeof(TW_Transaction*) * (keys->user_count * 2 + keys->node_count + 2)); // Users + roles + peers + system
    int txn_count = 0;

    // 1. Create user registration transactions
    printf("Creating user registration transactions...\n");
    for (uint32_t i = 0; i < keys->user_count; i++) {
        TW_Transaction* user_txn = create_user_registration_transaction(keys, i);
        if (user_txn) {
            init_transactions[txn_count++] = user_txn;
            printf("Created user registration transaction for user %u\n", i);
        } else {
            printf("Failed to create user registration transaction for user %u\n", i);
        }
    }

    // 2. Create role assignment transactions
    printf("Creating role assignment transactions...\n");
    for (uint32_t i = 0; i < keys->user_count; i++) {
        TW_Transaction* role_txn = create_role_assignment_transaction(keys, i);
        if (role_txn) {
            init_transactions[txn_count++] = role_txn;
            printf("Created role assignment transaction for user %u\n", i);
        } else {
            printf("Failed to create role assignment transaction for user %u\n", i);
        }
    }

    // 3. Create peer registration transactions
    printf("Creating peer registration transactions...\n");
    for (uint32_t i = 0; i < keys->node_count; i++) {
        TW_Transaction* peer_txn = create_peer_registration_transaction(peers, i, blockchain->creator_pubkey);
        if (peer_txn) {
            init_transactions[txn_count++] = peer_txn;
            printf("Created peer registration transaction for peer %u\n", i);
        } else {
            printf("Failed to create peer registration transaction for peer %u\n", i);
        }
    }

    // 4. Create system configuration transaction
    printf("Creating system configuration transaction...\n");
    TW_Transaction* config_txn = create_system_config_transaction(blockchain->creator_pubkey);
    if (config_txn) {
        init_transactions[txn_count++] = config_txn;
        printf("Created system config transaction\n");
    } else {
        printf("Failed to create system config transaction\n");
    }

    // 5. Create content filter transaction
    printf("Creating content filter transaction...\n");
    TW_Transaction* filter_txn = create_content_filter_transaction(blockchain->creator_pubkey);
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
        TW_Block_getHash(last_block, previous_hash);
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

    // Add the block to the blockchain
    if (TW_BlockChain_add_block(blockchain, init_block) == 0) {
        printf("Failed to add block to blockchain\n");
        TW_Block_destroy(init_block);
        free(init_transactions);
        return -1;
    }

    printf("Block added to blockchain successfully\n");

    free(init_transactions); // The block now owns the transaction pointers
    return 0;
}

// Transaction creation functions
TW_Transaction* create_user_registration_transaction(const GeneratedKeys* keys, uint32_t user_index) {
    if (!keys || user_index >= keys->user_count) return NULL;

    TW_TXN_UserRegistration user_data;
    memset(&user_data, 0, sizeof(user_data));
    
    // Create a simple username based on index
    snprintf(user_data.username, MAX_USERNAME_LENGTH, "user_%u", user_index);
    user_data.age = (user_index == 0) ? 35 : (user_index == 1) ? 32 : (12 + user_index); // Default ages

    unsigned char* serialized_buffer = NULL;
    int serialized_size = serialize_user_registration(&user_data, &serialized_buffer);
    if (serialized_size < 0 || !serialized_buffer) {
        return NULL;
    }

    EncryptedPayload* encrypted_payload = encrypt_payload_multi(
        serialized_buffer, 
        serialized_size, 
        keys->user_public_keys[user_index],
        1
    );
    free(serialized_buffer);
    if (!encrypted_payload) {
        return NULL;
    }

    TW_Transaction* txn = TW_Transaction_create(
        TW_TXN_USER_REGISTRATION,
        keys->user_public_keys[user_index],
        keys->user_public_keys[user_index],
        1,
        NULL,
        encrypted_payload,
        NULL
    );
    
    if (txn) {
        TW_Transaction_add_signature(txn);
    } else {
        free_encrypted_payload(encrypted_payload);
    }
    
    return txn;
}

TW_Transaction* create_role_assignment_transaction(const GeneratedKeys* keys, uint32_t user_index) {
    if (!keys || user_index >= keys->user_count) return NULL;

    TW_TXN_RoleAssignment role_data;
    memset(&role_data, 0, sizeof(role_data));

    if (user_index < 2) {
        // First two users get admin role
        strncpy(role_data.role_name, "admin", MAX_ROLE_NAME_LENGTH - 1);
        role_data.permission_set_count = 4;
        
        memcpy(&role_data.permission_sets[0], &ADMIN_MESSAGING, sizeof(PermissionSet));
        memcpy(&role_data.permission_sets[1], &ADMIN_GROUP_MANAGEMENT, sizeof(PermissionSet));
        memcpy(&role_data.permission_sets[2], &ADMIN_USER_MANAGEMENT, sizeof(PermissionSet));
        memcpy(&role_data.permission_sets[3], &ADMIN_SYSTEM, sizeof(PermissionSet));
    } else {
        // Other users get member role
        strncpy(role_data.role_name, "member", MAX_ROLE_NAME_LENGTH - 1);
        role_data.permission_set_count = 2;
        
        memcpy(&role_data.permission_sets[0], &MEMBER_MESSAGING, sizeof(PermissionSet));
        memcpy(&role_data.permission_sets[1], &MEMBER_BASIC, sizeof(PermissionSet));
    }

    unsigned char* serialized_buffer = NULL;
    int serialized_size = serialize_role_assignment(&role_data, &serialized_buffer);
    if (serialized_size < 0 || !serialized_buffer) {
        return NULL;
    }

    EncryptedPayload* encrypted_payload = encrypt_payload_multi(
        serialized_buffer, 
        serialized_size, 
        keys->user_public_keys[user_index],
        1
    );
    free(serialized_buffer);
    if (!encrypted_payload) {
        return NULL;
    }

    TW_Transaction* txn = TW_Transaction_create(
        TW_TXN_ROLE_ASSIGNMENT,
        keys->user_public_keys[user_index],
        keys->user_public_keys[user_index],
        1,
        NULL,
        encrypted_payload,
        NULL
    );
    
    if (txn) {
        TW_Transaction_add_signature(txn);
    }
    
    return txn;
}

TW_Transaction* create_peer_registration_transaction(const PeerInfo* peers, uint32_t peer_index, const unsigned char* creator_pubkey) {
    if (!peers || !creator_pubkey) return NULL;

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

    EncryptedPayload* encrypted_payload = encrypt_payload_multi(
        serialized_buffer, 
        serialized_size, 
        creator_pubkey,
        1
    );
    free(serialized_buffer);
    if (!encrypted_payload) {
        return NULL;
    }

    TW_Transaction* txn = TW_Transaction_create(
        TW_TXN_SYSTEM_CONFIG,
        creator_pubkey,
        creator_pubkey,
        1,
        NULL,
        encrypted_payload,
        NULL
    );
    
    if (txn) {
        TW_Transaction_add_signature(txn);
    }
    
    return txn;
}

TW_Transaction* create_system_config_transaction(const unsigned char* creator_pubkey) {
    if (!creator_pubkey) return NULL;

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

    EncryptedPayload* encrypted_payload = encrypt_payload_multi(
        serialized_buffer, 
        serialized_size, 
        creator_pubkey,
        1
    );
    free(serialized_buffer);
    if (!encrypted_payload) {
        return NULL;
    }

    TW_Transaction* txn = TW_Transaction_create(
        TW_TXN_SYSTEM_CONFIG,
        creator_pubkey,
        creator_pubkey,
        1,
        NULL,
        encrypted_payload,
        NULL
    );
    
    if (txn) {
        TW_Transaction_add_signature(txn);
    }
    
    return txn;
}

TW_Transaction* create_content_filter_transaction(const unsigned char* creator_pubkey) {
    if (!creator_pubkey) return NULL;

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

    EncryptedPayload* encrypted_payload = encrypt_payload_multi(
        serialized_buffer, 
        serialized_size, 
        creator_pubkey,
        1
    );
    free(serialized_buffer);
    if (!encrypted_payload) {
        return NULL;
    }

    TW_Transaction* txn = TW_Transaction_create(
        TW_TXN_CONTENT_FILTER,
        creator_pubkey,
        creator_pubkey,
        1,
        NULL,
        encrypted_payload,
        NULL
    );
    
    if (txn) {
        TW_Transaction_add_signature(txn);
    }
    
    return txn;
} 