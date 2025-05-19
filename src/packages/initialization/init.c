#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "init.h"
#include "packages/keystore/keystore.h"
#include "packages/structures/blockChain/blockchain.h"
#include "packages/signing/signing.h"
#include "packages/fileIO/blockchainIO.h"

// Main initialization function
int initialize_network(const InitConfig* config) {
    if (!config) return -1;

    // 1. Generate keys
    GeneratedKeys keys;
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
    TW_BlockChain* blockchain = TW_BlockChain_create(keys.node_public_keys[0], NULL, 0);
    if (!blockchain) {
        fprintf(stderr, "Error: Failed to create blockchain\n");
        free_generated_keys(&keys);
        return -1;
    }

    // 4. Generate peer list
    PeerInfo* peers = malloc(sizeof(PeerInfo) * config->node_count);
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

    // 7. Create genesis block
    if (create_genesis_block(blockchain) != 0) {
        fprintf(stderr, "Error: Failed to create genesis block\n");
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
        keys->node_private_keys[i] = malloc(SECRET_SIZE);
        keys->node_public_keys[i] = malloc(PUBKEY_SIZE);
        if (!keys->node_private_keys[i] || !keys->node_public_keys[i]) {
            free_generated_keys(keys);
            return -1;
        }
        if (!keystore_generate_keypair()) {
            free_generated_keys(keys);
            return -1;
        }
        if (!keystore_get_public_key(keys->node_public_keys[i]) || !_keystore_get_private_key(keys->node_private_keys[i])) {
            free_generated_keys(keys);
            return -1;
        }
    }
    for (uint32_t i = 0; i < keys->user_count; i++) {
        keys->user_private_keys[i] = malloc(SECRET_SIZE);
        keys->user_public_keys[i] = malloc(PUBKEY_SIZE);
        if (!keys->user_private_keys[i] || !keys->user_public_keys[i]) {
            free_generated_keys(keys);
            return -1;
        }
        if (!keystore_generate_keypair()) {
            free_generated_keys(keys);
            return -1;
        }
        if (!keystore_get_public_key(keys->user_public_keys[i]) || !_keystore_get_private_key(keys->user_private_keys[i])) {
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
        fwrite(keys->node_private_keys[i], 1, SECRET_SIZE, f);
        fclose(f);
    }
    // Save user keys
    for (uint32_t i = 0; i < keys->user_count; i++) {
        char user_key_path[256];
        snprintf(user_key_path, sizeof(user_key_path), "%s/user_%u_key.bin", keystore_path, i);
        FILE* f = fopen(user_key_path, "wb");
        if (!f) return -1;
        fwrite(keys->user_private_keys[i], 1, SECRET_SIZE, f);
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

    // TODO: Setup initial permissions
    // This will depend on your permission system implementation
    // For now, we'll just return success
    return 0;
}

int create_permission_transactions(TW_BlockChain* blockchain) {
    if (!blockchain) return -1;

    // TODO: Create permission transactions
    // This will depend on your transaction structure and blockchain implementation
    // For now, we'll just return success
    return 0;
}

// Helper functions
int create_genesis_block(TW_BlockChain* blockchain) {
    if (!blockchain) return -1;
    TW_BlockChain_create_genesis_block(blockchain, NULL);
    return 0;
}

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