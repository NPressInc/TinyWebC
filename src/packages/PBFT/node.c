#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include "node.h"
#include "packages/signing/signing.h"
#include "packages/structures/blockChain/blockchain.h"
#include "packages/structures/blockChain/block.h"
#include "packages/fileIO/blockchainIO.h"
#include "packages/keystore/keystore.h"
#include "packages/encryption/encryption.h"

// Speed modifier in microseconds (1 second = 1000000 microseconds)
#define SPEED_MODIFIER 1000000
#define KEYSTORE_PATH "state/keys/node_private.key" // Legacy path for backward compatibility
#define KEYSTORE_PASSPHRASE "testpass"  // TODO: Make this configurable

// Global node state
static NodeState node_state;

// Node state management functions
void node_state_init(void) {
    memset(&node_state, 0, sizeof(NodeState));
}

void node_state_cleanup(void) {
    if (node_state.blockchain) {
        TW_BlockChain_destroy(node_state.blockchain);
        node_state.blockchain = NULL;
    }
}

void runNode(void) {
    // Initialize node state
    printf("Starting PBFT node...\n");
    node_state_init();

    // Initialize keystore
    if (!keystore_init()) {
        printf("Error: Failed to initialize keystore\n");
        return;
    }

    // Load keypair from keystore
    if (!keystore_load_private_key(KEYSTORE_PATH, KEYSTORE_PASSPHRASE)) {
        printf("Error: Failed to load keypair from %s\n", KEYSTORE_PATH);
        return;
    }
    printf("Successfully loaded keypair\n");

    // Get signing public key for blockchain
    unsigned char signing_pubkey[PUBKEY_SIZE];
    if (!keystore_get_public_key(signing_pubkey)) {
        printf("Error: Failed to get public key\n");
        keystore_cleanup();
        return;
    }
    memcpy(node_state.public_key, signing_pubkey, PUBKEY_SIZE);

    // Load or create blockchain
    node_state.blockchain = readBlockChainFromFile();
    if (!node_state.blockchain) {
        printf("No existing blockchain found, creating new one...\n");
        node_state.blockchain = TW_BlockChain_create(signing_pubkey, NULL, 0);
        if (!node_state.blockchain) {
            printf("Error: Failed to create new blockchain\n");
            node_state_cleanup();
            keystore_cleanup();
            return;
        }
        
        // Create genesis block with our signing public key
        TW_BlockChain_create_genesis_block(node_state.blockchain, signing_pubkey);
        
        // Save the new blockchain
        if (!saveBlockChainToFile(node_state.blockchain)) {
            printf("Error: Failed to save new blockchain\n");
            node_state_cleanup();
            keystore_cleanup();
            return;
        }
        printf("Successfully created and saved new blockchain\n");
    } else {
        printf("Successfully loaded existing blockchain\n");
    }

    // TODO: Implement remaining node logic
    // 3. Set up network connections
    // 4. Start consensus protocol
    // 5. Handle incoming messages
    // 6. Process transactions
    // 7. Participate in block creation

    printf("PBFT node running...\n");

    // Main node loop
    while (1) {
        // TODO: Add node operations here
        // - Check for new messages
        // - Process pending transactions
        // - Participate in consensus
        // - Update blockchain state

        // Sleep for SPEED_MODIFIER microseconds
        usleep(SPEED_MODIFIER);
    }

    // Cleanup (though we never reach here due to infinite loop)
    node_state_cleanup();
    keystore_cleanup();
}


// Peer management functions
int node_add_peer(const unsigned char* public_key, const char* ip, uint32_t id) {
    if (!public_key || !ip) {
        return 0; // Invalid parameters
    }
    
    if (node_state.peer_count >= MAX_PEERS) {
        return 0; // Peer list is full
    }
    
    // Check if peer already exists (by ID or public key)
    for (size_t i = 0; i < node_state.peer_count; i++) {
        if (node_state.peers[i].id == id || 
            memcmp(node_state.peers[i].public_key, public_key, PUBKEY_SIZE) == 0) {
            return 0; // Peer already exists
        }
    }
    
    // Add to peers array
    PeerInfo* peer = &node_state.peers[node_state.peer_count];
    memcpy(peer->public_key, public_key, PUBKEY_SIZE);
    strncpy(peer->ip, ip, sizeof(peer->ip) - 1);
    peer->ip[sizeof(peer->ip) - 1] = '\0'; // Ensure null termination
    peer->id = id;
    peer->is_delinquent = 0;
    peer->delinquent_count = 0;
    peer->last_seen = time(NULL);
    
    // Add to ID-IP map
    node_state.id_ip_map[node_state.id_ip_count].id = id;
    strncpy(node_state.id_ip_map[node_state.id_ip_count].ip, ip, sizeof(node_state.id_ip_map[0].ip) - 1);
    node_state.id_ip_map[node_state.id_ip_count].ip[sizeof(node_state.id_ip_map[0].ip) - 1] = '\0';
    node_state.id_ip_count++;

    // Add to public key-IP map
    memcpy(node_state.pkey_ip_map[node_state.pkey_ip_count].public_key, public_key, PUBKEY_SIZE);
    strncpy(node_state.pkey_ip_map[node_state.pkey_ip_count].ip, ip, sizeof(node_state.pkey_ip_map[0].ip) - 1);
    node_state.pkey_ip_map[node_state.pkey_ip_count].ip[sizeof(node_state.pkey_ip_map[0].ip) - 1] = '\0';
    node_state.pkey_ip_count++;
    
    // Add to public key-ID map
    memcpy(node_state.pkey_id_map[node_state.pkey_id_count].public_key, public_key, PUBKEY_SIZE);
    node_state.pkey_id_map[node_state.pkey_id_count].id = id;
    node_state.pkey_id_count++;
    
    // Update peer count
    node_state.peer_count++;
    
    return 1; // Success
}

int node_remove_peer(uint32_t id) {
    // Find the peer to remove
    size_t peer_index = SIZE_MAX;
    for (size_t i = 0; i < node_state.peer_count; i++) {
        if (node_state.peers[i].id == id) {
            peer_index = i;
            break;
        }
    }
    
    if (peer_index == SIZE_MAX) {
        return 0; // Peer not found
    }
    
    // Get the public key before removing the peer
    unsigned char public_key[PUBKEY_SIZE];
    memcpy(public_key, node_state.peers[peer_index].public_key, PUBKEY_SIZE);
    
    // Remove from peers array by shifting remaining elements
    for (size_t i = peer_index; i < node_state.peer_count - 1; i++) {
        node_state.peers[i] = node_state.peers[i + 1];
    }
    node_state.peer_count--;
    
    // Remove from ID-IP map
    for (size_t i = 0; i < node_state.id_ip_count; i++) {
        if (node_state.id_ip_map[i].id == id) {
            // Shift remaining elements
            for (size_t j = i; j < node_state.id_ip_count - 1; j++) {
                node_state.id_ip_map[j] = node_state.id_ip_map[j + 1];
            }
            node_state.id_ip_count--;
            break;
        }
    }
    
    // Remove from public key-IP map
    for (size_t i = 0; i < node_state.pkey_ip_count; i++) {
        if (memcmp(node_state.pkey_ip_map[i].public_key, public_key, PUBKEY_SIZE) == 0) {
            // Shift remaining elements
            for (size_t j = i; j < node_state.pkey_ip_count - 1; j++) {
                node_state.pkey_ip_map[j] = node_state.pkey_ip_map[j + 1];
            }
            node_state.pkey_ip_count--;
            break;
        }
    }
    
    // Remove from public key-ID map
    for (size_t i = 0; i < node_state.pkey_id_count; i++) {
        if (memcmp(node_state.pkey_id_map[i].public_key, public_key, PUBKEY_SIZE) == 0) {
            // Shift remaining elements
            for (size_t j = i; j < node_state.pkey_id_count - 1; j++) {
                node_state.pkey_id_map[j] = node_state.pkey_id_map[j + 1];
            }
            node_state.pkey_id_count--;
            break;
        }
    }
    
    return 1; // Success
}

int node_mark_peer_delinquent(uint32_t id) {
    for (size_t i = 0; i < node_state.peer_count; i++) {
        if (node_state.peers[i].id == id) {
            node_state.peers[i].delinquent_count++;
            
            // Mark as delinquent if threshold exceeded (15 failures as per requirements)
            if (node_state.peers[i].delinquent_count >= 15) {
                node_state.peers[i].is_delinquent = 1;
            }
            
            return 1; // Successfully marked peer as delinquent
        }
    }
    return 0; // Peer not found
}

int node_reset_peer_delinquent(uint32_t id) {
    for (size_t i = 0; i < node_state.peer_count; i++) {
        if (node_state.peers[i].id == id) {
            node_state.peers[i].delinquent_count = 0;
            node_state.peers[i].is_delinquent = 0;
            node_state.peers[i].last_seen = time(NULL);
            return 1; // Successfully reset peer delinquent status
        }
    }
    return 0; // Peer not found
}

int node_get_peer_info(uint32_t id, PeerInfo* info) {
    if (!info) {
        return 0; // Invalid parameter
    }
    
    for (size_t i = 0; i < node_state.peer_count; i++) {
        if (node_state.peers[i].id == id) {
            memcpy(info, &node_state.peers[i], sizeof(PeerInfo));
            return 1;
        }
    }
    return 0;
}

size_t node_get_peer_count(void) {
    return node_state.peer_count;
}

size_t node_get_active_peer_count(void) {
    size_t active_count = 0;
    for (size_t i = 0; i < node_state.peer_count; i++) {
        if (!node_state.peers[i].is_delinquent) {
            active_count++;
        }
    }
    return active_count;
}

// Peer lookup functions
const char* node_get_ip_by_id(uint32_t id) {
    for (size_t i = 0; i < node_state.id_ip_count; i++) {
        if (node_state.id_ip_map[i].id == id) {
            return node_state.id_ip_map[i].ip;
        }
    }
    return NULL;
}

const char* node_get_ip_by_pubkey(const unsigned char* public_key) {
    for (size_t i = 0; i < node_state.pkey_ip_count; i++) {
        if (memcmp(node_state.pkey_ip_map[i].public_key, public_key, PUBKEY_SIZE) == 0) {
            return node_state.pkey_ip_map[i].ip;
        }
    }
    return NULL;
}

uint32_t node_get_id_by_pubkey(const unsigned char* public_key) {
    for (size_t i = 0; i < node_state.pkey_id_count; i++) {
        if (memcmp(node_state.pkey_id_map[i].public_key, public_key, PUBKEY_SIZE) == 0) {
            return node_state.pkey_id_map[i].id;
        }
    }
    return 0;
}

// Consensus functions
void node_set_proposer_id(uint32_t id) {
    node_state.proposer_id = id;
}

uint32_t node_get_proposer_id(void) {
    return node_state.proposer_id;
}

void node_set_proposer_offset(uint32_t offset) {
    node_state.proposer_offset = offset;
}

uint32_t node_get_proposer_offset(void) {
    return node_state.proposer_offset;
}
