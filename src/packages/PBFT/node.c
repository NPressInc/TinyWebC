#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "node.h"
#include "packages/signing/signing.h"
#include "packages/structures/blockChain/blockchain.h"
#include "packages/structures/blockChain/block.h"
#include "packages/fileIO/blockchainIO.h"
#include "packages/keystore/keystore.h"

// Speed modifier in microseconds (1 second = 1000000 microseconds)
#define SPEED_MODIFIER 1000000
#define KEYSTORE_PATH "state/keys/node_key.bin"
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

// Peer management functions
int node_add_peer(const unsigned char* public_key, const char* ip, uint32_t id) {
    if (node_state.peer_count >= MAX_PEERS) return 0;
    
    // Add to peers array
    PeerInfo* peer = &node_state.peers[node_state.peer_count];
    memcpy(peer->public_key, public_key, PUBKEY_SIZE);
    strncpy(peer->ip, ip, sizeof(peer->ip) - 1);
    peer->id = id;
    peer->is_delinquent = 0;
    
    // Add to lookup tables
    node_state.id_ip_map[node_state.id_ip_count].id = id;
    strncpy(node_state.id_ip_map[node_state.id_ip_count].ip, ip, sizeof(node_state.id_ip_map[0].ip) - 1);
    
    memcpy(node_state.pkey_ip_map[node_state.pkey_ip_count].public_key, public_key, PUBKEY_SIZE);
    strncpy(node_state.pkey_ip_map[node_state.pkey_ip_count].ip, ip, sizeof(node_state.pkey_ip_map[0].ip) - 1);
    
    memcpy(node_state.pkey_id_map[node_state.pkey_id_count].public_key, public_key, PUBKEY_SIZE);
    node_state.pkey_id_map[node_state.pkey_id_count].id = id;
    
    // Update counts
    node_state.peer_count++;
    node_state.id_ip_count++;
    node_state.pkey_ip_count++;
    node_state.pkey_id_count++;
    
    return 1;
}

int node_remove_peer(uint32_t id) {
    // TODO: Implement peer removal
    return 0;
}

int node_mark_peer_delinquent(uint32_t id) {
    for (size_t i = 0; i < node_state.peer_count; i++) {
        if (node_state.peers[i].id == id) {
            node_state.peers[i].is_delinquent = 1;
            return 1;
        }
    }
    return 0;
}

int node_get_peer_info(uint32_t id, PeerInfo* info) {
    for (size_t i = 0; i < node_state.peer_count; i++) {
        if (node_state.peers[i].id == id) {
            memcpy(info, &node_state.peers[i], sizeof(PeerInfo));
            return 1;
        }
    }
    return 0;
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
    keystore_get_signing_public_key(signing_pubkey);
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
