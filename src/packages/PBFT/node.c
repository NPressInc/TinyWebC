#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <stdint.h>
#include "node.h"
// (no additional local includes needed)

// Speed modifier in microseconds (1 second = 1000000 microseconds)
#define SPEED_MODIFIER 1000000

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

// (Removed unused consensus accessor functions)
