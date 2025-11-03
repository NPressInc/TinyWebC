#ifndef NODE_H
#define NODE_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include "features/blockchain/core/blockchain.h"

// Constants
#define MAX_PEERS 100
#define MAX_IP_LEN 50  // Enough for IPv6:port (39 + 1 + 5 + null terminator)

// Structure to hold peer information
typedef struct {
    unsigned char public_key[PUBKEY_SIZE];
    char ip[MAX_IP_LEN]; 
    uint32_t id;  // Node ID (proposer order)
    int is_delinquent;  // Flag for delinquent status
    uint32_t delinquent_count;  // Counter for delinquent failures
    time_t last_seen;
} PeerInfo;

// Structure to hold node state
typedef struct {
    // Node identity
    unsigned char private_key[SECRET_SIZE];
    unsigned char public_key[PUBKEY_SIZE];
    uint32_t id;  // Node ID (proposer order)
    
    // Peer management
    PeerInfo peers[MAX_PEERS];
    size_t peer_count;
    
    // Peer lookup tables
    struct {
        uint32_t id;
        char ip[MAX_IP_LEN];
    } id_ip_map[MAX_PEERS];
    size_t id_ip_count;
    
    struct {
        unsigned char public_key[PUBKEY_SIZE];
        char ip[MAX_IP_LEN];
    } pkey_ip_map[MAX_PEERS];
    size_t pkey_ip_count;
    
    struct {
        unsigned char public_key[PUBKEY_SIZE];
        uint32_t id;
    } pkey_id_map[MAX_PEERS];
    size_t pkey_id_count;
    
    // Consensus state
    uint32_t proposer_id;
    uint32_t proposer_offset;
    
    // Blockchain
    TW_BlockChain* blockchain;
} NodeState;

// Node state management functions
void node_state_init(void);
void node_state_cleanup(void);

// Peer management functions
int node_add_peer(const unsigned char* public_key, const char* ip_port, uint32_t id);
int node_remove_peer(uint32_t id);
int node_mark_peer_delinquent(uint32_t id);
int node_reset_peer_delinquent(uint32_t id);
int node_get_peer_info(uint32_t id, PeerInfo* info);
size_t node_get_peer_count(void);
size_t node_get_active_peer_count(void);

// Peer lookup functions
const char* node_get_ip_by_id(uint32_t id);
const char* node_get_ip_by_pubkey(const unsigned char* public_key);
uint32_t node_get_id_by_pubkey(const unsigned char* public_key);

// (Removed unused consensus accessor declarations)

#endif // NODE_H
