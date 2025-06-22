#ifndef TW_INTERNAL_TRANSACTION_H
#define TW_INTERNAL_TRANSACTION_H

#include <stddef.h>  // For size_t
#include <stdint.h>
#include <stdlib.h>
#include "packages/signing/signing.h"
#include "packages/structures/blockChain/block.h"

#define HASH_SIZE 32
#define MAX_PEERS 100
#define MAX_PAYLOAD_SIZE_INTERNAL 8096
#define MAX_BLOCK_SIZE_INTERNAL 65536
#define MAX_BLOCKCHAIN_HASH_LIST 1000

typedef enum {
    // PBFT Consensus Messages
    TW_INT_TXN_PROPOSE_BLOCK,          // Block proposal from proposer
    TW_INT_TXN_VOTE_VERIFY,            // Verification vote (phase 1)
    TW_INT_TXN_VOTE_COMMIT,            // Commit vote (phase 2)
    TW_INT_TXN_VOTE_NEW_ROUND,         // New round vote (phase 3)
    
    // Blockchain Synchronization
    TW_INT_TXN_GET_LAST_HASH,          // Request last block hash
    TW_INT_TXN_RESYNC_CHAIN,           // Request chain resync
    TW_INT_TXN_GET_PENDING_TXNS,       // Request pending transactions
    TW_INT_TXN_GET_CHAIN_LENGTH,       // Request blockchain length
    TW_INT_TXN_REQ_MISSING_BLOCKS,     // Request missing blocks
    TW_INT_TXN_REQ_FULL_CHAIN,         // Request entire blockchain
    
    // Broadcasting and Communication
    TW_INT_TXN_BROADCAST_BLOCK,        // Broadcast block to peers
    TW_INT_TXN_BROADCAST_CHAIN,        // Broadcast chain to new node
    TW_INT_TXN_REBROADCAST_MSG,        // Rebroadcast message to peers
    
    // Node Management
    TW_INT_TXN_HEARTBEAT,              // Node heartbeat/keepalive
    TW_INT_TXN_PEER_DISCOVERY,         // Peer discovery message
    TW_INT_TXN_NODE_STATUS,            // Node status update
    
    // Single Node Operations
    TW_INT_TXN_CREATE_BLOCK_SINGULAR,  // Create block for single node
    
    // Generic/Miscellaneous
    TW_INT_MISC
} TW_InternalTransactionType;

// Payload structures for different message types
typedef struct {
    unsigned char block_hash[HASH_SIZE];
    uint32_t round_number;
    uint8_t vote_phase;  // 1=verify, 2=commit, 3=new_round
} TW_VotePayload;

typedef struct {
    unsigned char last_known_hash[HASH_SIZE];
    uint32_t last_known_height;
    uint32_t max_blocks_requested;
} TW_SyncRequestPayload;

typedef struct {
    uint32_t chain_length;
    unsigned char last_block_hash[HASH_SIZE];
    uint64_t node_uptime;
    uint8_t peer_count;
} TW_NodeStatusPayload;

typedef struct {
    char peer_ip[64];
    uint16_t peer_port;
    unsigned char peer_pubkey[PUBKEY_SIZE];
    uint32_t peer_id;
} TW_PeerDiscoveryPayload;

// Main internal transaction structure
typedef struct {
    TW_InternalTransactionType type;
    unsigned char sender[PUBKEY_SIZE];
    uint64_t timestamp;
    uint32_t proposer_id;
    uint32_t round_number;
    
    // Message-specific data
    unsigned char block_hash[HASH_SIZE];
    TW_Block* block_data;  // Changed to pointer for optional data
    unsigned char chain_hash[HASH_SIZE];
    
    // Payload for different message types
    union {
        TW_VotePayload vote;
        TW_SyncRequestPayload sync_request;
        TW_NodeStatusPayload node_status;
        TW_PeerDiscoveryPayload peer_discovery;
        unsigned char raw_payload[MAX_PAYLOAD_SIZE_INTERNAL];
    } payload;
    
    size_t payload_size;
    unsigned char signature[SIGNATURE_SIZE];
} TW_InternalTransaction;

// Core Functions
TW_InternalTransaction* tw_create_internal_transaction(TW_InternalTransactionType type, 
                                                      const unsigned char* sender,
                                                      uint32_t proposer_id,
                                                      uint32_t round_number);

void tw_destroy_internal_transaction(TW_InternalTransaction* txn);

// Serialization Functions
size_t TW_InternalTransaction_serialize(TW_InternalTransaction* txn, unsigned char** buffer);
TW_InternalTransaction* TW_InternalTransaction_deserialize(const unsigned char* buffer, size_t buffer_size);

// Signature Functions
void TW_Internal_Transaction_add_signature(TW_InternalTransaction* txn);
void TW_InternalTransaction_hash(TW_InternalTransaction *txn, unsigned char *hash_out);
int TW_InternalTransaction_verify_signature(TW_InternalTransaction* txn);

// PBFT-specific helper functions
TW_InternalTransaction* tw_create_block_proposal(const unsigned char* sender, uint32_t proposer_id, 
                                                uint32_t round_number, TW_Block* block, 
                                                const unsigned char* block_hash);

TW_InternalTransaction* tw_create_vote_message(const unsigned char* sender, uint32_t proposer_id,
                                              uint32_t round_number, const unsigned char* block_hash,
                                              uint8_t vote_phase);

TW_InternalTransaction* tw_create_sync_request(const unsigned char* sender, 
                                              const unsigned char* last_known_hash,
                                              uint32_t last_known_height,
                                              uint32_t max_blocks_requested);

TW_InternalTransaction* tw_create_node_status(const unsigned char* sender, uint32_t chain_length,
                                             const unsigned char* last_block_hash,
                                             uint64_t node_uptime, uint8_t peer_count);

TW_InternalTransaction* tw_create_peer_discovery(const unsigned char* sender, const char* peer_ip,
                                                uint16_t peer_port, const unsigned char* peer_pubkey,
                                                uint32_t peer_id);

// HTTP Integration Functions for PBFT API
int tw_internal_transaction_to_http_binary(TW_InternalTransaction* txn, unsigned char** http_data, size_t* data_size);
TW_InternalTransaction* tw_internal_transaction_from_http_binary(const unsigned char* http_data, size_t data_size);

// Utility Functions
const char* tw_internal_transaction_type_to_string(TW_InternalTransactionType type);
int tw_internal_transaction_validate(TW_InternalTransaction* txn);
void tw_internal_transaction_print_debug(TW_InternalTransaction* txn);

#endif