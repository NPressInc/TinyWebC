#ifndef PBFT_NODE_H
#define PBFT_NODE_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include "node.h"
#include "features/blockchain/core/blockchain.h"
#include "features/blockchain/core/block.h"
#include "packages/transactions/transaction.h"
#include "features/blockchain/core/internalTransaction.h"
#include "packages/comm/httpClient.h"
#include "external/mongoose/mongoose.h"

// Forward declare constants from pbftApi.h to avoid circular dependency
#ifndef MAX_TRANSACTION_QUEUE
#define MAX_TRANSACTION_QUEUE 1000
#endif
#ifndef HASH_HEX_SIZE
#define HASH_HEX_SIZE 65
#endif

// Constants
#define SPEED_MODIFIER_USEC 1000000  // 1 second in microseconds
#define MAX_URL_LENGTH 256
#define MAX_JSON_RESPONSE_SIZE 8192
#define DELINQUENT_THRESHOLD 15
#define CONSENSUS_THRESHOLD_RATIO 0.67  // 2/3 + 1 for Byzantine fault tolerance

// Use HttpResponse from httpClient.h
struct HttpResponse;

// PBFT Node structure (extends base NodeState)
typedef struct {
    NodeState base;  // Inherits from base node state

    // Configuration
    bool debug_mode;  // true for debug mode, false for production mode
    bool consensus_enabled;

    // Network configuration
    char self_url[MAX_URL_LENGTH];
    uint16_t api_port;
    
    // Consensus timing
    uint32_t counter;
    time_t last_blockchain_save;
    int blockchain_has_progressed;
    uint32_t last_blockchain_length;
    
    // Threading
    pthread_t node_thread;
    pthread_t api_thread;
    pthread_mutex_t state_mutex;
    int running;
    
    // Delinquent peer tracking
    uint32_t delinquent_counts[MAX_PEERS];
    
    // Transaction queue management
    char pending_transaction_hashes[MAX_TRANSACTION_QUEUE][HASH_HEX_SIZE];
    int pending_transaction_count;

    // Current proposal state for consensus
    uint32_t current_proposal_round;
    uint32_t current_proposer_id;
    unsigned char current_proposal_hash[HASH_SIZE];
    TW_Block* current_proposal_block;  // Owned copy of the proposed block

    // Vote tracking for current proposal (by node id index)
    uint32_t verification_votes_count;
    uint8_t verification_voters[MAX_PEERS + 1];
    uint32_t commit_votes_count;
    uint8_t commit_voters[MAX_PEERS + 1];

    // View change state for Byzantine fault tolerance
    uint32_t current_view;
    time_t last_consensus_activity;
    bool view_change_pending;
    uint32_t view_change_votes_count;
    uint8_t view_change_voters[MAX_PEERS + 1];
    uint32_t proposed_new_view;
    uint32_t failed_rounds_count;
} PBFTNode;

// Global PBFT node instance
extern PBFTNode* pbft_node;

// Core PBFT node functions
PBFTNode* pbft_node_create(uint32_t node_id, uint16_t api_port, bool debug_mode);
void pbft_node_destroy(PBFTNode* node);
int pbft_node_initialize_keys(PBFTNode* node);
int pbft_node_load_or_create_blockchain(PBFTNode* node);

// Main node operations
void pbft_node_run(PBFTNode* node);
void* pbft_node_main_loop(void* arg);
void* pbft_node_api_server(void* arg);

// Block creation and management
TW_Block* pbft_node_create_block(PBFTNode* node);
int pbft_node_propose_block(PBFTNode* node, TW_Block* block);
int pbft_node_validate_block(PBFTNode* node, TW_Block* block);
int pbft_node_commit_block(PBFTNode* node, TW_Block* block);

// Peer management and discovery
int pbft_node_load_peers_from_blockchain(PBFTNode* node);
int pbft_node_add_peer(PBFTNode* node, const unsigned char* public_key, const char* ip, uint32_t id);
int pbft_node_remove_peer(PBFTNode* node, uint32_t peer_id);
int pbft_node_mark_peer_delinquent(PBFTNode* node, uint32_t peer_id);
int pbft_node_is_peer_active(PBFTNode* node, uint32_t peer_id);

// Peer address lookup (relay integration point for Task 3)
int pbft_node_lookup_peer_address(PBFTNode* node, const unsigned char* peer_pubkey, 
                                   uint32_t peer_node_id, char* ip_port_out, size_t out_size);

// Consensus algorithm
uint32_t pbft_node_calculate_proposer_id(PBFTNode* node);
int pbft_node_is_proposer(PBFTNode* node);
int pbft_node_calculate_min_approvals(PBFTNode* node);
int pbft_node_sync_with_longest_chain(PBFTNode* node);

// Network communication (deprecated - use httpClient.h functions directly)
HttpResponse* pbft_node_http_request(const char* url, const char* method, const char* json_data);
void pbft_node_free_http_response(HttpResponse* response);

// Peer communication functions
int pbft_node_broadcast_verification_vote(PBFTNode* node);
int pbft_node_broadcast_commit_vote(PBFTNode* node);
int pbft_node_broadcast_new_round_vote(PBFTNode* node);
int pbft_node_broadcast_blockchain_to_new_node(PBFTNode* node, const char* peer_url);
int pbft_node_rebroadcast_message(PBFTNode* node, TW_InternalTransaction* message, const char* exclude_peer_url);

// Individual peer communication
int pbft_node_send_block_to_peer(PBFTNode* node, const char* peer_url, TW_Block* block, const char* block_hash);
int pbft_node_send_verification_vote_to_peer(PBFTNode* node, const char* peer_url, const char* block_hash, const char* block_data);
int pbft_node_send_commit_vote_to_peer(PBFTNode* node, const char* peer_url, const char* block_hash, const char* block_data);
int pbft_node_send_new_round_vote_to_peer(PBFTNode* node, const char* peer_url, const char* block_hash, const char* block_data);

// Blockchain synchronization
int pbft_node_get_blockchain_length_from_peer(PBFTNode* node, const char* peer_url);
char* pbft_node_get_last_block_hash_from_peer(PBFTNode* node, const char* peer_url);
int pbft_node_request_missing_blocks_from_peer(PBFTNode* node, const char* peer_url);
int pbft_node_request_entire_blockchain_from_peer(PBFTNode* node, const char* peer_url);

// Transaction management
int pbft_node_get_pending_transactions_from_peer(PBFTNode* node, const char* peer_url, char* transactions_json);
int pbft_node_block_creation(PBFTNode* node, TW_Block* new_block);

// Utility functions
void pbft_node_shuffle_peers(PBFTNode* node);
int pbft_node_sign_data(PBFTNode* node, const char* data, char* signature_hex);
int pbft_node_verify_signature(const char* pubkey_hex, const char* signature_hex, const char* data);


// Hex encoding/decoding utilities
void pbft_node_bytes_to_hex(const unsigned char* bytes, size_t byte_len, char* hex_str);
int pbft_node_hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t max_bytes);

// Configuration and initialization
int pbft_node_save_blockchain_periodically(PBFTNode* node);

// Transaction processing functions
int parse_json_transaction(struct mg_str json_body, TW_Transaction** transaction);
int is_transaction_queued(const char* hash_hex);
int is_user_verified(const unsigned char* public_key, TW_BlockChain* blockchain);
int validate_transaction_permissions_for_node(TW_Transaction* transaction, PBFTNode* node);
int pbft_node_rebroadcast_transaction(PBFTNode* node, struct mg_str json_body);
int verify_blockchain_sync(PBFTNode* node, TW_Block* block);

#endif // PBFT_NODE_H 