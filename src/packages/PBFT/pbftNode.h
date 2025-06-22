#ifndef PBFT_NODE_H
#define PBFT_NODE_H

#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <pthread.h>
#include "node.h"
#include "packages/structures/blockChain/blockchain.h"
#include "packages/structures/blockChain/block.h"
#include "packages/structures/blockChain/transaction.h"
#include "packages/structures/blockChain/internalTransaction.h"
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

// HTTP client response structure
typedef struct {
    char* data;
    size_t size;
    int status_code;
} HttpResponse;

// PBFT Node structure (extends base NodeState)
typedef struct {
    NodeState base;  // Inherits from base node state
    
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
} PBFTNode;

// Global PBFT node instance
extern PBFTNode* pbft_node;

// Core PBFT node functions
PBFTNode* pbft_node_create(uint32_t node_id, uint16_t api_port);
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

// Consensus algorithm
uint32_t pbft_node_calculate_proposer_id(PBFTNode* node);
int pbft_node_is_proposer(PBFTNode* node);
int pbft_node_calculate_min_approvals(PBFTNode* node);
int pbft_node_sync_with_longest_chain(PBFTNode* node);

// Network communication
HttpResponse* pbft_node_http_request(const char* url, const char* method, const char* json_data);
void pbft_node_free_http_response(HttpResponse* response);

// Peer communication functions
int pbft_node_broadcast_block(PBFTNode* node, TW_Block* block, const char* block_hash);
int pbft_node_broadcast_verification_vote(PBFTNode* node, const char* block_hash, const char* block_data);
int pbft_node_broadcast_commit_vote(PBFTNode* node, const char* block_hash, const char* block_data);
int pbft_node_broadcast_new_round_vote(PBFTNode* node, const char* block_hash, const char* block_data);
int pbft_node_broadcast_blockchain_to_new_node(PBFTNode* node, const char* peer_url);
int pbft_node_rebroadcast_message(PBFTNode* node, const char* json_data, const char* route);

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
int pbft_node_send_block_creation_signal(PBFTNode* node);

// Utility functions
void pbft_node_shuffle_peers(PBFTNode* node);
int pbft_node_sign_data(PBFTNode* node, const char* data, char* signature_hex);
int pbft_node_verify_signature(const char* pubkey_hex, const char* signature_hex, const char* data);
void pbft_node_generate_self_url(PBFTNode* node);

// JSON serialization helpers
char* pbft_node_serialize_block_to_json(TW_Block* block);
char* pbft_node_serialize_transaction_to_json(TW_Transaction* transaction);
char* pbft_node_serialize_blockchain_to_json(TW_BlockChain* blockchain);
TW_Block* pbft_node_deserialize_block_from_json(const char* json_str);
TW_Transaction* pbft_node_deserialize_transaction_from_json(const char* json_str);
TW_BlockChain* pbft_node_deserialize_blockchain_from_json(const char* json_str);

// Hex encoding/decoding utilities
void pbft_node_bytes_to_hex(const unsigned char* bytes, size_t byte_len, char* hex_str);
int pbft_node_hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t max_bytes);

// Configuration and initialization
int pbft_node_configure_blockchain_for_first_use(PBFTNode* node);
int pbft_node_save_blockchain_periodically(PBFTNode* node);

// Transaction processing functions
int parse_json_transaction(struct mg_str json_body, TW_Transaction** transaction);
int is_transaction_queued(const char* hash_hex);
int is_user_verified(const unsigned char* public_key, TW_BlockChain* blockchain);
int validate_transaction_permissions_for_node(TW_Transaction* transaction, PBFTNode* node);
int pbft_node_rebroadcast_transaction(PBFTNode* node, struct mg_str json_body);
int verify_blockchain_sync(PBFTNode* node, TW_Block* block);

#endif // PBFT_NODE_H 