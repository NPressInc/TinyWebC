#ifndef PBFT_API_H
#define PBFT_API_H

#include <stdint.h>
#include <stddef.h>
#include "external/mongoose/mongoose.h"
#include "packages/structures/blockChain/blockchain.h"
#include "packages/structures/blockChain/transaction.h"
#include "packages/structures/blockChain/block.h"
#include "packages/structures/blockChain/internalTransaction.h"
#include "packages/PBFT/node.h"

// PBFT Message Queue Management
#define MAX_PENDING_BLOCKS 1000
#define MAX_COMMITTED_BLOCKS 1000
#define MAX_TRANSACTION_QUEUE 1000
#define MAX_VALIDATION_VOTES 1000
#define MAX_COMMIT_MESSAGES 1000
#define MAX_NEW_ROUND_MESSAGES 1000
#define TRANSACTION_QUEUE_LIMIT 3

// Hash size for block/transaction identification
#define HASH_HEX_SIZE 65  // 64 hex chars + null terminator

// Message queue structures using internal transactions
typedef struct {
    char hash[HASH_HEX_SIZE];
    TW_InternalTransaction* proposal;  // Block proposal message
} PendingBlock;

typedef struct {
    char hash[HASH_HEX_SIZE];
    char committed_hash[HASH_HEX_SIZE];
} CommittedBlock;

typedef struct {
    char hash[HASH_HEX_SIZE];
    TW_Transaction* transaction;
} QueuedTransaction;

typedef struct {
    char block_hash[HASH_HEX_SIZE];
    TW_InternalTransaction* votes[MAX_PEERS];  // Vote messages
    int vote_count;
} ValidationVotes;

typedef struct {
    char block_hash[HASH_HEX_SIZE];
    TW_InternalTransaction* votes[MAX_PEERS];  // Commit messages
    int vote_count;
} CommitMessages;

typedef struct {
    char block_hash[HASH_HEX_SIZE];
    TW_InternalTransaction* votes[MAX_PEERS];  // New round messages
    int vote_count;
} NewRoundMessages;

// Global message queues structure
typedef struct {
    PendingBlock pending_blocks[MAX_PENDING_BLOCKS];
    int pending_block_count;
    
    CommittedBlock committed_blocks[MAX_COMMITTED_BLOCKS];
    int committed_block_count;
    
    QueuedTransaction transaction_queue[MAX_TRANSACTION_QUEUE];
    int transaction_count;
    
    ValidationVotes validation_votes[MAX_VALIDATION_VOTES];
    int validation_vote_count;
    
    CommitMessages commit_messages[MAX_COMMIT_MESSAGES];
    int commit_message_count;
    
    NewRoundMessages new_round_messages[MAX_NEW_ROUND_MESSAGES];
    int new_round_message_count;
    
    char blockchain_parent[PUBKEY_SIZE * 2 + 1]; // Hex encoded
} MessageQueues;

// Global message queues instance
extern MessageQueues message_queues;

// PBFT REST API endpoints
void handle_transaction(struct mg_connection* c, struct mg_http_message* hm);
void handle_transaction_internal(struct mg_connection* c, struct mg_http_message* hm);
void handle_propose_block(struct mg_connection* c, struct mg_http_message* hm);
void handle_verification_vote(struct mg_connection* c, struct mg_http_message* hm);
void handle_commit_vote(struct mg_connection* c, struct mg_http_message* hm);
void handle_new_round(struct mg_connection* c, struct mg_http_message* hm);
void handle_blockchain_last_hash(struct mg_connection* c, struct mg_http_message* hm);
void handle_get_pending_transactions(struct mg_connection* c, struct mg_http_message* hm);
void handle_get_blockchain_length(struct mg_connection* c, struct mg_http_message* hm);
void handle_missing_block_request(struct mg_connection* c, struct mg_http_message* hm);
void handle_send_new_blockchain(struct mg_connection* c, struct mg_http_message* hm);
void handle_request_entire_blockchain(struct mg_connection* c, struct mg_http_message* hm);
void handle_add_new_block_singular(struct mg_connection* c, struct mg_http_message* hm);

// Helper functions using internal transactions
TW_Block* create_block_from_queue(void);
int add_to_pending_blocks(const char* hash, TW_InternalTransaction* proposal);
int add_to_committed_blocks(const char* hash);
int add_to_transaction_queue(const char* hash, TW_Transaction* transaction);
int add_validation_vote(const char* block_hash, TW_InternalTransaction* vote);
int add_commit_vote(const char* block_hash, TW_InternalTransaction* vote);
int add_new_round_vote(const char* block_hash, TW_InternalTransaction* vote);
int calculate_min_approvals(void);
int is_threshold_reached(int vote_count);
void clear_message_queues_for_block(const char* block_hash);

// Internal transaction processing
int process_internal_transaction(TW_InternalTransaction* txn);
TW_InternalTransaction* parse_internal_transaction_from_http(struct mg_str body);
void send_internal_transaction_response(struct mg_connection* c, TW_InternalTransaction* response_txn);

// Validation functions
int validate_internal_transaction_signature(TW_InternalTransaction* txn);
int validate_vote_message(TW_InternalTransaction* vote, const char* expected_block_hash);
int validate_block_proposal(TW_InternalTransaction* proposal);

// JSON parsing and response helpers
int parse_json_transaction(struct mg_str json_body, TW_Transaction** transaction);
int parse_json_block(struct mg_str json_body, TW_Block** block);
void send_json_response(struct mg_connection* c, int status, const char* json_response);
void send_error_response(struct mg_connection* c, const char* error_message);

// Message queue management
void init_message_queues(void);
void cleanup_message_queues(void);

// PBFT API server functions
void start_pbft_api_server(const char* port);
void setup_pbft_routes(void);

#endif // PBFT_API_H 