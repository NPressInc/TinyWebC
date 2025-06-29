#include "pbftApi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../structures/blockChain/internalTransaction.h"
#include "../structures/blockChain/block.h"

// Global message queues instance
MessageQueues message_queues;

// Initialize message queues
void init_message_queues(void) {
    memset(&message_queues, 0, sizeof(MessageQueues));
    printf("Message queues initialized\n");
}

// Cleanup message queues
void cleanup_message_queues(void) {
    // TODO: Free any allocated memory in queues
    printf("Message queues cleaned up\n");
}

// PBFT REST API endpoint handlers (stubs)
void handle_transaction(struct mg_connection* c, struct mg_http_message* hm) {
    send_json_response(c, 200, "{\"status\": \"ok\"}");
}

void handle_transaction_internal(struct mg_connection* c, struct mg_http_message* hm) {
    send_json_response(c, 200, "{\"response\": \"ok\"}");
}

void handle_propose_block(struct mg_connection* c, struct mg_http_message* hm) {
    send_json_response(c, 200, "{\"response\": \"ok\"}");
}

void handle_verification_vote(struct mg_connection* c, struct mg_http_message* hm) {
    send_json_response(c, 200, "{\"response\": \"ok\"}");
}

void handle_commit_vote(struct mg_connection* c, struct mg_http_message* hm) {
    send_json_response(c, 200, "{\"response\": \"ok\"}");
}

void handle_new_round(struct mg_connection* c, struct mg_http_message* hm) {
    send_json_response(c, 200, "{\"response\": \"ok\"}");
}

void handle_blockchain_last_hash(struct mg_connection* c, struct mg_http_message* hm) {
    send_json_response(c, 200, "{\"lastHash\": \"dummy_hash\"}");
}

void handle_get_pending_transactions(struct mg_connection* c, struct mg_http_message* hm) {
    send_json_response(c, 200, "{\"pendingTransactions\": {}}");
}

void handle_get_blockchain_length(struct mg_connection* c, struct mg_http_message* hm) {
    send_json_response(c, 200, "{\"chainLength\": 0}");
}

void handle_missing_block_request(struct mg_connection* c, struct mg_http_message* hm) {
    send_json_response(c, 200, "{\"response\": {\"missingBlocks\": []}}");
}

void handle_send_new_blockchain(struct mg_connection* c, struct mg_http_message* hm) {
    send_json_response(c, 200, "{\"response\": \"thankyoufor the blockchain\"}");
}

void handle_request_entire_blockchain(struct mg_connection* c, struct mg_http_message* hm) {
    send_json_response(c, 200, "{\"response\": \"ok\"}");
}

void handle_add_new_block_singular(struct mg_connection* c, struct mg_http_message* hm) {
    send_json_response(c, 200, "{\"response\": \"Added block to chain\"}");
}

// Helper functions using internal transactions
TW_Block* create_block_from_queue(void) { return NULL; }
int add_to_pending_blocks(const char* hash, TW_InternalTransaction* proposal) { return 0; }
int add_to_committed_blocks(const char* hash) { return 0; }

int add_to_transaction_queue(const char* hash, TW_Transaction* transaction) {
    if (!hash || !transaction) return -1;
    
    // Check if queue is full
    if (message_queues.transaction_count >= MAX_TRANSACTION_QUEUE) {
        printf("Transaction queue is full\n");
        return -1;
    }
    
    // Add transaction to queue
    QueuedTransaction* slot = &message_queues.transaction_queue[message_queues.transaction_count];
    strncpy(slot->hash, hash, HASH_HEX_SIZE - 1);
    slot->hash[HASH_HEX_SIZE - 1] = '\0';
    slot->transaction = transaction;
    
    message_queues.transaction_count++;
    
    printf("Added transaction to queue: %s (queue size: %d)\n", hash, message_queues.transaction_count);
    return 0;
}

int add_validation_vote(const char* block_hash, TW_InternalTransaction* vote) { return 0; }
int add_commit_vote(const char* block_hash, TW_InternalTransaction* vote) { return 0; }
int add_new_round_vote(const char* block_hash, TW_InternalTransaction* vote) { return 0; }
int calculate_min_approvals(void) { return 1; }
int is_threshold_reached(int vote_count) { return 1; }
void clear_message_queues_for_block(const char* block_hash) { }

// Internal transaction processing functions (FIXED IMPLEMENTATIONS)
int process_internal_transaction(TW_InternalTransaction* txn) {
    if (!txn) return -1;
    
    printf("Processing internal transaction: %s\n", tw_internal_transaction_type_to_string(txn->type));
    
    // Validate the transaction first
    if (!tw_internal_transaction_validate(txn)) {
        printf("Internal transaction validation failed\n");
        return -1;
    }
    
    // Process based on type
    switch (txn->type) {
        case TW_INT_TXN_PROPOSE_BLOCK:
            printf("Processing block proposal from proposer %u\n", txn->proposer_id);
            // Add to pending blocks for validation
            if (txn->block_data) {
                unsigned char block_hash[HASH_SIZE];
                if (TW_Block_getHash(txn->block_data, block_hash) == 1) {
                    char hash_hex[HASH_SIZE * 2 + 1];
                    // Convert hash to hex for storage
                    for (int i = 0; i < HASH_SIZE; i++) {
                        sprintf(hash_hex + (i * 2), "%02x", block_hash[i]);
                    }
                    return add_to_pending_blocks(hash_hex, txn);
                }
            }
            break;
            
        case TW_INT_TXN_VOTE_VERIFY:
            printf("Processing verification vote from node %u\n", txn->proposer_id);
            // Convert block hash to hex string
            char hash_hex[HASH_SIZE * 2 + 1];
            for (int i = 0; i < HASH_SIZE; i++) {
                sprintf(hash_hex + (i * 2), "%02x", txn->block_hash[i]);
            }
            return add_validation_vote(hash_hex, txn);
            
        case TW_INT_TXN_VOTE_COMMIT:
            printf("Processing commit vote from node %u\n", txn->proposer_id);
            // Convert block hash to hex string
            char commit_hash_hex[HASH_SIZE * 2 + 1];
            for (int i = 0; i < HASH_SIZE; i++) {
                sprintf(commit_hash_hex + (i * 2), "%02x", txn->block_hash[i]);
            }
            return add_commit_vote(commit_hash_hex, txn);
            
        case TW_INT_TXN_VOTE_NEW_ROUND:
            printf("Processing new round vote from node %u\n", txn->proposer_id);
            // Convert block hash to hex string
            char new_round_hash_hex[HASH_SIZE * 2 + 1];
            for (int i = 0; i < HASH_SIZE; i++) {
                sprintf(new_round_hash_hex + (i * 2), "%02x", txn->block_hash[i]);
            }
            return add_new_round_vote(new_round_hash_hex, txn);
            
        default:
            printf("Unhandled internal transaction type: %d\n", txn->type);
            return -1;
    }
    
    return 0;
}

TW_InternalTransaction* parse_internal_transaction_from_http(struct mg_str body) {
    if (!body.buf || body.len == 0) {
        printf("Empty HTTP body for internal transaction\n");
        return NULL;
    }
    
    printf("Parsing internal transaction from HTTP body (%zu bytes)\n", body.len);
    
    // The body should contain binary serialized internal transaction data
    TW_InternalTransaction* txn = tw_internal_transaction_from_http_binary(
        (const unsigned char*)body.buf, body.len);
    
    if (!txn) {
        printf("Failed to deserialize internal transaction from HTTP binary data\n");
        return NULL;
    }
    
    printf("Successfully parsed internal transaction: %s\n", 
           tw_internal_transaction_type_to_string(txn->type));
    
    return txn;
}

void send_internal_transaction_response(struct mg_connection* c, TW_InternalTransaction* response_txn) {
    if (!c || !response_txn) {
        if (c) {
            mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                         "{\"error\":\"Invalid response transaction\"}");
        }
        return;
    }
    
    // Serialize the response transaction to binary
    unsigned char* response_data = NULL;
    size_t response_size = 0;
    
    if (!tw_internal_transaction_to_http_binary(response_txn, &response_data, &response_size)) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Failed to serialize response\"}");
        return;
    }
    
    // Send binary response
    mg_http_reply(c, 200, "Content-Type: application/octet-stream\r\n", 
                 "%.*s", (int)response_size, response_data);
    
    free(response_data);
}

// Validation functions (PROPER IMPLEMENTATIONS)
int validate_internal_transaction_signature(TW_InternalTransaction* txn) {
    if (!txn) {
        printf("Cannot validate NULL internal transaction\n");
        return 0;
    }
    
    printf("Validating signature for internal transaction from node %u\n", txn->proposer_id);
    
    // Use the built-in signature verification
    int result = TW_InternalTransaction_verify_signature(txn);
    if (result) {
        printf("✅ Internal transaction signature validation: PASSED\n");
    } else {
        printf("❌ Internal transaction signature validation: FAILED\n");
    }
    
    return result;
}

int validate_vote_message(TW_InternalTransaction* vote, const char* expected_block_hash) {
    if (!vote || !expected_block_hash) return 0;
    
    // Check if it's a vote type
    if (vote->type != TW_INT_TXN_VOTE_VERIFY && 
        vote->type != TW_INT_TXN_VOTE_COMMIT && 
        vote->type != TW_INT_TXN_VOTE_NEW_ROUND) {
        printf("Invalid vote message type: %d\n", vote->type);
        return 0;
    }
    
    // Convert vote's block hash to hex and compare
    char vote_hash_hex[HASH_SIZE * 2 + 1];
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(vote_hash_hex + (i * 2), "%02x", vote->block_hash[i]);
    }
    
    if (strcmp(vote_hash_hex, expected_block_hash) != 0) {
        printf("Vote block hash mismatch: expected %s, got %s\n", 
               expected_block_hash, vote_hash_hex);
        return 0;
    }
    
    // Validate signature
    if (!validate_internal_transaction_signature(vote)) {
        return 0;
    }
    
    printf("✅ Vote message validation: PASSED\n");
    return 1;
}

int validate_block_proposal(TW_InternalTransaction* proposal) {
    if (!proposal) return 0;
    
    if (proposal->type != TW_INT_TXN_PROPOSE_BLOCK) {
        printf("Invalid block proposal type: %d\n", proposal->type);
        return 0;
    }
    
    if (!proposal->block_data) {
        printf("Block proposal missing block data\n");
        return 0;
    }
    
    // Validate signature
    if (!validate_internal_transaction_signature(proposal)) {
        return 0;
    }
    
    // Validate block hash matches block data
    unsigned char computed_hash[HASH_SIZE];
    if (TW_Block_getHash(proposal->block_data, computed_hash) != 1) {
        printf("Failed to compute block hash for validation\n");
        return 0;
    }
    
    if (memcmp(computed_hash, proposal->block_hash, HASH_SIZE) != 0) {
        printf("Block hash mismatch in proposal\n");
        return 0;
    }
    
    printf("✅ Block proposal validation: PASSED\n");
    return 1;
}

// JSON parsing and response helpers
int parse_json_block(struct mg_str json_body, TW_Block** block) { return 0; }

void send_json_response(struct mg_connection* c, int status, const char* json_response) {
    mg_http_reply(c, status, "Content-Type: application/json\r\n", "%s", json_response);
}

void send_error_response(struct mg_connection* c, const char* error_message) {
    char response[256];
    snprintf(response, sizeof(response), "{\"error\": \"%s\"}", error_message);
    send_json_response(c, 400, response);
}

// PBFT API server functions (stubs)
void start_pbft_api_server(const char* port) {
    printf("PBFT API server would start on port %s\n", port);
}

void setup_pbft_routes(void) {
    printf("PBFT routes would be set up here\n");
} 