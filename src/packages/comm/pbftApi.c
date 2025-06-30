#include "pbftApi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../structures/blockChain/internalTransaction.h"
#include "../structures/blockChain/block.h"
#include <cjson/cJSON.h>
#include "../fileIO/blockchainIO.h"
#include "../sql/database.h"
#include "../PBFT/pbftNode.h"
#include "../sql/queries.h"
// --- JSON serialization helpers declarations ---
static char* block_to_json_string(TW_Block* block);
static char* transaction_to_json_string(TW_Transaction* tx);

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
    // Return the hash of the last committed block (dummy for now)
    char last_hash[HASH_SIZE * 2 + 1] = "";
    if (message_queues.committed_block_count > 0) {
        // TODO: Compute real hash from last committed block
        strncpy(last_hash, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", HASH_SIZE * 2);
        last_hash[HASH_SIZE * 2] = '\0';
    }
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "lastHash", last_hash);
    char* json_str = cJSON_PrintUnformatted(resp);
    send_json_response(c, 200, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

void handle_get_pending_transactions(struct mg_connection* c, struct mg_http_message* hm) {
    cJSON* resp = cJSON_CreateObject();
    cJSON* txs = cJSON_CreateArray();
    for (int i = 0; i < message_queues.transaction_count; i++) {
        TW_Transaction* tx = message_queues.transaction_queue[i].transaction;
        char* tx_json = transaction_to_json_string(tx);
        if (tx_json) {
            cJSON* tx_obj = cJSON_Parse(tx_json);
            if (tx_obj) cJSON_AddItemToArray(txs, tx_obj);
            free(tx_json);
        }
    }
    cJSON_AddItemToObject(resp, "pendingTransactions", txs);
    char* json_str = cJSON_PrintUnformatted(resp);
    send_json_response(c, 200, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

void handle_get_blockchain_length(struct mg_connection* c, struct mg_http_message* hm) {
    // For now, just return the count of committed blocks
    int length = message_queues.committed_block_count;
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddNumberToObject(resp, "chainLength", length);
    char* json_str = cJSON_PrintUnformatted(resp);
    send_json_response(c, 200, json_str);
    free(json_str);
    cJSON_Delete(resp);
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
    mg_http_reply(c, status,
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization\r\n",
        "%s", json_response);
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

// --- JSON serialization helpers ---
static char* block_to_json_string(TW_Block* block) {
    if (!block) return NULL;
    cJSON* block_obj = cJSON_CreateObject();
    if (!block_obj) return NULL;
    // Block index
    cJSON_AddNumberToObject(block_obj, "index", block->index);
    // Timestamp
    cJSON_AddNumberToObject(block_obj, "timestamp", block->timestamp);
    // Previous hash
    char prev_hash_hex[HASH_SIZE * 2 + 1];
    for (int j = 0; j < HASH_SIZE; j++) {
        sprintf(prev_hash_hex + (j * 2), "%02x", block->previous_hash[j]);
    }
    cJSON_AddStringToObject(block_obj, "previous_hash", prev_hash_hex);
    // Proposer ID
    char proposer_hex[PROP_ID_SIZE * 2 + 1];
    for (int j = 0; j < PROP_ID_SIZE; j++) {
        sprintf(proposer_hex + (j * 2), "%02x", block->proposer_id[j]);
    }
    cJSON_AddStringToObject(block_obj, "proposer_id", proposer_hex);
    // Merkle root hash
    char merkle_hex[HASH_SIZE * 2 + 1];
    for (int j = 0; j < HASH_SIZE; j++) {
        sprintf(merkle_hex + (j * 2), "%02x", block->merkle_root_hash[j]);
    }
    cJSON_AddStringToObject(block_obj, "merkle_root_hash", merkle_hex);
    // Transactions array (empty for now)
    cJSON* txns_array = cJSON_CreateArray();
    cJSON_AddItemToObject(block_obj, "transactions", txns_array);
    // TODO: Add real transactions if needed
    char* json_str = cJSON_PrintUnformatted(block_obj);
    cJSON_Delete(block_obj);
    return json_str;
}

static char* transaction_to_json_string(TW_Transaction* tx) {
    if (!tx) return NULL;
    cJSON* tx_obj = cJSON_CreateObject();
    if (!tx_obj) return NULL;
    cJSON_AddNumberToObject(tx_obj, "type", tx->type);
    char sender_hex[PUBKEY_SIZE * 2 + 1];
    for (int k = 0; k < PUBKEY_SIZE; k++) {
        sprintf(sender_hex + (k * 2), "%02x", tx->sender[k]);
    }
    cJSON_AddStringToObject(tx_obj, "sender", sender_hex);
    cJSON_AddNumberToObject(tx_obj, "timestamp", tx->timestamp);
    // Recipients (empty for now)
    cJSON* recipients_array = cJSON_CreateArray();
    cJSON_AddItemToObject(tx_obj, "recipients", recipients_array);
    // TODO: Add real recipients if needed
    char* json_str = cJSON_PrintUnformatted(tx_obj);
    cJSON_Delete(tx_obj);
    return json_str;
}

// --- REST API endpoint handlers ---
void handle_get_network_stats(struct mg_connection* c, struct mg_http_message* hm) {
    cJSON* resp = cJSON_CreateObject();
    if (!resp) {
        send_error_response(c, "Failed to create JSON response");
        return;
    }
    
    // Get actual network statistics from database and node
    uint32_t total_blocks = 0;
    uint64_t total_transactions = 0;
    
    if (db_is_initialized()) {
        db_get_block_count(&total_blocks);
        db_get_transaction_count(&total_transactions);
    }
    
    // Calculate network statistics
    uint32_t total_nodes = 1; // At least this node
    uint32_t online_nodes = 1; // At least this node is online
    
    // Get peer information from external PBFT node if available
    extern PBFTNode* pbft_node;
    if (pbft_node) {
        total_nodes += pbft_node->base.peer_count;
        // Count online peers (for now, assume all peers are online)
        // In a real implementation, you'd check last_seen timestamps
        online_nodes += pbft_node->base.peer_count;
    }
    
    // Calculate average block time (in seconds)
    double average_block_time = 10.0; // Default 10 seconds
    if (total_blocks > 1) {
        // Get timestamp of first and last block to calculate average
        // For now, use a reasonable default based on PBFT timing
        average_block_time = 15.0; // Typical PBFT block time
    }
    
    // Calculate network health (0-100 percentage)
    int network_health = 100;
    if (total_nodes > 1) {
        // Health based on percentage of online nodes
        network_health = (online_nodes * 100) / total_nodes;
        
        // Adjust health based on recent block activity
        if (total_blocks == 0) {
            network_health = 50; // No blocks created yet
        }
        
        // Cap at 100%
        if (network_health > 100) network_health = 100;
    }
    
    // Get last block timestamp
    uint64_t last_block_time = 0;
    if (pbft_node && pbft_node->base.blockchain && pbft_node->base.blockchain->length > 0) {
        TW_Block* last_block = pbft_node->base.blockchain->blocks[pbft_node->base.blockchain->length - 1];
        if (last_block) {
            last_block_time = last_block->timestamp;
        }
    }
    
    // Build JSON response matching the NetworkStats interface
    cJSON_AddNumberToObject(resp, "totalNodes", total_nodes);
    cJSON_AddNumberToObject(resp, "onlineNodes", online_nodes);
    cJSON_AddNumberToObject(resp, "totalBlocks", total_blocks);
    cJSON_AddNumberToObject(resp, "averageBlockTime", average_block_time);
    cJSON_AddNumberToObject(resp, "networkHealth", network_health);
    cJSON_AddNumberToObject(resp, "lastBlockTime", last_block_time);
    
    // Add recentActivity array for dashboard compatibility using real database query
    cJSON* recentActivity = cJSON_CreateArray();
    
    TransactionRecord* tx_results = NULL;
    size_t tx_count = 0;
    
    if (query_recent_activity(3, &tx_results, &tx_count) == 0 && tx_results) {
        for (size_t i = 0; i < tx_count; i++) {
            cJSON* activity = cJSON_CreateObject();
            
            char activity_id[32];
            snprintf(activity_id, sizeof(activity_id), "tx_%lu", tx_results[i].transaction_id);
            cJSON_AddStringToObject(activity, "id", activity_id);
            cJSON_AddNumberToObject(activity, "timestamp", tx_results[i].timestamp);
            
            // Map transaction type to activity type
            const char* activity_type = "transaction";
            const char* description = "Transaction processed";
            
            switch (tx_results[i].type) {
                case TW_TXN_MESSAGE:
                    activity_type = "transaction";
                    description = "Message transaction processed";
                    break;
                case TW_TXN_SYSTEM_CONFIG:
                    activity_type = "block_created";
                    description = "System configuration updated";
                    break;
                case TW_TXN_USER_REGISTRATION:
                    activity_type = "user_joined";
                    description = "New user registered";
                    break;
                case TW_TXN_ROLE_ASSIGNMENT:
                    activity_type = "permission_granted";
                    description = "Role assignment updated";
                    break;
                case TW_TXN_INVITATION_CREATE:
                    activity_type = "invitation_sent";
                    description = "Invitation created";
                    break;
                case TW_TXN_INVITATION_ACCEPT:
                    activity_type = "user_joined";
                    description = "Invitation accepted";
                    break;
                default:
                    activity_type = "transaction";
                    description = "Transaction processed";
                    break;
            }
            
            cJSON_AddStringToObject(activity, "type", activity_type);
            cJSON_AddStringToObject(activity, "description", description);
            cJSON_AddStringToObject(activity, "userName", "System");
            
            cJSON_AddItemToArray(recentActivity, activity);
        }
        
        db_free_transaction_records(tx_results, tx_count);
    }
    
    // If no database activity, add a fallback activity
    if (cJSON_GetArraySize(recentActivity) == 0) {
        cJSON* activity = cJSON_CreateObject();
        cJSON_AddStringToObject(activity, "id", "system_001");
        cJSON_AddNumberToObject(activity, "timestamp", time(NULL) - 300);
        cJSON_AddStringToObject(activity, "type", "block_created");
        cJSON_AddStringToObject(activity, "description", "PBFT node initialized");
        cJSON_AddStringToObject(activity, "userName", "System");
        cJSON_AddItemToArray(recentActivity, activity);
    }
    
    cJSON_AddItemToObject(resp, "recentActivity", recentActivity);
    
    char* json_str = cJSON_PrintUnformatted(resp);
    if (json_str) {
        send_json_response(c, 200, json_str);
        free(json_str);
    } else {
        send_error_response(c, "Failed to serialize JSON response");
    }
    cJSON_Delete(resp);
}

void handle_get_block_by_hash(struct mg_connection* c, struct mg_http_message* hm) {
    // Parse hash from URL (assume /api/blocks/{hash})
    char hash[HASH_HEX_SIZE] = {0};
    snprintf(hash, HASH_HEX_SIZE, "%.*s", (int)hm->uri.len - (int)strlen("/api/blocks/"), hm->uri.buf + strlen("/api/blocks/"));
    // Search committed blocks for this hash (dummy: just return first block)
    TW_Block* block = NULL;
    if (message_queues.committed_block_count > 0) {
        block = NULL; // TODO: Lookup by hash
    }
    cJSON* resp = cJSON_CreateObject();
    if (block) {
        char* block_json = block_to_json_string(block);
        if (block_json) {
            cJSON* block_obj = cJSON_Parse(block_json);
            cJSON_AddItemToObject(resp, "block", block_obj);
            free(block_json);
        }
    } else {
        cJSON_AddStringToObject(resp, "error", "Block not found");
    }
    char* json_str = cJSON_PrintUnformatted(resp);
    send_json_response(c, 200, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

// Stub endpoint handlers (return dummy data for now)
void handle_get_invitation_stats(struct mg_connection* c, struct mg_http_message* hm) {
    cJSON* resp = cJSON_CreateObject();
    if (!resp) {
        send_error_response(c, "Failed to create JSON response");
        return;
    }
    
    // Dummy invitation statistics matching InvitationStats interface
    cJSON_AddNumberToObject(resp, "totalCreated", 5);
    cJSON_AddNumberToObject(resp, "totalAccepted", 3);
    cJSON_AddNumberToObject(resp, "totalPending", 2);
    cJSON_AddNumberToObject(resp, "totalExpired", 0);
    
    char* json_str = cJSON_PrintUnformatted(resp);
    if (json_str) {
        send_json_response(c, 200, json_str);
        free(json_str);
    } else {
        send_error_response(c, "Failed to serialize JSON response");
    }
    cJSON_Delete(resp);
}

void handle_get_family_members(struct mg_connection* c, struct mg_http_message* hm) {
    cJSON* members = cJSON_CreateArray();
    
    // Dummy family members - return as direct array
    cJSON* member1 = cJSON_CreateObject();
    cJSON_AddStringToObject(member1, "publicKey", "0x1234567890123456789012345678901234567890");
    cJSON_AddStringToObject(member1, "name", "Alice Smith");
    cJSON_AddStringToObject(member1, "role", "parent");
    cJSON_AddNumberToObject(member1, "permissions", 255); // Full permissions
    cJSON_AddBoolToObject(member1, "requiresSupervision", false);
    cJSON_AddNumberToObject(member1, "joinedAt", 1640995200); // Jan 1, 2022
    cJSON_AddNumberToObject(member1, "lastActive", time(NULL) - 300); // 5 minutes ago
    cJSON_AddStringToObject(member1, "status", "active");
    cJSON_AddItemToArray(members, member1);
    
    cJSON* member2 = cJSON_CreateObject();
    cJSON_AddStringToObject(member2, "publicKey", "0x0987654321098765432109876543210987654321");
    cJSON_AddStringToObject(member2, "name", "Bob Smith");
    cJSON_AddStringToObject(member2, "role", "child");
    cJSON_AddNumberToObject(member2, "permissions", 15); // Limited permissions
    cJSON_AddBoolToObject(member2, "requiresSupervision", true);
    cJSON_AddNumberToObject(member2, "joinedAt", 1640995200);
    cJSON_AddNumberToObject(member2, "lastActive", time(NULL) - 600); // 10 minutes ago
    cJSON_AddStringToObject(member2, "status", "active");
    cJSON_AddItemToArray(members, member2);
    
    char* json_str = cJSON_PrintUnformatted(members);
    if (json_str) {
        send_json_response(c, 200, json_str);
        free(json_str);
    } else {
        send_error_response(c, "Failed to serialize JSON response");
    }
    cJSON_Delete(members);
}

void handle_get_activity(struct mg_connection* c, struct mg_http_message* hm) {
    cJSON* activities = cJSON_CreateArray();
    
    // Parse limit parameter from query string
    uint32_t limit = 10; // Default limit
    if (hm->query.len > 0) {
        char query_str[256];
        size_t query_len = hm->query.len < sizeof(query_str) - 1 ? hm->query.len : sizeof(query_str) - 1;
        strncpy(query_str, hm->query.buf, query_len);
        query_str[query_len] = '\0';
        
        char* limit_param = strstr(query_str, "limit=");
        if (limit_param) {
            limit = atoi(limit_param + 6);
            if (limit > 100) limit = 100; // Cap at 100
            if (limit < 1) limit = 10;    // Minimum 1
        }
    }
    
    // Query recent activity from database
    TransactionRecord* tx_results = NULL;
    size_t tx_count = 0;
    
    if (query_recent_activity(limit, &tx_results, &tx_count) == 0 && tx_results) {
        for (size_t i = 0; i < tx_count; i++) {
            cJSON* activity = cJSON_CreateObject();
            
            char activity_id[32];
            snprintf(activity_id, sizeof(activity_id), "tx_%lu", tx_results[i].transaction_id);
            cJSON_AddStringToObject(activity, "id", activity_id);
            cJSON_AddNumberToObject(activity, "timestamp", tx_results[i].timestamp);
            
            // Map transaction type to activity type
            const char* activity_type = "transaction";
            const char* description = "Transaction processed";
            const char* userName = "System";
            
            switch (tx_results[i].type) {
                case TW_TXN_MESSAGE:
                    activity_type = "transaction";
                    description = "Message transaction processed";
                    break;
                case TW_TXN_SYSTEM_CONFIG:
                    activity_type = "block_created";
                    description = "System configuration updated";
                    break;
                case TW_TXN_USER_REGISTRATION:
                    activity_type = "user_joined";
                    description = "New user registered";
                    break;
                case TW_TXN_ROLE_ASSIGNMENT:
                    activity_type = "permission_granted";
                    description = "Role assignment updated";
                    break;
                case TW_TXN_INVITATION_CREATE:
                    activity_type = "invitation_sent";
                    description = "Invitation created";
                    break;
                case TW_TXN_INVITATION_ACCEPT:
                    activity_type = "user_joined";
                    description = "Invitation accepted";
                    break;
                default:
                    activity_type = "transaction";
                    description = "Transaction processed";
                    break;
            }
            
            cJSON_AddStringToObject(activity, "type", activity_type);
            cJSON_AddStringToObject(activity, "description", description);
            cJSON_AddStringToObject(activity, "userName", userName);
            
            // Add metadata with transaction details
            cJSON* metadata = cJSON_CreateObject();
            cJSON_AddNumberToObject(metadata, "blockIndex", tx_results[i].block_index);
            cJSON_AddNumberToObject(metadata, "transactionIndex", tx_results[i].transaction_index);
            cJSON_AddStringToObject(metadata, "sender", tx_results[i].sender);
            cJSON_AddItemToObject(activity, "metadata", metadata);
            
            cJSON_AddItemToArray(activities, activity);
        }
        
        db_free_transaction_records(tx_results, tx_count);
    }
    
    // If no database activity, add a fallback activity
    if (cJSON_GetArraySize(activities) == 0) {
        cJSON* activity = cJSON_CreateObject();
        cJSON_AddStringToObject(activity, "id", "system_001");
        cJSON_AddNumberToObject(activity, "timestamp", time(NULL) - 300);
        cJSON_AddStringToObject(activity, "type", "block_created");
        cJSON_AddStringToObject(activity, "description", "PBFT node initialized");
        cJSON_AddStringToObject(activity, "userName", "System");
        cJSON_AddItemToArray(activities, activity);
    }
    
    char* json_str = cJSON_PrintUnformatted(activities);
    if (json_str) {
        send_json_response(c, 200, json_str);
        free(json_str);
    } else {
        send_error_response(c, "Failed to serialize JSON response");
    }
    cJSON_Delete(activities);
}

void handle_get_blocks(struct mg_connection* c, struct mg_http_message* hm) {
    cJSON* resp = cJSON_CreateObject();
    cJSON* items = cJSON_CreateArray();
    
    // Parse pagination parameters from query string
    uint32_t page = 1;
    uint32_t pageSize = 10;
    
    if (hm->query.len > 0) {
        char query_str[256];
        size_t query_len = hm->query.len < sizeof(query_str) - 1 ? hm->query.len : sizeof(query_str) - 1;
        strncpy(query_str, hm->query.buf, query_len);
        query_str[query_len] = '\0';
        
        char* page_param = strstr(query_str, "page=");
        if (page_param) {
            page = atoi(page_param + 5);
            if (page < 1) page = 1;
        }
        
        char* pageSize_param = strstr(query_str, "pageSize=");
        if (pageSize_param) {
            pageSize = atoi(pageSize_param + 9);
            if (pageSize > 100) pageSize = 100; // Cap at 100
            if (pageSize < 1) pageSize = 10;    // Minimum 1
        }
    }
    
    // Get total block count from database
    uint32_t total_blocks = 0;
    if (db_is_initialized()) {
        db_get_block_count(&total_blocks);
    }
    
    // Get actual blockchain length from PBFT node
    extern PBFTNode* pbft_node;
    uint32_t blockchain_length = 0;
    if (pbft_node && pbft_node->base.blockchain) {
        blockchain_length = pbft_node->base.blockchain->length;
    }
    
    // Calculate pagination using blockchain length
    uint32_t total_pages = (blockchain_length + pageSize - 1) / pageSize;
    uint32_t start_index = (page - 1) * pageSize;
    uint32_t end_index = start_index + pageSize;
    if (end_index > blockchain_length) end_index = blockchain_length;
    
    // Get blocks from PBFT node blockchain  
    if (pbft_node && pbft_node->base.blockchain && blockchain_length > 0) {
        // Iterate through requested range (newest first) - use blockchain length
        uint32_t effective_total = blockchain_length; // Use actual blockchain length, not database count
        for (uint32_t i = 0; i < pageSize && start_index + i < effective_total; i++) {
            uint32_t block_index = effective_total - 1 - start_index - i; // Reverse order (newest first)
            
            if (block_index < blockchain_length) {
                TW_Block* block = pbft_node->base.blockchain->blocks[block_index];
                if (block) {
                    cJSON* block_obj = cJSON_CreateObject();
                    
                    // Calculate block hash
                    unsigned char block_hash[HASH_SIZE];
                    char hash_hex[HASH_SIZE * 2 + 1];
                    char prev_hash_hex[HASH_SIZE * 2 + 1];
                    char merkle_hex[HASH_SIZE * 2 + 1];
                    char proposer_hex[PROP_ID_SIZE * 2 + 1];
                    
                    if (TW_Block_getHash(block, block_hash)) {
                        for (int j = 0; j < HASH_SIZE; j++) {
                            sprintf(hash_hex + (j * 2), "%02x", block_hash[j]);
                        }
                        hash_hex[HASH_SIZE * 2] = '\0';
                        cJSON_AddStringToObject(block_obj, "hash", hash_hex);
                    } else {
                        cJSON_AddStringToObject(block_obj, "hash", "0x0000000000000000000000000000000000000000");
                    }
                    
                    // Convert previous hash to hex
                    for (int j = 0; j < HASH_SIZE; j++) {
                        sprintf(prev_hash_hex + (j * 2), "%02x", block->previous_hash[j]);
                    }
                    prev_hash_hex[HASH_SIZE * 2] = '\0';
                    cJSON_AddStringToObject(block_obj, "previousHash", prev_hash_hex);
                    
                    // Convert merkle root to hex
                    for (int j = 0; j < HASH_SIZE; j++) {
                        sprintf(merkle_hex + (j * 2), "%02x", block->merkle_root_hash[j]);
                    }
                    merkle_hex[HASH_SIZE * 2] = '\0';
                    cJSON_AddStringToObject(block_obj, "merkleRoot", merkle_hex);
                    
                    // Convert proposer ID to hex
                    for (int j = 0; j < PROP_ID_SIZE; j++) {
                        sprintf(proposer_hex + (j * 2), "%02x", block->proposer_id[j]);
                    }
                    proposer_hex[PROP_ID_SIZE * 2] = '\0';
                    cJSON_AddStringToObject(block_obj, "creatorPubkey", proposer_hex);
                    
                    cJSON_AddNumberToObject(block_obj, "timestamp", block->timestamp);
                    cJSON_AddNumberToObject(block_obj, "nonce", 0); // PBFT doesn't use nonce
                    cJSON_AddNumberToObject(block_obj, "difficulty", 0); // PBFT doesn't use difficulty
                    
                    // Add transactions array
                    cJSON* transactions = cJSON_CreateArray();
                    for (int32_t tx_idx = 0; tx_idx < block->txn_count; tx_idx++) {
                        TW_Transaction* tx = block->txns[tx_idx];
                        if (tx) {
                            cJSON* tx_obj = cJSON_CreateObject();
                            
                            // Create transaction hash (simplified)
                            char tx_hash[65];
                            snprintf(tx_hash, sizeof(tx_hash), "0x%08x%08x%08x%08x", 
                                   (unsigned int)tx->timestamp, 
                                   (unsigned int)block_index,
                                   (unsigned int)tx_idx,
                                   (unsigned int)tx->type);
                            cJSON_AddStringToObject(tx_obj, "hash", tx_hash);
                            
                            cJSON_AddNumberToObject(tx_obj, "timestamp", tx->timestamp);
                            
                            // Convert sender to hex
                            char sender_hex[PUBKEY_SIZE * 2 + 1];
                            for (int k = 0; k < PUBKEY_SIZE; k++) {
                                sprintf(sender_hex + (k * 2), "%02x", tx->sender[k]);
                            }
                            sender_hex[PUBKEY_SIZE * 2] = '\0';
                            cJSON_AddStringToObject(tx_obj, "fromPubkey", sender_hex);
                            
                            // For toPubkey, use first recipient if available
                            if (tx->recipient_count > 0) {
                                char recipient_hex[PUBKEY_SIZE * 2 + 1];
                                for (int k = 0; k < PUBKEY_SIZE; k++) {
                                    sprintf(recipient_hex + (k * 2), "%02x", tx->recipients[k]);
                                }
                                recipient_hex[PUBKEY_SIZE * 2] = '\0';
                                cJSON_AddStringToObject(tx_obj, "toPubkey", recipient_hex);
                            } else {
                                cJSON_AddStringToObject(tx_obj, "toPubkey", "");
                            }
                            
                            cJSON_AddStringToObject(tx_obj, "data", "encrypted");
                            
                            // Convert signature to hex
                            char signature_hex[SIGNATURE_SIZE * 2 + 1];
                            for (int k = 0; k < SIGNATURE_SIZE; k++) {
                                sprintf(signature_hex + (k * 2), "%02x", tx->signature[k]);
                            }
                            signature_hex[SIGNATURE_SIZE * 2] = '\0';
                            cJSON_AddStringToObject(tx_obj, "signature", signature_hex);
                            
                            cJSON_AddNumberToObject(tx_obj, "type", tx->type);
                            
                            cJSON_AddItemToArray(transactions, tx_obj);
                        }
                    }
                    cJSON_AddItemToObject(block_obj, "transactions", transactions);
                    
                    cJSON_AddItemToArray(items, block_obj);
                }
            }
        }
    }
    
    // PaginatedResponse structure - use blockchain length for consistency
    // Recalculate total_pages with blockchain_length  
    total_pages = (blockchain_length + pageSize - 1) / pageSize;
    
    cJSON_AddItemToObject(resp, "items", items);
    cJSON_AddNumberToObject(resp, "total", blockchain_length); // Use actual blockchain length
    cJSON_AddNumberToObject(resp, "page", page);
    cJSON_AddNumberToObject(resp, "pageSize", pageSize);
    cJSON_AddBoolToObject(resp, "hasNext", page < total_pages);
    cJSON_AddBoolToObject(resp, "hasPrevious", page > 1);
    
    char* json_str = cJSON_PrintUnformatted(resp);
    if (json_str) {
        send_json_response(c, 200, json_str);
        free(json_str);
    } else {
        send_error_response(c, "Failed to serialize JSON response");
    }
    cJSON_Delete(resp);
}

void handle_get_transactions(struct mg_connection* c, struct mg_http_message* hm) {
    cJSON* resp = cJSON_CreateObject();
    cJSON* items = cJSON_CreateArray();
    
    // Parse pagination parameters from query string
    uint32_t page = 1;
    uint32_t pageSize = 20;
    
    if (hm->query.len > 0) {
        char query_str[256];
        size_t query_len = hm->query.len < sizeof(query_str) - 1 ? hm->query.len : sizeof(query_str) - 1;
        strncpy(query_str, hm->query.buf, query_len);
        query_str[query_len] = '\0';
        
        char* page_param = strstr(query_str, "page=");
        if (page_param) {
            page = atoi(page_param + 5);
            if (page < 1) page = 1;
        }
        
        char* pageSize_param = strstr(query_str, "pageSize=");
        if (pageSize_param) {
            pageSize = atoi(pageSize_param + 9);
            if (pageSize > 100) pageSize = 100; // Cap at 100
            if (pageSize < 1) pageSize = 20;    // Minimum 1
        }
    }
    
    // Create transaction filter for pagination
    TransactionFilter* filter = create_transaction_filter();
    if (!filter) {
        send_error_response(c, "Failed to create transaction filter");
        cJSON_Delete(resp);
        return;
    }
    
    filter->limit = pageSize;
    filter->offset = (page - 1) * pageSize;
    
    // Query transactions from database
    TransactionRecord* tx_results = NULL;
    size_t tx_count = 0;
    
    int query_result = query_transactions(filter, &tx_results, &tx_count);
    
    if (query_result == 0 && tx_count > 0) {
        for (size_t i = 0; i < tx_count; i++) {
            cJSON* tx_obj = cJSON_CreateObject();
            
            // Create transaction hash (simplified)
            char tx_hash[65];
            snprintf(tx_hash, sizeof(tx_hash), "0x%08lx%08x%08x%08x", 
                   tx_results[i].transaction_id,
                   tx_results[i].block_index,
                   tx_results[i].transaction_index,
                   tx_results[i].type);
            cJSON_AddStringToObject(tx_obj, "hash", tx_hash);
            
            cJSON_AddNumberToObject(tx_obj, "timestamp", tx_results[i].timestamp);
            cJSON_AddStringToObject(tx_obj, "fromPubkey", tx_results[i].sender);
            
            // For toPubkey, we would need to query recipients table
            // For now, use empty string or first recipient if available
            cJSON_AddStringToObject(tx_obj, "toPubkey", ""); // TODO: Query recipients
            
            cJSON_AddStringToObject(tx_obj, "data", "encrypted");
            cJSON_AddStringToObject(tx_obj, "signature", tx_results[i].signature);
            cJSON_AddNumberToObject(tx_obj, "type", tx_results[i].type);
            
            cJSON_AddItemToArray(items, tx_obj);
        }
        
        db_free_transaction_records(tx_results, tx_count);
    } else {
        // Free results even if we don't process them
        if (tx_results) {
            db_free_transaction_records(tx_results, tx_count);
        }
    }
    
    // Get total transaction count for pagination
    uint64_t total_transactions = 0;
    if (db_is_initialized()) {
        db_get_transaction_count(&total_transactions);
    }
    
    // Calculate pagination info
    uint32_t total_pages = (total_transactions + pageSize - 1) / pageSize;
    
    // PaginatedResponse structure
    cJSON_AddItemToObject(resp, "items", items);
    cJSON_AddNumberToObject(resp, "total", total_transactions);
    cJSON_AddNumberToObject(resp, "page", page);
    cJSON_AddNumberToObject(resp, "pageSize", pageSize);
    cJSON_AddBoolToObject(resp, "hasNext", page < total_pages);
    cJSON_AddBoolToObject(resp, "hasPrevious", page > 1);
    
    free_transaction_filter(filter);
    
    char* json_str = cJSON_PrintUnformatted(resp);
    if (json_str) {
        send_json_response(c, 200, json_str);
        free(json_str);
    } else {
        send_error_response(c, "Failed to serialize JSON response");
    }
    cJSON_Delete(resp);
} 