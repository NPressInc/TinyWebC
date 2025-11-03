#include "blockChainQueryApi.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cjson/cJSON.h>
#include "packages/sql/database.h"
#include "packages/sql/queries.h"
#include "pbftApi.h"
#include <unistd.h>

// Forward declarations
cJSON* create_transaction_json_with_payload(TransactionRecord* tx_record);

// JSON response helper functions
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

// JSON serialization helpers
char* block_to_json_string(TW_Block* block) {
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
    // STUB: This helper function is not used by API routes (deprecated in favor of database queries)
    cJSON* txns_array = cJSON_CreateArray();
    cJSON_AddItemToObject(block_obj, "transactions", txns_array);
    char* json_str = cJSON_PrintUnformatted(block_obj);
    cJSON_Delete(block_obj);
    return json_str;
}

char* transaction_to_json_string(TW_Transaction* tx) {
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
    // STUB: This helper function is not used by API routes (deprecated in favor of database queries)
    cJSON* recipients_array = cJSON_CreateArray();
    cJSON_AddItemToObject(tx_obj, "recipients", recipients_array);
    char* json_str = cJSON_PrintUnformatted(tx_obj);
    cJSON_Delete(tx_obj);
    return json_str;
}

// Utility function to get configured node count from network config
uint32_t get_configured_node_count(void) {
    // Read the network configuration file to get actual node count
    FILE* file = fopen("src/packages/initialization/configs/network_config.json", "r");
    if (!file) {
        // Fallback: try relative path from different working directories
        file = fopen("configs/network_config.json", "r");
        if (!file) {
            file = fopen("../configs/network_config.json", "r");
            if (!file) {
                // Default fallback if config file can't be read
                return 1;
            }
        }
    }

    // Read file content
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char* content = malloc(file_size + 1);
    if (!content) {
        fclose(file);
        return 1;
    }
    
    fread(content, 1, file_size, file);
    content[file_size] = '\0';
    fclose(file);

    // Parse JSON to count nodes
    cJSON* json = cJSON_Parse(content);
    free(content);
    
    if (!json) {
        return 1;
    }

    cJSON* nodes = cJSON_GetObjectItem(json, "nodes");
    uint32_t node_count = 1; // Default fallback
    
    if (nodes && cJSON_IsArray(nodes)) {
        node_count = (uint32_t)cJSON_GetArraySize(nodes);
    }
    
    cJSON_Delete(json);
    return node_count;
}

// REST API endpoint handlers
void handle_get_network_stats(struct mg_connection* c, struct mg_http_message* hm) {
    cJSON* resp = cJSON_CreateObject();
    if (!resp) {
        send_error_response(c, "Failed to create JSON response");
        return;
    }
    
    // Get actual network statistics from database only
    uint32_t total_blocks = 0;
    uint32_t blocks_with_transactions = 0;
    uint64_t total_transactions = 0;
    
    if (db_is_initialized()) {
        db_get_block_count(&total_blocks);
        db_get_block_count_with_transactions(&blocks_with_transactions);
        db_get_transaction_count(&total_transactions);
    }
    
    // Get node counts from consensus_nodes (authorized/active nodes)
    uint32_t total_nodes = 0;
    uint32_t online_nodes = 0;
    if (db_is_initialized()) {
        if (db_count_consensus_nodes(&total_nodes) != 0) {
            total_nodes = get_configured_node_count();
        }
        // For MVP, treat active consensus node count as online count
        online_nodes = total_nodes;
    } else {
        total_nodes = get_configured_node_count();
        online_nodes = total_nodes;
    }
    
    // Calculate average block time (in seconds) using database
    double average_block_time = 10.0; // Default 10 seconds
    
    // For now, use a reasonable default based on PBFT timing since
    // we don't have direct block timestamp queries implemented yet
    if (total_blocks > 1) {
        average_block_time = 10.0; // Based on our 10-second block creation interval
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
    
    // Get last block timestamp from recent activity since we don't have
    // direct block timestamp queries implemented yet
    uint64_t last_block_time = 0;
    TransactionRecord* recent_tx = NULL;
    size_t recent_count = 0;
    
    if (query_recent_activity(1, &recent_tx, &recent_count) == 0 && recent_tx && recent_count > 0) {
        last_block_time = recent_tx[0].timestamp;
        db_free_transaction_records(recent_tx, recent_count);
    }
    
    // Build JSON response matching the NetworkStats interface
    cJSON_AddNumberToObject(resp, "totalNodes", total_nodes);
    cJSON_AddNumberToObject(resp, "onlineNodes", online_nodes);
    cJSON_AddNumberToObject(resp, "totalBlocks", total_blocks);
    cJSON_AddNumberToObject(resp, "blocksWithTransactions", blocks_with_transactions);
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
    
    // Note: Return empty activity array if no database activity found
    // This is more accurate than showing test data
    
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
    const char* hash_start = strstr(hm->uri.buf, "/api/blocks/");
    if (hash_start) {
        hash_start += strlen("/api/blocks/");
        size_t hash_len = hm->uri.len - (hash_start - hm->uri.buf);
        if (hash_len < HASH_HEX_SIZE) {
            strncpy(hash, hash_start, hash_len);
            hash[hash_len] = '\0';
        }
    }
    
    cJSON* resp = cJSON_CreateObject();
    
    if (strlen(hash) == 0) {
        cJSON_AddStringToObject(resp, "error", "Invalid block hash");
        char* json_str = cJSON_PrintUnformatted(resp);
        send_json_response(c, 400, json_str);
        free(json_str);
        cJSON_Delete(resp);
        return;
    }
    
    // Look up block by hash in database
    ApiBlockRecord* block_record = NULL;
    if (db_get_block_by_hash(hash, &block_record) == 0 && block_record) {
        // Convert block record to JSON response
        cJSON* block_data = cJSON_CreateObject();
        cJSON_AddStringToObject(block_data, "hash", block_record->hash);
        cJSON_AddNumberToObject(block_data, "height", block_record->height);
        cJSON_AddStringToObject(block_data, "previousHash", block_record->previous_hash);
        cJSON_AddNumberToObject(block_data, "timestamp", block_record->timestamp);
        cJSON_AddNumberToObject(block_data, "transactionCount", block_record->transaction_count);
        
        // Add transactions array if block has transactions
        if (block_record->transaction_count > 0 && block_record->transactions) {
            cJSON* transactions = cJSON_CreateArray();
            for (size_t i = 0; i < block_record->transaction_count; i++) {
                TransactionRecord* tx = &block_record->transactions[i];
                cJSON* tx_obj = cJSON_CreateObject();
                                 // Create transaction hash based on transaction ID
                 char tx_hash[65];
                 snprintf(tx_hash, sizeof(tx_hash), "0x%016lx", tx->transaction_id);
                 cJSON_AddStringToObject(tx_obj, "hash", tx_hash);
                 
                 cJSON_AddStringToObject(tx_obj, "type", get_transaction_type_name(tx->type));
                 cJSON_AddNumberToObject(tx_obj, "timestamp", tx->timestamp);
                 cJSON_AddStringToObject(tx_obj, "sender", tx->sender);
                 
                 // STUB: Recipient information requires additional query
                 cJSON_AddStringToObject(tx_obj, "recipient", "[Multiple recipients - see recipient_count]");
                 cJSON_AddNumberToObject(tx_obj, "recipient_count", tx->recipient_count);
                 
                 // STUB: Amount field not applicable to this blockchain system
                 cJSON_AddNumberToObject(tx_obj, "amount", 0);
                cJSON_AddItemToArray(transactions, tx_obj);
            }
            cJSON_AddItemToObject(block_data, "transactions", transactions);
        }
        
        cJSON_AddItemToObject(resp, "block", block_data);
        cJSON_AddBoolToObject(resp, "found", true);
        
        // Free the block record
        db_free_block_record(block_record);
        
        char* json_str = cJSON_PrintUnformatted(resp);
        send_json_response(c, 200, json_str);
        free(json_str);
    } else {
        // Block not found
        cJSON_AddBoolToObject(resp, "found", false);
        cJSON_AddStringToObject(resp, "message", "Block not found");
        cJSON_AddStringToObject(resp, "requestedHash", hash);
        
        char* json_str = cJSON_PrintUnformatted(resp);
        send_json_response(c, 404, json_str); // 404 Not Found
        free(json_str);
    }
    
    cJSON_Delete(resp);
}

void handle_get_family_members(struct mg_connection* c, struct mg_http_message* hm) {
    cJSON* members = cJSON_CreateArray();
    
    if (db_is_initialized()) {
        // Query user registration transactions to get family members
        TransactionRecord* user_results = NULL;
        size_t user_count = 0;
        
        if (query_transactions_by_type(TW_TXN_USER_REGISTRATION, 1000, &user_results, &user_count) == 0 && user_results) {
            for (size_t i = 0; i < user_count; i++) {
                cJSON* member = cJSON_CreateObject();
                
                // Add basic user information from the transaction
                cJSON_AddStringToObject(member, "publicKey", user_results[i].sender);
                
                // Extract name from decrypted content if available, otherwise use default
                const char* name = "Unknown User";
                if (user_results[i].is_decrypted && user_results[i].decrypted_content) {
                    // In a real system, you'd parse the decrypted JSON to extract the name
                    name = "Family Member"; // Placeholder
                }
                cJSON_AddStringToObject(member, "name", name);
                
                // Default values - in a real system, you'd query role assignment transactions
                // to get the actual role and permissions for each user
                cJSON_AddStringToObject(member, "role", "member");
                cJSON_AddNumberToObject(member, "permissions", 31); // Default permissions
                cJSON_AddBoolToObject(member, "requiresSupervision", false);
                
                // Use transaction timestamp as join time
                cJSON_AddNumberToObject(member, "joinedAt", user_results[i].timestamp);
                
                // For last active time, use the registration timestamp for now
                // In a full implementation, you'd query all transactions by this user
                uint64_t last_active = user_results[i].timestamp;
                
                cJSON_AddNumberToObject(member, "lastActive", last_active);
                cJSON_AddStringToObject(member, "status", "active");
                
                cJSON_AddItemToArray(members, member);
            }
            
            db_free_transaction_records(user_results, user_count);
        }
        
        // Note: If no users are found in database, return empty array
        // This is more accurate than showing fake data
    } else {
        // Database not available - this indicates a system error
        // Return empty array rather than fake data
    }
    
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
    
    // Note: Return empty activity array if no database activity found
    // This is more accurate than showing test data
    
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
    
    // Get total block count with transactions from database (only blocks that have transactions)
    uint32_t total_blocks_with_transactions = 0;
    if (db_is_initialized()) {
        db_get_block_count_with_transactions(&total_blocks_with_transactions);
    }
    
    // Calculate initial pagination parameters (will be updated after finding actual unique blocks)
    uint32_t start_index = (page - 1) * pageSize;
    uint32_t end_index = start_index + pageSize;
    
    // Query ALL transactions to properly identify blocks that have transactions
    if (db_is_initialized() && total_blocks_with_transactions > 0) {
        // Step 1: Get ALL transactions to find all unique blocks
        TransactionRecord* all_tx_results = NULL;
        size_t all_tx_count = 0;
        
        // Query ALL transactions using the transaction filter
        TransactionFilter* filter = create_transaction_filter();
        if (filter) {
            // Don't limit the query - get all transactions
            filter->limit = 0; // 0 typically means no limit
            filter->offset = 0;
            
            if (query_transactions(filter, &all_tx_results, &all_tx_count) == 0 && all_tx_results) {
                // Step 2: Find ALL unique block indices that have transactions
                uint32_t* all_unique_blocks = malloc(total_blocks_with_transactions * sizeof(uint32_t));
                uint32_t all_unique_count = 0;
                
                if (all_unique_blocks) {
                    // Collect all unique block indices (newest first by processing transactions in reverse order)
                    for (int i = all_tx_count - 1; i >= 0; i--) {
                        uint32_t block_index = all_tx_results[i].block_index;
                        
                        // Check if this block index is already in our list
                        bool already_added = false;
                        for (uint32_t j = 0; j < all_unique_count; j++) {
                            if (all_unique_blocks[j] == block_index) {
                                already_added = true;
                                break;
                            }
                        }
                        
                        if (!already_added) {
                            all_unique_blocks[all_unique_count] = block_index;
                            all_unique_count++;
                        }
                    }
                    
                    // Step 3: Apply pagination to the complete list of unique blocks
                    uint32_t blocks_to_show = 0;
                    for (uint32_t i = start_index; i < end_index && i < all_unique_count; i++) {
                        uint32_t block_index = all_unique_blocks[i];
                        
                        cJSON* block_obj = cJSON_CreateObject();
                        
                        // Performance optimization: Use only database data
                        // Block metadata will be derived from transaction data
                        
                        // Generate block identifier based on index
                        char block_hash[65];
                        snprintf(block_hash, sizeof(block_hash), "block_%u", block_index);
                        
                        // Use transaction timestamp as block timestamp (from first transaction in block)
                        uint64_t block_timestamp = time(NULL) - (block_index * 10); // Fallback
                        uint32_t transaction_count = 0;
                        
                        for (size_t k = 0; k < all_tx_count; k++) {
                            if (all_tx_results[k].block_index == block_index) {
                                if (transaction_count == 0) {
                                    // Use first transaction's timestamp as block timestamp
                                    block_timestamp = all_tx_results[k].timestamp;
                                }
                                transaction_count++;
                            }
                        }
                        
                        // Add database-derived block information
                        cJSON_AddStringToObject(block_obj, "hash", block_hash);
                        cJSON_AddNumberToObject(block_obj, "index", block_index);
                        cJSON_AddNumberToObject(block_obj, "timestamp", block_timestamp);
                        cJSON_AddNumberToObject(block_obj, "transactionCount", transaction_count);
                        
                        // STUB: Block hash, previousHash, merkleRoot, creatorPubkey require database schema extension
                        cJSON_AddStringToObject(block_obj, "previousHash", "[Requires database schema update]");
                        cJSON_AddStringToObject(block_obj, "merkleRoot", "[Requires database schema update]");
                        cJSON_AddStringToObject(block_obj, "creatorPubkey", "[Requires database schema update]");
                        cJSON_AddNumberToObject(block_obj, "nonce", 0); // PBFT doesn't use nonce
                        cJSON_AddNumberToObject(block_obj, "difficulty", 0); // PBFT doesn't use difficulty
                        
                        // Step 4: Add all transactions from this specific block
                        cJSON* transactions = cJSON_CreateArray();
                        
                        // Find all transactions for this specific block
                        for (size_t j = 0; j < all_tx_count; j++) {
                            if (all_tx_results[j].block_index == block_index) {
                                cJSON* tx_obj = cJSON_CreateObject();
                                
                                // Create transaction hash
                                char tx_hash[65];
                                snprintf(tx_hash, sizeof(tx_hash), "0x%08lx%08x%08x%08x", 
                                       all_tx_results[j].transaction_id,
                                       all_tx_results[j].block_index,
                                       all_tx_results[j].transaction_index,
                                       all_tx_results[j].type);
                                cJSON_AddStringToObject(tx_obj, "hash", tx_hash);
                                
                                cJSON_AddNumberToObject(tx_obj, "timestamp", all_tx_results[j].timestamp);
                                cJSON_AddStringToObject(tx_obj, "fromPubkey", all_tx_results[j].sender);
                                // STUB: Recipient lookup not implemented yet
                                cJSON_AddStringToObject(tx_obj, "toPubkey", "[Recipient lookup not implemented]");
                                cJSON_AddStringToObject(tx_obj, "data", "encrypted");
                                cJSON_AddStringToObject(tx_obj, "signature", all_tx_results[j].signature);
                                cJSON_AddNumberToObject(tx_obj, "type", all_tx_results[j].type);
                                
                                cJSON_AddItemToArray(transactions, tx_obj);
                            }
                        }
                        
                        cJSON_AddItemToObject(block_obj, "transactions", transactions);
                        cJSON_AddItemToArray(items, block_obj);
                        blocks_to_show++;
                    }
                    
                    // Update the total count with the actual number of unique blocks found
                    total_blocks_with_transactions = all_unique_count;
                    
                    free(all_unique_blocks);
                }
                
                db_free_transaction_records(all_tx_results, all_tx_count);
            }
            
            free_transaction_filter(filter);
        }
    }
    
    // Calculate pagination info based on actual unique blocks found
    uint32_t total_pages = (total_blocks_with_transactions + pageSize - 1) / pageSize;
    
    cJSON_AddItemToObject(resp, "items", items);
    cJSON_AddNumberToObject(resp, "total", total_blocks_with_transactions); // Use count of blocks with transactions
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
            cJSON* tx_obj = create_transaction_json_with_payload(&tx_results[i]);
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

// Handle health check endpoint
void handle_health_check(struct mg_connection* c, struct mg_http_message* hm) {
    cJSON* resp = cJSON_CreateObject();
    cJSON_AddStringToObject(resp, "status", "healthy");
    cJSON_AddNumberToObject(resp, "timestamp", time(NULL));
    cJSON_AddStringToObject(resp, "version", "1.0.0");
    cJSON_AddStringToObject(resp, "service", "TinyWeb PBFT Node");
    
    char* json_str = cJSON_PrintUnformatted(resp);
    send_json_response(c, 200, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

// Handle blockchain info endpoint
void handle_get_blockchain_info(struct mg_connection* c, struct mg_http_message* hm) {
    cJSON* resp = cJSON_CreateObject();
    
    if (db_is_initialized()) {
        uint32_t total_blocks = 0;
        uint64_t total_transactions = 0;
        
        // Get blockchain stats from database
        if (db_get_block_count(&total_blocks) == 0 && 
            db_get_transaction_count(&total_transactions) == 0) {
            
            cJSON* blocks_array = cJSON_CreateArray();
            cJSON_AddItemToObject(resp, "blocks", blocks_array);
            cJSON_AddNumberToObject(resp, "length", total_blocks);
            
            // STUB: Creator public key would need to be stored in database
            cJSON_AddStringToObject(resp, "creatorPubkey", "Node Creator Public Key");
            
            // Additional stats
            cJSON_AddNumberToObject(resp, "totalTransactions", total_transactions);
            cJSON_AddNumberToObject(resp, "lastUpdated", time(NULL));
            
        } else {
            cJSON_AddStringToObject(resp, "error", "Failed to retrieve blockchain statistics");
            char* json_str = cJSON_PrintUnformatted(resp);
            send_json_response(c, 500, json_str);
            free(json_str);
            cJSON_Delete(resp);
            return;
        }
    } else {
        cJSON_AddStringToObject(resp, "error", "Database not initialized");
        char* json_str = cJSON_PrintUnformatted(resp);
        send_json_response(c, 503, json_str);
        free(json_str);
        cJSON_Delete(resp);
        return;
    }
    
    char* json_str = cJSON_PrintUnformatted(resp);
    send_json_response(c, 200, json_str);
    free(json_str);
    cJSON_Delete(resp);
}

// Handle get transaction by hash endpoint  
void handle_get_transaction_by_hash(struct mg_connection* c, struct mg_http_message* hm) {
    // Parse hash from URL (assume /api/transactions/{hash})
    char hash[65] = {0};
    const char* hash_start = strstr(hm->uri.buf, "/api/transactions/");
    if (hash_start) {
        hash_start += strlen("/api/transactions/");
        size_t hash_len = hm->uri.len - (hash_start - hm->uri.buf);
        if (hash_len < sizeof(hash)) {
            strncpy(hash, hash_start, hash_len);
            hash[hash_len] = '\0';
        }
    }
    
    cJSON* resp = cJSON_CreateObject();
    
    if (strlen(hash) == 0) {
        cJSON_AddStringToObject(resp, "error", "Invalid transaction hash");
        char* json_str = cJSON_PrintUnformatted(resp);
        send_json_response(c, 400, json_str);
        free(json_str);
        cJSON_Delete(resp);
        return;
    }
    
    // STUB: Transaction lookup by hash not implemented yet
    // This would require implementing transaction hash indexing in the database
    cJSON_AddBoolToObject(resp, "found", false);
    cJSON_AddStringToObject(resp, "message", "Transaction lookup by hash not implemented yet");
    cJSON_AddStringToObject(resp, "requestedHash", hash);
    cJSON_AddStringToObject(resp, "note", "Transactions can be queried by sender, type, or block index using existing endpoints");
    
    char* json_str = cJSON_PrintUnformatted(resp);
    send_json_response(c, 501, json_str); // 501 Not Implemented
    free(json_str);
    cJSON_Delete(resp);
}

// Add this function to create detailed transaction JSON with encrypted payload
cJSON* create_transaction_json_with_payload(TransactionRecord* tx_record) {
    cJSON* tx_obj = cJSON_CreateObject();
    
    // Basic transaction info
    char tx_hash[65];
    snprintf(tx_hash, sizeof(tx_hash), "0x%08lx%08x%08x%08x", 
           tx_record->transaction_id, tx_record->block_index, 
           tx_record->transaction_index, tx_record->type);
    cJSON_AddStringToObject(tx_obj, "hash", tx_hash);
    
    cJSON_AddNumberToObject(tx_obj, "timestamp", tx_record->timestamp);
    cJSON_AddStringToObject(tx_obj, "fromPubkey", tx_record->sender);
    cJSON_AddStringToObject(tx_obj, "signature", tx_record->signature);
    cJSON_AddNumberToObject(tx_obj, "type", tx_record->type);
    cJSON_AddNumberToObject(tx_obj, "recipientCount", tx_record->recipient_count);
    
    // Query and add actual recipient list
    char** recipients = NULL;
    size_t recipient_count = 0;
    if (db_get_recipients_for_transaction(tx_record->transaction_id, &recipients, &recipient_count) == 0 && recipients) {
        cJSON* recipients_array = cJSON_CreateArray();
        for (size_t i = 0; i < recipient_count; i++) {
            cJSON_AddItemToArray(recipients_array, cJSON_CreateString(recipients[i]));
        }
        cJSON_AddItemToObject(tx_obj, "recipients", recipients_array);
        
        // Also set toPubkey for backward compatibility (first recipient or "[Multiple recipients]")
        if (recipient_count == 1) {
            cJSON_AddStringToObject(tx_obj, "toPubkey", recipients[0]);
        } else if (recipient_count > 1) {
            cJSON_AddStringToObject(tx_obj, "toPubkey", "[Multiple recipients]");
        } else {
            cJSON_AddStringToObject(tx_obj, "toPubkey", "[No recipients]");
        }
        
        db_free_recipients(recipients, recipient_count);
    } else {
        // Fallback if recipient lookup fails
        cJSON_AddItemToObject(tx_obj, "recipients", cJSON_CreateArray());
        cJSON_AddStringToObject(tx_obj, "toPubkey", "[Recipient lookup failed]");
    }
    
    // Add encrypted payload details if present
    if (tx_record->encrypted_payload && tx_record->payload_size > 0) {
        // Deserialize the encrypted payload from the stored blob
        const char* payload_ptr = (const char*)tx_record->encrypted_payload;
        EncryptedPayload* payload = encrypted_payload_deserialize(&payload_ptr);
        
        if (payload) {
            cJSON* payload_obj = cJSON_CreateObject();
            
            // Add payload metadata
            cJSON_AddNumberToObject(payload_obj, "size", tx_record->payload_size);
            cJSON_AddNumberToObject(payload_obj, "numRecipients", payload->num_recipients);
            cJSON_AddNumberToObject(payload_obj, "ciphertextLength", payload->ciphertext_len);
            
            // Add ephemeral public key (hex encoded)
            char ephemeral_hex[PUBKEY_SIZE * 2 + 1];
            for (int k = 0; k < PUBKEY_SIZE; k++) {
                sprintf(ephemeral_hex + (k * 2), "%02x", payload->ephemeral_pubkey[k]);
            }
            cJSON_AddStringToObject(payload_obj, "ephemeralPubkey", ephemeral_hex);
            
            // Add nonce (hex encoded)
            char nonce_hex[NONCE_SIZE * 2 + 1];
            for (int k = 0; k < NONCE_SIZE; k++) {
                sprintf(nonce_hex + (k * 2), "%02x", payload->nonce[k]);
            }
            cJSON_AddStringToObject(payload_obj, "nonce", nonce_hex);
            
            // Add encrypted ciphertext (hex encoded)
            if (payload->ciphertext && payload->ciphertext_len > 0) {
                char* ciphertext_hex = malloc(payload->ciphertext_len * 2 + 1);
                if (ciphertext_hex) {
                    for (size_t k = 0; k < payload->ciphertext_len; k++) {
                        sprintf(ciphertext_hex + (k * 2), "%02x", payload->ciphertext[k]);
                    }
                    cJSON_AddStringToObject(payload_obj, "ciphertext", ciphertext_hex);
                    free(ciphertext_hex);
                }
            }
            
            // Add encrypted keys for each recipient
            if (payload->encrypted_keys && payload->key_nonces && payload->num_recipients > 0) {
                cJSON* keys_array = cJSON_CreateArray();
                for (size_t k = 0; k < payload->num_recipients; k++) {
                    cJSON* key_obj = cJSON_CreateObject();
                    
                    // Add encrypted key (hex encoded)
                    char key_hex[ENCRYPTED_KEY_SIZE * 2 + 1];
                    for (int l = 0; l < ENCRYPTED_KEY_SIZE; l++) {
                        sprintf(key_hex + (l * 2), "%02x", payload->encrypted_keys[k * ENCRYPTED_KEY_SIZE + l]);
                    }
                    cJSON_AddStringToObject(key_obj, "encryptedKey", key_hex);
                    
                    // Add key nonce (hex encoded)
                    char key_nonce_hex[NONCE_SIZE * 2 + 1];
                    for (int l = 0; l < NONCE_SIZE; l++) {
                        sprintf(key_nonce_hex + (l * 2), "%02x", payload->key_nonces[k * NONCE_SIZE + l]);
                    }
                    cJSON_AddStringToObject(key_obj, "keyNonce", key_nonce_hex);
                    
                    cJSON_AddItemToArray(keys_array, key_obj);
                }
                cJSON_AddItemToObject(payload_obj, "encryptedKeys", keys_array);
            }
            
            cJSON_AddItemToObject(tx_obj, "encryptedPayload", payload_obj);
            free_encrypted_payload(payload);
        } else {
            // Payload exists but couldn't be deserialized
            cJSON_AddStringToObject(tx_obj, "data", "encrypted (parse error)");
        }
    } else {
        // No payload or empty payload
        cJSON_AddStringToObject(tx_obj, "data", "no payload");
    }
    
    return tx_obj;
}
