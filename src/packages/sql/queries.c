#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include "queries.h"
#include "database.h"
#include "schema.h"

// Helper to get database handle
static sqlite3* get_db_handle(void) {
    return db_get_handle();
}

// Helper function to build dynamic SQL queries
static char* build_transaction_query(const TransactionFilter* filter, bool count_only) {
    char* query = malloc(2048);
    if (!query) return NULL;

    if (count_only) {
        strcpy(query, "SELECT COUNT(*) FROM transactions t");
    } else {
        strcpy(query, 
            "SELECT t.id, t.block_index, t.transaction_index, t.type, t.sender, t.timestamp, "
            "t.recipient_count, t.group_id, t.signature, t.payload_size, t.encrypted_payload, "
            "t.decrypted_content, t.is_decrypted FROM transactions t");
    }

    bool has_where = false;
    bool needs_join = false;

    // Check if we need to join with recipients table
    if (filter && filter->recipient_pubkey) {
        strcat(query, " JOIN transaction_recipients tr ON t.id = tr.transaction_id");
        needs_join = true;
    }

    // Add WHERE conditions
    if (filter) {
        if (filter->sender_pubkey) {
            strcat(query, has_where ? " AND" : " WHERE");
            strcat(query, " t.sender = ?");
            has_where = true;
        }

        if (filter->recipient_pubkey) {
            strcat(query, has_where ? " AND" : " WHERE");
            strcat(query, " tr.recipient_pubkey = ?");
            has_where = true;
        }

        if (filter->type < TW_TXN_TYPE_COUNT) {
            strcat(query, has_where ? " AND" : " WHERE");
            strcat(query, " t.type = ?");
            has_where = true;
        }

        if (filter->start_timestamp > 0) {
            strcat(query, has_where ? " AND" : " WHERE");
            strcat(query, " t.timestamp >= ?");
            has_where = true;
        }

        if (filter->end_timestamp > 0) {
            strcat(query, has_where ? " AND" : " WHERE");
            strcat(query, " t.timestamp <= ?");
            has_where = true;
        }

        if (filter->start_block > 0) {
            strcat(query, has_where ? " AND" : " WHERE");
            strcat(query, " t.block_index >= ?");
            has_where = true;
        }

        if (filter->end_block > 0) {
            strcat(query, has_where ? " AND" : " WHERE");
            strcat(query, " t.block_index <= ?");
            has_where = true;
        }

        if (filter->group_id) {
            strcat(query, has_where ? " AND" : " WHERE");
            strcat(query, " t.group_id = ?");
            has_where = true;
        }

        if (filter->only_decrypted) {
            strcat(query, has_where ? " AND" : " WHERE");
            strcat(query, " t.is_decrypted = 1");
            has_where = true;
        }
    }

    if (!count_only) {
        strcat(query, " ORDER BY t.timestamp DESC");
        
        if (filter && filter->limit > 0) {
            strcat(query, " LIMIT ?");
            if (filter->offset > 0) {
                strcat(query, " OFFSET ?");
            }
        }
    }

    return query;
}

// Helper function to bind parameters to prepared statement
static int bind_transaction_filter_params(sqlite3_stmt* stmt, const TransactionFilter* filter, bool count_only) {
    int param_index = 1;

    if (!filter) return 0;

    if (filter->sender_pubkey) {
        sqlite3_bind_text(stmt, param_index++, filter->sender_pubkey, -1, SQLITE_STATIC);
    }

    if (filter->recipient_pubkey) {
        sqlite3_bind_text(stmt, param_index++, filter->recipient_pubkey, -1, SQLITE_STATIC);
    }

    if (filter->type < TW_TXN_TYPE_COUNT) {
        sqlite3_bind_int(stmt, param_index++, filter->type);
    }

    if (filter->start_timestamp > 0) {
        sqlite3_bind_int64(stmt, param_index++, filter->start_timestamp);
    }

    if (filter->end_timestamp > 0) {
        sqlite3_bind_int64(stmt, param_index++, filter->end_timestamp);
    }

    if (filter->start_block > 0) {
        sqlite3_bind_int(stmt, param_index++, filter->start_block);
    }

    if (filter->end_block > 0) {
        sqlite3_bind_int(stmt, param_index++, filter->end_block);
    }

    if (filter->group_id) {
        sqlite3_bind_text(stmt, param_index++, filter->group_id, -1, SQLITE_STATIC);
    }

    if (!count_only && filter->limit > 0) {
        sqlite3_bind_int(stmt, param_index++, filter->limit);
        if (filter->offset > 0) {
            sqlite3_bind_int(stmt, param_index++, filter->offset);
        }
    }

    return 0;
}

// Helper function to populate TransactionRecord from SQL result
static void populate_transaction_record(sqlite3_stmt* stmt, TransactionRecord* record) {
    record->transaction_id = sqlite3_column_int64(stmt, 0);
    record->block_index = sqlite3_column_int(stmt, 1);
    record->transaction_index = sqlite3_column_int(stmt, 2);
    record->type = sqlite3_column_int(stmt, 3);
    
    const char* sender = (const char*)sqlite3_column_text(stmt, 4);
    if (sender) strncpy(record->sender, sender, sizeof(record->sender) - 1);
    
    record->timestamp = sqlite3_column_int64(stmt, 5);
    record->recipient_count = sqlite3_column_int(stmt, 6);
    
    const char* group_id = (const char*)sqlite3_column_text(stmt, 7);
    if (group_id) strncpy(record->group_id, group_id, sizeof(record->group_id) - 1);
    
    const char* signature = (const char*)sqlite3_column_text(stmt, 8);
    if (signature) strncpy(record->signature, signature, sizeof(record->signature) - 1);
    
    record->payload_size = sqlite3_column_int(stmt, 9);
    
    // Handle encrypted payload blob
    const void* payload_blob = sqlite3_column_blob(stmt, 10);
    int payload_blob_size = sqlite3_column_bytes(stmt, 10);
    if (payload_blob && payload_blob_size > 0) {
        record->encrypted_payload = malloc(payload_blob_size);
        if (record->encrypted_payload) {
            memcpy(record->encrypted_payload, payload_blob, payload_blob_size);
        }
    } else {
        record->encrypted_payload = NULL;
    }
    
    // Handle decrypted content
    const char* decrypted = (const char*)sqlite3_column_text(stmt, 11);
    if (decrypted) {
        record->decrypted_content = malloc(strlen(decrypted) + 1);
        if (record->decrypted_content) {
            strcpy(record->decrypted_content, decrypted);
        }
    } else {
        record->decrypted_content = NULL;
    }
    
    record->is_decrypted = sqlite3_column_int(stmt, 12) != 0;
}

// High-level query functions
int query_transactions(const TransactionFilter* filter, TransactionRecord** results, size_t* count) {
    if (!db_is_initialized() || !results || !count) {
        return -1;
    }

    *results = NULL;
    *count = 0;

    // First, get the count
    char* count_query = build_transaction_query(filter, true);
    if (!count_query) return -1;
    
    // Query logging removed

    sqlite3_stmt* count_stmt;
    sqlite3* db = get_db_handle();
    if (!db) return -1;
    
    int rc = sqlite3_prepare_v2(db, count_query, -1, &count_stmt, NULL);
    free(count_query);

    if (rc != SQLITE_OK) {
        return -1;
    }

    bind_transaction_filter_params(count_stmt, filter, true);
    
    rc = sqlite3_step(count_stmt);
    if (rc == SQLITE_ROW) {
        *count = sqlite3_column_int64(count_stmt, 0);
        // Count logged
    }
    sqlite3_finalize(count_stmt);

    if (*count == 0) {
        return 0;
    }

    // Now get the actual results
    char* data_query = build_transaction_query(filter, false);
    if (!data_query) return -1;
    
    // Query logging removed

    sqlite3_stmt* data_stmt;
    rc = sqlite3_prepare_v2(db, data_query, -1, &data_stmt, NULL);
    free(data_query);

    if (rc != SQLITE_OK) {
        return -1;
    }

    bind_transaction_filter_params(data_stmt, filter, false);

    // Allocate results array
    *results = calloc(*count, sizeof(TransactionRecord));
    if (!*results) {
        sqlite3_finalize(data_stmt);
        return -1;
    }

    size_t result_index = 0;
    while (sqlite3_step(data_stmt) == SQLITE_ROW && result_index < *count) {
        populate_transaction_record(data_stmt, &(*results)[result_index]);
        result_index++;
    }

    sqlite3_finalize(data_stmt);
    *count = result_index;
    return 0;
}

// Convenience query functions
int query_messages_for_user(const char* user_pubkey, TransactionRecord** results, size_t* count) {
    TransactionFilter filter = {0};
    filter.sender_pubkey = (char*)user_pubkey;
    filter.type = TW_TXN_MESSAGE;
    filter.limit = 100;

    return query_transactions(&filter, results, count);
}

int query_recent_activity(uint32_t limit, TransactionRecord** results, size_t* count) {
    TransactionFilter filter = {0};
    filter.limit = limit;

    return query_transactions(&filter, results, count);
}

int query_transactions_by_type(TW_TransactionType type, uint32_t limit, TransactionRecord** results, size_t* count) {
    TransactionFilter filter = {0};
    filter.type = type;
    filter.limit = limit;

    return query_transactions(&filter, results, count);
}

int query_group_messages(const char* group_id, TransactionRecord** results, size_t* count) {
    TransactionFilter filter = {0};
    filter.group_id = (char*)group_id;
    filter.type = TW_TXN_GROUP_MESSAGE;

    return query_transactions(&filter, results, count);
}

int query_user_activity(const char* user_pubkey, uint64_t start_time, uint64_t end_time, TransactionRecord** results, size_t* count) {
    TransactionFilter filter = {0};
    filter.sender_pubkey = (char*)user_pubkey;
    filter.start_timestamp = start_time;
    filter.end_timestamp = end_time;

    return query_transactions(&filter, results, count);
}

// Statistics functions
int query_transaction_stats(uint64_t* total_count, uint64_t* message_count, uint64_t* system_count) {
    if (!db_is_initialized()) return -1;

    // Get total count
    if (total_count) {
        db_get_transaction_count(total_count);
    }

    // Get message count
    if (message_count) {
        TransactionFilter filter = {0};
        filter.type = TW_TXN_MESSAGE;
        size_t count;
        TransactionRecord* results;
        if (query_transactions(&filter, &results, &count) == 0) {
            *message_count = count;
            if (results) db_free_transaction_records(results, count);
        } else {
            *message_count = 0;
        }
    }

    // Get system config count
    if (system_count) {
        TransactionFilter filter = {0};
        filter.type = TW_TXN_SYSTEM_CONFIG;
        size_t count;
        TransactionRecord* results;
        if (query_transactions(&filter, &results, &count) == 0) {
            *system_count = count;
            if (results) db_free_transaction_records(results, count);
        } else {
            *system_count = 0;
        }
    }

    return 0;
}

// Helper functions for filters
TransactionFilter* create_transaction_filter(void) {
    TransactionFilter* filter = calloc(1, sizeof(TransactionFilter));
    if (filter) {
        filter->type = TW_TXN_TYPE_COUNT; // Use TYPE_COUNT as "no filter" sentinel
    }
    return filter;
}

void free_transaction_filter(TransactionFilter* filter) {
    if (!filter) return;
    
    if (filter->sender_pubkey) free(filter->sender_pubkey);
    if (filter->recipient_pubkey) free(filter->recipient_pubkey);
    if (filter->group_id) free(filter->group_id);
    free(filter);
}

BlockFilter* create_block_filter(void) {
    return calloc(1, sizeof(BlockFilter));
}

void free_block_filter(BlockFilter* filter) {
    if (filter) free(filter);
}

void free_block_records(BlockRecord* records, size_t count) {
    if (!records) return;
    
    for (size_t i = 0; i < count; i++) {
        // Free any dynamically allocated fields if they exist
        // Currently BlockRecord fields are all static, so no need to free individual fields
    }
    
    free(records);
}

// Node status management functions
int db_register_node(const char* node_id, const char* node_name, const char* ip_address, uint16_t port, bool is_validator) {
    if (!node_id || !node_name || !ip_address) return -1;
    
    sqlite3* db = get_db_handle();
    if (!db) return -1;
    
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, SQL_INSERT_NODE_STATUS, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare node registration statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    // Bind parameters (node_id appears twice in the query for heartbeat counting)
    sqlite3_bind_text(stmt, 1, node_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, node_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, ip_address, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, port);
    sqlite3_bind_int(stmt, 5, is_validator ? 1 : 0);
    sqlite3_bind_text(stmt, 6, node_id, -1, SQLITE_STATIC); // For heartbeat count lookup
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        printf("Failed to register node: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    printf("Node %s registered successfully\n", node_id);
    return 0;
}

int db_update_node_heartbeat(const char* node_id) {
    if (!node_id) return -1;
    
    sqlite3* db = get_db_handle();
    if (!db) return -1;
    
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, SQL_UPDATE_NODE_HEARTBEAT, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare heartbeat update statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, node_id, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        printf("Failed to update node heartbeat: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    return 0;
}

int db_set_node_offline(const char* node_id) {
    if (!node_id) return -1;
    
    sqlite3* db = get_db_handle();
    if (!db) return -1;
    
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, SQL_SET_NODE_OFFLINE, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare set offline statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, node_id, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        printf("Failed to set node offline: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    return 0;
}

int db_cleanup_stale_nodes(void) {
    sqlite3* db = get_db_handle();
    if (!db) return -1;
    
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, SQL_SET_STALE_NODES_OFFLINE, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare stale nodes cleanup statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    rc = sqlite3_step(stmt);
    int changes = sqlite3_changes(db);
    sqlite3_finalize(stmt);
    
    if (rc != SQLITE_DONE) {
        printf("Failed to cleanup stale nodes: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    if (changes > 0) {
        printf("Marked %d stale nodes as offline\n", changes);
    }
    
    return 0;
}

static void populate_node_record(sqlite3_stmt* stmt, NodeStatusRecord* record) {
    const char* node_id = (const char*)sqlite3_column_text(stmt, 0);
    if (node_id) strncpy(record->node_id, node_id, sizeof(record->node_id) - 1);
    
    const char* node_name = (const char*)sqlite3_column_text(stmt, 1);
    if (node_name) strncpy(record->node_name, node_name, sizeof(record->node_name) - 1);
    
    const char* ip_address = (const char*)sqlite3_column_text(stmt, 2);
    if (ip_address) strncpy(record->ip_address, ip_address, sizeof(record->ip_address) - 1);
    
    record->port = (uint16_t)sqlite3_column_int(stmt, 3);
    record->is_validator = sqlite3_column_int(stmt, 4) != 0;
    
    const char* status = (const char*)sqlite3_column_text(stmt, 5);
    if (status) strncpy(record->status, status, sizeof(record->status) - 1);
    
    record->last_seen = sqlite3_column_int64(stmt, 6);
    record->heartbeat_count = sqlite3_column_int(stmt, 7);
}

int db_get_all_nodes(NodeStatusRecord** results, size_t* count) {
    if (!results || !count) return -1;
    
    sqlite3* db = get_db_handle();
    if (!db) return -1;
    
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, SQL_SELECT_ALL_NODES, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare get all nodes statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    // First count the results
    size_t result_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        result_count++;
    }
    
    sqlite3_reset(stmt);
    
    if (result_count == 0) {
        *results = NULL;
        *count = 0;
        sqlite3_finalize(stmt);
        return 0;
    }
    
    // Allocate memory for results
    NodeStatusRecord* records = malloc(sizeof(NodeStatusRecord) * result_count);
    if (!records) {
        sqlite3_finalize(stmt);
        return -1;
    }
    
    // Populate results
    size_t i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < result_count) {
        memset(&records[i], 0, sizeof(NodeStatusRecord));
        populate_node_record(stmt, &records[i]);
        i++;
    }
    
    sqlite3_finalize(stmt);
    
    *results = records;
    *count = result_count;
    return 0;
}

int db_get_online_nodes(NodeStatusRecord** results, size_t* count) {
    if (!results || !count) return -1;
    
    sqlite3* db = get_db_handle();
    if (!db) return -1;
    
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, SQL_SELECT_ONLINE_NODES, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare get online nodes statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    // First count the results
    size_t result_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        result_count++;
    }
    
    sqlite3_reset(stmt);
    
    if (result_count == 0) {
        *results = NULL;
        *count = 0;
        sqlite3_finalize(stmt);
        return 0;
    }
    
    // Allocate memory for results
    NodeStatusRecord* records = malloc(sizeof(NodeStatusRecord) * result_count);
    if (!records) {
        sqlite3_finalize(stmt);
        return -1;
    }
    
    // Populate results
    size_t i = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && i < result_count) {
        memset(&records[i], 0, sizeof(NodeStatusRecord));
        populate_node_record(stmt, &records[i]);
        i++;
    }
    
    sqlite3_finalize(stmt);
    
    *results = records;
    *count = result_count;
    return 0;
}

int db_count_total_nodes(uint32_t* count) {
    if (!count) return -1;
    
    sqlite3* db = get_db_handle();
    if (!db) return -1;
    
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, SQL_COUNT_TOTAL_NODES, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare count total nodes statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *count = (uint32_t)sqlite3_column_int(stmt, 0);
    } else {
        *count = 0;
    }
    
    sqlite3_finalize(stmt);
    return (rc == SQLITE_ROW) ? 0 : -1;
}

int db_count_online_nodes(uint32_t* count) {
    if (!count) return -1;
    
    sqlite3* db = get_db_handle();
    if (!db) return -1;
    
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, SQL_COUNT_ONLINE_NODES, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare count online nodes statement: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *count = (uint32_t)sqlite3_column_int(stmt, 0);
    } else {
        *count = 0;
    }
    
    sqlite3_finalize(stmt);
    return (rc == SQLITE_ROW) ? 0 : -1;
}

void db_free_node_records(NodeStatusRecord* records, size_t count) {
    if (!records) return;
    free(records);
} 