#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include "database.h"
#include "schema.h"
#include "packages/encryption/encryption.h"
#include "packages/structures/blockChain/block.h"
#include "packages/structures/blockChain/transaction.h"

// Global database context
static DatabaseContext g_db_ctx = {0};

// Helper function to ensure directory exists
static bool ensure_directory_exists(const char* path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        #ifdef _WIN32
            if (_mkdir(path) == -1) {
        #else
            if (mkdir(path, 0700) == -1) {
        #endif
                printf("Failed to create directory: %s\n", path);
                return false;
            }
    }
    return true;
}

// Core database functions
int db_init(const char* db_path) {
    if (g_db_ctx.is_initialized) {
        printf("Database already initialized\n");
        return 0;
    }

    if (!db_path) {
        db_path = DEFAULT_DB_PATH;
    }

    // Ensure the directory exists
    char dir_path[256];
    strncpy(dir_path, db_path, sizeof(dir_path) - 1);
    dir_path[sizeof(dir_path) - 1] = '\0';
    
    char* last_slash = strrchr(dir_path, '/');
    if (last_slash) {
        *last_slash = '\0';
        if (!ensure_directory_exists(dir_path)) {
            return -1;
        }
    }

    // Open database
    int rc = sqlite3_open(db_path, &g_db_ctx.db);
    if (rc != SQLITE_OK) {
        printf("Failed to open database: %s\n", sqlite3_errmsg(g_db_ctx.db));
        sqlite3_close(g_db_ctx.db);
        return -1;
    }

    // Store database path
    g_db_ctx.db_path = malloc(strlen(db_path) + 1);
    if (!g_db_ctx.db_path) {
        sqlite3_close(g_db_ctx.db);
        return -1;
    }
    strcpy(g_db_ctx.db_path, db_path);

    // Configure WAL mode and other optimizations
    if (db_configure_wal_mode() != 0) {
        printf("Warning: Failed to configure WAL mode\n");
    }

    // Check schema version and migrate if necessary
    int current_version;
    if (schema_check_version(g_db_ctx.db, &current_version) != 0) {
        printf("Failed to check schema version\n");
        db_close();
        return -1;
    }

    if (current_version < CURRENT_SCHEMA_VERSION) {
        printf("Database schema needs migration from version %d to %d\n", 
               current_version, CURRENT_SCHEMA_VERSION);
        if (schema_migrate(g_db_ctx.db, current_version, CURRENT_SCHEMA_VERSION) != 0) {
            printf("Failed to migrate database schema\n");
            db_close();
            return -1;
        }
    }

    g_db_ctx.is_initialized = true;
    printf("Database initialized successfully: %s\n", db_path);
    return 0;
}

int db_close(void) {
    if (!g_db_ctx.is_initialized) {
        return 0;
    }

    if (g_db_ctx.db) {
        sqlite3_close(g_db_ctx.db);
        g_db_ctx.db = NULL;
    }

    if (g_db_ctx.db_path) {
        free(g_db_ctx.db_path);
        g_db_ctx.db_path = NULL;
    }

    g_db_ctx.is_initialized = false;
    g_db_ctx.wal_enabled = false;

    printf("Database closed successfully\n");
    return 0;
}

int db_configure_wal_mode(void) {
    if (!g_db_ctx.db) {
        return -1;
    }

    char* error_msg = NULL;
    int rc;

    // Enable WAL mode
    rc = sqlite3_exec(g_db_ctx.db, "PRAGMA journal_mode=WAL;", NULL, NULL, &error_msg);
    if (rc != SQLITE_OK) {
        printf("Failed to enable WAL mode: %s\n", error_msg);
        sqlite3_free(error_msg);
        return -1;
    }

    // Optimize for blockchain workload
    const char* optimizations[] = {
        "PRAGMA synchronous=NORMAL;",        // Faster writes
        "PRAGMA cache_size=10000;",          // More memory cache
        "PRAGMA temp_store=memory;",         // Temp tables in RAM
        "PRAGMA mmap_size=268435456;",       // 256MB memory mapping
        "PRAGMA wal_autocheckpoint=1000;",   // Auto-checkpoint every 1000 pages
        NULL
    };

    for (int i = 0; optimizations[i] != NULL; i++) {
        rc = sqlite3_exec(g_db_ctx.db, optimizations[i], NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            printf("Warning: Failed to apply optimization: %s\n", error_msg);
            sqlite3_free(error_msg);
        }
    }

    g_db_ctx.wal_enabled = true;
    printf("WAL mode and optimizations configured successfully\n");
    return 0;
}

bool db_is_initialized(void) {
    return g_db_ctx.is_initialized;
}

sqlite3* db_get_handle(void) {
    return g_db_ctx.is_initialized ? g_db_ctx.db : NULL;
}

// Utility functions
int db_hex_encode(const unsigned char* input, size_t input_len, char* output, size_t output_len) {
    if (output_len < (input_len * 2 + 1)) {
        return -1;
    }

    for (size_t i = 0; i < input_len; i++) {
        sprintf(output + (i * 2), "%02x", input[i]);
    }
    output[input_len * 2] = '\0';
    return 0;
}

int db_hex_decode(const char* input, unsigned char* output, size_t output_len) {
    size_t input_len = strlen(input);
    if (input_len % 2 != 0 || output_len < (input_len / 2)) {
        return -1;
    }

    for (size_t i = 0; i < input_len; i += 2) {
        unsigned int byte;
        if (sscanf(input + i, "%2x", &byte) != 1) {
            return -1;
        }
        output[i / 2] = (unsigned char)byte;
    }
    return input_len / 2;
}

// Blockchain synchronization functions
int db_sync_blockchain(TW_BlockChain* blockchain) {
    if (!g_db_ctx.is_initialized || !blockchain) {
        return -1;
    }

    printf("Syncing blockchain to database (%u blocks)...\n", blockchain->length);

    // Begin transaction for better performance
    sqlite3_exec(g_db_ctx.db, "BEGIN TRANSACTION;", NULL, NULL, NULL);

    // Update blockchain info
    if (db_update_blockchain_info(blockchain) != 0) {
        sqlite3_exec(g_db_ctx.db, "ROLLBACK;", NULL, NULL, NULL);
        return -1;
    }

    // Sync all blocks
    for (uint32_t i = 0; i < blockchain->length; i++) {
        if (db_add_block(blockchain->blocks[i], i) != 0) {
            printf("Failed to sync block %u\n", i);
            sqlite3_exec(g_db_ctx.db, "ROLLBACK;", NULL, NULL, NULL);
            return -1;
        }

        if (i % 100 == 0) {
            printf("Synced block %u/%u\n", i, blockchain->length);
        }
    }

    // Commit transaction
    int rc = sqlite3_exec(g_db_ctx.db, "COMMIT;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to commit blockchain sync transaction\n");
        return -1;
    }

    printf("Blockchain sync completed successfully\n");
    return 0;
}

int db_update_blockchain_info(TW_BlockChain* blockchain) {
    if (!g_db_ctx.is_initialized || !blockchain) {
        return -1;
    }

    sqlite3_stmt* stmt;
    int rc;

    // Convert creator pubkey to hex
    char creator_hex[PUBKEY_SIZE * 2 + 1];
    if (db_hex_encode(blockchain->creator_pubkey, PUBKEY_SIZE, creator_hex, sizeof(creator_hex)) != 0) {
        return -1;
    }

    rc = sqlite3_prepare_v2(g_db_ctx.db, SQL_INSERT_BLOCKCHAIN_INFO, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, creator_hex, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, blockchain->length);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int db_add_block(TW_Block* block, uint32_t block_index) {
    if (!g_db_ctx.is_initialized || !block) {
        return -1;
    }

    sqlite3_stmt* stmt;
    int rc;

    // Convert binary data to hex strings
    char prev_hash_hex[HASH_SIZE * 2 + 1];
    char merkle_hash_hex[HASH_SIZE * 2 + 1];
    char proposer_hex[PROP_ID_SIZE * 2 + 1];
    char block_hash_hex[HASH_SIZE * 2 + 1];

    if (db_hex_encode(block->previous_hash, HASH_SIZE, prev_hash_hex, sizeof(prev_hash_hex)) != 0 ||
        db_hex_encode(block->merkle_root_hash, HASH_SIZE, merkle_hash_hex, sizeof(merkle_hash_hex)) != 0 ||
        db_hex_encode(block->proposer_id, PROP_ID_SIZE, proposer_hex, sizeof(proposer_hex)) != 0) {
        return -1;
    }

    // Calculate block hash
    unsigned char block_hash[HASH_SIZE];
    if (!TW_Block_getHash(block, block_hash)) {
        return -1;
    }
    if (db_hex_encode(block_hash, HASH_SIZE, block_hash_hex, sizeof(block_hash_hex)) != 0) {
        return -1;
    }

    // Insert block
    rc = sqlite3_prepare_v2(g_db_ctx.db, SQL_INSERT_BLOCK, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, block_index);
    sqlite3_bind_int64(stmt, 2, block->timestamp);
    sqlite3_bind_text(stmt, 3, prev_hash_hex, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, merkle_hash_hex, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, proposer_hex, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 6, block->txn_count);
    sqlite3_bind_text(stmt, 7, block_hash_hex, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return -1;
    }

    // Add all transactions in this block
    for (int32_t i = 0; i < block->txn_count; i++) {
        if (db_add_transaction(block->txns[i], block_index, i) != 0) {
            return -1;
        }
    }

    return 0;
}

int db_add_transaction(TW_Transaction* tx, uint32_t block_index, uint32_t tx_index) {
    if (!g_db_ctx.is_initialized || !tx) {
        return -1;
    }

    sqlite3_stmt* stmt;
    int rc;

    // Convert binary data to hex strings
    char sender_hex[PUBKEY_SIZE * 2 + 1];
    char group_hex[GROUP_ID_SIZE * 2 + 1];
    char signature_hex[SIGNATURE_SIZE * 2 + 1];

    if (db_hex_encode(tx->sender, PUBKEY_SIZE, sender_hex, sizeof(sender_hex)) != 0 ||
        db_hex_encode(tx->group_id, GROUP_ID_SIZE, group_hex, sizeof(group_hex)) != 0 ||
        db_hex_encode(tx->signature, SIGNATURE_SIZE, signature_hex, sizeof(signature_hex)) != 0) {
        return -1;
    }

    // Serialize encrypted payload
    unsigned char* payload_data = NULL;
    size_t payload_size = 0;
    if (tx->payload && tx->payload_size > 0) {
        payload_size = encrypted_payload_get_size(tx->payload);
        payload_data = malloc(payload_size);
        if (!payload_data) {
            return -1;
        }
        
        unsigned char* ptr = payload_data;
        if (encrypted_payload_serialize(tx->payload, &ptr) != 0) {
            free(payload_data);
            return -1;
        }
    }

    // Insert transaction
    rc = sqlite3_prepare_v2(g_db_ctx.db, SQL_INSERT_TRANSACTION, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        if (payload_data) free(payload_data);
        return -1;
    }

    sqlite3_bind_int(stmt, 1, block_index);
    sqlite3_bind_int(stmt, 2, tx_index);
    sqlite3_bind_int(stmt, 3, tx->type);
    sqlite3_bind_text(stmt, 4, sender_hex, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, tx->timestamp);
    sqlite3_bind_int(stmt, 6, tx->recipient_count);
    sqlite3_bind_text(stmt, 7, group_hex, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, signature_hex, -1, SQLITE_STATIC);
    
    if (payload_data && payload_size > 0) {
        sqlite3_bind_blob(stmt, 9, payload_data, payload_size, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 10, payload_size);
    } else {
        sqlite3_bind_null(stmt, 9);
        sqlite3_bind_int(stmt, 10, 0);
    }

    rc = sqlite3_step(stmt);
    int64_t transaction_id = sqlite3_last_insert_rowid(g_db_ctx.db);
    sqlite3_finalize(stmt);

    if (payload_data) free(payload_data);

    if (rc != SQLITE_DONE) {
        return -1;
    }

    // Add recipients
    for (uint8_t i = 0; i < tx->recipient_count; i++) {
        char recipient_hex[PUBKEY_SIZE * 2 + 1];
        if (db_hex_encode(tx->recipients + (i * PUBKEY_SIZE), PUBKEY_SIZE, 
                         recipient_hex, sizeof(recipient_hex)) != 0) {
            continue; // Skip this recipient but don't fail the whole transaction
        }

        rc = sqlite3_prepare_v2(g_db_ctx.db, SQL_INSERT_RECIPIENT, -1, &stmt, NULL);
        if (rc == SQLITE_OK) {
            sqlite3_bind_int64(stmt, 1, transaction_id);
            sqlite3_bind_text(stmt, 2, recipient_hex, -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 3, i);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    return 0;
}

// Query functions
int db_get_transaction_count(uint64_t* count) {
    if (!g_db_ctx.is_initialized || !count) {
        return -1;
    }

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(g_db_ctx.db, SQL_SELECT_TRANSACTION_COUNT, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *count = sqlite3_column_int64(stmt, 0);
    } else {
        *count = 0;
    }

    sqlite3_finalize(stmt);
    return 0;
}

// Get recipients for a specific transaction
int db_get_recipients_for_transaction(uint64_t transaction_id, char*** recipients, size_t* count) {
    if (!g_db_ctx.is_initialized || !recipients || !count) {
        return -1;
    }

    *recipients = NULL;
    *count = 0;

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(g_db_ctx.db, SQL_SELECT_RECIPIENTS_BY_TRANSACTION, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, transaction_id);

    // First pass: count the recipients
    size_t recipient_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        recipient_count++;
    }

    if (recipient_count == 0) {
        sqlite3_finalize(stmt);
        return 0;
    }

    // Allocate memory for recipient array
    char** recipient_array = malloc(recipient_count * sizeof(char*));
    if (!recipient_array) {
        sqlite3_finalize(stmt);
        return -1;
    }

    // Reset and second pass: collect the recipients
    sqlite3_reset(stmt);
    size_t index = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && index < recipient_count) {
        const char* recipient_pubkey = (const char*)sqlite3_column_text(stmt, 0);
        if (recipient_pubkey) {
            recipient_array[index] = malloc(strlen(recipient_pubkey) + 1);
            if (recipient_array[index]) {
                strcpy(recipient_array[index], recipient_pubkey);
                index++;
            }
        }
    }

    sqlite3_finalize(stmt);

    *recipients = recipient_array;
    *count = index;
    return 0;
}

// Free the recipients array
void db_free_recipients(char** recipients, size_t count) {
    if (!recipients) return;
    
    for (size_t i = 0; i < count; i++) {
        if (recipients[i]) {
            free(recipients[i]);
        }
    }
    free(recipients);
}

int db_get_block_count(uint32_t* count) {
    if (!g_db_ctx.is_initialized || !count) {
        return -1;
    }

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(g_db_ctx.db, SQL_SELECT_BLOCK_COUNT, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *count = sqlite3_column_int(stmt, 0);
    } else {
        *count = 0;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int db_get_block_count_with_transactions(uint32_t* count) {
    if (!g_db_ctx.is_initialized || !count) {
        return -1;
    }

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(g_db_ctx.db, SQL_SELECT_BLOCK_COUNT_WITH_TRANSACTIONS, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *count = sqlite3_column_int(stmt, 0);
    } else {
        *count = 0;
    }

    sqlite3_finalize(stmt);
    return 0;
}

// Memory management functions
void db_free_transaction_record(TransactionRecord* record) {
    if (!record) return;
    
    if (record->encrypted_payload) {
        free(record->encrypted_payload);
    }
    if (record->decrypted_content) {
        free(record->decrypted_content);
    }
}

void db_free_transaction_records(TransactionRecord* records, size_t count) {
    if (!records) return;
    
    for (size_t i = 0; i < count; i++) {
        db_free_transaction_record(&records[i]);
    }
    free(records);
}

// Cache management functions
int db_cache_decrypted_content(uint64_t transaction_id, const char* content) {
    if (!g_db_ctx.is_initialized || !content) {
        return -1;
    }

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(g_db_ctx.db, SQL_UPDATE_CACHED_CONTENT, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    // Calculate content hash (simple for now)
    char content_hash[65];
    snprintf(content_hash, sizeof(content_hash), "%08x", (unsigned int)strlen(content));

    sqlite3_bind_text(stmt, 1, content, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, content_hash, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, transaction_id);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

// Database maintenance functions
int db_checkpoint_wal(void) {
    if (!g_db_ctx.is_initialized || !g_db_ctx.wal_enabled) {
        return -1;
    }

    int rc = sqlite3_wal_checkpoint(g_db_ctx.db, NULL);
    if (rc != SQLITE_OK) {
        printf("WAL checkpoint failed: %s\n", sqlite3_errmsg(g_db_ctx.db));
        return -1;
    }

    printf("WAL checkpoint completed successfully\n");
    return 0;
}

int db_vacuum(void) {
    if (!g_db_ctx.is_initialized) {
        return -1;
    }

    char* error_msg = NULL;
    int rc = sqlite3_exec(g_db_ctx.db, "VACUUM;", NULL, NULL, &error_msg);
    if (rc != SQLITE_OK) {
        printf("Database vacuum failed: %s\n", error_msg);
        sqlite3_free(error_msg);
        return -1;
    }

    printf("Database vacuum completed successfully\n");
    return 0;
}

// Get block by hash with transactions
int db_get_block_by_hash(const char* block_hash, ApiBlockRecord** block_record) {
    if (!g_db_ctx.is_initialized || !block_hash || !block_record) {
        return -1;
    }

    *block_record = NULL;

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(g_db_ctx.db, SQL_SELECT_BLOCK_BY_HASH, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_text(stmt, 1, block_hash, -1, SQLITE_STATIC);
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return -1; // Block not found
    }

    // Allocate the ApiBlockRecord
    ApiBlockRecord* record = malloc(sizeof(ApiBlockRecord));
    if (!record) {
        sqlite3_finalize(stmt);
        return -1;
    }

    // Populate basic block info
    record->height = sqlite3_column_int(stmt, 0);
    record->timestamp = sqlite3_column_int64(stmt, 1);
    
    const char* prev_hash = (const char*)sqlite3_column_text(stmt, 2);
    if (prev_hash) {
        strncpy(record->previous_hash, prev_hash, sizeof(record->previous_hash) - 1);
        record->previous_hash[sizeof(record->previous_hash) - 1] = '\0';
    }
    
    record->transaction_count = sqlite3_column_int(stmt, 5);
    
    const char* hash = (const char*)sqlite3_column_text(stmt, 6);
    if (hash) {
        strncpy(record->hash, hash, sizeof(record->hash) - 1);
        record->hash[sizeof(record->hash) - 1] = '\0';
    }

    sqlite3_finalize(stmt);

    // Now get the transactions for this block
    record->transactions = NULL;
    if (record->transaction_count > 0) {
        TransactionRecord* transactions = NULL;
        size_t tx_count = 0;
        
        if (db_get_transactions_by_block(record->height, &transactions, &tx_count) == 0) {
            record->transactions = transactions;
            record->transaction_count = tx_count; // Update with actual count
        }
    }

    *block_record = record;
    return 0;
}

// Get transactions by block index
int db_get_transactions_by_block(uint32_t block_index, TransactionRecord** results, size_t* count) {
    if (!g_db_ctx.is_initialized || !results || !count) {
        return -1;
    }

    *results = NULL;
    *count = 0;

    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(g_db_ctx.db, SQL_SELECT_TRANSACTIONS_BY_BLOCK, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, block_index);

    // Count results first
    size_t result_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        result_count++;
    }

    if (result_count == 0) {
        sqlite3_finalize(stmt);
        return 0;
    }

    // Reset and allocate memory
    sqlite3_reset(stmt);
    TransactionRecord* records = malloc(result_count * sizeof(TransactionRecord));
    if (!records) {
        sqlite3_finalize(stmt);
        return -1;
    }

    // Populate results
    size_t index = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW && index < result_count) {
        TransactionRecord* record = &records[index];
        memset(record, 0, sizeof(TransactionRecord));
        
        record->transaction_id = sqlite3_column_int64(stmt, 0);
        record->block_index = sqlite3_column_int(stmt, 1);
        record->transaction_index = sqlite3_column_int(stmt, 2);
        record->type = sqlite3_column_int(stmt, 3);
        
        const char* sender = (const char*)sqlite3_column_text(stmt, 4);
        if (sender) {
            strncpy(record->sender, sender, sizeof(record->sender) - 1);
            record->sender[sizeof(record->sender) - 1] = '\0';
        }
        
        record->timestamp = sqlite3_column_int64(stmt, 5);
        record->recipient_count = sqlite3_column_int(stmt, 6);
        
        const char* group_id = (const char*)sqlite3_column_text(stmt, 7);
        if (group_id) {
            strncpy(record->group_id, group_id, sizeof(record->group_id) - 1);
            record->group_id[sizeof(record->group_id) - 1] = '\0';
        }
        
        const char* signature = (const char*)sqlite3_column_text(stmt, 8);
        if (signature) {
            strncpy(record->signature, signature, sizeof(record->signature) - 1);
            record->signature[sizeof(record->signature) - 1] = '\0';
        }
        
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
        
        index++;
    }

    sqlite3_finalize(stmt);

    *results = records;
    *count = index;
    return 0;
}

// Free ApiBlockRecord
void db_free_block_record(ApiBlockRecord* record) {
    if (!record) return;
    
    if (record->transactions) {
        db_free_transaction_records(record->transactions, record->transaction_count);
    }
    free(record);
}

// Get transaction type name
const char* get_transaction_type_name(TW_TransactionType type) {
    switch (type) {
        case TW_TXN_USER_REGISTRATION:      return "USER_REGISTRATION";
        case TW_TXN_ROLE_ASSIGNMENT:        return "ROLE_ASSIGNMENT";
        case TW_TXN_MESSAGE:                return "MESSAGE";
        case TW_TXN_GROUP_MESSAGE:          return "GROUP_MESSAGE";
        case TW_TXN_GROUP_CREATE:           return "GROUP_CREATE";
        case TW_TXN_GROUP_UPDATE:           return "GROUP_UPDATE";
        case TW_TXN_GROUP_MEMBER_ADD:       return "GROUP_MEMBER_ADD";
        case TW_TXN_GROUP_MEMBER_REMOVE:    return "GROUP_MEMBER_REMOVE";
        case TW_TXN_GROUP_MEMBER_LEAVE:     return "GROUP_MEMBER_LEAVE";
        case TW_TXN_PERMISSION_EDIT:        return "PERMISSION_EDIT";
        case TW_TXN_PARENTAL_CONTROL:       return "PARENTAL_CONTROL";
        case TW_TXN_CONTENT_FILTER:         return "CONTENT_FILTER";
        case TW_TXN_LOCATION_UPDATE:        return "LOCATION_UPDATE";
        case TW_TXN_EMERGENCY_ALERT:        return "EMERGENCY_ALERT";
        case TW_TXN_SYSTEM_CONFIG:          return "SYSTEM_CONFIG";
        case TW_TXN_INVITATION_CREATE:      return "INVITATION_CREATE";
        case TW_TXN_INVITATION_ACCEPT:      return "INVITATION_ACCEPT";
        case TW_TXN_INVITATION_REVOKE:      return "INVITATION_REVOKE";
        case TW_TXN_PROXIMITY_INVITATION:   return "PROXIMITY_INVITATION";
        case TW_TXN_PROXIMITY_VALIDATION:   return "PROXIMITY_VALIDATION";
        case TW_TXN_VOICE_CALL_REQ:         return "VOICE_CALL_REQ";
        case TW_TXN_VIDEO_CALL_REQ:         return "VIDEO_CALL_REQ";
        case TW_TXN_MEDIA_DOWNLOAD:         return "MEDIA_DOWNLOAD";
        case TW_TXN_CONTENT_ACCESS_UPDATE:  return "CONTENT_ACCESS_UPDATE";
        case TW_TXN_CREATION_UPLOAD:        return "CREATION_UPLOAD";
        case TW_TXN_CREATION_SHARE_REQUEST: return "CREATION_SHARE_REQUEST";
        case TW_TXN_EDUCATIONAL_RESOURCE_ADD: return "EDUCATIONAL_RESOURCE_ADD";
        case TW_TXN_CHALLENGE_COMPLETE:     return "CHALLENGE_COMPLETE";
        case TW_TXN_BOOK_ADD_TO_LIBRARY:    return "BOOK_ADD_TO_LIBRARY";
        case TW_TXN_CHORE_ASSIGN:           return "CHORE_ASSIGN";
        case TW_TXN_CHORE_COMPLETE:         return "CHORE_COMPLETE";
        case TW_TXN_REWARD_DISTRIBUTE:      return "REWARD_DISTRIBUTE";
        case TW_TXN_GEOFENCE_CREATE:        return "GEOFENCE_CREATE";
        case TW_TXN_GEOFENCE_CONFIG_UPDATE: return "GEOFENCE_CONFIG_UPDATE";
        case TW_TXN_USAGE_POLICY_UPDATE:    return "USAGE_POLICY_UPDATE";
        case TW_TXN_GAME_SESSION_START:     return "GAME_SESSION_START";
        case TW_TXN_GAME_PERMISSION_UPDATE: return "GAME_PERMISSION_UPDATE";
        case TW_TXN_EVENT_CREATE:           return "EVENT_CREATE";
        case TW_TXN_EVENT_INVITE:           return "EVENT_INVITE";
        case TW_TXN_EVENT_RSVP:             return "EVENT_RSVP";
        case TW_TXN_COMMUNITY_POST_CREATE:  return "COMMUNITY_POST_CREATE";
        case TW_TXN_SHARED_ALBUM_CREATE:    return "SHARED_ALBUM_CREATE";
        case TW_TXN_MEDIA_ADD_TO_ALBUM_REQUEST: return "MEDIA_ADD_TO_ALBUM_REQUEST";
        default:                            return "UNKNOWN";
    }
} 