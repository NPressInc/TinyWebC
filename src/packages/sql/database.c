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