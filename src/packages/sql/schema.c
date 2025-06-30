#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include "schema.h"

// SQL statements for creating tables
const char* SQL_CREATE_BLOCKCHAIN_INFO = 
    "CREATE TABLE IF NOT EXISTS blockchain_info ("
    "    id INTEGER PRIMARY KEY,"
    "    creator_pubkey TEXT NOT NULL,"
    "    length INTEGER NOT NULL,"
    "    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
    ");";

const char* SQL_CREATE_BLOCKS = 
    "CREATE TABLE IF NOT EXISTS blocks ("
    "    block_index INTEGER PRIMARY KEY,"
    "    timestamp INTEGER NOT NULL,"
    "    previous_hash TEXT NOT NULL,"
    "    merkle_root_hash TEXT NOT NULL,"
    "    proposer_id TEXT NOT NULL,"
    "    transaction_count INTEGER NOT NULL,"
    "    block_hash TEXT NOT NULL,"
    "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
    ");";

const char* SQL_CREATE_TRANSACTIONS = 
    "CREATE TABLE IF NOT EXISTS transactions ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    block_index INTEGER NOT NULL,"
    "    transaction_index INTEGER NOT NULL,"
    "    type INTEGER NOT NULL,"
    "    sender TEXT NOT NULL,"
    "    timestamp INTEGER NOT NULL,"
    "    recipient_count INTEGER NOT NULL,"
    "    group_id TEXT,"
    "    signature TEXT NOT NULL,"
    "    encrypted_payload BLOB,"
    "    payload_size INTEGER DEFAULT 0,"
    "    decrypted_content TEXT,"
    "    content_hash TEXT,"
    "    is_decrypted BOOLEAN DEFAULT FALSE,"
    "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    FOREIGN KEY (block_index) REFERENCES blocks(block_index),"
    "    UNIQUE(block_index, transaction_index)"
    ");";

const char* SQL_CREATE_TRANSACTION_RECIPIENTS = 
    "CREATE TABLE IF NOT EXISTS transaction_recipients ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    transaction_id INTEGER NOT NULL,"
    "    recipient_pubkey TEXT NOT NULL,"
    "    recipient_order INTEGER NOT NULL,"
    "    FOREIGN KEY (transaction_id) REFERENCES transactions(id)"
    ");";

// SQL statements for creating indexes
const char* SQL_CREATE_INDEX_TRANSACTIONS_SENDER = 
    "CREATE INDEX IF NOT EXISTS idx_transactions_sender ON transactions(sender);";

const char* SQL_CREATE_INDEX_TRANSACTIONS_TYPE = 
    "CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type);";

const char* SQL_CREATE_INDEX_TRANSACTIONS_TIMESTAMP = 
    "CREATE INDEX IF NOT EXISTS idx_transactions_timestamp ON transactions(timestamp);";

const char* SQL_CREATE_INDEX_TRANSACTIONS_BLOCK = 
    "CREATE INDEX IF NOT EXISTS idx_transactions_block ON transactions(block_index);";

const char* SQL_CREATE_INDEX_RECIPIENTS_PUBKEY = 
    "CREATE INDEX IF NOT EXISTS idx_recipients_pubkey ON transaction_recipients(recipient_pubkey);";

const char* SQL_CREATE_INDEX_TRANSACTIONS_GROUP_ID = 
    "CREATE INDEX IF NOT EXISTS idx_transactions_group_id ON transactions(group_id);";

// SQL statements for common operations
const char* SQL_INSERT_BLOCKCHAIN_INFO = 
    "INSERT OR REPLACE INTO blockchain_info (id, creator_pubkey, length, last_updated) "
    "VALUES (1, ?, ?, CURRENT_TIMESTAMP);";

const char* SQL_UPDATE_BLOCKCHAIN_INFO = 
    "UPDATE blockchain_info SET length = ?, last_updated = CURRENT_TIMESTAMP WHERE id = 1;";

const char* SQL_INSERT_BLOCK = 
    "INSERT OR REPLACE INTO blocks "
    "(block_index, timestamp, previous_hash, merkle_root_hash, proposer_id, transaction_count, block_hash) "
    "VALUES (?, ?, ?, ?, ?, ?, ?);";

const char* SQL_INSERT_TRANSACTION = 
    "INSERT INTO transactions "
    "(block_index, transaction_index, type, sender, timestamp, recipient_count, group_id, signature, encrypted_payload, payload_size) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

const char* SQL_INSERT_RECIPIENT = 
    "INSERT INTO transaction_recipients (transaction_id, recipient_pubkey, recipient_order) "
    "VALUES (?, ?, ?);";

// SQL statements for queries
const char* SQL_SELECT_TRANSACTION_COUNT = 
    "SELECT COUNT(*) FROM transactions;";

const char* SQL_SELECT_BLOCK_COUNT = 
    "SELECT COUNT(*) FROM blocks;";

const char* SQL_SELECT_BLOCK_COUNT_WITH_TRANSACTIONS = 
    "SELECT COUNT(*) FROM blocks WHERE transaction_count > 0;";

const char* SQL_SELECT_TRANSACTIONS_BY_SENDER = 
    "SELECT id, block_index, transaction_index, type, sender, timestamp, recipient_count, "
    "group_id, signature, payload_size, encrypted_payload, decrypted_content, is_decrypted "
    "FROM transactions WHERE sender = ? ORDER BY timestamp DESC;";

const char* SQL_SELECT_TRANSACTIONS_BY_RECIPIENT = 
    "SELECT t.id, t.block_index, t.transaction_index, t.type, t.sender, t.timestamp, t.recipient_count, "
    "t.group_id, t.signature, t.payload_size, t.encrypted_payload, t.decrypted_content, t.is_decrypted "
    "FROM transactions t "
    "JOIN transaction_recipients tr ON t.id = tr.transaction_id "
    "WHERE tr.recipient_pubkey = ? ORDER BY t.timestamp DESC;";

const char* SQL_SELECT_TRANSACTIONS_BY_TYPE = 
    "SELECT id, block_index, transaction_index, type, sender, timestamp, recipient_count, "
    "group_id, signature, payload_size, encrypted_payload, decrypted_content, is_decrypted "
    "FROM transactions WHERE type = ? ORDER BY timestamp DESC;";

const char* SQL_SELECT_TRANSACTIONS_BY_BLOCK = 
    "SELECT id, block_index, transaction_index, type, sender, timestamp, recipient_count, "
    "group_id, signature, payload_size, encrypted_payload, decrypted_content, is_decrypted "
    "FROM transactions WHERE block_index = ? ORDER BY transaction_index;";

const char* SQL_SELECT_RECENT_TRANSACTIONS = 
    "SELECT id, block_index, transaction_index, type, sender, timestamp, recipient_count, "
    "group_id, signature, payload_size, encrypted_payload, decrypted_content, is_decrypted "
    "FROM transactions ORDER BY timestamp DESC LIMIT ?;";

const char* SQL_SELECT_BLOCK_INFO = 
    "SELECT block_index, timestamp, previous_hash, merkle_root_hash, proposer_id, transaction_count, block_hash "
    "FROM blocks WHERE block_index = ?;";

const char* SQL_UPDATE_CACHED_CONTENT = 
    "UPDATE transactions SET decrypted_content = ?, content_hash = ?, is_decrypted = TRUE WHERE id = ?;";

const char* SQL_SELECT_CACHED_CONTENT = 
    "SELECT decrypted_content FROM transactions WHERE id = ? AND is_decrypted = TRUE;";

// Schema management functions
int schema_create_all_tables(sqlite3* db) {
    char* error_msg = NULL;
    int rc;

    // Create tables in dependency order
    const char* table_statements[] = {
        SQL_CREATE_BLOCKCHAIN_INFO,
        SQL_CREATE_BLOCKS,
        SQL_CREATE_TRANSACTIONS,
        SQL_CREATE_TRANSACTION_RECIPIENTS,
        NULL
    };

    for (int i = 0; table_statements[i] != NULL; i++) {
        rc = sqlite3_exec(db, table_statements[i], NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            printf("Failed to create table: %s\n", error_msg);
            sqlite3_free(error_msg);
            return -1;
        }
    }

    printf("All database tables created successfully\n");
    return 0;
}

int schema_create_all_indexes(sqlite3* db) {
    char* error_msg = NULL;
    int rc;

    const char* index_statements[] = {
        SQL_CREATE_INDEX_TRANSACTIONS_SENDER,
        SQL_CREATE_INDEX_TRANSACTIONS_TYPE,
        SQL_CREATE_INDEX_TRANSACTIONS_TIMESTAMP,
        SQL_CREATE_INDEX_TRANSACTIONS_BLOCK,
        SQL_CREATE_INDEX_RECIPIENTS_PUBKEY,
        SQL_CREATE_INDEX_TRANSACTIONS_GROUP_ID,
        NULL
    };

    for (int i = 0; index_statements[i] != NULL; i++) {
        rc = sqlite3_exec(db, index_statements[i], NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            printf("Failed to create index: %s\n", error_msg);
            sqlite3_free(error_msg);
            return -1;
        }
    }

    printf("All database indexes created successfully\n");
    return 0;
}

int schema_check_version(sqlite3* db, int* version) {
    sqlite3_stmt* stmt;
    int rc;

    // Check if schema_version table exists
    const char* check_table_sql = 
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version';";
    
    rc = sqlite3_prepare_v2(db, check_table_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_ROW) {
        // Table doesn't exist, assume version 0
        *version = 0;
        return 0;
    }

    // Get version from table
    const char* get_version_sql = "SELECT version FROM schema_version WHERE id = 1;";
    rc = sqlite3_prepare_v2(db, get_version_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *version = sqlite3_column_int(stmt, 0);
    } else {
        *version = 0;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int schema_set_version(sqlite3* db, int version) {
    char* error_msg = NULL;
    int rc;

    // Create schema_version table if it doesn't exist
    const char* create_version_table = 
        "CREATE TABLE IF NOT EXISTS schema_version ("
        "    id INTEGER PRIMARY KEY,"
        "    version INTEGER NOT NULL,"
        "    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ");";

    rc = sqlite3_exec(db, create_version_table, NULL, NULL, &error_msg);
    if (rc != SQLITE_OK) {
        printf("Failed to create schema_version table: %s\n", error_msg);
        sqlite3_free(error_msg);
        return -1;
    }

    // Insert or update version
    const char* set_version_sql = 
        "INSERT OR REPLACE INTO schema_version (id, version, updated_at) "
        "VALUES (1, ?, CURRENT_TIMESTAMP);";

    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, set_version_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, version);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return -1;
    }

    printf("Database schema version set to %d\n", version);
    return 0;
}

int schema_migrate(sqlite3* db, int from_version, int to_version) {
    printf("Migrating database schema from version %d to %d\n", from_version, to_version);

    // For now, we only have version 1, so no migrations needed
    // Future migrations would be implemented here
    if (from_version == 0 && to_version == 1) {
        // Initial schema creation
        if (schema_create_all_tables(db) != 0) {
            return -1;
        }
        if (schema_create_all_indexes(db) != 0) {
            return -1;
        }
        if (schema_set_version(db, 1) != 0) {
            return -1;
        }
        return 0;
    }

    // No migration path found
    printf("No migration path from version %d to %d\n", from_version, to_version);
    return -1;
} 