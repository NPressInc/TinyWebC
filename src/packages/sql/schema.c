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
    "    resource_id TEXT,"
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

// Node status tracking table
const char* SQL_CREATE_NODE_STATUS = 
    "CREATE TABLE IF NOT EXISTS node_status ("
    "    node_id TEXT PRIMARY KEY,"
    "    node_name TEXT NOT NULL,"
    "    ip_address TEXT NOT NULL,"
    "    port INTEGER NOT NULL,"
    "    is_validator BOOLEAN NOT NULL DEFAULT TRUE,"
    "    status TEXT NOT NULL DEFAULT 'offline',"  // 'online', 'offline', 'unknown'
    "    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    first_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    heartbeat_count INTEGER DEFAULT 0"
    ");";

// User, Role, and Permission tables
const char* SQL_CREATE_USERS = 
    "CREATE TABLE IF NOT EXISTS users ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    pubkey TEXT NOT NULL UNIQUE,"
    "    username TEXT NOT NULL,"
    "    age INTEGER,"
    "    registration_transaction_id INTEGER,"
    "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    is_active BOOLEAN DEFAULT TRUE,"
    "    FOREIGN KEY (registration_transaction_id) REFERENCES transactions(id)"
    ");";

const char* SQL_CREATE_ROLES = 
    "CREATE TABLE IF NOT EXISTS roles ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    name TEXT NOT NULL UNIQUE,"
    "    description TEXT,"
    "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    assignment_transaction_id INTEGER,"
    "    FOREIGN KEY (assignment_transaction_id) REFERENCES transactions(id)"
    ");";

const char* SQL_CREATE_PERMISSIONS = 
    "CREATE TABLE IF NOT EXISTS permissions ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    name TEXT NOT NULL UNIQUE,"
    "    permission_flags INTEGER NOT NULL,"
    "    scope_flags INTEGER NOT NULL,"
    "    condition_flags INTEGER NOT NULL,"
    "    category INTEGER NOT NULL,"
    "    description TEXT,"
    "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    edit_transaction_id INTEGER,"
    "    FOREIGN KEY (edit_transaction_id) REFERENCES transactions(id)"
    ");";

const char* SQL_CREATE_USER_ROLES = 
    "CREATE TABLE IF NOT EXISTS user_roles ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    user_id INTEGER NOT NULL,"
    "    role_id INTEGER NOT NULL,"
    "    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    assigned_by_user_id INTEGER,"
    "    assignment_transaction_id INTEGER,"
    "    is_active BOOLEAN DEFAULT TRUE,"
    "    FOREIGN KEY (user_id) REFERENCES users(id),"
    "    FOREIGN KEY (role_id) REFERENCES roles(id),"
    "    FOREIGN KEY (assigned_by_user_id) REFERENCES users(id),"
    "    FOREIGN KEY (assignment_transaction_id) REFERENCES transactions(id),"
    "    UNIQUE(user_id, role_id)"
    ");";

const char* SQL_CREATE_ROLE_PERMISSIONS = 
    "CREATE TABLE IF NOT EXISTS role_permissions ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    role_id INTEGER NOT NULL,"
    "    permission_id INTEGER NOT NULL,"
    "    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    granted_by_user_id INTEGER,"
    "    grant_transaction_id INTEGER,"
    "    time_start INTEGER,"
    "    time_end INTEGER,"
    "    is_active BOOLEAN DEFAULT TRUE,"
    "    FOREIGN KEY (role_id) REFERENCES roles(id),"
    "    FOREIGN KEY (permission_id) REFERENCES permissions(id),"
    "    FOREIGN KEY (granted_by_user_id) REFERENCES users(id),"
    "    FOREIGN KEY (grant_transaction_id) REFERENCES transactions(id),"
    "    UNIQUE(role_id, permission_id)"
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

const char* SQL_CREATE_INDEX_TRANSACTIONS_RESOURCE_ID = 
    "CREATE INDEX IF NOT EXISTS idx_transactions_resource_id ON transactions(resource_id);";

const char* SQL_CREATE_INDEX_BLOCKS_HASH = 
    "CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(block_hash);";

// User, Role, and Permission indexes
const char* SQL_CREATE_INDEX_USERS_PUBKEY = 
    "CREATE INDEX IF NOT EXISTS idx_users_pubkey ON users(pubkey);";

const char* SQL_CREATE_INDEX_USERS_USERNAME = 
    "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);";

const char* SQL_CREATE_INDEX_ROLES_NAME = 
    "CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);";

const char* SQL_CREATE_INDEX_USER_ROLES_USER = 
    "CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);";

const char* SQL_CREATE_INDEX_USER_ROLES_ROLE = 
    "CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);";

const char* SQL_CREATE_INDEX_ROLE_PERMISSIONS_ROLE = 
    "CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);";

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
    "(block_index, transaction_index, type, sender, timestamp, recipient_count, group_id, signature, resource_id, encrypted_payload, payload_size) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);";

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
    "group_id, signature, resource_id, payload_size, encrypted_payload, decrypted_content, is_decrypted "
    "FROM transactions WHERE sender = ? ORDER BY timestamp DESC;";

const char* SQL_SELECT_TRANSACTIONS_BY_RECIPIENT = 
    "SELECT t.id, t.block_index, t.transaction_index, t.type, t.sender, t.timestamp, t.recipient_count, "
    "t.group_id, t.signature, t.resource_id, t.payload_size, t.encrypted_payload, t.decrypted_content, t.is_decrypted "
    "FROM transactions t "
    "JOIN transaction_recipients tr ON t.id = tr.transaction_id "
    "WHERE tr.recipient_pubkey = ? ORDER BY t.timestamp DESC;";

const char* SQL_SELECT_TRANSACTIONS_BY_TYPE = 
    "SELECT id, block_index, transaction_index, type, sender, timestamp, recipient_count, "
    "group_id, signature, resource_id, payload_size, encrypted_payload, decrypted_content, is_decrypted "
    "FROM transactions WHERE type = ? ORDER BY timestamp DESC;";

const char* SQL_SELECT_TRANSACTIONS_BY_BLOCK = 
    "SELECT id, block_index, transaction_index, type, sender, timestamp, recipient_count, "
    "group_id, signature, resource_id, payload_size, encrypted_payload, decrypted_content, is_decrypted "
    "FROM transactions WHERE block_index = ? ORDER BY transaction_index;";

const char* SQL_SELECT_RECENT_TRANSACTIONS = 
    "SELECT id, block_index, transaction_index, type, sender, timestamp, recipient_count, "
    "group_id, signature, resource_id, payload_size, encrypted_payload, decrypted_content, is_decrypted "
    "FROM transactions ORDER BY timestamp DESC LIMIT ?;";

const char* SQL_SELECT_BLOCK_INFO = 
    "SELECT block_index, timestamp, previous_hash, merkle_root_hash, proposer_id, transaction_count, block_hash "
    "FROM blocks WHERE block_index = ?;";

const char* SQL_SELECT_BLOCK_BY_HASH = 
    "SELECT block_index, timestamp, previous_hash, merkle_root_hash, proposer_id, transaction_count, block_hash "
    "FROM blocks WHERE block_hash = ?;";

const char* SQL_SELECT_RECIPIENTS_BY_TRANSACTION = 
    "SELECT recipient_pubkey, recipient_order FROM transaction_recipients "
    "WHERE transaction_id = ? ORDER BY recipient_order;";

const char* SQL_UPDATE_CACHED_CONTENT = 
    "UPDATE transactions SET decrypted_content = ?, content_hash = ?, is_decrypted = TRUE WHERE id = ?;";

const char* SQL_SELECT_CACHED_CONTENT = 
    "SELECT decrypted_content FROM transactions WHERE id = ? AND is_decrypted = TRUE;";

// Node status management queries
const char* SQL_INSERT_NODE_STATUS = 
    "INSERT OR REPLACE INTO node_status "
    "(node_id, node_name, ip_address, port, is_validator, status, last_seen, heartbeat_count) "
    "VALUES (?, ?, ?, ?, ?, 'online', CURRENT_TIMESTAMP, COALESCE((SELECT heartbeat_count FROM node_status WHERE node_id = ?), 0) + 1);";

const char* SQL_UPDATE_NODE_HEARTBEAT = 
    "UPDATE node_status SET status = 'online', last_seen = CURRENT_TIMESTAMP, heartbeat_count = heartbeat_count + 1 "
    "WHERE node_id = ?;";

const char* SQL_SET_NODE_OFFLINE = 
    "UPDATE node_status SET status = 'offline' WHERE node_id = ?;";

const char* SQL_SET_STALE_NODES_OFFLINE = 
    "UPDATE node_status SET status = 'offline' "
    "WHERE status = 'online' AND last_seen < datetime('now', '-30 seconds');";

const char* SQL_SELECT_ALL_NODES = 
    "SELECT node_id, node_name, ip_address, port, is_validator, status, last_seen, heartbeat_count "
    "FROM node_status ORDER BY node_id;";

const char* SQL_SELECT_ONLINE_NODES = 
    "SELECT node_id, node_name, ip_address, port, is_validator, status, last_seen, heartbeat_count "
    "FROM node_status WHERE status = 'online' ORDER BY node_id;";

const char* SQL_COUNT_TOTAL_NODES = 
    "SELECT COUNT(*) FROM node_status;";

const char* SQL_COUNT_ONLINE_NODES = 
    "SELECT COUNT(*) FROM node_status WHERE status = 'online';";

// User, Role, and Permission management queries
const char* SQL_INSERT_USER = 
    "INSERT OR REPLACE INTO users (pubkey, username, age, registration_transaction_id, updated_at) "
    "VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP);";

const char* SQL_UPDATE_USER = 
    "UPDATE users SET username = ?, age = ?, updated_at = CURRENT_TIMESTAMP WHERE pubkey = ?;";

const char* SQL_SELECT_USER_BY_PUBKEY = 
    "SELECT id, pubkey, username, age, registration_transaction_id, created_at, updated_at, is_active "
    "FROM users WHERE pubkey = ?;";

const char* SQL_SELECT_USER_BY_USERNAME = 
    "SELECT id, pubkey, username, age, registration_transaction_id, created_at, updated_at, is_active "
    "FROM users WHERE username = ?;";

const char* SQL_SELECT_ALL_USERS = 
    "SELECT id, pubkey, username, age, registration_transaction_id, created_at, updated_at, is_active "
    "FROM users WHERE is_active = 1 ORDER BY username;";

const char* SQL_DELETE_USER = 
    "UPDATE users SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE pubkey = ?;";

const char* SQL_INSERT_ROLE = 
    "INSERT OR REPLACE INTO roles (name, description, assignment_transaction_id, updated_at) "
    "VALUES (?, ?, ?, CURRENT_TIMESTAMP);";

const char* SQL_UPDATE_ROLE = 
    "UPDATE roles SET description = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?;";

const char* SQL_SELECT_ROLE_BY_NAME = 
    "SELECT id, name, description, created_at, updated_at, assignment_transaction_id "
    "FROM roles WHERE name = ?;";

const char* SQL_SELECT_ALL_ROLES = 
    "SELECT id, name, description, created_at, updated_at, assignment_transaction_id "
    "FROM roles ORDER BY name;";

const char* SQL_DELETE_ROLE = 
    "DELETE FROM roles WHERE name = ?;";

const char* SQL_INSERT_PERMISSION = 
    "INSERT OR REPLACE INTO permissions (name, permission_flags, scope_flags, condition_flags, category, description, edit_transaction_id, updated_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);";

const char* SQL_UPDATE_PERMISSION = 
    "UPDATE permissions SET permission_flags = ?, scope_flags = ?, condition_flags = ?, category = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?;";

const char* SQL_SELECT_PERMISSION_BY_NAME = 
    "SELECT id, name, permission_flags, scope_flags, condition_flags, category, description, created_at, updated_at, edit_transaction_id "
    "FROM permissions WHERE name = ?;";

const char* SQL_SELECT_ALL_PERMISSIONS = 
    "SELECT id, name, permission_flags, scope_flags, condition_flags, category, description, created_at, updated_at, edit_transaction_id "
    "FROM permissions ORDER BY name;";

const char* SQL_DELETE_PERMISSION = 
    "DELETE FROM permissions WHERE name = ?;";

const char* SQL_INSERT_USER_ROLE = 
    "INSERT OR REPLACE INTO user_roles (user_id, role_id, assigned_by_user_id, assignment_transaction_id) "
    "VALUES (?, ?, ?, ?);";

const char* SQL_DELETE_USER_ROLE = 
    "UPDATE user_roles SET is_active = 0 WHERE user_id = ? AND role_id = ?;";

const char* SQL_SELECT_USER_ROLES = 
    "SELECT ur.id, ur.user_id, ur.role_id, ur.assigned_at, ur.assigned_by_user_id, ur.assignment_transaction_id, r.name as role_name "
    "FROM user_roles ur "
    "JOIN roles r ON ur.role_id = r.id "
    "WHERE ur.user_id = ? AND ur.is_active = 1;";

const char* SQL_SELECT_ROLE_USERS = 
    "SELECT ur.id, ur.user_id, ur.role_id, ur.assigned_at, ur.assigned_by_user_id, ur.assignment_transaction_id, u.username, u.pubkey "
    "FROM user_roles ur "
    "JOIN users u ON ur.user_id = u.id "
    "WHERE ur.role_id = ? AND ur.is_active = 1 AND u.is_active = 1;";

const char* SQL_INSERT_ROLE_PERMISSION = 
    "INSERT OR REPLACE INTO role_permissions (role_id, permission_id, granted_by_user_id, grant_transaction_id, time_start, time_end) "
    "VALUES (?, ?, ?, ?, ?, ?);";

const char* SQL_DELETE_ROLE_PERMISSION = 
    "UPDATE role_permissions SET is_active = 0 WHERE role_id = ? AND permission_id = ?;";

const char* SQL_SELECT_ROLE_PERMISSIONS = 
    "SELECT rp.id, rp.role_id, rp.permission_id, rp.granted_at, rp.granted_by_user_id, rp.grant_transaction_id, "
    "rp.time_start, rp.time_end, p.name as permission_name, p.permission_flags, p.scope_flags, p.condition_flags, p.category "
    "FROM role_permissions rp "
    "JOIN permissions p ON rp.permission_id = p.id "
    "WHERE rp.role_id = ? AND rp.is_active = 1;";

const char* SQL_SELECT_PERMISSION_ROLES = 
    "SELECT rp.id, rp.role_id, rp.permission_id, rp.granted_at, rp.granted_by_user_id, rp.grant_transaction_id, "
    "rp.time_start, rp.time_end, r.name as role_name "
    "FROM role_permissions rp "
    "JOIN roles r ON rp.role_id = r.id "
    "WHERE rp.permission_id = ? AND rp.is_active = 1;";

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
        SQL_CREATE_NODE_STATUS,
        SQL_CREATE_USERS,
        SQL_CREATE_ROLES,
        SQL_CREATE_PERMISSIONS,
        SQL_CREATE_USER_ROLES,
        SQL_CREATE_ROLE_PERMISSIONS,
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
        SQL_CREATE_INDEX_TRANSACTIONS_RESOURCE_ID,
        SQL_CREATE_INDEX_BLOCKS_HASH,
        SQL_CREATE_INDEX_USERS_PUBKEY,
        SQL_CREATE_INDEX_USERS_USERNAME,
        SQL_CREATE_INDEX_ROLES_NAME,
        SQL_CREATE_INDEX_USER_ROLES_USER,
        SQL_CREATE_INDEX_USER_ROLES_ROLE,
        SQL_CREATE_INDEX_ROLE_PERMISSIONS_ROLE,
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

    if (from_version == 0 && to_version == 2) {
        // Initial schema creation with new tables
        if (schema_create_all_tables(db) != 0) {
            return -1;
        }
        if (schema_create_all_indexes(db) != 0) {
            return -1;
        }
        if (schema_set_version(db, 2) != 0) {
            return -1;
        }
        return 0;
    }

    if (from_version == 1 && to_version == 2) {
        // Add new user, role, and permission tables
        const char* new_tables[] = {
            SQL_CREATE_USERS,
            SQL_CREATE_ROLES,
            SQL_CREATE_PERMISSIONS,
            SQL_CREATE_USER_ROLES,
            SQL_CREATE_ROLE_PERMISSIONS,
            NULL
        };

        const char* new_indexes[] = {
            SQL_CREATE_INDEX_USERS_PUBKEY,
            SQL_CREATE_INDEX_USERS_USERNAME,
            SQL_CREATE_INDEX_ROLES_NAME,
            SQL_CREATE_INDEX_USER_ROLES_USER,
            SQL_CREATE_INDEX_USER_ROLES_ROLE,
            SQL_CREATE_INDEX_ROLE_PERMISSIONS_ROLE,
            NULL
        };

        char* error_msg = NULL;
        int rc;

        // Create new tables
        for (int i = 0; new_tables[i] != NULL; i++) {
            rc = sqlite3_exec(db, new_tables[i], NULL, NULL, &error_msg);
            if (rc != SQLITE_OK) {
                printf("Failed to create table during migration: %s\n", error_msg);
                sqlite3_free(error_msg);
                return -1;
            }
        }

        // Create new indexes
        for (int i = 0; new_indexes[i] != NULL; i++) {
            rc = sqlite3_exec(db, new_indexes[i], NULL, NULL, &error_msg);
            if (rc != SQLITE_OK) {
                printf("Failed to create index during migration: %s\n", error_msg);
                sqlite3_free(error_msg);
                return -1;
            }
        }

        if (schema_set_version(db, 2) != 0) {
            return -1;
        }
        return 0;
    }

    if (from_version == 2 && to_version == 3) {
        // Add resource_id column and index
        char* error_msg = NULL;
        int rc;

        rc = sqlite3_exec(db, "ALTER TABLE transactions ADD COLUMN resource_id TEXT;", NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            // If column exists already, ignore error
            printf("Warning: Adding resource_id column may have failed (possibly exists): %s\n", error_msg ? error_msg : "");
            sqlite3_free(error_msg);
        }

        rc = sqlite3_exec(db, SQL_CREATE_INDEX_TRANSACTIONS_RESOURCE_ID, NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            printf("Warning: Failed to create resource_id index: %s\n", error_msg);
            sqlite3_free(error_msg);
        }

        if (schema_set_version(db, 3) != 0) {
            return -1;
        }
        return 0;
    }

    if (from_version == 0 && to_version == 3) {
        // Fresh create all tables, then set to 3
        if (schema_create_all_tables(db) != 0) {
            return -1;
        }
        if (schema_create_all_indexes(db) != 0) {
            return -1;
        }

        // Ensure resource_id index exists
        char* error_msg = NULL;
        int rc = sqlite3_exec(db, SQL_CREATE_INDEX_TRANSACTIONS_RESOURCE_ID, NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            printf("Warning: Failed to create resource_id index (0->3 path): %s\n", error_msg);
            sqlite3_free(error_msg);
        }

        if (schema_set_version(db, 3) != 0) {
            return -1;
        }
        return 0;
    }

    // No migration path found
    printf("No migration path from version %d to %d\n", from_version, to_version);
    return -1;
} 