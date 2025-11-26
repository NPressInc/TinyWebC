#include "schema.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "database_gossip.h"
#include "packages/utils/logger.h"

#define GOSSIP_CREATE_TABLE_SQL \
    "CREATE TABLE IF NOT EXISTS gossip_messages (" \
    "id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "type INTEGER NOT NULL," \
    "sender BLOB NOT NULL," \
    "timestamp INTEGER NOT NULL," \
    "payload BLOB NOT NULL," \
    "payload_size INTEGER NOT NULL," \
    "expires_at INTEGER NOT NULL," \
    "created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))" \
    ");"

#define GOSSIP_CREATE_INDEX_EXPIRES \
    "CREATE INDEX IF NOT EXISTS idx_gossip_expires_at ON gossip_messages(expires_at);"

#define GOSSIP_CREATE_INDEX_SENDER \
    "CREATE INDEX IF NOT EXISTS idx_gossip_sender ON gossip_messages(sender);"

#define GOSSIP_CREATE_TABLE_ENVELOPES \
    "CREATE TABLE IF NOT EXISTS gossip_envelopes (" \
    "id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "version INTEGER NOT NULL," \
    "content_type INTEGER NOT NULL," \
    "schema_version INTEGER NOT NULL," \
    "timestamp INTEGER NOT NULL," \
    "sender BLOB NOT NULL," \
    "envelope BLOB NOT NULL," \
    "envelope_size INTEGER NOT NULL," \
    "expires_at INTEGER NOT NULL," \
    "created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))" \
    ");"

#define GOSSIP_CREATE_INDEX_ENV_EXPIRES \
    "CREATE INDEX IF NOT EXISTS idx_gossip_env_expires ON gossip_envelopes(expires_at);"

#define GOSSIP_CREATE_INDEX_ENV_SENDER \
    "CREATE INDEX IF NOT EXISTS idx_gossip_env_sender ON gossip_envelopes(sender);"

/* Legacy user/permission schema reused for gossip */
#define GOSSIP_CREATE_USERS \
    "CREATE TABLE IF NOT EXISTS users (" \
    "    id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "    pubkey TEXT NOT NULL UNIQUE," \
    "    username TEXT NOT NULL," \
    "    age INTEGER," \
    "    registration_transaction_id INTEGER," \
    "    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))," \
    "    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))," \
    "    is_active INTEGER DEFAULT 1" \
    ");"

#define GOSSIP_CREATE_ROLES \
    "CREATE TABLE IF NOT EXISTS roles (" \
    "    id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "    name TEXT NOT NULL UNIQUE," \
    "    description TEXT," \
    "    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))," \
    "    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))" \
    ");"

#define GOSSIP_CREATE_PERMISSIONS \
    "CREATE TABLE IF NOT EXISTS permissions (" \
    "    id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "    name TEXT NOT NULL UNIQUE," \
    "    permission_flags INTEGER NOT NULL," \
    "    scope_flags INTEGER NOT NULL," \
    "    condition_flags INTEGER NOT NULL," \
    "    category INTEGER NOT NULL," \
    "    description TEXT," \
    "    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))," \
    "    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))" \
    ");"

#define GOSSIP_CREATE_USER_ROLES \
    "CREATE TABLE IF NOT EXISTS user_roles (" \
    "    id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "    user_id INTEGER NOT NULL," \
    "    role_id INTEGER NOT NULL," \
    "    assigned_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))," \
    "    assigned_by_user_id INTEGER," \
    "    assignment_transaction_id INTEGER," \
    "    is_active INTEGER DEFAULT 1," \
    "    UNIQUE(user_id, role_id)" \
    ");"

#define GOSSIP_CREATE_ROLE_PERMISSIONS \
    "CREATE TABLE IF NOT EXISTS role_permissions (" \
    "    id INTEGER PRIMARY KEY AUTOINCREMENT," \
    "    role_id INTEGER NOT NULL," \
    "    permission_id INTEGER NOT NULL," \
    "    granted_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))," \
    "    granted_by_user_id INTEGER," \
    "    grant_transaction_id INTEGER," \
    "    scope_flags INTEGER NOT NULL DEFAULT 0," \
    "    condition_flags INTEGER NOT NULL DEFAULT 0," \
    "    time_start INTEGER," \
    "    time_end INTEGER," \
    "    is_active INTEGER DEFAULT 1," \
    "    UNIQUE(role_id, permission_id)" \
    ");"

#define GOSSIP_CREATE_TRANSACTION_PERMISSIONS \
    "CREATE TABLE IF NOT EXISTS transaction_permissions (" \
    "    txn_type INTEGER PRIMARY KEY," \
    "    required_permission INTEGER NOT NULL," \
    "    required_scope INTEGER NOT NULL" \
    ");"

#define GOSSIP_CREATE_INDEX_USERS_PUBKEY \
    "CREATE INDEX IF NOT EXISTS idx_users_pubkey ON users(pubkey);"

#define GOSSIP_CREATE_INDEX_ROLES_NAME \
    "CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);"

#define GOSSIP_CREATE_INDEX_USER_ROLES_USER \
    "CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);"

#define GOSSIP_CREATE_INDEX_USER_ROLES_ROLE \
    "CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);"

#define GOSSIP_CREATE_INDEX_ROLE_PERMISSIONS_ROLE \
    "CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);"

#define GOSSIP_CREATE_SEEN_DIGESTS \
    "CREATE TABLE IF NOT EXISTS gossip_seen (" \
    "    digest BLOB PRIMARY KEY," \
    "    expires_at INTEGER NOT NULL" \
    ");"

#define GOSSIP_CREATE_INDEX_SEEN_EXPIRES \
    "CREATE INDEX IF NOT EXISTS idx_gossip_seen_expires ON gossip_seen(expires_at);"

// SQL query constants for permissions.c and other modules
const char* SQL_SELECT_USER_BY_PUBKEY =
    "SELECT id, pubkey, username, age, created_at, updated_at, is_active "
    "FROM users WHERE pubkey = ?;";

const char* SQL_SELECT_USER_ROLES =
    "SELECT ur.id, ur.user_id, ur.role_id, ur.assigned_at, ur.assigned_by_user_id, r.name as role_name "
    "FROM user_roles ur "
    "JOIN roles r ON ur.role_id = r.id "
    "WHERE ur.user_id = ? AND ur.is_active = 1;";

const char* SQL_SELECT_ROLE_PERMISSIONS =
    "SELECT rp.id, rp.role_id, rp.permission_id, rp.granted_at, rp.granted_by_user_id, "
    "rp.scope_flags, rp.condition_flags, rp.time_start, rp.time_end, "
    "p.name as permission_name, p.permission_flags, p.category "
    "FROM role_permissions rp "
    "JOIN permissions p ON rp.permission_id = p.id "
    "WHERE rp.role_id = ? AND rp.is_active = 1;";

const char* SQL_INSERT_ROLE_PERMISSION =
    "INSERT OR REPLACE INTO role_permissions (role_id, permission_id, granted_by_user_id, scope_flags, condition_flags, time_start, time_end) "
    "VALUES (?, ?, ?, ?, ?, ?, ?);";

int gossip_store_init(void) {
    if (!db_is_initialized()) {
        return -1;
    }

    sqlite3* db = db_get_handle();
    if (!db) {
        return -1;
    }

    char* error_msg = NULL;
    int rc = sqlite3_exec(db, GOSSIP_CREATE_TABLE_SQL, NULL, NULL, &error_msg);
    if (rc != SQLITE_OK) {
        logger_error("gossip_store", "failed to create table: %s", error_msg);
        sqlite3_free(error_msg);
        return -1;
    }

    rc = sqlite3_exec(db, GOSSIP_CREATE_INDEX_EXPIRES, NULL, NULL, &error_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "gossip_store: failed to create expires index: %s\n", error_msg);
        sqlite3_free(error_msg);
        return -1;
    }

    rc = sqlite3_exec(db, GOSSIP_CREATE_INDEX_SENDER, NULL, NULL, &error_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "gossip_store: failed to create sender index: %s\n", error_msg);
        sqlite3_free(error_msg);
        return -1;
    }

    // Envelopes tables and indexes
    rc = sqlite3_exec(db, GOSSIP_CREATE_TABLE_ENVELOPES, NULL, NULL, &error_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "gossip_store: failed to create envelopes table: %s\n", error_msg);
        sqlite3_free(error_msg);
        return -1;
    }
    rc = sqlite3_exec(db, GOSSIP_CREATE_INDEX_ENV_EXPIRES, NULL, NULL, &error_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "gossip_store: failed to create envelopes expires index: %s\n", error_msg);
        sqlite3_free(error_msg);
        return -1;
    }
    rc = sqlite3_exec(db, GOSSIP_CREATE_INDEX_ENV_SENDER, NULL, NULL, &error_msg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "gossip_store: failed to create envelopes sender index: %s\n", error_msg);
        sqlite3_free(error_msg);
        return -1;
    }

    /* Gossip user/permission schema */
    const char* schema_statements[] = {
        GOSSIP_CREATE_USERS,
        GOSSIP_CREATE_ROLES,
        GOSSIP_CREATE_PERMISSIONS,
        GOSSIP_CREATE_USER_ROLES,
        GOSSIP_CREATE_ROLE_PERMISSIONS,
        GOSSIP_CREATE_TRANSACTION_PERMISSIONS,
        GOSSIP_CREATE_SEEN_DIGESTS,
        GOSSIP_CREATE_INDEX_USERS_PUBKEY,
        GOSSIP_CREATE_INDEX_ROLES_NAME,
        GOSSIP_CREATE_INDEX_USER_ROLES_USER,
        GOSSIP_CREATE_INDEX_USER_ROLES_ROLE,
        GOSSIP_CREATE_INDEX_ROLE_PERMISSIONS_ROLE,
        GOSSIP_CREATE_INDEX_SEEN_EXPIRES,
        NULL
    };

    for (int i = 0; schema_statements[i] != NULL; ++i) {
        rc = sqlite3_exec(db, schema_statements[i], NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "gossip_store: failed to apply schema statement: %s\n", error_msg);
            sqlite3_free(error_msg);
            return -1;
        }
    }

    return 0;
}

int gossip_store_cleanup(uint64_t now_epoch) {
    if (!db_is_initialized()) {
        return -1;
    }

    sqlite3* db = db_get_handle();
    if (!db) {
        return -1;
    }

    const char* delete_envelopes_sql =
        "DELETE FROM gossip_envelopes WHERE expires_at <= ?;";
    const char* delete_seen_sql =
        "DELETE FROM gossip_seen WHERE expires_at <= ?;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, delete_envelopes_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, now_epoch);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return -1;
    }

    rc = sqlite3_prepare_v2(db, delete_seen_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, now_epoch);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int gossip_store_has_seen(const unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE], int* is_seen) {
    if (!digest || !is_seen || !db_is_initialized()) {
        return -1;
    }

    *is_seen = 0;

    sqlite3* db = db_get_handle();
    if (!db) {
        return -1;
    }

    const char* sql = "SELECT 1 FROM gossip_seen WHERE digest = ? LIMIT 1";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, digest, GOSSIP_SEEN_DIGEST_SIZE, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *is_seen = 1;
        sqlite3_finalize(stmt);
        return 0;
    }

    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int gossip_store_mark_seen(const unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE], uint64_t expires_at) {
    if (!digest || !db_is_initialized()) {
        return -1;
    }

    sqlite3* db = db_get_handle();
    if (!db) {
        return -1;
    }

    const char* sql =
        "INSERT OR REPLACE INTO gossip_seen (digest, expires_at) VALUES (?, ?);";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_blob(stmt, 1, digest, GOSSIP_SEEN_DIGEST_SIZE, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (sqlite3_int64)expires_at);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int gossip_store_save_envelope(uint32_t version, uint32_t content_type, uint32_t schema_version,
                               const unsigned char sender[PUBKEY_SIZE],
                               uint64_t timestamp,
                               const unsigned char* envelope, size_t envelope_size,
                               uint64_t expires_at) {
    if (!db_is_initialized() || !envelope || envelope_size == 0) return -1;
    sqlite3* db = db_get_handle(); if (!db) return -1;

    const char* sql =
        "INSERT INTO gossip_envelopes(version, content_type, schema_version, timestamp, sender, envelope, envelope_size, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?);";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, (int)version);
    sqlite3_bind_int(stmt, 2, (int)content_type);
    sqlite3_bind_int(stmt, 3, (int)schema_version);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)timestamp);
    sqlite3_bind_blob(stmt, 5, sender, PUBKEY_SIZE, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 6, envelope, (int)envelope_size, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, (int)envelope_size);
    sqlite3_bind_int64(stmt, 8, (sqlite3_int64)expires_at);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int gossip_store_fetch_recent_envelopes(uint32_t limit,
                                        GossipStoredEnvelope** out,
                                        size_t* count) {
    if (!out || !count || !db_is_initialized()) return -1;
    *out = NULL; *count = 0;
    sqlite3* db = db_get_handle(); if (!db) return -1;
    const char* sql =
        "SELECT id, version, content_type, schema_version, timestamp, sender, envelope, envelope_size, expires_at "
        "FROM gossip_envelopes ORDER BY timestamp DESC LIMIT ?;";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, (int)limit);
    GossipStoredEnvelope* rows = calloc(limit ? limit : 1, sizeof(GossipStoredEnvelope));
    if (!rows) { sqlite3_finalize(stmt); return -1; }
    size_t idx = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        rows[idx].id = sqlite3_column_int64(stmt, 0);
        rows[idx].version = sqlite3_column_int(stmt, 1);
        rows[idx].content_type = sqlite3_column_int(stmt, 2);
        rows[idx].schema_version = sqlite3_column_int(stmt, 3);
        rows[idx].timestamp = sqlite3_column_int64(stmt, 4);
        const void* sender_blob = sqlite3_column_blob(stmt, 5);
        int sender_len = sqlite3_column_bytes(stmt, 5);
        if (sender_blob && sender_len == PUBKEY_SIZE) {
            memcpy(rows[idx].sender, sender_blob, PUBKEY_SIZE);
        }
        const void* env_blob = sqlite3_column_blob(stmt, 6);
        int env_len = sqlite3_column_bytes(stmt, 6);
        if (env_blob && env_len > 0) {
            rows[idx].envelope = malloc(env_len);
            if (rows[idx].envelope) {
                memcpy(rows[idx].envelope, env_blob, env_len);
                rows[idx].envelope_size = (size_t)env_len;
            }
        }
        rows[idx].expires_at = sqlite3_column_int64(stmt, 8);
        idx++;
    }
    sqlite3_finalize(stmt);
    *out = rows; *count = idx; return 0;
}

void gossip_store_free_envelopes(GossipStoredEnvelope* envs, size_t count) {
    if (!envs) return;
    for (size_t i = 0; i < count; ++i) {
        free(envs[i].envelope);
    }
    free(envs);
}

// Schema versioning functions (needed for migration to version 2 with nodes table)
#define CURRENT_SCHEMA_VERSION 1  // Will be updated to 2 when nodes table is added

int schema_check_version(sqlite3* db, int* version) {
    if (!db || !version) return -1;
    
    // Check if schema_version table exists
    const char* check_table_sql = 
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version';";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, check_table_sql, -1, &stmt, NULL);
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
    if (!db) return -1;
    
    char* error_msg = NULL;
    
    // Create schema_version table if it doesn't exist
    const char* create_version_table = 
        "CREATE TABLE IF NOT EXISTS schema_version ("
        "    id INTEGER PRIMARY KEY,"
        "    version INTEGER NOT NULL,"
        "    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))"
        ");";
    
    int rc = sqlite3_exec(db, create_version_table, NULL, NULL, &error_msg);
    if (rc != SQLITE_OK) {
        if (error_msg) {
            fprintf(stderr, "Failed to create schema_version table: %s\n", error_msg);
            sqlite3_free(error_msg);
        }
        return -1;
    }
    
    // Insert or update version
    const char* set_version_sql = 
        "INSERT OR REPLACE INTO schema_version (id, version, updated_at) "
        "VALUES (1, ?, strftime('%s','now'));";
    
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
    
    return 0;
}

int schema_migrate(sqlite3* db, int from_version, int to_version) {
    if (!db) return -1;
    
    // Migration from 0 to 1: Create all tables and indexes
    if (from_version == 0 && to_version >= 1) {
        char* error_msg = NULL;
        int rc;
        
        // Create gossip_messages table and indexes
        rc = sqlite3_exec(db, GOSSIP_CREATE_TABLE_SQL, NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            if (error_msg) {
                fprintf(stderr, "schema_migrate: failed to create gossip_messages table: %s\n", error_msg);
                sqlite3_free(error_msg);
            }
            return -1;
        }
        
        rc = sqlite3_exec(db, GOSSIP_CREATE_INDEX_EXPIRES, NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            if (error_msg) {
                fprintf(stderr, "schema_migrate: failed to create gossip expires index: %s\n", error_msg);
                sqlite3_free(error_msg);
            }
            return -1;
        }
        
        rc = sqlite3_exec(db, GOSSIP_CREATE_INDEX_SENDER, NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            if (error_msg) {
                fprintf(stderr, "schema_migrate: failed to create gossip sender index: %s\n", error_msg);
                sqlite3_free(error_msg);
            }
            return -1;
        }
        
        // Create gossip_envelopes table and indexes
        rc = sqlite3_exec(db, GOSSIP_CREATE_TABLE_ENVELOPES, NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            if (error_msg) {
                fprintf(stderr, "schema_migrate: failed to create gossip_envelopes table: %s\n", error_msg);
                sqlite3_free(error_msg);
            }
            return -1;
        }
        
        rc = sqlite3_exec(db, GOSSIP_CREATE_INDEX_ENV_EXPIRES, NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            if (error_msg) {
                fprintf(stderr, "schema_migrate: failed to create envelopes expires index: %s\n", error_msg);
                sqlite3_free(error_msg);
            }
            return -1;
        }
        
        rc = sqlite3_exec(db, GOSSIP_CREATE_INDEX_ENV_SENDER, NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            if (error_msg) {
                fprintf(stderr, "schema_migrate: failed to create envelopes sender index: %s\n", error_msg);
                sqlite3_free(error_msg);
            }
            return -1;
        }
        
        // Create user/permission tables and indexes
        const char* schema_statements[] = {
            GOSSIP_CREATE_USERS,
            GOSSIP_CREATE_ROLES,
            GOSSIP_CREATE_PERMISSIONS,
            GOSSIP_CREATE_USER_ROLES,
            GOSSIP_CREATE_ROLE_PERMISSIONS,
            GOSSIP_CREATE_TRANSACTION_PERMISSIONS,
            GOSSIP_CREATE_SEEN_DIGESTS,
            GOSSIP_CREATE_INDEX_USERS_PUBKEY,
            GOSSIP_CREATE_INDEX_ROLES_NAME,
            GOSSIP_CREATE_INDEX_USER_ROLES_USER,
            GOSSIP_CREATE_INDEX_USER_ROLES_ROLE,
            GOSSIP_CREATE_INDEX_ROLE_PERMISSIONS_ROLE,
            GOSSIP_CREATE_INDEX_SEEN_EXPIRES,
            NULL
        };
        
        for (int i = 0; schema_statements[i] != NULL; ++i) {
            rc = sqlite3_exec(db, schema_statements[i], NULL, NULL, &error_msg);
            if (rc != SQLITE_OK) {
                if (error_msg) {
                    fprintf(stderr, "schema_migrate: failed to apply schema statement: %s\n", error_msg);
                    sqlite3_free(error_msg);
                }
                return -1;
            }
        }
        
        // Set version to 1
        if (schema_set_version(db, 1) != 0) {
            return -1;
        }
        
        return 0;
    }
    
    // Future: Add migration from 1 to 2 (add nodes table) here
    
    fprintf(stderr, "No migration path from version %d to %d\n", from_version, to_version);
    return -1;
}

