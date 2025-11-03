#include "gossip_store.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "database.h"

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
        fprintf(stderr, "gossip_store: failed to create table: %s\n", error_msg);
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

    return 0;
}

int gossip_store_save_transaction(const TW_Transaction* transaction,
                                  uint64_t expires_at) {
    if (!transaction || !db_is_initialized()) {
        return -1;
    }

    sqlite3* db = db_get_handle();
    if (!db) {
        return -1;
    }

    size_t serialized_size = TW_Transaction_get_size(transaction);
    if (serialized_size == 0) {
        return -1;
    }

    unsigned char* buffer = malloc(serialized_size);
    if (!buffer) {
        return -1;
    }

    unsigned char* write_ptr = buffer;
    if (TW_Transaction_serialize((TW_Transaction*)transaction, &write_ptr) != 0) {
        free(buffer);
        return -1;
    }

    const char* insert_sql =
        "INSERT INTO gossip_messages (type, sender, timestamp, payload, payload_size, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?);";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(buffer);
        return -1;
    }

    sqlite3_bind_int(stmt, 1, transaction->type);
    sqlite3_bind_blob(stmt, 2, transaction->sender, PUBKEY_SIZE, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, transaction->timestamp);
    sqlite3_bind_blob(stmt, 4, buffer, (int)serialized_size, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 5, (int)serialized_size);
    sqlite3_bind_int64(stmt, 6, expires_at);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    free(buffer);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

int gossip_store_fetch_recent(uint32_t limit,
                              GossipStoredMessage** messages,
                              size_t* count) {
    if (!messages || !count || !db_is_initialized()) {
        return -1;
    }

    *messages = NULL;
    *count = 0;

    sqlite3* db = db_get_handle();
    if (!db) {
        return -1;
    }

    const char* select_sql =
        "SELECT id, type, sender, timestamp, payload, payload_size, expires_at "
        "FROM gossip_messages ORDER BY timestamp DESC LIMIT ?;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, select_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, (int)limit);

    GossipStoredMessage* results = calloc(limit ? limit : 1, sizeof(GossipStoredMessage));
    if (!results) {
        sqlite3_finalize(stmt);
        return -1;
    }

    size_t index = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results[index].id = sqlite3_column_int64(stmt, 0);
        results[index].type = sqlite3_column_int(stmt, 1);

        const void* sender_blob = sqlite3_column_blob(stmt, 2);
        int sender_size = sqlite3_column_bytes(stmt, 2);
        if (sender_blob && sender_size == PUBKEY_SIZE) {
            memcpy(results[index].sender, sender_blob, PUBKEY_SIZE);
        }

        results[index].timestamp = sqlite3_column_int64(stmt, 3);

        const void* payload_blob = sqlite3_column_blob(stmt, 4);
        int payload_size = sqlite3_column_bytes(stmt, 4);
        if (payload_blob && payload_size > 0) {
            results[index].payload = malloc(payload_size);
            if (results[index].payload) {
                memcpy(results[index].payload, payload_blob, payload_size);
                results[index].payload_size = (size_t)payload_size;
            }
        }

        results[index].expires_at = sqlite3_column_int64(stmt, 6);
        index++;
    }

    sqlite3_finalize(stmt);

    *messages = results;
    *count = index;
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

    const char* delete_sql =
        "DELETE FROM gossip_messages WHERE expires_at <= ?;";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, delete_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int64(stmt, 1, now_epoch);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return (rc == SQLITE_DONE) ? 0 : -1;
}

void gossip_store_free_messages(GossipStoredMessage* messages,
                                size_t count) {
    if (!messages) {
        return;
    }

    for (size_t i = 0; i < count; ++i) {
        free(messages[i].payload);
    }

    free(messages);
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

