#include "gossip_peers.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "database_gossip.h"

#define GOSSIP_PEERS_CREATE_TABLE \
    "CREATE TABLE IF NOT EXISTS gossip_peers (" \
    " hostname TEXT PRIMARY KEY," \
    " gossip_port INTEGER NOT NULL," \
    " api_port INTEGER NOT NULL," \
    " first_seen INTEGER NOT NULL," \
    " last_seen INTEGER NOT NULL," \
    " tags TEXT" \
    ");"

#define GOSSIP_PEERS_ADD_API_PORT \
    "ALTER TABLE gossip_peers ADD COLUMN api_port INTEGER NOT NULL DEFAULT 0;"

#define GOSSIP_PEERS_CREATE_INDEX_LAST_SEEN \
    "CREATE INDEX IF NOT EXISTS idx_gossip_peers_last_seen ON gossip_peers(last_seen);"

static int ensure_initialized(void) {
    if (!db_is_initialized()) {
        fprintf(stderr, "gossip_peers: database not initialized\n");
        return -1;
    }
    sqlite3* db = db_get_handle();
    if (!db) {
        fprintf(stderr, "gossip_peers: missing sqlite handle\n");
        return -1;
    }
    char* err = NULL;
    int rc = sqlite3_exec(db, GOSSIP_PEERS_CREATE_TABLE, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "gossip_peers: failed to create table: %s\n", err);
        sqlite3_free(err);
        return -1;
    }

    /* Ensure api_port column exists for upgrades from earlier schema */
    rc = sqlite3_exec(db, GOSSIP_PEERS_ADD_API_PORT, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        if (err && strstr(err, "duplicate column name") == NULL) {
            fprintf(stderr, "gossip_peers: failed to add api_port column: %s\n", err);
            sqlite3_free(err);
            return -1;
        }
        sqlite3_free(err);
    }

    rc = sqlite3_exec(db, GOSSIP_PEERS_CREATE_INDEX_LAST_SEEN, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "gossip_peers: failed to create index: %s\n", err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

int gossip_peers_init(void) {
    return ensure_initialized();
}

int gossip_peers_add_or_update(const char* hostname, uint16_t gossip_port, uint16_t api_port, const char* tags) {
    if (!hostname || hostname[0] == '\0') {
        return -1;
    }
    if (ensure_initialized() != 0) {
        return -1;
    }

    sqlite3* db = db_get_handle();
    const char* sql =
        "INSERT INTO gossip_peers (hostname, gossip_port, api_port, first_seen, last_seen, tags) "
        "VALUES (?, ?, ?, ?, ?, ?) "
        "ON CONFLICT(hostname) DO UPDATE SET gossip_port=excluded.gossip_port, api_port=excluded.api_port, last_seen=excluded.last_seen, tags=excluded.tags";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    uint64_t now = (uint64_t)time(NULL);
    sqlite3_bind_text(stmt, 1, hostname, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 2, (int)gossip_port);
    sqlite3_bind_int(stmt, 3, (int)api_port);
    sqlite3_bind_int64(stmt, 4, (sqlite3_int64)now);
    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)now);
    if (tags && tags[0] != '\0') {
        sqlite3_bind_text(stmt, 6, tags, -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 6);
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return (rc == SQLITE_DONE) ? 0 : -1;
}

int gossip_peers_touch(const char* hostname) {
    if (!hostname || hostname[0] == '\0') {
        return -1;
    }
    if (ensure_initialized() != 0) {
        return -1;
    }

    sqlite3* db = db_get_handle();
    const char* sql = "UPDATE gossip_peers SET last_seen = ? WHERE hostname = ?";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int64(stmt, 1, (sqlite3_int64)time(NULL));
    sqlite3_bind_text(stmt, 2, hostname, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        return -1;
    }
    if (sqlite3_changes(db) == 0) {
        return gossip_peers_add_or_update(hostname, 0, 0, NULL);
    }
    return 0;
}

int gossip_peers_fetch_all(GossipPeerInfo** peers, size_t* count) {
    if (!peers || !count) {
        return -1;
    }
    *peers = NULL;
    *count = 0;
    if (ensure_initialized() != 0) {
        return -1;
    }

    sqlite3* db = db_get_handle();
    const char* sql = "SELECT hostname, gossip_port, api_port, first_seen, last_seen, COALESCE(tags, '') FROM gossip_peers ORDER BY hostname";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    size_t capacity = 8;
    GossipPeerInfo* list = malloc(sizeof(GossipPeerInfo) * capacity);
    if (!list) {
        sqlite3_finalize(stmt);
        return -1;
    }

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (*count >= capacity) {
            capacity *= 2;
            GossipPeerInfo* tmp = realloc(list, sizeof(GossipPeerInfo) * capacity);
            if (!tmp) {
                free(list);
                sqlite3_finalize(stmt);
                return -1;
            }
            list = tmp;
        }
        GossipPeerInfo* item = &list[*count];
        memset(item, 0, sizeof(*item));
        const unsigned char* host_txt = sqlite3_column_text(stmt, 0);
        if (host_txt) {
            strncpy(item->hostname, (const char*)host_txt, sizeof(item->hostname) - 1);
        }
        item->gossip_port = (uint16_t)sqlite3_column_int(stmt, 1);
        item->api_port = (uint16_t)sqlite3_column_int(stmt, 2);
        item->first_seen = (uint64_t)sqlite3_column_int64(stmt, 3);
        item->last_seen = (uint64_t)sqlite3_column_int64(stmt, 4);
        const unsigned char* tags_txt = sqlite3_column_text(stmt, 5);
        if (tags_txt) {
            strncpy(item->tags, (const char*)tags_txt, sizeof(item->tags) - 1);
        }
        (*count)++;
    }

    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        free(list);
        return -1;
    }

    *peers = list;
    return 0;
}

void gossip_peers_free(GossipPeerInfo* peers, size_t count) {
    (void)count;
    free(peers);
}


