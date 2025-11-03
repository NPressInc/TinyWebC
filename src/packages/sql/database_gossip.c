#include "database_gossip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sqlite3* g_db = NULL;
static int g_initialized = 0;

int db_init_gossip(const char* db_path) {
    if (!db_path || g_initialized) {
        return -1;
    }

    int rc = sqlite3_open(db_path, &g_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to open database: %s\n", sqlite3_errmsg(g_db));
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    // Enable WAL mode for better concurrency
    rc = sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Failed to enable WAL mode\n");
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    g_initialized = 1;
    return 0;
}

int db_is_initialized(void) {
    return g_initialized && g_db != NULL;
}

sqlite3* db_get_handle(void) {
    return g_db;
}

int db_close(void) {
    if (!g_db) {
        return 0;
    }
    int rc = sqlite3_close(g_db);
    g_db = NULL;
    g_initialized = 0;
    return (rc == SQLITE_OK) ? 0 : -1;
}
