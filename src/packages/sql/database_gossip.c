#include "database_gossip.h"
#include "packages/utils/error.h"
#include "packages/utils/logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static sqlite3* g_db = NULL;
static int g_initialized = 0;

int db_init_gossip(const char* db_path) {
    if (!db_path) {
        tw_error_create(TW_ERROR_NULL_POINTER, "database", __func__, __LINE__, "db_path is NULL");
        logger_error("database", "db_path is NULL");
        return -1;
    }
    if (g_initialized) {
        tw_error_create(TW_ERROR_INVALID_STATE, "database", __func__, __LINE__, "Database already initialized");
        logger_error("database", "Database already initialized");
        return -1;
    }

    int rc = sqlite3_open(db_path, &g_db);
    if (rc != SQLITE_OK) {
        const char* err_msg = sqlite3_errmsg(g_db);
        tw_error_create(tw_error_from_sqlite_error(rc), "database", __func__, __LINE__, "Failed to open database: %s", err_msg);
        logger_error("database", "Failed to open database: %s", err_msg);
        sqlite3_close(g_db);
        g_db = NULL;
        return -1;
    }

    // Enable WAL mode for better concurrency
    // Note: SQLite with WAL mode is thread-safe for concurrent reads
    // Multiple readers can access the database simultaneously
    // Only one writer at a time is allowed
    rc = sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        const char* err_msg = sqlite3_errmsg(g_db);
        tw_error_create(tw_error_from_sqlite_error(rc), "database", __func__, __LINE__, "Failed to enable WAL mode: %s", err_msg);
        logger_error("database", "Failed to enable WAL mode: %s", err_msg);
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
    if (rc != SQLITE_OK) {
        const char* err_msg = sqlite3_errmsg(g_db);
        tw_error_create(tw_error_from_sqlite_error(rc), "database", __func__, __LINE__, "Failed to close database: %s", err_msg);
        logger_error("database", "Failed to close database: %s", err_msg);
    }
    g_db = NULL;
    g_initialized = 0;
    return (rc == SQLITE_OK) ? 0 : -1;
}
