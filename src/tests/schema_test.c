#include "schema_test.h"
#include "test_init.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <errno.h>

#include "packages/sql/database_gossip.h"
#include "packages/sql/schema.h"  // Now contains gossip_store_init() (renamed from gossip_store.c)

#define ASSERT_TEST(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s\n", msg); \
            return -1; \
        } \
    } while (0)

static void ensure_directory_exists(const char* path) {
    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
        fprintf(stderr, "Failed to create directory %s: %s\n", path, strerror(errno));
    }
}

// Helper to check if a table exists
static int table_exists(sqlite3* db, const char* table_name) {
    char sql[256];
    snprintf(sql, sizeof(sql), "SELECT name FROM sqlite_master WHERE type='table' AND name='%s';", table_name);
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return 0;
    }
    
    rc = sqlite3_step(stmt);
    int exists = (rc == SQLITE_ROW);
    sqlite3_finalize(stmt);
    
    return exists;
}

// Test that all expected tables are created
static int test_table_creation(void) {
    printf("  - test_table_creation...\n");
    
    ensure_directory_exists("test_state");
    const char* db_path = "test_state/schema_test.db";
    remove(db_path);
    
    int result = -1;
    if (db_init_gossip(db_path) != 0) {
        goto cleanup;
    }
    
    sqlite3* db = db_get_handle();
    if (db == NULL) {
        goto cleanup;
    }
    
    // Create all tables (gossip_store_init() creates all tables and indexes)
    if (gossip_store_init() != 0) {
        goto cleanup;
    }
    
    // Verify gossip-related tables exist
    if (table_exists(db, "gossip_messages") != 1) {
        fprintf(stderr, "[FAIL] gossip_messages table not created\n");
        goto cleanup;
    }
    if (table_exists(db, "gossip_envelopes") != 1) {
        fprintf(stderr, "[FAIL] gossip_envelopes table not created\n");
        goto cleanup;
    }
    if (table_exists(db, "gossip_seen") != 1) {
        fprintf(stderr, "[FAIL] gossip_seen table not created\n");
        goto cleanup;
    }
    
    // Verify user/role/permission tables exist
    if (table_exists(db, "users") != 1) {
        fprintf(stderr, "[FAIL] users table not created\n");
        goto cleanup;
    }
    if (table_exists(db, "roles") != 1) {
        fprintf(stderr, "[FAIL] roles table not created\n");
        goto cleanup;
    }
    if (table_exists(db, "permissions") != 1) {
        fprintf(stderr, "[FAIL] permissions table not created\n");
        goto cleanup;
    }
    if (table_exists(db, "user_roles") != 1) {
        fprintf(stderr, "[FAIL] user_roles table not created\n");
        goto cleanup;
    }
    if (table_exists(db, "role_permissions") != 1) {
        fprintf(stderr, "[FAIL] role_permissions table not created\n");
        goto cleanup;
    }
    if (table_exists(db, "transaction_permissions") != 1) {
        fprintf(stderr, "[FAIL] transaction_permissions table not created\n");
        goto cleanup;
    }
    
    // Verify blockchain tables do NOT exist
    if (table_exists(db, "blockchain_info") != 0) {
        fprintf(stderr, "[FAIL] blockchain_info table should not exist\n");
        goto cleanup;
    }
    if (table_exists(db, "blocks") != 0) {
        fprintf(stderr, "[FAIL] blocks table should not exist\n");
        goto cleanup;
    }
    if (table_exists(db, "transactions") != 0) {
        fprintf(stderr, "[FAIL] transactions table should not exist\n");
        goto cleanup;
    }
    if (table_exists(db, "transaction_recipients") != 0) {
        fprintf(stderr, "[FAIL] transaction_recipients table should not exist\n");
        goto cleanup;
    }
    if (table_exists(db, "consensus_nodes") != 0) {
        fprintf(stderr, "[FAIL] consensus_nodes table should not exist\n");
        goto cleanup;
    }
    
    result = 0;
    
cleanup:
    db_close();
    remove(db_path);
    
    if (result == 0) {
        printf("    ✓ table creation passed\n");
    }
    return result;
}

// Test index creation
static int test_index_creation(void) {
    printf("  - test_index_creation...\n");
    
    ensure_directory_exists("test_state");
    const char* db_path = "test_state/schema_index_test.db";
    remove(db_path);
    
    int result = -1;
    if (db_init_gossip(db_path) != 0) {
        goto cleanup;
    }
    
    sqlite3* db = db_get_handle();
    if (db == NULL) {
        goto cleanup;
    }
    
    // gossip_store_init() creates all tables and indexes
    if (gossip_store_init() != 0) {
        goto cleanup;
    }
    
    // Verify all expected indexes exist
    sqlite3_stmt* stmt;
    const char* check_index_sql = "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%';";
    int rc = sqlite3_prepare_v2(db, check_index_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[FAIL] Failed to prepare index check statement\n");
        goto cleanup;
    }
    
    int found_gossip_expires = 0;
    int found_gossip_sender = 0;
    int found_gossip_env_expires = 0;
    int found_gossip_env_sender = 0;
    int found_gossip_seen_expires = 0;
    int found_users_pubkey = 0;
    int found_roles_name = 0;
    int found_user_roles_user = 0;
    int found_user_roles_role = 0;
    int found_role_permissions_role = 0;
    int found_blockchain_index = 0;
    
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char* index_name = (const char*)sqlite3_column_text(stmt, 0);
        if (strcmp(index_name, "idx_gossip_expires_at") == 0) found_gossip_expires = 1;
        if (strcmp(index_name, "idx_gossip_sender") == 0) found_gossip_sender = 1;
        if (strcmp(index_name, "idx_gossip_env_expires") == 0) found_gossip_env_expires = 1;
        if (strcmp(index_name, "idx_gossip_env_sender") == 0) found_gossip_env_sender = 1;
        if (strcmp(index_name, "idx_gossip_seen_expires") == 0) found_gossip_seen_expires = 1;
        if (strcmp(index_name, "idx_users_pubkey") == 0) found_users_pubkey = 1;
        if (strcmp(index_name, "idx_roles_name") == 0) found_roles_name = 1;
        if (strcmp(index_name, "idx_user_roles_user") == 0) found_user_roles_user = 1;
        if (strcmp(index_name, "idx_user_roles_role") == 0) found_user_roles_role = 1;
        if (strcmp(index_name, "idx_role_permissions_role") == 0) found_role_permissions_role = 1;
        if (strstr(index_name, "transactions") != NULL || strstr(index_name, "blocks") != NULL) {
            found_blockchain_index = 1;
        }
    }
    sqlite3_finalize(stmt);
    
    if (found_gossip_expires != 1) {
        fprintf(stderr, "[FAIL] idx_gossip_expires_at index not found\n");
        goto cleanup;
    }
    if (found_gossip_sender != 1) {
        fprintf(stderr, "[FAIL] idx_gossip_sender index not found\n");
        goto cleanup;
    }
    if (found_gossip_env_expires != 1) {
        fprintf(stderr, "[FAIL] idx_gossip_env_expires index not found\n");
        goto cleanup;
    }
    if (found_gossip_env_sender != 1) {
        fprintf(stderr, "[FAIL] idx_gossip_env_sender index not found\n");
        goto cleanup;
    }
    if (found_gossip_seen_expires != 1) {
        fprintf(stderr, "[FAIL] idx_gossip_seen_expires index not found\n");
        goto cleanup;
    }
    if (found_users_pubkey != 1) {
        fprintf(stderr, "[FAIL] idx_users_pubkey index not found\n");
        goto cleanup;
    }
    if (found_roles_name != 1) {
        fprintf(stderr, "[FAIL] idx_roles_name index not found\n");
        goto cleanup;
    }
    if (found_user_roles_user != 1) {
        fprintf(stderr, "[FAIL] idx_user_roles_user index not found\n");
        goto cleanup;
    }
    if (found_user_roles_role != 1) {
        fprintf(stderr, "[FAIL] idx_user_roles_role index not found\n");
        goto cleanup;
    }
    if (found_role_permissions_role != 1) {
        fprintf(stderr, "[FAIL] idx_role_permissions_role index not found\n");
        goto cleanup;
    }
    if (found_blockchain_index != 0) {
        fprintf(stderr, "[FAIL] Blockchain indexes should not exist\n");
        goto cleanup;
    }
    
    result = 0;
    
cleanup:
    db_close();
    remove(db_path);
    
    if (result == 0) {
        printf("    ✓ index creation passed\n");
    }
    return result;
}

// Test schema version management
static int test_schema_version(void) {
    printf("  - test_schema_version...\n");
    
    ensure_directory_exists("test_state");
    const char* db_path = "test_state/schema_version_test.db";
    remove(db_path);
    
    int result = -1;
    if (db_init_gossip(db_path) != 0) {
        goto cleanup;
    }
    
    sqlite3* db = db_get_handle();
    if (db == NULL) {
        goto cleanup;
    }
    
    // Check version on fresh database (should be 0)
    int version = -1;
    if (schema_check_version(db, &version) != 0) {
        fprintf(stderr, "[FAIL] schema_check_version failed\n");
        goto cleanup;
    }
    if (version != 0) {
        fprintf(stderr, "[FAIL] Expected version 0 for fresh database, got %d\n", version);
        goto cleanup;
    }
    
    // Set version to 1
    if (schema_set_version(db, 1) != 0) {
        fprintf(stderr, "[FAIL] schema_set_version failed\n");
        goto cleanup;
    }
    
    // Check version again
    version = -1;
    if (schema_check_version(db, &version) != 0) {
        fprintf(stderr, "[FAIL] schema_check_version failed\n");
        goto cleanup;
    }
    if (version != 1) {
        fprintf(stderr, "[FAIL] Expected version 1 after set_version, got %d\n", version);
        goto cleanup;
    }
    
    result = 0;
    
cleanup:
    db_close();
    remove(db_path);
    
    if (result == 0) {
        printf("    ✓ schema version management passed\n");
    }
    return result;
}

// Test schema migration
static int test_schema_migration(void) {
    printf("  - test_schema_migration...\n");
    
    ensure_directory_exists("test_state");
    const char* db_path = "test_state/schema_migration_test.db";
    remove(db_path);
    
    int result = -1;
    if (db_init_gossip(db_path) != 0) {
        goto cleanup;
    }
    
    sqlite3* db = db_get_handle();
    if (db == NULL) {
        goto cleanup;
    }
    
    // Migrate from version 0 to 1
    if (schema_migrate(db, 0, 1) != 0) {
        fprintf(stderr, "[FAIL] schema_migrate failed\n");
        goto cleanup;
    }
    
    // Verify tables were created
    if (table_exists(db, "gossip_messages") != 1) {
        fprintf(stderr, "[FAIL] gossip_messages table not created by migration\n");
        goto cleanup;
    }
    if (table_exists(db, "gossip_envelopes") != 1) {
        fprintf(stderr, "[FAIL] gossip_envelopes table not created by migration\n");
        goto cleanup;
    }
    if (table_exists(db, "gossip_seen") != 1) {
        fprintf(stderr, "[FAIL] gossip_seen table not created by migration\n");
        goto cleanup;
    }
    if (table_exists(db, "users") != 1) {
        fprintf(stderr, "[FAIL] users table not created by migration\n");
        goto cleanup;
    }
    if (table_exists(db, "roles") != 1) {
        fprintf(stderr, "[FAIL] roles table not created by migration\n");
        goto cleanup;
    }
    if (table_exists(db, "permissions") != 1) {
        fprintf(stderr, "[FAIL] permissions table not created by migration\n");
        goto cleanup;
    }
    
    // Verify version was set
    int version = -1;
    if (schema_check_version(db, &version) != 0) {
        fprintf(stderr, "[FAIL] schema_check_version failed\n");
        goto cleanup;
    }
    if (version != 1) {
        fprintf(stderr, "[FAIL] Expected version 1 after migration, got %d\n", version);
        goto cleanup;
    }
    
    result = 0;
    
cleanup:
    db_close();
    remove(db_path);
    
    if (result == 0) {
        printf("    ✓ schema migration passed\n");
    }
    return result;
}

// Test that tables can be used (INSERT/SELECT)
static int test_table_operations(void) {
    printf("  - test_table_operations...\n");
    
    ensure_directory_exists("test_state");
    const char* db_path = "test_state/schema_ops_test.db";
    remove(db_path);
    
    int result = -1;
    if (db_init_gossip(db_path) != 0) {
        goto cleanup;
    }
    
    sqlite3* db = db_get_handle();
    if (db == NULL) {
        goto cleanup;
    }
    
    // gossip_store_init() creates all tables and indexes
    if (gossip_store_init() != 0) {
        fprintf(stderr, "[FAIL] gossip_store_init failed\n");
        goto cleanup;
    }
    
    // Test INSERT into users table
    sqlite3_stmt* stmt;
    const char* insert_user_sql = "INSERT INTO users (pubkey, username, age) VALUES (?, ?, ?);";
    int rc = sqlite3_prepare_v2(db, insert_user_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[FAIL] Failed to prepare INSERT statement\n");
        goto cleanup;
    }
    
    const char* test_pubkey = "test_pubkey_123456789012345678901234567890";
    const char* test_username = "testuser";
    int test_age = 25;
    
    sqlite3_bind_text(stmt, 1, test_pubkey, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, test_username, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, test_age);
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[FAIL] INSERT into users failed\n");
        sqlite3_finalize(stmt);
        goto cleanup;
    }
    sqlite3_finalize(stmt);
    
    // Test SELECT from users table
    const char* select_user_sql = "SELECT username, age FROM users WHERE pubkey = ?;";
    rc = sqlite3_prepare_v2(db, select_user_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[FAIL] Failed to prepare SELECT statement\n");
        goto cleanup;
    }
    
    sqlite3_bind_text(stmt, 1, test_pubkey, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        fprintf(stderr, "[FAIL] SELECT from users returned no rows\n");
        sqlite3_finalize(stmt);
        goto cleanup;
    }
    
    const char* found_username = (const char*)sqlite3_column_text(stmt, 0);
    int found_age = sqlite3_column_int(stmt, 1);
    if (strcmp(found_username, test_username) != 0) {
        fprintf(stderr, "[FAIL] Username mismatch: expected '%s', got '%s'\n", test_username, found_username);
        sqlite3_finalize(stmt);
        goto cleanup;
    }
    if (found_age != test_age) {
        fprintf(stderr, "[FAIL] Age mismatch: expected %d, got %d\n", test_age, found_age);
        sqlite3_finalize(stmt);
        goto cleanup;
    }
    
    sqlite3_finalize(stmt);
    
    result = 0;
    
cleanup:
    db_close();
    remove(db_path);
    
    if (result == 0) {
        printf("    ✓ table operations passed\n");
    }
    return result;
}

int schema_test_main(void) {
    printf("Running schema tests...\n\n");
    
    int passed = 0;
    int failed = 0;
    
    if (test_table_creation() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    if (test_index_creation() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    if (test_schema_version() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    if (test_schema_migration() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    if (test_table_operations() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    printf("\nSchema Tests: %d passed, %d failed\n", passed, failed);
    
    return (failed > 0) ? -1 : 0;
}

