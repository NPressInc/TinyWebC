#include "schema_test.h"
#include "test_init.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sys/stat.h>
#include <errno.h>

#include "packages/sql/database_gossip.h"
#include "packages/sql/schema.h"

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

// Test that only user/role/permission tables are created
static int test_table_creation(void) {
    printf("  - test_table_creation...\n");
    
    ensure_directory_exists("test_state");
    const char* db_path = "test_state/schema_test.db";
    remove(db_path);
    
    ASSERT_TEST(db_init_gossip(db_path) == 0, "db_init_gossip failed");
    
    sqlite3* db = db_get_handle();
    ASSERT_TEST(db != NULL, "db_get_handle returned NULL");
    
    // Create all tables
    ASSERT_TEST(schema_create_all_tables(db) == 0, "schema_create_all_tables failed");
    
    // Verify user/role/permission tables exist
    ASSERT_TEST(table_exists(db, "users") == 1, "users table not created");
    ASSERT_TEST(table_exists(db, "roles") == 1, "roles table not created");
    ASSERT_TEST(table_exists(db, "permissions") == 1, "permissions table not created");
    ASSERT_TEST(table_exists(db, "user_roles") == 1, "user_roles table not created");
    ASSERT_TEST(table_exists(db, "role_permissions") == 1, "role_permissions table not created");
    
    // Verify blockchain tables do NOT exist
    ASSERT_TEST(table_exists(db, "blockchain_info") == 0, "blockchain_info table should not exist");
    ASSERT_TEST(table_exists(db, "blocks") == 0, "blocks table should not exist");
    ASSERT_TEST(table_exists(db, "transactions") == 0, "transactions table should not exist");
    ASSERT_TEST(table_exists(db, "transaction_recipients") == 0, "transaction_recipients table should not exist");
    ASSERT_TEST(table_exists(db, "consensus_nodes") == 0, "consensus_nodes table should not exist");
    
    ASSERT_TEST(db_close() == 0, "db_close failed");
    remove(db_path);
    
    printf("    ✓ table creation passed\n");
    return 0;
}

// Test index creation
static int test_index_creation(void) {
    printf("  - test_index_creation...\n");
    
    ensure_directory_exists("test_state");
    const char* db_path = "test_state/schema_index_test.db";
    remove(db_path);
    
    ASSERT_TEST(db_init_gossip(db_path) == 0, "db_init_gossip failed");
    
    sqlite3* db = db_get_handle();
    ASSERT_TEST(schema_create_all_tables(db) == 0, "schema_create_all_tables failed");
    ASSERT_TEST(schema_create_all_indexes(db) == 0, "schema_create_all_indexes failed");
    
    // Verify user/role/permission indexes exist
    sqlite3_stmt* stmt;
    const char* check_index_sql = "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%';";
    int rc = sqlite3_prepare_v2(db, check_index_sql, -1, &stmt, NULL);
    ASSERT_TEST(rc == SQLITE_OK, "Failed to prepare index check statement");
    
    int found_users_pubkey = 0;
    int found_users_username = 0;
    int found_roles_name = 0;
    int found_blockchain_index = 0;
    
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char* index_name = (const char*)sqlite3_column_text(stmt, 0);
        if (strcmp(index_name, "idx_users_pubkey") == 0) found_users_pubkey = 1;
        if (strcmp(index_name, "idx_users_username") == 0) found_users_username = 1;
        if (strcmp(index_name, "idx_roles_name") == 0) found_roles_name = 1;
        if (strstr(index_name, "transactions") != NULL || strstr(index_name, "blocks") != NULL) {
            found_blockchain_index = 1;
        }
    }
    sqlite3_finalize(stmt);
    
    ASSERT_TEST(found_users_pubkey == 1, "idx_users_pubkey index not found");
    ASSERT_TEST(found_users_username == 1, "idx_users_username index not found");
    ASSERT_TEST(found_roles_name == 1, "idx_roles_name index not found");
    ASSERT_TEST(found_blockchain_index == 0, "Blockchain indexes should not exist");
    
    ASSERT_TEST(db_close() == 0, "db_close failed");
    remove(db_path);
    
    printf("    ✓ index creation passed\n");
    return 0;
}

// Test schema version management
static int test_schema_version(void) {
    printf("  - test_schema_version...\n");
    
    ensure_directory_exists("test_state");
    const char* db_path = "test_state/schema_version_test.db";
    remove(db_path);
    
    ASSERT_TEST(db_init_gossip(db_path) == 0, "db_init_gossip failed");
    
    sqlite3* db = db_get_handle();
    
    // Check version on fresh database (should be 0)
    int version = -1;
    ASSERT_TEST(schema_check_version(db, &version) == 0, "schema_check_version failed");
    ASSERT_TEST(version == 0, "Expected version 0 for fresh database");
    
    // Set version to 1
    ASSERT_TEST(schema_set_version(db, 1) == 0, "schema_set_version failed");
    
    // Check version again
    version = -1;
    ASSERT_TEST(schema_check_version(db, &version) == 0, "schema_check_version failed");
    ASSERT_TEST(version == 1, "Expected version 1 after set_version");
    
    ASSERT_TEST(db_close() == 0, "db_close failed");
    remove(db_path);
    
    printf("    ✓ schema version management passed\n");
    return 0;
}

// Test schema migration
static int test_schema_migration(void) {
    printf("  - test_schema_migration...\n");
    
    ensure_directory_exists("test_state");
    const char* db_path = "test_state/schema_migration_test.db";
    remove(db_path);
    
    ASSERT_TEST(db_init_gossip(db_path) == 0, "db_init_gossip failed");
    
    sqlite3* db = db_get_handle();
    
    // Migrate from version 0 to 1
    ASSERT_TEST(schema_migrate(db, 0, 1) == 0, "schema_migrate failed");
    
    // Verify tables were created
    ASSERT_TEST(table_exists(db, "users") == 1, "users table not created by migration");
    ASSERT_TEST(table_exists(db, "roles") == 1, "roles table not created by migration");
    ASSERT_TEST(table_exists(db, "permissions") == 1, "permissions table not created by migration");
    
    // Verify version was set
    int version = -1;
    ASSERT_TEST(schema_check_version(db, &version) == 0, "schema_check_version failed");
    ASSERT_TEST(version == 1, "Expected version 1 after migration");
    
    ASSERT_TEST(db_close() == 0, "db_close failed");
    remove(db_path);
    
    printf("    ✓ schema migration passed\n");
    return 0;
}

// Test that tables can be used (INSERT/SELECT)
static int test_table_operations(void) {
    printf("  - test_table_operations...\n");
    
    ensure_directory_exists("test_state");
    const char* db_path = "test_state/schema_ops_test.db";
    remove(db_path);
    
    ASSERT_TEST(db_init_gossip(db_path) == 0, "db_init_gossip failed");
    
    sqlite3* db = db_get_handle();
    ASSERT_TEST(schema_create_all_tables(db) == 0, "schema_create_all_tables failed");
    ASSERT_TEST(schema_create_all_indexes(db) == 0, "schema_create_all_indexes failed");
    
    // Test INSERT into users table
    sqlite3_stmt* stmt;
    const char* insert_user_sql = "INSERT INTO users (pubkey, username, age) VALUES (?, ?, ?);";
    int rc = sqlite3_prepare_v2(db, insert_user_sql, -1, &stmt, NULL);
    ASSERT_TEST(rc == SQLITE_OK, "Failed to prepare INSERT statement");
    
    const char* test_pubkey = "test_pubkey_123456789012345678901234567890";
    const char* test_username = "testuser";
    int test_age = 25;
    
    sqlite3_bind_text(stmt, 1, test_pubkey, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, test_username, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, test_age);
    
    rc = sqlite3_step(stmt);
    ASSERT_TEST(rc == SQLITE_DONE, "INSERT into users failed");
    sqlite3_finalize(stmt);
    
    // Test SELECT from users table
    const char* select_user_sql = "SELECT username, age FROM users WHERE pubkey = ?;";
    rc = sqlite3_prepare_v2(db, select_user_sql, -1, &stmt, NULL);
    ASSERT_TEST(rc == SQLITE_OK, "Failed to prepare SELECT statement");
    
    sqlite3_bind_text(stmt, 1, test_pubkey, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    ASSERT_TEST(rc == SQLITE_ROW, "SELECT from users returned no rows");
    
    const char* found_username = (const char*)sqlite3_column_text(stmt, 0);
    int found_age = sqlite3_column_int(stmt, 1);
    ASSERT_TEST(strcmp(found_username, test_username) == 0, "Username mismatch");
    ASSERT_TEST(found_age == test_age, "Age mismatch");
    
    sqlite3_finalize(stmt);
    
    ASSERT_TEST(db_close() == 0, "db_close failed");
    remove(db_path);
    
    printf("    ✓ table operations passed\n");
    return 0;
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

