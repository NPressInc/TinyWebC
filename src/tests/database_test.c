#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

#include "database_test.h"
#include "packages/sql/database.h"
#include "packages/sql/queries.h"
#include "packages/sql/schema.h"
#include "features/blockchain/core/blockchain.h"
#include "features/blockchain/core/transaction_types.h"
#include "features/blockchain/persistence/blockchain_io.h"
#include "packages/keystore/keystore.h"
#include "structs/permission/permission.h"

#define TEST_DB_PATH "test_state/blockchain/test_blockchain.db"
#define BLOCKCHAIN_FILE_PATH "state/blockchain/blockchain.dat"

// Helper function to remove test database files
static void cleanup_test_db(void) {
    unlink(TEST_DB_PATH);
    unlink("test_blockchain.db-wal");
    unlink("test_blockchain.db-shm");
}

// Helper function to check if blockchain file exists
static int check_blockchain_file_exists(void) {
    struct stat st;
    if (stat(BLOCKCHAIN_FILE_PATH, &st) == 0) {
        printf("Found blockchain file: %s (size: %ld bytes)\n", BLOCKCHAIN_FILE_PATH, st.st_size);
        return 1;
    }
    return 0;
}

// Test database initialization
static int test_db_initialization(void) {
    printf("Testing database initialization...\n");
    
    // Clean up any existing test database
    cleanup_test_db();
    
    // Initialize database
    if (db_init(TEST_DB_PATH) != 0) {
        printf("✗ Failed to initialize database\n");
        return 1;
    }
    
    // Check if database is initialized
    if (!db_is_initialized()) {
        printf("✗ Database not marked as initialized\n");
        db_close();
        return 1;
    }
    
    // Check if database file was created
    struct stat st;
    if (stat(TEST_DB_PATH, &st) != 0) {
        printf("✗ Database file was not created\n");
        db_close();
        return 1;
    }
    
    printf("✓ Database initialization successful\n");
    return 0;
}

// Test blockchain loading and syncing
static int test_blockchain_sync(void) {
    printf("Testing blockchain sync to database...\n");
    
    // Check if blockchain file exists
    if (!check_blockchain_file_exists()) {
        printf("✗ Blockchain file not found: %s\n", BLOCKCHAIN_FILE_PATH);
        printf("  Please run blockchain test first to create the blockchain file\n");
        return 1;
    }
    
    // Load blockchain from file
    printf("Loading blockchain from file...\n");
    TW_BlockChain* blockchain = readBlockChainFromFile();
    if (!blockchain) {
        printf("✗ Failed to load blockchain from file\n");
        return 1;
    }
    
    printf("✓ Loaded blockchain with %u blocks\n", blockchain->length);
    
    // Sync blockchain to database
    printf("Syncing blockchain to database...\n");
    clock_t start_time = clock();
    
    if (db_sync_blockchain(blockchain) != 0) {
        printf("✗ Failed to sync blockchain to database\n");
        TW_BlockChain_destroy(blockchain);
        return 1;
    }
    
    clock_t end_time = clock();
    double sync_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("✓ Blockchain sync completed in %.2f seconds\n", sync_time);
    
    // Verify block count in database
    uint32_t db_block_count;
    if (db_get_block_count(&db_block_count) != 0) {
        printf("✗ Failed to get block count from database\n");
        TW_BlockChain_destroy(blockchain);
        return 1;
    }
    
    if (db_block_count != blockchain->length) {
        printf("✗ Block count mismatch: blockchain=%u, database=%u\n", 
               blockchain->length, db_block_count);
        TW_BlockChain_destroy(blockchain);
        return 1;
    }
    
    printf("✓ Block count verified: %u blocks\n", db_block_count);
    
    // Verify transaction count in database
    uint64_t db_tx_count;
    if (db_get_transaction_count(&db_tx_count) != 0) {
        printf("✗ Failed to get transaction count from database\n");
        TW_BlockChain_destroy(blockchain);
        return 1;
    }
    
    // Calculate expected transaction count
    uint64_t expected_tx_count = 0;
    for (uint32_t i = 0; i < blockchain->length; i++) {
        expected_tx_count += blockchain->blocks[i]->txn_count;
    }
    
    if (db_tx_count != expected_tx_count) {
        printf("✗ Transaction count mismatch: expected=%lu, database=%lu\n", 
               expected_tx_count, db_tx_count);
        TW_BlockChain_destroy(blockchain);
        return 1;
    }
    
    printf("✓ Transaction count verified: %lu transactions\n", db_tx_count);
    
    TW_BlockChain_destroy(blockchain);
    return 0;
}

// Test database queries
static int test_database_queries(void) {
    printf("Testing database queries...\n");
    
    // Test recent activity query
    TransactionRecord* records = NULL;
    size_t record_count = 0;
    
    if (query_recent_activity(10, &records, &record_count) != 0) {
        printf("✗ Failed to query recent activity\n");
        return 1;
    }
    
    printf("✓ Recent activity query returned %zu records\n", record_count);
    
    // Verify some basic properties of the records
    if (record_count > 0) {
        printf("  Sample record: Block %u, Transaction %u, Type %d\n",
               records[0].block_index, records[0].transaction_index, records[0].type);
        
        // Check if timestamps are reasonable (not zero and not in the future)
        time_t now = time(NULL);
        if (records[0].timestamp == 0 || records[0].timestamp > now + 3600) {
            printf("✗ Invalid timestamp in record: %lu\n", records[0].timestamp);
            db_free_transaction_records(records, record_count);
            return 1;
        }
    }
    
    db_free_transaction_records(records, record_count);
    
    // Test filtered query by type
    records = NULL;
    record_count = 0;
    
    if (query_transactions_by_type(TW_TXN_GROUP_MESSAGE, 5, &records, &record_count) != 0) {
        printf("✗ Failed to query filtered transactions\n");
        return 1;
    }
    
    printf("✓ Filtered query returned %zu records\n", record_count);
    
    // Verify filter was applied
    for (size_t i = 0; i < record_count; i++) {
        if (records[i].type != TW_TXN_GROUP_MESSAGE) {
            printf("✗ Filter not applied correctly: expected type %d, got %d\n",
                   TW_TXN_GROUP_MESSAGE, records[i].type);
            db_free_transaction_records(records, record_count);
            return 1;
        }
    }
    
    db_free_transaction_records(records, record_count);
    
    printf("✓ Database queries completed successfully\n");
    return 0;
}

// Test database performance and integrity
static int test_database_performance(void) {
    printf("Testing database performance and integrity...\n");
    
    // Test WAL checkpoint
    if (db_checkpoint_wal() != 0) {
        printf("✗ Failed to checkpoint WAL\n");
        return 1;
    }
    printf("✓ WAL checkpoint successful\n");
    
    // Get database statistics
    uint32_t block_count;
    uint64_t tx_count;
    
    if (db_get_block_count(&block_count) != 0 || db_get_transaction_count(&tx_count) != 0) {
        printf("✗ Failed to get database statistics\n");
        return 1;
    }
    
    printf("✓ Database statistics: %u blocks, %lu transactions\n", block_count, tx_count);
    
    // Test database file size
    struct stat st;
    if (stat(TEST_DB_PATH, &st) == 0) {
        printf("✓ Database file size: %ld bytes (%.2f MB)\n", 
               st.st_size, (double)st.st_size / (1024 * 1024));
    }
    
    return 0;
}

// Test user management functions
static int test_user_management(void) {
    printf("Testing user management functions...\n");
    
    // Test adding a user
    const char* test_pubkey = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    const char* test_username = "test_user";
    uint8_t test_age = 25;
    uint64_t test_tx_id = 12345;
    
    if (db_add_user(test_pubkey, test_username, test_age, test_tx_id) != 0) {
        printf("✗ Failed to add user\n");
        return 1;
    }
    printf("✓ User added successfully\n");
    
    // Test getting user by pubkey
    UserRecord user;
    if (db_get_user_by_pubkey(test_pubkey, &user) != 0) {
        printf("✗ Failed to get user by pubkey\n");
        return 1;
    }
    
    // Verify user data
    if (strcmp(user.pubkey, test_pubkey) != 0 ||
        strcmp(user.username, test_username) != 0 ||
        user.age != test_age ||
        user.registration_transaction_id != test_tx_id) {
        printf("✗ User data mismatch\n");
        return 1;
    }
    printf("✓ User retrieval by pubkey successful\n");
    
    // Test getting user by username
    UserRecord user2;
    if (db_get_user_by_username(test_username, &user2) != 0) {
        printf("✗ Failed to get user by username\n");
        return 1;
    }
    
    if (strcmp(user2.pubkey, test_pubkey) != 0) {
        printf("✗ Username lookup failed\n");
        return 1;
    }
    printf("✓ User retrieval by username successful\n");
    
    // Test updating user
    const char* new_username = "updated_user";
    uint8_t new_age = 26;
    
    if (db_update_user(test_pubkey, new_username, new_age) != 0) {
        printf("✗ Failed to update user\n");
        return 1;
    }
    
    // Verify update
    if (db_get_user_by_pubkey(test_pubkey, &user) != 0) {
        printf("✗ Failed to get updated user\n");
        return 1;
    }
    
    if (strcmp(user.username, new_username) != 0 || user.age != new_age) {
        printf("✗ User update verification failed\n");
        return 1;
    }
    printf("✓ User update successful\n");
    
    // Test getting all users
    UserRecord* users;
    size_t user_count;
    
    if (db_get_all_users(&users, &user_count) != 0) {
        printf("✗ Failed to get all users\n");
        return 1;
    }
    
    printf("✓ Retrieved %zu users\n", user_count);
    
    // Should have at least our test user
    if (user_count == 0) {
        printf("✗ No users found\n");
        return 1;
    }
    
    db_free_user_records(users, user_count);
    
    printf("✓ User management tests completed successfully\n");
    return 0;
}

// Test role management functions
static int test_role_management(void) {
    printf("Testing role management functions...\n");
    
    // Test adding a role
    const char* test_role_name = "test_admin";
    const char* test_description = "Test administrator role";
    uint64_t test_tx_id = 54321;
    
    if (db_add_role(test_role_name, test_description, test_tx_id) != 0) {
        printf("✗ Failed to add role\n");
        return 1;
    }
    printf("✓ Role added successfully\n");
    
    // Test getting role by name
    RoleRecord role;
    if (db_get_role_by_name(test_role_name, &role) != 0) {
        printf("✗ Failed to get role by name\n");
        return 1;
    }
    
    // Verify role data
    if (strcmp(role.name, test_role_name) != 0 ||
        strcmp(role.description, test_description) != 0 ||
        role.assignment_transaction_id != test_tx_id) {
        printf("✗ Role data mismatch\n");
        return 1;
    }
    printf("✓ Role retrieval successful\n");
    
    // Test updating role
    const char* new_description = "Updated administrator role";
    
    if (db_update_role(test_role_name, new_description) != 0) {
        printf("✗ Failed to update role\n");
        return 1;
    }
    
    // Verify update
    if (db_get_role_by_name(test_role_name, &role) != 0) {
        printf("✗ Failed to get updated role\n");
        return 1;
    }
    
    if (strcmp(role.description, new_description) != 0) {
        printf("✗ Role update verification failed\n");
        return 1;
    }
    printf("✓ Role update successful\n");
    
    // Test getting all roles
    RoleRecord* roles;
    size_t role_count;
    
    if (db_get_all_roles(&roles, &role_count) != 0) {
        printf("✗ Failed to get all roles\n");
        return 1;
    }
    
    printf("✓ Retrieved %zu roles\n", role_count);
    
    if (role_count == 0) {
        printf("✗ No roles found\n");
        return 1;
    }
    
    db_free_role_records(roles, role_count);
    
    printf("✓ Role management tests completed successfully\n");
    return 0;
}

// Test permission management functions
static int test_permission_management(void) {
    printf("Testing permission management functions...\n");
    
    // Test adding a permission
    const char* test_perm_name = "test_send_message";
    uint64_t test_perm_flags = PERMISSION_SEND_MESSAGE;
    uint32_t test_scope_flags = (1 << SCOPE_PRIMARY_GROUP);
    uint64_t test_condition_flags = CONDITION_ALWAYS;
    uint8_t test_category = PERM_CATEGORY_MESSAGING;
    const char* test_description = "Test messaging permission";
    uint64_t test_tx_id = 67890;
    
    if (db_add_permission(test_perm_name, test_perm_flags, test_scope_flags, 
                         test_condition_flags, test_category, test_description, test_tx_id) != 0) {
        printf("✗ Failed to add permission\n");
        return 1;
    }
    printf("✓ Permission added successfully\n");
    
    // Test getting permission by name
    PermissionRecord permission;
    if (db_get_permission_by_name(test_perm_name, &permission) != 0) {
        printf("✗ Failed to get permission by name\n");
        return 1;
    }
    
    // Verify permission data
    if (strcmp(permission.name, test_perm_name) != 0 ||
        permission.permission_flags != test_perm_flags ||
        permission.scope_flags != test_scope_flags ||
        permission.condition_flags != test_condition_flags ||
        permission.category != test_category ||
        strcmp(permission.description, test_description) != 0 ||
        permission.edit_transaction_id != test_tx_id) {
        printf("✗ Permission data mismatch\n");
        printf("  Expected flags: %lu, got: %lu\n", test_perm_flags, permission.permission_flags);
        printf("  Expected scope: %u, got: %u\n", test_scope_flags, permission.scope_flags);
        return 1;
    }
    printf("✓ Permission retrieval successful\n");
    
    // Test updating permission
    const char* new_description = "Updated messaging permission";
    uint64_t new_perm_flags = PERMISSION_SEND_MESSAGE | PERMISSION_READ_MESSAGE;
    
    if (db_update_permission(test_perm_name, new_perm_flags, test_scope_flags, 
                            test_condition_flags, test_category, new_description) != 0) {
        printf("✗ Failed to update permission\n");
        return 1;
    }
    
    // Verify update
    if (db_get_permission_by_name(test_perm_name, &permission) != 0) {
        printf("✗ Failed to get updated permission\n");
        return 1;
    }
    
    if (strcmp(permission.description, new_description) != 0 ||
        permission.permission_flags != new_perm_flags) {
        printf("✗ Permission update verification failed\n");
        return 1;
    }
    printf("✓ Permission update successful\n");
    
    // Test getting all permissions
    PermissionRecord* permissions;
    size_t permission_count;
    
    if (db_get_all_permissions(&permissions, &permission_count) != 0) {
        printf("✗ Failed to get all permissions\n");
        return 1;
    }
    
    printf("✓ Retrieved %zu permissions\n", permission_count);
    
    if (permission_count == 0) {
        printf("✗ No permissions found\n");
        return 1;
    }
    
    db_free_permission_records(permissions, permission_count);
    
    printf("✓ Permission management tests completed successfully\n");
    return 0;
}

// Test user-role and role-permission relationships
static int test_relationships(void) {
    printf("Testing user-role and role-permission relationships...\n");
    
    // First, get the IDs of our test user and role
    UserRecord user;
    if (db_get_user_by_username("updated_user", &user) != 0) {
        printf("✗ Failed to get test user for relationship test\n");
        return 1;
    }
    
    RoleRecord role;
    if (db_get_role_by_name("test_admin", &role) != 0) {
        printf("✗ Failed to get test role for relationship test\n");
        return 1;
    }
    
    PermissionRecord permission;
    if (db_get_permission_by_name("test_send_message", &permission) != 0) {
        printf("✗ Failed to get test permission for relationship test\n");
        return 1;
    }
    
    // Test assigning user to role
    uint64_t assignment_tx_id = 99999;
    if (db_assign_user_role(user.id, role.id, user.id, assignment_tx_id) != 0) {
        printf("✗ Failed to assign user to role\n");
        return 1;
    }
    printf("✓ User assigned to role successfully\n");
    
    // Test granting permission to role
    uint64_t grant_tx_id = 88888;
    uint64_t time_start = 0;  // No time restriction
    uint64_t time_end = 0;
    
    if (db_grant_role_permission(role.id, permission.id, user.id, grant_tx_id, time_start, time_end) != 0) {
        printf("✗ Failed to grant permission to role\n");
        return 1;
    }
    printf("✓ Permission granted to role successfully\n");
    
    printf("✓ Relationship tests completed successfully\n");
    return 0;
}

// Test schema migration
static int test_schema_migration(void) {
    printf("Testing schema migration...\n");
    
    // Check current schema version
    sqlite3* db = db_get_handle();
    if (!db) {
        printf("✗ Failed to get database handle\n");
        return 1;
    }
    
    int version;
    if (schema_check_version(db, &version) != 0) {
        printf("✗ Failed to check schema version\n");
        return 1;
    }
    
    printf("✓ Current schema version: %d\n", version);
    
    if (version != CURRENT_SCHEMA_VERSION) {
        printf("✗ Schema version mismatch: expected %d, got %d\n", CURRENT_SCHEMA_VERSION, version);
        return 1;
    }
    
    printf("✓ Schema migration test completed successfully\n");
    return 0;
}

int database_test_main(void) {
    printf("=== Database Test Suite ===\n");
    
    int tests_passed = 0;
    int tests_failed = 0;
    
    // Test 1: Database initialization
    if (test_db_initialization() == 0) {
        tests_passed++;
        printf("✓ Database initialization test passed\n\n");
    } else {
        tests_failed++;
        printf("✗ Database initialization test failed\n\n");
        cleanup_test_db();
        return 1;
    }
    
    // Test 2: Blockchain sync
    if (test_blockchain_sync() == 0) {
        tests_passed++;
        printf("✓ Blockchain sync test passed\n\n");
    } else {
        tests_failed++;
        printf("✗ Blockchain sync test failed\n\n");
        db_close();
        cleanup_test_db();
        return 1;
    }
    
    // Test 3: Database queries
    if (test_database_queries() == 0) {
        tests_passed++;
        printf("✓ Database queries test passed\n\n");
    } else {
        tests_failed++;
        printf("✗ Database queries test failed\n\n");
        db_close();
        cleanup_test_db();
        return 1;
    }
    
    // Test 4: Performance and integrity
    if (test_database_performance() == 0) {
        tests_passed++;
        printf("✓ Database performance test passed\n\n");
    } else {
        tests_failed++;
        printf("✗ Database performance test failed\n\n");
        db_close();
        cleanup_test_db();
        return 1;
    }
    
    // Test 5: User management
    if (test_user_management() == 0) {
        tests_passed++;
        printf("✓ User management test passed\n\n");
    } else {
        tests_failed++;
        printf("✗ User management test failed\n\n");
        db_close();
        cleanup_test_db();
        return 1;
    }
    
    // Test 6: Role management
    if (test_role_management() == 0) {
        tests_passed++;
        printf("✓ Role management test passed\n\n");
    } else {
        tests_failed++;
        printf("✗ Role management test failed\n\n");
        db_close();
        cleanup_test_db();
        return 1;
    }
    
    // Test 7: Permission management
    if (test_permission_management() == 0) {
        tests_passed++;
        printf("✓ Permission management test passed\n\n");
    } else {
        tests_failed++;
        printf("✗ Permission management test failed\n\n");
        db_close();
        cleanup_test_db();
        return 1;
    }
    
    // Test 8: Relationships
    if (test_relationships() == 0) {
        tests_passed++;
        printf("✓ Relationships test passed\n\n");
    } else {
        tests_failed++;
        printf("✗ Relationships test failed\n\n");
        db_close();
        cleanup_test_db();
        return 1;
    }
    
    // Test 9: Schema migration
    if (test_schema_migration() == 0) {
        tests_passed++;
        printf("✓ Schema migration test passed\n\n");
    } else {
        tests_failed++;
        printf("✗ Schema migration test failed\n\n");
        db_close();
        cleanup_test_db();
        return 1;
    }
    
    // Close database and cleanup
    db_close();
    //cleanup_test_db();
    
    // Print summary
    printf("=== Database Test Summary ===\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("Total tests: %d\n", tests_passed + tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
} 