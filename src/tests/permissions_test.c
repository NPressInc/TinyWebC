#include "permissions_test.h"
#include "test_init.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sodium.h>
#include "packages/sql/database_gossip.h"
#include "packages/sql/schema.h"
#include "packages/sql/permissions.h"
#include "structs/permission/permission.h"
#include "packages/initialization/init.h"

#define ASSERT(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "FAIL: %s\n", message); \
            return -1; \
        } \
    } while (0)

// Helper to hex encode pubkey
static void hex_encode_pubkey(const unsigned char* pubkey, char* hex_out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        hex_out[i * 2] = hex[(pubkey[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = hex[pubkey[i] & 0xF];
    }
    hex_out[64] = '\0';
}

// Test that roles are created
static int test_roles_exist(sqlite3* db) {
    printf("  Testing roles exist...\n");
    
    const char* sql = "SELECT name, description FROM roles ORDER BY name";
    sqlite3_stmt* stmt = NULL;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    int found_admin = 0, found_member = 0, found_contact = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* name = (const char*)sqlite3_column_text(stmt, 0);
        if (strcmp(name, "admin") == 0) found_admin = 1;
        if (strcmp(name, "member") == 0) found_member = 1;
        if (strcmp(name, "contact") == 0) found_contact = 1;
    }
    
    sqlite3_finalize(stmt);
    
    ASSERT(found_admin, "admin role not found");
    ASSERT(found_member, "member role not found");
    ASSERT(found_contact, "contact role not found");
    
    printf("    ✓ All roles exist (admin, member, contact)\n");
    return 0;
}

// Test that permissions are seeded
static int test_permissions_seeded(sqlite3* db) {
    printf("  Testing permissions are seeded...\n");
    
    // Check for key messaging permissions
    const char* sql = "SELECT name, permission_flags FROM permissions WHERE name IN (?, ?, ?)";
    sqlite3_stmt* stmt = NULL;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, "send_message", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, "read_message", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, "manage_roles", -1, SQLITE_STATIC);
    
    int found_send = 0, found_read = 0, found_manage = 0;
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* name = (const char*)sqlite3_column_text(stmt, 0);
        uint64_t flags = sqlite3_column_int64(stmt, 1);
        
        if (strcmp(name, "send_message") == 0) {
            found_send = 1;
            ASSERT(flags == PERMISSION_SEND_MESSAGE, "send_message has wrong permission flag");
        }
        if (strcmp(name, "read_message") == 0) {
            found_read = 1;
            ASSERT(flags == PERMISSION_READ_MESSAGE, "read_message has wrong permission flag");
        }
        if (strcmp(name, "manage_roles") == 0) {
            found_manage = 1;
            ASSERT(flags == PERMISSION_MANAGE_ROLES, "manage_roles has wrong permission flag");
        }
    }
    
    sqlite3_finalize(stmt);
    
    ASSERT(found_send, "send_message permission not found");
    ASSERT(found_read, "read_message permission not found");
    ASSERT(found_manage, "manage_roles permission not found");
    
    printf("    ✓ Key permissions are seeded with correct flags\n");
    return 0;
}

// Test that role-permission mappings have scopes
static int test_role_permissions_with_scopes(sqlite3* db) {
    printf("  Testing role-permission mappings with scopes...\n");
    
    // Get admin role ID
    const char* get_role_sql = "SELECT id FROM roles WHERE name = ?";
    sqlite3_stmt* stmt = NULL;
    int admin_role_id = -1;
    
    if (sqlite3_prepare_v2(db, get_role_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, "admin", -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            admin_role_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    
    ASSERT(admin_role_id > 0, "admin role ID not found");
    
    // Get role_permissions for admin role
    const char* sql = SQL_SELECT_ROLE_PERMISSIONS;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, admin_role_id);
    
    int found_send_message = 0;
    uint32_t send_message_scope = 0;
    int row_count = 0;
    
    printf("    DEBUG: Checking role_permissions for admin role (id=%d)...\n", admin_role_id);
    
    // First, check what permissions exist in the database
    const char* check_perms_sql = "SELECT id, name, permission_flags FROM permissions WHERE name = 'send_message'";
    sqlite3_stmt* check_stmt = NULL;
    if (sqlite3_prepare_v2(db, check_perms_sql, -1, &check_stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(check_stmt) == SQLITE_ROW) {
            int perm_id = sqlite3_column_int(check_stmt, 0);
            const char* name = (const char*)sqlite3_column_text(check_stmt, 1);
            uint64_t flags = sqlite3_column_int64(check_stmt, 2);
            printf("    DEBUG: send_message permission exists: id=%d, name=%s, flags=0x%llx\n", 
                   perm_id, name ? name : "NULL", (unsigned long long)flags);
        } else {
            printf("    DEBUG: send_message permission NOT FOUND in permissions table!\n");
        }
        sqlite3_finalize(check_stmt);
    }
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        row_count++;
        // SQL_SELECT_ROLE_PERMISSIONS columns:
        // 0: rp.id, 1: rp.role_id, 2: rp.permission_id, 3: rp.granted_at, 4: rp.granted_by_user_id,
        // 5: rp.scope_flags, 6: rp.condition_flags, 7: rp.time_start, 8: rp.time_end,
        // 9: p.name as permission_name, 10: p.permission_flags, 11: p.category
        int perm_id = sqlite3_column_int(stmt, 2); // rp.permission_id (for debugging)
        const char* perm_name = (const char*)sqlite3_column_text(stmt, 9); // permission_name (column 9, not 8)
        uint32_t scope_flags = sqlite3_column_int(stmt, 5); // rp.scope_flags
        uint64_t perm_flags = sqlite3_column_int64(stmt, 10); // p.permission_flags (column 10, not 9)
        
        printf("    DEBUG: Row %d: permission_id=%d, name=%s, scope_flags=0x%x, permission_flags=0x%llx\n", 
               row_count, perm_id, perm_name ? perm_name : "NULL", scope_flags, (unsigned long long)perm_flags);
        
        if (perm_name && strcmp(perm_name, "send_message") == 0) {
            found_send_message = 1;
            send_message_scope = scope_flags;
        }
    }
    
    sqlite3_finalize(stmt);
    
    printf("    DEBUG: Total role_permissions rows: %d, found_send_message: %d\n", row_count, found_send_message);
    
    if (row_count == 0) {
        fprintf(stderr, "    ERROR: No role_permissions found for admin role. Check if seed_role_permissions() ran successfully.\n");
    }
    
    ASSERT(found_send_message, "admin role missing send_message permission");
    // ADMIN_MESSAGING has scopes: DIRECT | PRIMARY_GROUP | EXTENDED_GROUP | CONTACT_GROUP | COMMUNITY | ORGANIZATION
    uint32_t expected_scopes = (1 << SCOPE_DIRECT) | (1 << SCOPE_PRIMARY_GROUP) | 
                              (1 << SCOPE_EXTENDED_GROUP) | (1 << SCOPE_CONTACT_GROUP) |
                              (1 << SCOPE_COMMUNITY) | (1 << SCOPE_ORGANIZATION);
    ASSERT(send_message_scope == expected_scopes, "admin send_message has wrong scope flags");
    
    printf("    ✓ Role-permission mappings have correct scopes\n");
    return 0;
}

// Test that users have roles assigned
static int test_users_have_roles(sqlite3* db) {
    printf("  Testing users have roles assigned...\n");
    
    // Get a user pubkey from the database
    const char* sql = "SELECT u.pubkey, r.name FROM users u "
                      "JOIN user_roles ur ON u.id = ur.user_id "
                      "JOIN roles r ON ur.role_id = r.id "
                      "WHERE ur.is_active = 1 LIMIT 1";
    sqlite3_stmt* stmt = NULL;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    int found_user = 0;
    char user_pubkey_hex[65] = {0};
    char role_name[32] = {0};
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* pubkey = (const char*)sqlite3_column_text(stmt, 0);
        const char* role = (const char*)sqlite3_column_text(stmt, 1);
        if (pubkey && role) {
            strncpy(user_pubkey_hex, pubkey, 64);
            strncpy(role_name, role, 31);
            found_user = 1;
        }
    }
    
    sqlite3_finalize(stmt);
    
    ASSERT(found_user, "No users with roles found");
    ASSERT(strlen(role_name) > 0, "User role name is empty");
    
    printf("    ✓ Users have roles assigned (found user with role: %s)\n", role_name);
    return 0;
}

// Test loading user roles from database
static int test_load_user_roles(sqlite3* db) {
    printf("  Testing load_user_roles...\n");
    
    // Get a user pubkey
    const char* sql = "SELECT pubkey FROM users LIMIT 1";
    sqlite3_stmt* stmt = NULL;
    char user_pubkey_hex[65] = {0};
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        fprintf(stderr, "No users found in database\n");
        return -1;
    }
    
    const char* pubkey_hex = (const char*)sqlite3_column_text(stmt, 0);
    if (!pubkey_hex) {
        sqlite3_finalize(stmt);
        fprintf(stderr, "No users found in database\n");
        return -1;
    }
    strncpy(user_pubkey_hex, pubkey_hex, 64);
    user_pubkey_hex[64] = '\0';
    sqlite3_finalize(stmt);
    
    printf("    DEBUG: Got pubkey from DB: %s (length: %zu)\n", user_pubkey_hex, strlen(user_pubkey_hex));
    
    // Convert hex to binary
    unsigned char user_pubkey[32];
    if (strlen(user_pubkey_hex) < 64) {
        fprintf(stderr, "    ERROR: Invalid pubkey hex length: %zu (expected 64)\n", strlen(user_pubkey_hex));
        return -1;
    }
    for (size_t i = 0; i < 32; i++) {
        char hex_byte[3] = {user_pubkey_hex[i*2], user_pubkey_hex[i*2+1], 0};
        user_pubkey[i] = (unsigned char)strtoul(hex_byte, NULL, 16);
    }
    printf("    DEBUG: Converted to binary (first 8 bytes: ");
    for (size_t i = 0; i < 8; i++) {
        printf("%02x", user_pubkey[i]);
    }
    printf(")\n");
    
    // Load user roles
    Role* roles = NULL;
    size_t role_count = 0;
    
    printf("    DEBUG: Loading roles for user with pubkey: %s\n", user_pubkey_hex);
    int result = load_user_roles(user_pubkey, &roles, &role_count);
    printf("    DEBUG: load_user_roles returned: %d, role_count: %zu\n", result, role_count);
    
    if (result != 0) {
        fprintf(stderr, "    ERROR: load_user_roles failed with code %d\n", result);
    }
    
    ASSERT(result == 0, "load_user_roles failed");
    ASSERT(role_count > 0, "User has no roles");
    ASSERT(roles != NULL, "load_user_roles returned NULL");
    
    // Verify roles have permission sets
    int has_permission_sets = 0;
    for (size_t i = 0; i < role_count; i++) {
        if (roles[i].permission_set_count > 0 && roles[i].permission_sets != NULL) {
            has_permission_sets = 1;
            break;
        }
    }
    
    ASSERT(has_permission_sets, "User roles have no permission sets");
    
    // Clean up
    free_role_array(roles, role_count);
    
    printf("    ✓ Successfully loaded user roles with permission sets\n");
    return 0;
}

// Test permission checking
static int test_permission_checks(sqlite3* db) {
    printf("  Testing permission checks...\n");
    
    // Get admin user pubkey
    const char* sql = "SELECT u.pubkey FROM users u "
                      "JOIN user_roles ur ON u.id = ur.user_id "
                      "JOIN roles r ON ur.role_id = r.id "
                      "WHERE r.name = 'admin' AND ur.is_active = 1 LIMIT 1";
    sqlite3_stmt* stmt = NULL;
    char admin_pubkey_hex[65] = {0};
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        fprintf(stderr, "No admin user found\n");
        return -1;
    }
    
    const char* pubkey_hex = (const char*)sqlite3_column_text(stmt, 0);
    if (!pubkey_hex) {
        sqlite3_finalize(stmt);
        fprintf(stderr, "No admin user found\n");
        return -1;
    }
    strncpy(admin_pubkey_hex, pubkey_hex, 64);
    admin_pubkey_hex[64] = '\0'; // Ensure null termination
    sqlite3_finalize(stmt);
    
    printf("    DEBUG: Got admin pubkey from DB: %s (length: %zu)\n", admin_pubkey_hex, strlen(admin_pubkey_hex));
    
    // Convert hex to binary
    unsigned char admin_pubkey[32];
    if (strlen(admin_pubkey_hex) < 64) {
        fprintf(stderr, "    ERROR: Invalid admin pubkey hex length: %zu (expected 64)\n", strlen(admin_pubkey_hex));
        return -1;
    }
    for (size_t i = 0; i < 32; i++) {
        char hex_byte[3] = {admin_pubkey_hex[i*2], admin_pubkey_hex[i*2+1], 0};
        admin_pubkey[i] = (unsigned char)strtoul(hex_byte, NULL, 16);
    }
    printf("    DEBUG: Converted admin pubkey to binary (first 8 bytes: ");
    for (size_t i = 0; i < 8; i++) {
        printf("%02x", admin_pubkey[i]);
    }
    printf(")\n");
    
    // Verify hex conversion matches
    char reconverted_hex[65];
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        reconverted_hex[i * 2] = hex[(admin_pubkey[i] >> 4) & 0xF];
        reconverted_hex[i * 2 + 1] = hex[admin_pubkey[i] & 0xF];
    }
    reconverted_hex[64] = '\0';
    printf("    DEBUG: Reconverted binary to hex: %s\n", reconverted_hex);
    if (strcmp(admin_pubkey_hex, reconverted_hex) != 0) {
        fprintf(stderr, "    ERROR: Hex conversion mismatch! DB: %s, Reconverted: %s\n", 
                admin_pubkey_hex, reconverted_hex);
        return -1;
    }
    
    // Test admin should have SEND_MESSAGE in DIRECT scope
    printf("    DEBUG: Checking permission for admin: PERMISSION_SEND_MESSAGE (0x%llx) in SCOPE_DIRECT\n", 
           (unsigned long long)PERMISSION_SEND_MESSAGE);
    bool has_perm = check_user_permission(admin_pubkey, PERMISSION_SEND_MESSAGE, SCOPE_DIRECT);
    printf("    DEBUG: Permission check result: %s\n", has_perm ? "ALLOWED" : "DENIED");
    ASSERT(has_perm, "Admin should have SEND_MESSAGE in DIRECT scope");
    
    // Test admin should have SEND_MESSAGE in PRIMARY_GROUP scope
    has_perm = check_user_permission(admin_pubkey, PERMISSION_SEND_MESSAGE, SCOPE_PRIMARY_GROUP);
    ASSERT(has_perm, "Admin should have SEND_MESSAGE in PRIMARY_GROUP scope");
    
    // Test admin should have MANAGE_ROLES in ORGANIZATION scope
    has_perm = check_user_permission(admin_pubkey, PERMISSION_MANAGE_ROLES, SCOPE_ORGANIZATION);
    ASSERT(has_perm, "Admin should have MANAGE_ROLES in ORGANIZATION scope");
    
    // Get member user pubkey
    sql = "SELECT u.pubkey FROM users u "
          "JOIN user_roles ur ON u.id = ur.user_id "
          "JOIN roles r ON ur.role_id = r.id "
          "WHERE r.name = 'member' AND ur.is_active = 1 LIMIT 1";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        pubkey_hex = (const char*)sqlite3_column_text(stmt, 0);
        if (!pubkey_hex || strlen(pubkey_hex) < 64) {
            sqlite3_finalize(stmt);
            printf("    ⚠ No valid member user found, skipping member permission tests\n");
            goto admin_tests_done;
        }
        unsigned char member_pubkey[32];
        for (size_t i = 0; i < 32; i++) {
            char hex_byte[3] = {pubkey_hex[i*2], pubkey_hex[i*2+1], 0};
            member_pubkey[i] = (unsigned char)strtoul(hex_byte, NULL, 16);
        }
        sqlite3_finalize(stmt);
        
        // Member should have SEND_MESSAGE in DIRECT scope
        has_perm = check_user_permission(member_pubkey, PERMISSION_SEND_MESSAGE, SCOPE_DIRECT);
        ASSERT(has_perm, "Member should have SEND_MESSAGE in DIRECT scope");
        
        // Member should NOT have MANAGE_ROLES
        has_perm = check_user_permission(member_pubkey, PERMISSION_MANAGE_ROLES, SCOPE_ORGANIZATION);
        ASSERT(!has_perm, "Member should NOT have MANAGE_ROLES");
    } else {
        sqlite3_finalize(stmt);
        printf("    ⚠ No member user found, skipping member permission tests\n");
    }
    
admin_tests_done:
    printf("    ✓ Permission checks work correctly\n");
    return 0;
}

// Test PermissionSet reconstruction
static int test_permission_set_reconstruction(sqlite3* db) {
    printf("  Testing PermissionSet reconstruction...\n");
    
    // Get admin role ID
    const char* sql = "SELECT id FROM roles WHERE name = ?";
    sqlite3_stmt* stmt = NULL;
    int admin_role_id = -1;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, "admin", -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            admin_role_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    
    ASSERT(admin_role_id > 0, "admin role ID not found");
    
    // Load permission sets for admin role
    PermissionSet* sets = NULL;
    size_t set_count = 0;
    
    int result = load_role_permission_sets(admin_role_id, &sets, &set_count);
    ASSERT(result == 0, "load_role_permission_sets failed");
    ASSERT(set_count > 0, "Admin role has no permission sets");
    ASSERT(sets != NULL, "Permission sets array is NULL");
    
    // Verify ADMIN_MESSAGING PermissionSet is reconstructed
    int found_messaging_set = 0;
    uint32_t expected_messaging_scopes = (1 << SCOPE_DIRECT) | (1 << SCOPE_PRIMARY_GROUP) | 
                                        (1 << SCOPE_EXTENDED_GROUP) | (1 << SCOPE_CONTACT_GROUP) |
                                        (1 << SCOPE_COMMUNITY) | (1 << SCOPE_ORGANIZATION);
    
    for (size_t i = 0; i < set_count; i++) {
        // Check if this set matches ADMIN_MESSAGING scopes
        if (sets[i].scopes == expected_messaging_scopes) {
            // Verify it has the messaging permissions
            bool has_send = (sets[i].permissions & PERMISSION_SEND_MESSAGE) != 0;
            bool has_read = (sets[i].permissions & PERMISSION_READ_MESSAGE) != 0;
            if (has_send && has_read) {
                found_messaging_set = 1;
                break;
            }
        }
    }
    
    ASSERT(found_messaging_set, "ADMIN_MESSAGING PermissionSet not properly reconstructed");
    
    // Clean up
    free(sets);
    
    printf("    ✓ PermissionSets are properly reconstructed from database\n");
    return 0;
}

int permissions_test_main(void) {
    printf("Running permissions integration tests...\n\n");
    
    // Ensure database is initialized
    if (!db_is_initialized()) {
        const char* db_path = test_get_db_path();
        if (db_init_gossip(db_path) != 0) {
            fprintf(stderr, "Failed to initialize database\n");
            return -1;
        }
    }
    
    sqlite3* db = db_get_handle();
    if (!db) {
        fprintf(stderr, "Failed to get database handle\n");
        return -1;
    }
    
    // Create schema tables if they don't exist
    if (schema_create_all_tables(db) != 0) {
        fprintf(stderr, "Failed to create schema tables\n");
        return -1;
    }
    
    if (schema_create_all_indexes(db) != 0) {
        fprintf(stderr, "Failed to create schema indexes\n");
        return -1;
    }
    
    // Seed database with initial data
    if (seed_basic_roles(db) != 0) {
        fprintf(stderr, "Failed to seed roles\n");
        return -1;
    }
    
    if (seed_basic_permissions(db) != 0) {
        fprintf(stderr, "Failed to seed permissions\n");
        return -1;
    }
    
    if (seed_role_permissions(db) != 0) {
        fprintf(stderr, "Failed to seed role-permission mappings\n");
        return -1;
    }
    
    // Create a test user with admin role for testing
    unsigned char test_pubkey[32] = {0};
    for (int i = 0; i < 32; i++) {
        test_pubkey[i] = (unsigned char)(i + 1);
    }
    char test_pubkey_hex[65];
    hex_encode_pubkey(test_pubkey, test_pubkey_hex);
    
    const char* insert_user_sql = 
        "INSERT OR REPLACE INTO users (pubkey, username, age, is_active) VALUES (?, ?, ?, 1)";
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, insert_user_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, test_pubkey_hex, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, "test_admin", -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, 30);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    // Assign admin role to test user
    const char* get_user_id_sql = "SELECT id FROM users WHERE pubkey = ?";
    const char* get_role_id_sql = "SELECT id FROM roles WHERE name = ?";
    const char* insert_user_role_sql = 
        "INSERT OR REPLACE INTO user_roles (user_id, role_id, is_active) VALUES (?, ?, 1)";
    
    int user_id = -1;
    int admin_role_id = -1;
    
    if (sqlite3_prepare_v2(db, get_user_id_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, test_pubkey_hex, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            user_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    
    if (sqlite3_prepare_v2(db, get_role_id_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, "admin", -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            admin_role_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    
    if (user_id > 0 && admin_role_id > 0) {
        if (sqlite3_prepare_v2(db, insert_user_role_sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, user_id);
            sqlite3_bind_int(stmt, 2, admin_role_id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    // Create a test member user
    unsigned char member_pubkey[32] = {0};
    for (int i = 0; i < 32; i++) {
        member_pubkey[i] = (unsigned char)(i + 100);
    }
    char member_pubkey_hex[65];
    hex_encode_pubkey(member_pubkey, member_pubkey_hex);
    
    if (sqlite3_prepare_v2(db, insert_user_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, member_pubkey_hex, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, "test_member", -1, SQLITE_STATIC);
        sqlite3_bind_int(stmt, 3, 15);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    int member_user_id = -1;
    int member_role_id = -1;
    
    if (sqlite3_prepare_v2(db, get_user_id_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, member_pubkey_hex, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            member_user_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    
    if (sqlite3_prepare_v2(db, get_role_id_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, "member", -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            member_role_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    
    if (member_user_id > 0 && member_role_id > 0) {
        if (sqlite3_prepare_v2(db, insert_user_role_sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, member_user_id);
            sqlite3_bind_int(stmt, 2, member_role_id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    int tests_passed = 0;
    int tests_failed = 0;
    
    // Run all tests
    if (test_roles_exist(db) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_permissions_seeded(db) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_role_permissions_with_scopes(db) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_users_have_roles(db) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_load_user_roles(db) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_permission_checks(db) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    if (test_permission_set_reconstruction(db) == 0) {
        tests_passed++;
    } else {
        tests_failed++;
    }
    
    printf("\n=== Permissions Test Summary ===\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    printf("===============================\n\n");
    
    return (tests_failed > 0) ? -1 : 0;
}

