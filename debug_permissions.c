#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "src/packages/structures/blockChain/transaction_types.h"
#include "src/packages/validation/transaction_validation.h"
#include "src/packages/sql/database.h"
#include "src/structs/permission/permission.h"

int main() {
    printf("=== TinyWeb Permission Debug Tool ===\n\n");
    
    // Test transaction type 15 (TW_TXN_ACCESS_REQUEST)
    printf("1. Testing TW_TXN_ACCESS_REQUEST (type 15) requirements:\n");
    
    uint64_t required_permissions = get_transaction_permissions(TW_TXN_ACCESS_REQUEST);
    permission_scope_t required_scope = get_transaction_scope(TW_TXN_ACCESS_REQUEST);
    
    printf("   Required permissions: 0x%lx\n", required_permissions);
    printf("   Required scope: %d (SCOPE_SELF = %d)\n", required_scope, SCOPE_SELF);
    
    // Test admin role creation
    printf("\n2. Testing admin role creation:\n");
    Role* admin_role = create_admin_role();
    if (!admin_role) {
        printf("   ❌ Failed to create admin role\n");
        return 1;
    }
    
    printf("   ✅ Admin role created successfully\n");
    printf("   Role name: %s\n", admin_role->role_name);
    printf("   Permission sets: %zu\n", admin_role->permission_set_count);
    
    // Test permission checking
    printf("\n3. Testing permission validation:\n");
    
    // Test with no permissions required (should always pass)
    if (required_permissions == 0) {
        printf("   ✅ No special permissions required - should always pass\n");
    } else {
        bool has_perm = has_permission_in_scope(admin_role, required_permissions, required_scope);
        printf("   Permission check result: %s\n", has_perm ? "✅ ALLOWED" : "❌ DENIED");
    }
    
    // Test scope validation
    printf("\n4. Testing scope validation:\n");
    uint32_t available_scopes = get_scopes_for_permission(admin_role, required_permissions);
    printf("   Available scopes for admin: 0x%x\n", available_scopes);
    printf("   Required scope bit: 0x%x\n", (1 << required_scope));
    printf("   Scope check: %s\n", 
           (available_scopes & (1 << required_scope)) ? "✅ ALLOWED" : "❌ DENIED");
    
    // Test individual permission sets
    printf("\n5. Testing individual permission sets:\n");
    for (size_t i = 0; i < admin_role->permission_set_count; i++) {
        const PermissionSet* perm_set = &admin_role->permission_sets[i];
        printf("   Permission set %zu:\n", i);
        printf("     Permissions: 0x%lx\n", perm_set->permissions);
        printf("     Scopes: 0x%x\n", perm_set->scopes);
        printf("     Has SCOPE_SELF: %s\n", 
               (perm_set->scopes & (1 << SCOPE_SELF)) ? "✅ YES" : "❌ NO");
    }
    
    // Test the exact validation function
    printf("\n6. Testing exact validation function:\n");
    
    // Initialize database
    if (db_init("state/blockchain/blockchain.db") != 0) {
        printf("   ❌ Failed to initialize database\n");
        destroy_role(admin_role);
        return 1;
    }
    
    sqlite3* db = db_get_handle();
    if (!db) {
        printf("   ❌ Failed to get database handle\n");
        db_close();
        destroy_role(admin_role);
        return 1;
    }
    
    // Create validation context
    ValidationContext context = {
        .blockchain = NULL,
        .database = db,
        .current_timestamp = time(NULL),
        .strict_validation = true
    };
    
    // Create user info for user_0 (admin)
    UserInfo user_info = {0};
    memcpy(user_info.public_key, "6586316455a9b63a61477751a40966c915509f0753b57c00f8852223b570defc", 32);
    user_info.role = admin_role;
    user_info.is_registered = true;
    user_info.registration_timestamp = time(NULL);
    
    // Test type permissions
    TxnValidationResult type_result = validate_txn_type_permissions(TW_TXN_ACCESS_REQUEST, &user_info, &context);
    printf("   Type permission validation: %s (%d)\n", 
           type_result == TXN_VALIDATION_SUCCESS ? "✅ SUCCESS" : "❌ FAILED", type_result);
    
    // Test scope validation
    TW_Transaction mock_txn = {0};
    mock_txn.type = TW_TXN_ACCESS_REQUEST;
    mock_txn.recipient_count = 1;
    
    TxnValidationResult scope_result = validate_txn_scope(&mock_txn, &user_info, &context);
    printf("   Scope validation: %s (%d)\n", 
           scope_result == TXN_VALIDATION_SUCCESS ? "✅ SUCCESS" : "❌ FAILED", scope_result);
    
    // Cleanup
    db_close();
    destroy_role(admin_role);
    
    printf("\n=== Debug Complete ===\n");
    return 0;
} 