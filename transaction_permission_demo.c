#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "src/packages/validation/transaction_validation.h"
#include "src/packages/structures/blockChain/transaction.h"
#include "src/packages/structures/blockChain/transaction_types.h"
#include "src/packages/sql/database.h"
#include "src/packages/keystore/keystore.h"
#include "src/packages/signing/signing.h"

void demo_transaction_validation() {
    printf("=== Transaction Permission Validation Demo ===\n\n");
    
    // Initialize database for testing
    printf("1. Initializing test database...\n");
    if (db_init("test_state/blockchain/test_blockchain.db") != 0) {
        printf("Failed to initialize database\n");
        return;
    }
    
    sqlite3* db = db_get_handle();
    if (!db) {
        printf("Failed to get database handle\n");
        db_close();
        return;
    }
    
    printf("✓ Database initialized successfully\n\n");
    
    // Create a validation context
    ValidationContext* context = create_validation_context(NULL, db);
    if (!context) {
        printf("Failed to create validation context\n");
        db_close();
        return;
    }
    
    printf("2. Testing user registration validation...\n");
    
    // Test 1: Unregistered user
    unsigned char unregistered_user[PUBKEY_SIZE];
    memset(unregistered_user, 0xAA, PUBKEY_SIZE);
    
    UserInfo user_info;
    TxnValidationResult result = validate_txn_user_registration(unregistered_user, context, &user_info);
    
    printf("   Testing unregistered user: %s\n", 
           result == TXN_VALIDATION_ERROR_USER_NOT_REGISTERED ? "✓ Correctly rejected" : "✗ Unexpected result");
    
    printf("\n3. Testing transaction type permissions...\n");
    
    // Create a mock admin role for testing
    Role* admin_role = create_admin_role();
    Role* member_role = create_member_role();
    
    if (!admin_role || !member_role) {
        printf("Failed to create test roles\n");
        destroy_validation_context(context);
        db_close();
        return;
    }
    
    // Test admin permissions
    printf("   Testing admin role permissions:\n");
    
    struct {
        TW_TransactionType type;
        const char* name;
    } test_transactions[] = {
        {TW_TXN_MESSAGE, "Message"},
        {TW_TXN_GROUP_CREATE, "Group Create"},
        {TW_TXN_PERMISSION_EDIT, "Permission Edit"},
        {TW_TXN_SYSTEM_CONFIG, "System Config"}
    };
    
    for (int i = 0; i < 4; i++) {
        TxnValidationResult admin_result = validate_txn_type_permissions(
            test_transactions[i].type, 
            &(UserInfo){.role = admin_role}, 
            context
        );
        
        printf("     %s: %s\n", 
               test_transactions[i].name,
               admin_result == TXN_VALIDATION_SUCCESS ? "✓ Allowed" : "✗ Denied");
    }
    
    // Test member permissions
    printf("   Testing member role permissions:\n");
    
    for (int i = 0; i < 4; i++) {
        TxnValidationResult member_result = validate_txn_type_permissions(
            test_transactions[i].type, 
            &(UserInfo){.role = member_role}, 
            context
        );
        
        printf("     %s: %s\n", 
               test_transactions[i].name,
               member_result == TXN_VALIDATION_SUCCESS ? "✓ Allowed" : "✗ Denied");
    }
    
    printf("\n4. Testing transaction scope validation...\n");
    
    // Create a mock transaction
    TW_Transaction mock_transaction = {0};
    mock_transaction.type = TW_TXN_MESSAGE;
    mock_transaction.recipient_count = 1;
    
    TxnValidationResult scope_result = validate_txn_scope(
        &mock_transaction, 
        &(UserInfo){.role = member_role}, 
        context
    );
    
    printf("   Message transaction scope for member: %s\n",
           scope_result == TXN_VALIDATION_SUCCESS ? "✓ Valid scope" : "✗ Invalid scope");
    
    printf("\n5. Testing transaction category validation...\n");
    
    // Test different transaction categories
    struct {
        TW_TransactionType type;
        TW_PermissionCategory expected_category;
        const char* name;
    } category_tests[] = {
        {TW_TXN_MESSAGE, PERM_CATEGORY_MESSAGING, "Message"},
        {TW_TXN_GROUP_CREATE, PERM_CATEGORY_GROUP_MGMT, "Group Create"},
        {TW_TXN_PERMISSION_EDIT, PERM_CATEGORY_USER_MGMT, "Permission Edit"},
        {TW_TXN_SYSTEM_CONFIG, PERM_CATEGORY_ADMIN, "System Config"}
    };
    
    for (int i = 0; i < 4; i++) {
        TW_PermissionCategory category = get_transaction_category(category_tests[i].type);
        printf("   %s: Category %d %s\n", 
               category_tests[i].name,
               category,
               category == category_tests[i].expected_category ? "✓ Correct" : "✗ Incorrect");
    }
    
    printf("\n6. Testing error handling...\n");
    
    // Test null pointer handling
    TxnValidationResult null_result = validate_txn_permissions(NULL, context);
    printf("   Null transaction: %s (%s)\n",
           null_result == TXN_VALIDATION_ERROR_NULL_POINTER ? "✓ Correctly handled" : "✗ Unexpected result",
           txn_validation_error_string(null_result));
    
    // Test invalid transaction type
    mock_transaction.type = 999; // Invalid type
    TxnValidationResult invalid_result = validate_txn_type_permissions(
        999, 
        &(UserInfo){.role = admin_role}, 
        context
    );
    printf("   Invalid transaction type: %s\n",
           invalid_result != TXN_VALIDATION_SUCCESS ? "✓ Correctly rejected" : "✗ Unexpected acceptance");
    
    printf("\n7. Performance test...\n");
    
    clock_t start = clock();
    int iterations = 1000;
    
    for (int i = 0; i < iterations; i++) {
        mock_transaction.type = TW_TXN_MESSAGE;
        validate_txn_type_permissions(
            TW_TXN_MESSAGE, 
            &(UserInfo){.role = member_role}, 
            context
        );
    }
    
    clock_t end = clock();
    double time_taken = ((double)(end - start)) / CLOCKS_PER_SEC;
    
    printf("   Performed %d permission validations in %.3f seconds\n", iterations, time_taken);
    printf("   Average time per validation: %.6f seconds\n", time_taken / iterations);
    
    // Cleanup
    destroy_role(admin_role);
    destroy_role(member_role);
    destroy_validation_context(context);
    db_close();
    
    printf("\n=== Demo completed successfully ===\n");
}

int main() {
    printf("TinyWeb Transaction Permission Validation Demo\n");
    printf("==============================================\n\n");
    
    demo_transaction_validation();
    
    return 0;
} 