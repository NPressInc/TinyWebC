#include "transaction_validation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sqlite3.h>
#include "packages/structures/blockChain/transaction_types.h"
#include "packages/utils/byteorder.h"

// Core validation function
TxnValidationResult validate_txn_permissions(
    const TW_Transaction* transaction,
    const ValidationContext* context
) {
    if (!transaction || !context) {
        return TXN_VALIDATION_ERROR_NULL_POINTER;
    }

    // Load sender information
    UserInfo sender_info = {0};
    TxnValidationResult result = validate_txn_user_registration(transaction->sender, context, &sender_info);
    if (result != TXN_VALIDATION_SUCCESS) {
        return result;
    }

    // Validate transaction type permissions
    result = validate_txn_type_permissions(transaction->type, &sender_info, context);
    if (result != TXN_VALIDATION_SUCCESS) {
        free_user_info(&sender_info);
        return result;
    }

    // Validate transaction scope
    result = validate_txn_scope(transaction, &sender_info, context);
    if (result != TXN_VALIDATION_SUCCESS) {
        free_user_info(&sender_info);
        return result;
    }

    // Validate recipients if applicable
    if (transaction->recipient_count > 0) {
        result = validate_txn_recipients(transaction, &sender_info, context);
        if (result != TXN_VALIDATION_SUCCESS) {
            free_user_info(&sender_info);
            return result;
        }
    }

    // Transaction-specific validation
    switch (get_transaction_category(transaction->type)) {
        case PERM_CATEGORY_MESSAGING:
            result = validate_message_transaction(transaction, &sender_info, context);
            break;
        case PERM_CATEGORY_GROUP_MGMT:
            result = validate_group_management_transaction(transaction, &sender_info, context);
            break;
        case PERM_CATEGORY_USER_MGMT:
            result = validate_user_management_transaction(transaction, &sender_info, context);
            break;
        case PERM_CATEGORY_ADMIN:
            result = validate_admin_transaction(transaction, &sender_info, context);
            break;
        default:
            result = TXN_VALIDATION_ERROR_INVALID_TRANSACTION_TYPE;
    }

    free_user_info(&sender_info);
    return result;
}

// Validate user registration and load user info
TxnValidationResult validate_txn_user_registration(
    const unsigned char* user_pubkey,
    const ValidationContext* context,
    UserInfo* user_info_out
) {
    if (!user_pubkey || !context || !user_info_out) {
        return TXN_VALIDATION_ERROR_NULL_POINTER;
    }

    // Initialize user info
    memset(user_info_out, 0, sizeof(UserInfo));
    memcpy(user_info_out->public_key, user_pubkey, PUBKEY_SIZE);

    // Check if user is registered in the blockchain
    bool is_registered = false;
    uint64_t registration_timestamp = 0;
    
    TxnValidationResult result = query_user_registration_transaction(
        user_pubkey, context->database, &is_registered, &registration_timestamp
    );
    
    if (result != TXN_VALIDATION_SUCCESS) {
        return result;
    }

    if (!is_registered) {
        return TXN_VALIDATION_ERROR_USER_NOT_REGISTERED;
    }

    user_info_out->is_registered = true;
    user_info_out->registration_timestamp = registration_timestamp;

    // Load user role
    result = query_user_role_assignment_transaction(
        user_pubkey, context->database, &user_info_out->role
    );
    
    if (result != TXN_VALIDATION_SUCCESS) {
        return result;
    }

    if (!user_info_out->role) {
        return TXN_VALIDATION_ERROR_ROLE_NOT_FOUND;
    }

    return TXN_VALIDATION_SUCCESS;
}

// Validate transaction type permissions
TxnValidationResult validate_txn_type_permissions(
    TW_TransactionType type,
    const UserInfo* user_info,
    const ValidationContext* context
) {
    if (!user_info || !context) {
        return TXN_VALIDATION_ERROR_NULL_POINTER;
    }

    // Get required permissions for this transaction type
    uint64_t required_permissions = get_transaction_permissions(type);
    permission_scope_t required_scope = get_transaction_scope(type);

    // If no special permissions required, allow
    if (required_permissions == 0) {
        return TXN_VALIDATION_SUCCESS;
    }

    // Check if user has required permissions in required scope
    if (!has_permission_in_scope(user_info->role, required_permissions, required_scope)) {
        printf("User lacks permission 0x%lx in scope %d for transaction type %d\n", 
               required_permissions, required_scope, type);
        return TXN_VALIDATION_ERROR_INSUFFICIENT_PERMISSIONS;
    }

    return TXN_VALIDATION_SUCCESS;
}

// Validate transaction scope
TxnValidationResult validate_txn_scope(
    const TW_Transaction* transaction,
    const UserInfo* user_info,
    const ValidationContext* context
) {
    if (!transaction || !user_info || !context) {
        return TXN_VALIDATION_ERROR_NULL_POINTER;
    }

    permission_scope_t required_scope = get_transaction_scope(transaction->type);
    uint64_t required_permissions = get_transaction_permissions(transaction->type);

    // Check if user can operate in the required scope
    uint32_t available_scopes = get_scopes_for_permission(user_info->role, required_permissions);
    
    if (!(available_scopes & (1 << required_scope))) {
        printf("User cannot operate in scope %d for transaction type %d\n", 
               required_scope, transaction->type);
        return TXN_VALIDATION_ERROR_INVALID_SCOPE;
    }

    return TXN_VALIDATION_SUCCESS;
}

// Validate transaction recipients
TxnValidationResult validate_txn_recipients(
    const TW_Transaction* transaction,
    const UserInfo* sender_info,
    const ValidationContext* context
) {
    if (!transaction || !sender_info || !context) {
        return TXN_VALIDATION_ERROR_NULL_POINTER;
    }

    // For now, just check that recipients are registered users
    // More sophisticated validation can be added later
    for (uint8_t i = 0; i < transaction->recipient_count; i++) {
        unsigned char* recipient_pubkey = transaction->recipients + (i * PUBKEY_SIZE);
        
        bool is_registered = false;
        uint64_t registration_timestamp = 0;
        
        TxnValidationResult result = query_user_registration_transaction(
            recipient_pubkey, context->database, &is_registered, &registration_timestamp
        );
        
        if (result != TXN_VALIDATION_SUCCESS) {
            return result;
        }
        
        if (!is_registered) {
            printf("Recipient %d is not registered\n", i);
            return TXN_VALIDATION_ERROR_USER_NOT_FOUND;
        }
    }

    return TXN_VALIDATION_SUCCESS;
}

// Database query functions
TxnValidationResult query_user_registration_transaction(
    const unsigned char* user_pubkey,
    sqlite3* database,
    bool* is_registered,
    uint64_t* registration_timestamp
) {
    if (!user_pubkey || !database || !is_registered || !registration_timestamp) {
        return TXN_VALIDATION_ERROR_NULL_POINTER;
    }

    *is_registered = false;
    *registration_timestamp = 0;

    // Convert public key to hex string for database query
    char pubkey_hex[PUBKEY_SIZE * 2 + 1];
    for (int i = 0; i < PUBKEY_SIZE; i++) {
        sprintf(pubkey_hex + (i * 2), "%02x", user_pubkey[i]);
    }
    pubkey_hex[PUBKEY_SIZE * 2] = '\0';

    // Query for user registration transaction
    const char* sql = "SELECT timestamp FROM transactions WHERE type = ? AND sender = ? ORDER BY timestamp ASC LIMIT 1";
    sqlite3_stmt* stmt;
    
    int rc = sqlite3_prepare_v2(database, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare registration query: %s\n", sqlite3_errmsg(database));
        return TXN_VALIDATION_ERROR_DATABASE_ERROR;
    }

    sqlite3_bind_int(stmt, 1, TW_TXN_USER_REGISTRATION);
    sqlite3_bind_text(stmt, 2, pubkey_hex, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *is_registered = true;
        *registration_timestamp = sqlite3_column_int64(stmt, 0);
    } else if (rc != SQLITE_DONE) {
        printf("Database error in registration query: %s\n", sqlite3_errmsg(database));
        sqlite3_finalize(stmt);
        return TXN_VALIDATION_ERROR_DATABASE_ERROR;
    }

    sqlite3_finalize(stmt);
    return TXN_VALIDATION_SUCCESS;
}

TxnValidationResult query_user_role_assignment_transaction(
    const unsigned char* user_pubkey,
    sqlite3* database,
    Role** role_out
) {
    if (!user_pubkey || !database || !role_out) {
        return TXN_VALIDATION_ERROR_NULL_POINTER;
    }

    *role_out = NULL;

    // Convert public key to hex string for database query
    char pubkey_hex[PUBKEY_SIZE * 2 + 1];
    for (int i = 0; i < PUBKEY_SIZE; i++) {
        sprintf(pubkey_hex + (i * 2), "%02x", user_pubkey[i]);
    }
    pubkey_hex[PUBKEY_SIZE * 2] = '\0';

    // Query for most recent role assignment transaction for this user
    const char* sql = "SELECT encrypted_payload, payload_size FROM transactions WHERE type = ? AND "
                     "id IN (SELECT transaction_id FROM transaction_recipients WHERE recipient_pubkey = ?) "
                     "ORDER BY timestamp DESC LIMIT 1";
    sqlite3_stmt* stmt;
    
    int rc = sqlite3_prepare_v2(database, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare role query: %s\n", sqlite3_errmsg(database));
        return TXN_VALIDATION_ERROR_DATABASE_ERROR;
    }

    sqlite3_bind_int(stmt, 1, TW_TXN_ROLE_ASSIGNMENT);
    sqlite3_bind_text(stmt, 2, pubkey_hex, -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        // For now, create a default role based on the fact that a role assignment exists
        // In a full implementation, we would decrypt and deserialize the role data
        const char* role_name = "member"; // Default role
        
        // Check if this is an admin (first few users in the system)
        // This is a simplified check - in reality we'd decrypt the payload
        const char* admin_sql = "SELECT COUNT(*) FROM transactions WHERE type = ? AND timestamp < "
                               "(SELECT MIN(timestamp) FROM transactions WHERE type = ? AND "
                               "id IN (SELECT transaction_id FROM transaction_recipients WHERE recipient_pubkey = ?))";
        sqlite3_stmt* admin_stmt;
        
        if (sqlite3_prepare_v2(database, admin_sql, -1, &admin_stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(admin_stmt, 1, TW_TXN_ROLE_ASSIGNMENT);
            sqlite3_bind_int(admin_stmt, 2, TW_TXN_ROLE_ASSIGNMENT);
            sqlite3_bind_text(admin_stmt, 3, pubkey_hex, -1, SQLITE_STATIC);
            
            if (sqlite3_step(admin_stmt) == SQLITE_ROW) {
                int role_count = sqlite3_column_int(admin_stmt, 0);
                if (role_count < 2) {  // First two users are admins
                    role_name = "admin";
                }
            }
            sqlite3_finalize(admin_stmt);
        }

        // Create appropriate role
        if (strcmp(role_name, "admin") == 0) {
            *role_out = create_admin_role();
        } else {
            *role_out = create_member_role();
        }
        
        if (!*role_out) {
            sqlite3_finalize(stmt);
            return TXN_VALIDATION_ERROR_DATABASE_ERROR;
        }
    } else if (rc != SQLITE_DONE) {
        printf("Database error in role query: %s\n", sqlite3_errmsg(database));
        sqlite3_finalize(stmt);
        return TXN_VALIDATION_ERROR_DATABASE_ERROR;
    }

    sqlite3_finalize(stmt);
    
    if (!*role_out) {
        return TXN_VALIDATION_ERROR_ROLE_NOT_FOUND;
    }
    
    return TXN_VALIDATION_SUCCESS;
}

// Transaction-specific validation functions
TxnValidationResult validate_message_transaction(
    const TW_Transaction* transaction,
    const UserInfo* sender_info,
    const ValidationContext* context
) {
    // Basic messaging validation - users can send messages to registered recipients
    return TXN_VALIDATION_SUCCESS;
}

TxnValidationResult validate_group_management_transaction(
    const TW_Transaction* transaction,
    const UserInfo* sender_info,
    const ValidationContext* context
) {
    // Group management requires appropriate permissions
    // Additional validation could check group ownership, etc.
    return TXN_VALIDATION_SUCCESS;
}

TxnValidationResult validate_user_management_transaction(
    const TW_Transaction* transaction,
    const UserInfo* sender_info,
    const ValidationContext* context
) {
    // User management requires admin permissions and supervision scope
    return TXN_VALIDATION_SUCCESS;
}

TxnValidationResult validate_admin_transaction(
    const TW_Transaction* transaction,
    const UserInfo* sender_info,
    const ValidationContext* context
) {
    // Admin transactions require admin role
    if (!sender_info->role || strcmp(sender_info->role->role_name, "admin") != 0) {
        return TXN_VALIDATION_ERROR_INSUFFICIENT_PERMISSIONS;
    }
    return TXN_VALIDATION_SUCCESS;
}

// Helper functions
const char* txn_validation_error_string(TxnValidationResult result) {
    switch (result) {
        case TXN_VALIDATION_SUCCESS:
            return "Success";
        case TXN_VALIDATION_ERROR_NULL_POINTER:
            return "Null pointer error";
        case TXN_VALIDATION_ERROR_USER_NOT_FOUND:
            return "User not found";
        case TXN_VALIDATION_ERROR_USER_NOT_REGISTERED:
            return "User not registered";
        case TXN_VALIDATION_ERROR_INSUFFICIENT_PERMISSIONS:
            return "Insufficient permissions";
        case TXN_VALIDATION_ERROR_INVALID_SCOPE:
            return "Invalid scope";
        case TXN_VALIDATION_ERROR_INVALID_TARGET:
            return "Invalid target";
        case TXN_VALIDATION_ERROR_TIME_RESTRICTED:
            return "Time restricted";
        case TXN_VALIDATION_ERROR_DATABASE_ERROR:
            return "Database error";
        case TXN_VALIDATION_ERROR_ROLE_NOT_FOUND:
            return "Role not found";
        case TXN_VALIDATION_ERROR_INVALID_TRANSACTION_TYPE:
            return "Invalid transaction type";
        default:
            return "Unknown error";
    }
}

void free_user_info(UserInfo* user_info) {
    if (user_info && user_info->role) {
        destroy_role(user_info->role);
        user_info->role = NULL;
    }
}

ValidationContext* create_validation_context(TW_BlockChain* blockchain, sqlite3* database) {
    ValidationContext* context = malloc(sizeof(ValidationContext));
    if (!context) return NULL;
    
    context->blockchain = blockchain;
    context->database = database;
    context->current_timestamp = time(NULL);
    context->strict_validation = true;
    
    return context;
}

void destroy_validation_context(ValidationContext* context) {
    if (context) {
        free(context);
    }
}

// Stub implementations for other functions
TxnValidationResult query_group_membership(
    const unsigned char* user_pubkey,
    const unsigned char* group_id,
    sqlite3* database,
    bool* is_member
) {
    if (is_member) *is_member = true;  // Stub: assume all users are members
    return TXN_VALIDATION_SUCCESS;
}

bool can_user_send_to_recipients(
    const UserInfo* sender,
    const TW_Transaction* transaction,
    const ValidationContext* context
) {
    return true;  // Stub: allow all sends for now
}

bool is_emergency_transaction(const TW_Transaction* transaction) {
    return transaction->type == TW_TXN_EMERGENCY_ALERT;
}

bool is_user_in_supervision_scope(
    const unsigned char* supervisor_pubkey,
    const unsigned char* user_pubkey,
    const ValidationContext* context
) {
    return true;  // Stub: assume all supervision relationships are valid
} 