#ifndef TRANSACTION_VALIDATION_H
#define TRANSACTION_VALIDATION_H

#include <stdint.h>
#include <stdbool.h>
#include "packages/transactions/transaction.h"
#include "features/blockchain/core/blockchain.h"
#include "features/blockchain/core/transaction_types.h"
#include "packages/sql/database.h"
#include "structs/permission/permission.h"

// Transaction validation result codes
typedef enum {
    TXN_VALIDATION_SUCCESS = 0,
    TXN_VALIDATION_ERROR_NULL_POINTER = -1,
    TXN_VALIDATION_ERROR_USER_NOT_FOUND = -2,
    TXN_VALIDATION_ERROR_USER_NOT_REGISTERED = -3,
    TXN_VALIDATION_ERROR_INSUFFICIENT_PERMISSIONS = -4,
    TXN_VALIDATION_ERROR_INVALID_SCOPE = -5,
    TXN_VALIDATION_ERROR_INVALID_TARGET = -6,
    TXN_VALIDATION_ERROR_TIME_RESTRICTED = -7,
    TXN_VALIDATION_ERROR_DATABASE_ERROR = -8,
    TXN_VALIDATION_ERROR_ROLE_NOT_FOUND = -9,
    TXN_VALIDATION_ERROR_INVALID_TRANSACTION_TYPE = -10
} TxnValidationResult;

// User information structure for validation
typedef struct {
    unsigned char public_key[PUBKEY_SIZE];
    char username[MAX_USERNAME_LENGTH];
    Role* role;
    bool is_registered;
    uint64_t registration_timestamp;
} UserInfo;

// Transaction validation context
typedef struct {
    TW_BlockChain* blockchain;
    sqlite3* database;
    uint64_t current_timestamp;
    bool strict_validation;  // Whether to enforce strict permission checks
} ValidationContext;

// Core validation functions
TxnValidationResult validate_txn_permissions(
    const TW_Transaction* transaction,
    const ValidationContext* context
);

TxnValidationResult validate_txn_user_registration(
    const unsigned char* user_pubkey,
    const ValidationContext* context,
    UserInfo* user_info_out
);

TxnValidationResult validate_txn_type_permissions(
    TW_TransactionType type,
    const UserInfo* user_info,
    const ValidationContext* context
);

TxnValidationResult validate_txn_scope(
    const TW_Transaction* transaction,
    const UserInfo* user_info,
    const ValidationContext* context
);

TxnValidationResult validate_txn_recipients(
    const TW_Transaction* transaction,
    const UserInfo* sender_info,
    const ValidationContext* context
);

// User and role management functions
TxnValidationResult load_user_info_from_blockchain(
    const unsigned char* user_pubkey,
    const ValidationContext* context,
    UserInfo* user_info
);

TxnValidationResult load_user_role_from_transactions(
    const unsigned char* user_pubkey,
    const ValidationContext* context,
    Role** role_out
);

// Database query functions for validation
TxnValidationResult query_user_registration_transaction(
    const unsigned char* user_pubkey,
    sqlite3* database,
    bool* is_registered,
    uint64_t* registration_timestamp
);

TxnValidationResult query_user_role_assignment_transaction(
    const unsigned char* user_pubkey,
    sqlite3* database,
    Role** role_out
);

TxnValidationResult query_group_membership(
    const unsigned char* user_pubkey,
    const unsigned char* group_id,
    sqlite3* database,
    bool* is_member
);

// Helper functions
const char* txn_validation_error_string(TxnValidationResult result);
void free_user_info(UserInfo* user_info);
ValidationContext* create_validation_context(TW_BlockChain* blockchain, sqlite3* database);
void destroy_validation_context(ValidationContext* context);

// Utility functions for permission checking
bool can_user_send_to_recipients(
    const UserInfo* sender,
    const TW_Transaction* transaction,
    const ValidationContext* context
);

bool is_emergency_transaction(const TW_Transaction* transaction);
bool is_user_in_supervision_scope(
    const unsigned char* supervisor_pubkey,
    const unsigned char* user_pubkey,
    const ValidationContext* context
);

// Transaction-specific validation functions
TxnValidationResult validate_message_transaction(
    const TW_Transaction* transaction,
    const UserInfo* sender_info,
    const ValidationContext* context
);

TxnValidationResult validate_group_management_transaction(
    const TW_Transaction* transaction,
    const UserInfo* sender_info,
    const ValidationContext* context
);

TxnValidationResult validate_user_management_transaction(
    const TW_Transaction* transaction,
    const UserInfo* sender_info,
    const ValidationContext* context
);

TxnValidationResult validate_admin_transaction(
    const TW_Transaction* transaction,
    const UserInfo* sender_info,
    const ValidationContext* context
);

TxnValidationResult validate_access_request_transaction(
    const TW_Transaction* transaction,
    const UserInfo* sender_info,
    const ValidationContext* context
);

#endif // TRANSACTION_VALIDATION_H 