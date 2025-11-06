#ifndef TRANSACTION_VALIDATION_H
#define TRANSACTION_VALIDATION_H

#include <stdbool.h>
#include <sqlite3.h>
#include <stdint.h>
#include "packages/transactions/transaction.h"
#include "structs/permission/permission.h"

struct TW_BlockChain;

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

typedef struct {
    int id;
    unsigned char public_key[PUBKEY_SIZE];
    char username[MAX_USERNAME_LENGTH];
    uint32_t age;
    bool is_active;
} UserInfo;

typedef struct {
    int role_id;
    char role_name[MAX_ROLE_NAME_LENGTH];
} UserRoleInfo;

typedef struct {
    uint64_t permission_flags;
    uint32_t scope_flags;
} RolePermissions;

typedef struct {
    struct TW_BlockChain* blockchain;
    sqlite3* database;
    uint64_t current_timestamp;
    bool strict_validation;
} ValidationContext;

TxnValidationResult validate_txn_permissions(
    const TW_Transaction* transaction,
    const ValidationContext* context
);

ValidationContext* create_validation_context(struct TW_BlockChain* blockchain, sqlite3* database);
void destroy_validation_context(ValidationContext* context);
void free_user_info(UserInfo* user_info);
const char* txn_validation_error_string(TxnValidationResult result);

#endif // TRANSACTION_VALIDATION_H 