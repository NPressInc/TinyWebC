#include "transaction_validation.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "features/blockchain/core/transaction_types.h"

static void pubkey_to_hex(const unsigned char* pubkey, char* out, size_t out_len) {
    static const char hex[] = "0123456789abcdef";
    if (!out || out_len < PUBKEY_SIZE * 2 + 1) return;
    for (size_t i = 0; i < PUBKEY_SIZE; ++i) {
        out[i * 2] = hex[(pubkey[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[pubkey[i] & 0xF];
    }
    out[PUBKEY_SIZE * 2] = '\0';
}

static int query_user(sqlite3* db, const unsigned char* pubkey, UserInfo* out) {
    static const char* SQL =
        "SELECT id, username, age, is_active FROM users WHERE pubkey = ? LIMIT 1";
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        return SQLITE_ERROR;
    }

    char pub_hex[PUBKEY_SIZE * 2 + 1];
    pubkey_to_hex(pubkey, pub_hex, sizeof(pub_hex));
    sqlite3_bind_text(stmt, 1, pub_hex, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        out->id = sqlite3_column_int(stmt, 0);
        const unsigned char* username = sqlite3_column_text(stmt, 1);
        if (username) {
            strncpy(out->username, (const char*)username, sizeof(out->username) - 1);
            out->username[sizeof(out->username) - 1] = '\0';
        }
        out->age = (uint32_t)sqlite3_column_int(stmt, 2);
        out->is_active = sqlite3_column_int(stmt, 3) != 0;
        memcpy(out->public_key, pubkey, PUBKEY_SIZE);
        sqlite3_finalize(stmt);
        return SQLITE_OK;
    }

    sqlite3_finalize(stmt);
    return SQLITE_ERROR;
}

static int query_user_role(sqlite3* db, int user_id, UserRoleInfo* out) {
    static const char* SQL =
        "SELECT r.id, r.name FROM user_roles ur "
        "JOIN roles r ON ur.role_id = r.id "
        "WHERE ur.user_id = ? AND ur.is_active = 1 LIMIT 1";

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        return SQLITE_ERROR;
    }

    sqlite3_bind_int(stmt, 1, user_id);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        out->role_id = sqlite3_column_int(stmt, 0);
        const unsigned char* name = sqlite3_column_text(stmt, 1);
        if (name) {
            strncpy(out->role_name, (const char*)name, sizeof(out->role_name) - 1);
            out->role_name[sizeof(out->role_name) - 1] = '\0';
        }
        sqlite3_finalize(stmt);
        return SQLITE_OK;
    }

    sqlite3_finalize(stmt);
    return SQLITE_ERROR;
}

static int query_role_permissions(sqlite3* db, int role_id, RolePermissions* out) {
    static const char* SQL =
        "SELECT p.permission_flags, p.scope_flags FROM role_permissions rp "
        "JOIN permissions p ON rp.permission_id = p.id "
        "WHERE rp.role_id = ? AND rp.is_active = 1";

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        return SQLITE_ERROR;
    }

    sqlite3_bind_int(stmt, 1, role_id);

    uint64_t aggregate_flags = 0;
    uint32_t aggregate_scopes = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        aggregate_flags |= (uint64_t)sqlite3_column_int64(stmt, 0);
        aggregate_scopes |= (uint32_t)sqlite3_column_int(stmt, 1);
    }

    sqlite3_finalize(stmt);
    out->permission_flags = aggregate_flags;
    out->scope_flags = aggregate_scopes;
    return SQLITE_OK;
}

static int query_transaction_permission(sqlite3* db, TW_TransactionType type, const RolePermissions* perms) {
    if (!perms) return SQLITE_ERROR;

    static const char* SQL =
        "SELECT required_permission, required_scope FROM transaction_permissions WHERE txn_type = ? LIMIT 1";

    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL, -1, &stmt, NULL) != SQLITE_OK) {
        return SQLITE_ERROR;
    }

    sqlite3_bind_int(stmt, 1, (int)type);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        uint64_t required_perm = (uint64_t)sqlite3_column_int64(stmt, 0);
        uint32_t required_scope = (uint32_t)sqlite3_column_int(stmt, 1);
        sqlite3_finalize(stmt);

        if ((perms->permission_flags & required_perm) == required_perm &&
            (perms->scope_flags & required_scope) == required_scope) {
            return SQLITE_OK;
        }
        return SQLITE_ERROR;
    }

    sqlite3_finalize(stmt);
    return SQLITE_OK;
}

TxnValidationResult validate_txn_permissions(
    const TW_Transaction* transaction,
    const ValidationContext* context
) {
    if (!transaction || !context || !context->database) {
        return TXN_VALIDATION_ERROR_NULL_POINTER;
    }

    UserInfo sender = {0};
    if (query_user(context->database, transaction->sender, &sender) != SQLITE_OK || !sender.is_active) {
        return TXN_VALIDATION_ERROR_USER_NOT_REGISTERED;
    }

    UserRoleInfo role = {0};
    if (query_user_role(context->database, sender.id, &role) != SQLITE_OK) {
        return TXN_VALIDATION_ERROR_ROLE_NOT_FOUND;
    }

    RolePermissions perms = {0};
    if (query_role_permissions(context->database, role.role_id, &perms) != SQLITE_OK) {
        return TXN_VALIDATION_ERROR_INSUFFICIENT_PERMISSIONS;
    }

    if (query_transaction_permission(context->database, transaction->type, &perms) != SQLITE_OK) {
        return TXN_VALIDATION_ERROR_INSUFFICIENT_PERMISSIONS;
    }

    (void)context;
    return TXN_VALIDATION_SUCCESS;
}

ValidationContext* create_validation_context(struct TW_BlockChain* blockchain, sqlite3* database) {
    ValidationContext* ctx = calloc(1, sizeof(ValidationContext));
    if (!ctx) {
        return NULL;
    }
    ctx->blockchain = blockchain;
    ctx->database = database;
    ctx->current_timestamp = (uint64_t)time(NULL);
    ctx->strict_validation = true;
    return ctx;
}

void destroy_validation_context(ValidationContext* context) {
    free(context);
}

void free_user_info(UserInfo* user_info) {
    if (!user_info) return;
    memset(user_info, 0, sizeof(UserInfo));
}

const char* txn_validation_error_string(TxnValidationResult result) {
    switch (result) {
        case TXN_VALIDATION_SUCCESS: return "success";
        case TXN_VALIDATION_ERROR_NULL_POINTER: return "null pointer";
        case TXN_VALIDATION_ERROR_USER_NOT_FOUND: return "user not found";
        case TXN_VALIDATION_ERROR_USER_NOT_REGISTERED: return "user not registered";
        case TXN_VALIDATION_ERROR_INSUFFICIENT_PERMISSIONS: return "insufficient permissions";
        case TXN_VALIDATION_ERROR_INVALID_SCOPE: return "invalid scope";
        case TXN_VALIDATION_ERROR_INVALID_TARGET: return "invalid target";
        case TXN_VALIDATION_ERROR_TIME_RESTRICTED: return "time restricted";
        case TXN_VALIDATION_ERROR_DATABASE_ERROR: return "database error";
        case TXN_VALIDATION_ERROR_ROLE_NOT_FOUND: return "role not found";
        case TXN_VALIDATION_ERROR_INVALID_TRANSACTION_TYPE: return "invalid transaction type";
        default: return "unknown error";
    }
} 