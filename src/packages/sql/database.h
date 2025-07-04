#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <stdint.h>
#include <stdbool.h>
#include "packages/structures/blockChain/blockchain.h"
#include "packages/structures/blockChain/block.h"
#include "packages/structures/blockChain/transaction.h"
#include "packages/structures/blockChain/transaction_types.h"

// Database configuration
#define DEFAULT_DB_PATH "state/blockchain/blockchain.db"
#define DB_SCHEMA_VERSION 2

// Database connection management
typedef struct {
    sqlite3* db;
    char* db_path;
    bool is_initialized;
    bool wal_enabled;
} DatabaseContext;

// Query result structures
typedef struct {
    uint64_t transaction_id;
    uint32_t block_index;
    uint32_t transaction_index;
    TW_TransactionType type;
    char sender[65];  // Hex string (32 bytes * 2 + null terminator)
    uint64_t timestamp;
    uint8_t recipient_count;
    char group_id[33];  // Hex string (16 bytes * 2 + null terminator)
    char signature[129];  // Hex string (64 bytes * 2 + null terminator)
    size_t payload_size;
    unsigned char* encrypted_payload;
    char* decrypted_content;  // Cached decrypted content (if available)
    bool is_decrypted;
} TransactionRecord;

typedef struct {
    uint32_t block_index;
    uint64_t timestamp;
    char previous_hash[65];  // Hex string
    char merkle_root_hash[65];  // Hex string
    char proposer_id[33];  // Hex string
    uint32_t transaction_count;
    char block_hash[65];  // Hex string
} BlockRecord;

// Extended block record with transactions for API responses
typedef struct {
    char hash[65];           // Block hash (mapped from block_hash)
    uint32_t height;         // Block height (mapped from block_index)
    char previous_hash[65];  // Previous block hash
    uint64_t timestamp;      // Block timestamp
    uint32_t transaction_count;  // Number of transactions
    TransactionRecord* transactions;  // Array of transactions
} ApiBlockRecord;

// User, Role, and Permission structures
typedef struct {
    uint64_t id;
    char pubkey[65];  // Hex string
    char username[MAX_USERNAME_LENGTH];
    uint8_t age;
    uint64_t registration_transaction_id;
    uint64_t created_at;
    uint64_t updated_at;
    bool is_active;
} UserRecord;

typedef struct {
    uint64_t id;
    char name[MAX_ROLE_NAME_LENGTH];
    char description[256];
    uint64_t created_at;
    uint64_t updated_at;
    uint64_t assignment_transaction_id;
} RoleRecord;

typedef struct {
    uint64_t id;
    char name[MAX_PERMISSION_NAME_LENGTH];
    uint64_t permission_flags;
    uint32_t scope_flags;
    uint64_t condition_flags;
    uint8_t category;
    char description[256];
    uint64_t created_at;
    uint64_t updated_at;
    uint64_t edit_transaction_id;
} PermissionRecord;

typedef struct {
    uint64_t id;
    uint64_t user_id;
    uint64_t role_id;
    uint64_t assigned_at;
    uint64_t assigned_by_user_id;
    uint64_t assignment_transaction_id;
    bool is_active;
    char role_name[MAX_ROLE_NAME_LENGTH];  // Joined from roles table
} UserRoleRecord;

typedef struct {
    uint64_t id;
    uint64_t role_id;
    uint64_t permission_id;
    uint64_t granted_at;
    uint64_t granted_by_user_id;
    uint64_t grant_transaction_id;
    uint64_t time_start;
    uint64_t time_end;
    bool is_active;
    char permission_name[MAX_PERMISSION_NAME_LENGTH];  // Joined from permissions table
    uint64_t permission_flags;
    uint32_t scope_flags;
    uint64_t condition_flags;
    uint8_t category;
} RolePermissionRecord;

// Core database functions
int db_init(const char* db_path);
int db_close(void);
int db_create_schema(void);
int db_configure_wal_mode(void);
bool db_is_initialized(void);
int db_get_recipients_for_transaction(uint64_t transaction_id, char*** recipients, size_t* count);
void db_free_recipients(char** recipients, size_t count);
sqlite3* db_get_handle(void);

// Blockchain synchronization functions
int db_sync_blockchain(TW_BlockChain* blockchain);
int db_add_block(TW_Block* block, uint32_t block_index);
int db_add_transaction(TW_Transaction* tx, uint32_t block_index, uint32_t tx_index);
int db_update_blockchain_info(TW_BlockChain* blockchain);

// Transaction parsing and sync functions
int db_parse_and_sync_user_registration(TW_Transaction* tx, uint64_t transaction_id);
int db_parse_and_sync_role_assignment(TW_Transaction* tx, uint64_t transaction_id);
int db_parse_and_sync_permission_edit(TW_Transaction* tx, uint64_t transaction_id);

// Query functions
int db_get_transaction_count(uint64_t* count);
int db_get_block_count(uint32_t* count);
int db_get_block_count_with_transactions(uint32_t* count);
int db_get_transactions_by_sender(const char* sender_pubkey, TransactionRecord** results, size_t* count);
int db_get_transactions_by_recipient(const char* recipient_pubkey, TransactionRecord** results, size_t* count);
int db_get_transactions_by_type(TW_TransactionType type, TransactionRecord** results, size_t* count);
int db_get_transactions_by_block(uint32_t block_index, TransactionRecord** results, size_t* count);
int db_get_recent_transactions(uint32_t limit, TransactionRecord** results, size_t* count);
int db_get_block_info(uint32_t block_index, BlockRecord* block_info);
int db_get_block_by_hash(const char* block_hash, ApiBlockRecord** block_record);

// User management functions
int db_add_user(const char* pubkey, const char* username, uint8_t age, uint64_t registration_transaction_id);
int db_update_user(const char* pubkey, const char* username, uint8_t age);
int db_get_user_by_pubkey(const char* pubkey, UserRecord* user);
int db_get_user_by_username(const char* username, UserRecord* user);
int db_get_all_users(UserRecord** users, size_t* count);
int db_delete_user(const char* pubkey);

// Role management functions
int db_add_role(const char* name, const char* description, uint64_t assignment_transaction_id);
int db_update_role(const char* name, const char* description);
int db_get_role_by_name(const char* name, RoleRecord* role);
int db_get_all_roles(RoleRecord** roles, size_t* count);
int db_delete_role(const char* name);

// Permission management functions
int db_add_permission(const char* name, uint64_t permission_flags, uint32_t scope_flags, 
                     uint64_t condition_flags, uint8_t category, const char* description, 
                     uint64_t edit_transaction_id);
int db_update_permission(const char* name, uint64_t permission_flags, uint32_t scope_flags, 
                        uint64_t condition_flags, uint8_t category, const char* description);
int db_get_permission_by_name(const char* name, PermissionRecord* permission);
int db_get_all_permissions(PermissionRecord** permissions, size_t* count);
int db_delete_permission(const char* name);

// User-Role relationship functions
int db_assign_user_role(uint64_t user_id, uint64_t role_id, uint64_t assigned_by_user_id, 
                       uint64_t assignment_transaction_id);
int db_remove_user_role(uint64_t user_id, uint64_t role_id);
int db_get_user_roles(uint64_t user_id, UserRoleRecord** roles, size_t* count);
int db_get_role_users(uint64_t role_id, UserRoleRecord** users, size_t* count);

// Role-Permission relationship functions
int db_grant_role_permission(uint64_t role_id, uint64_t permission_id, uint64_t granted_by_user_id, 
                            uint64_t grant_transaction_id, uint64_t time_start, uint64_t time_end);
int db_revoke_role_permission(uint64_t role_id, uint64_t permission_id);
int db_get_role_permissions(uint64_t role_id, RolePermissionRecord** permissions, size_t* count);
int db_get_permission_roles(uint64_t permission_id, RolePermissionRecord** roles, size_t* count);

// Utility functions
void db_free_transaction_records(TransactionRecord* records, size_t count);
void db_free_transaction_record(TransactionRecord* record);
void db_free_block_record(ApiBlockRecord* record);
void db_free_user_records(UserRecord* records, size_t count);
void db_free_role_records(RoleRecord* records, size_t count);
void db_free_permission_records(PermissionRecord* records, size_t count);
void db_free_user_role_records(UserRoleRecord* records, size_t count);
void db_free_role_permission_records(RolePermissionRecord* records, size_t count);

const char* get_transaction_type_name(TW_TransactionType type);
int db_hex_encode(const unsigned char* input, size_t input_len, char* output, size_t output_len);
int db_hex_decode(const char* input, unsigned char* output, size_t output_len);

// Cache management functions
int db_cache_decrypted_content(uint64_t transaction_id, const char* content);
int db_get_cached_content(uint64_t transaction_id, char** content);
int db_clear_cache(void);

// Database maintenance functions
int db_vacuum(void);
int db_checkpoint_wal(void);
int db_get_database_size(uint64_t* size_bytes);

#endif // DATABASE_H 