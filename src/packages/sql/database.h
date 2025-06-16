#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <stdint.h>
#include <stdbool.h>
#include "packages/structures/blockChain/blockchain.h"
#include "packages/structures/blockChain/block.h"
#include "packages/structures/blockChain/transaction.h"

// Database configuration
#define DEFAULT_DB_PATH "state/blockchain/blockchain.db"
#define DB_SCHEMA_VERSION 1

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

// Core database functions
int db_init(const char* db_path);
int db_close(void);
int db_create_schema(void);
int db_configure_wal_mode(void);
bool db_is_initialized(void);
sqlite3* db_get_handle(void);

// Blockchain synchronization functions
int db_sync_blockchain(TW_BlockChain* blockchain);
int db_add_block(TW_Block* block, uint32_t block_index);
int db_add_transaction(TW_Transaction* tx, uint32_t block_index, uint32_t tx_index);
int db_update_blockchain_info(TW_BlockChain* blockchain);

// Query functions
int db_get_transaction_count(uint64_t* count);
int db_get_block_count(uint32_t* count);
int db_get_transactions_by_sender(const char* sender_pubkey, TransactionRecord** results, size_t* count);
int db_get_transactions_by_recipient(const char* recipient_pubkey, TransactionRecord** results, size_t* count);
int db_get_transactions_by_type(TW_TransactionType type, TransactionRecord** results, size_t* count);
int db_get_transactions_by_block(uint32_t block_index, TransactionRecord** results, size_t* count);
int db_get_recent_transactions(uint32_t limit, TransactionRecord** results, size_t* count);
int db_get_block_info(uint32_t block_index, BlockRecord* block_info);

// Utility functions
void db_free_transaction_records(TransactionRecord* records, size_t count);
void db_free_transaction_record(TransactionRecord* record);
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