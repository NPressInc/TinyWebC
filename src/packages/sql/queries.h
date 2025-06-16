#ifndef QUERIES_H
#define QUERIES_H

#include <stdint.h>
#include <stdbool.h>
#include "database.h"
#include "packages/structures/blockChain/transaction.h"

// Query filter structures
typedef struct {
    char* sender_pubkey;
    char* recipient_pubkey;
    TW_TransactionType type;
    uint64_t start_timestamp;
    uint64_t end_timestamp;
    uint32_t start_block;
    uint32_t end_block;
    char* group_id;
    bool only_decrypted;
    uint32_t limit;
    uint32_t offset;
} TransactionFilter;

typedef struct {
    uint32_t start_block;
    uint32_t end_block;
    uint64_t start_timestamp;
    uint64_t end_timestamp;
    uint32_t limit;
    uint32_t offset;
} BlockFilter;

// High-level query functions
int query_transactions(const TransactionFilter* filter, TransactionRecord** results, size_t* count);
int query_blocks(const BlockFilter* filter, BlockRecord** results, size_t* count);

// Convenience query functions
int query_messages_for_user(const char* user_pubkey, TransactionRecord** results, size_t* count);
int query_recent_activity(uint32_t limit, TransactionRecord** results, size_t* count);
int query_transactions_by_type(TW_TransactionType type, uint32_t limit, TransactionRecord** results, size_t* count);
int query_group_messages(const char* group_id, TransactionRecord** results, size_t* count);
int query_user_activity(const char* user_pubkey, uint64_t start_time, uint64_t end_time, TransactionRecord** results, size_t* count);

// Statistics functions
int query_transaction_stats(uint64_t* total_count, uint64_t* message_count, uint64_t* system_count);
int query_user_stats(const char* user_pubkey, uint64_t* sent_count, uint64_t* received_count);
int query_block_stats(uint32_t* total_blocks, uint64_t* total_transactions, uint64_t* avg_block_size);

// Search functions
int search_transactions_by_content(const char* search_term, TransactionRecord** results, size_t* count);
int search_users_by_activity(uint64_t min_activity_count, char*** user_pubkeys, size_t* count);

// Helper functions for filters
TransactionFilter* create_transaction_filter(void);
void free_transaction_filter(TransactionFilter* filter);
BlockFilter* create_block_filter(void);
void free_block_filter(BlockFilter* filter);

// Result management
void free_block_records(BlockRecord* records, size_t count);

#endif // QUERIES_H 