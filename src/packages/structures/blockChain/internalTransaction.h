#ifndef TW_INTERNAL_TRANSACTION_H
#define TW_INTERNAL_TRANSACTION_H

#include <stddef.h>  // For size_t
#include <stdint.h>
#include <stdlib.h>

#define SIG_SIZE 64
#define HASH_SIZE 32
#define MAX_PEERS 10
#define MAX_PAYLOAD_SIZE_INTERNAL 8096

typedef enum {
    TW_INT_TXN_PROPOSE_BLOCK,
    TW_INT_TXN_VOTE_VERIFY,
    TW_INT_TXN_VOTE_COMMIT,
    TW_INT_TXN_VOTE_NEW_ROUND,
    TW_INT_TXN_GET_LAST_HASH,
    TW_INT_TXN_RESYNC_CHAIN,
    TW_INT_TXN_GET_PENDING_TXNS,
    TW_INT_TXN_GET_CHAIN_LENGTH,
    TW_INT_TXN_REQ_MISSING_BLOCKS,
    TW_INT_TXN_REQ_FULL_CHAIN,
    TW_INT_TXN_BROADCAST_BLOCK,
    TW_INT_TXN_BROADCAST_CHAIN,
    TW_INT_TXN_REBROADCAST_MSG
} TW_InternalTransactionType;

typedef struct {
    TW_InternalTransactionType type;
    unsigned char sender[PUBKEY_SIZE];
    uint64_t timestamp;
    unsigned char targets[PUBKEY_SIZE * MAX_PEERS];
    uint8_t target_count;
    unsigned char last_hash[HASH_SIZE];
    unsigned char payload[MAX_PAYLOAD_SIZE_INTERNAL]; // Pre-formatted, e.g., from external logic
    uint16_t payload_len;
    unsigned char signature[SIG_SIZE];       // Pre-validated externally
} TW_InternalTransaction;

typedef struct {
    uint32_t proposer_id;
    unsigned char block_hash[HASH_SIZE];
    char block_data[512];
    unsigned char chain_hash[HASH_SIZE];
} ProposeBlockPayload;

// Functions
void tw_create_internal_transaction(TW_InternalTransaction* txn, TW_InternalTransactionType type, 
                                   const unsigned char* sender, const unsigned char* targets, 
                                   uint8_t target_count, const unsigned char* last_hash, 
                                   const unsigned char* payload, uint16_t payload_len, 
                                   const unsigned char* signature);

size_t TW_InternalTransaction_serialize(TW_InternalTransaction* txn, unsigned char** buffer);
TW_InternalTransaction* TW_InternalTransaction_deserialize(const unsigned char* buffer, size_t buffer_size);

void tw_destroy_internal_transaction(TW_InternalTransaction* txn);

#endif