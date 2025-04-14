#ifndef TW_INTERNAL_TRANSACTION_H
#define TW_INTERNAL_TRANSACTION_H

#include <stddef.h>  // For size_t
#include <stdint.h>
#include <stdlib.h>
#include "packages/signing/signing.h"
#include "packages/structures/blockChain/block.h"

#define HASH_SIZE 32
#define MAX_PEERS 10
#define MAX_PAYLOAD_SIZE_INTERNAL 8096
#define MAX_BLOCK_SIZE

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
    TW_INT_TXN_REBROADCAST_MSG,
    TW_INT_MISC
} TW_InternalTransactionType;

typedef struct {
    TW_InternalTransactionType type;
    unsigned char sender[PUBKEY_SIZE];
    uint64_t timestamp;
    uint32_t proposer_id;
    unsigned char block_hash[HASH_SIZE];
    TW_Block block_data;
    unsigned char chain_hash[HASH_SIZE];
    unsigned char signature[SIGNATURE_SIZE];
} TW_InternalTransaction;

// Functions
TW_InternalTransaction* tw_create_internal_transaction(TW_InternalTransactionType type, const unsigned char* properser_id,
                                    TW_Block* block_data, unsigned char* chain_hash, 
                                    const unsigned char* sender, const unsigned char* block_hash, 
                                    const unsigned char* signature);

size_t TW_InternalTransaction_serialize(TW_InternalTransaction* txn, unsigned char** buffer);
TW_InternalTransaction* TW_InternalTransaction_deserialize(const unsigned char* buffer, size_t buffer_size);

void tw_destroy_internal_transaction(TW_InternalTransaction* txn);

void TW_Internal_Transaction_add_signature(TW_InternalTransaction* txn);

void TW_InternalTransaction_hash(TW_InternalTransaction *txn, unsigned char *hash_out);

#endif