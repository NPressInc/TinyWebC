#include "internalTransaction.h"
#include <string.h>
#include <time.h>
#include <stddef.h>  // For size_t
#include <stdint.h>

/** Creates an internal transaction with pre-prepared data (no signing or hashing here). */
void tw_create_internal_transaction(TW_InternalTransaction* txn, TW_InternalTransactionType type, 
                                   const unsigned char* sender, const unsigned char* targets, 
                                   uint8_t target_count, const unsigned char* last_hash, 
                                   const unsigned char* payload, uint16_t payload_len, 
                                   const unsigned char* signature) {
    txn->type = type;
    memcpy(txn->sender, sender, PUBKEY_SIZE);
    txn->timestamp = (uint64_t)time(NULL);
    txn->target_count = (target_count > MAX_PEERS) ? MAX_PEERS : target_count;
    if (targets) {
        memcpy(txn->targets, targets, PUBKEY_SIZE * txn->target_count);
    } else {
        memset(txn->targets, 0, PUBKEY_SIZE * MAX_PEERS);
    }
    memcpy(txn->last_hash, last_hash, HASH_SIZE);
    if (payload && payload_len > 0) {
        memcpy(txn->payload, payload, payload_len <= MAX_PAYLOAD_SIZE_INTERNAL ? payload_len : MAX_PAYLOAD_SIZE_INTERNAL);
        txn->payload_len = payload_len <= MAX_PAYLOAD_SIZE_INTERNAL ? payload_len : MAX_PAYLOAD_SIZE_INTERNAL;
    } else {
        txn->payload_len = 0;
    }
    if (signature) {
        memcpy(txn->signature, signature, SIG_SIZE);
    } else {
        memset(txn->signature, 0, SIG_SIZE);
    }
}

size_t TW_InternalTransaction_serialize(TW_InternalTransaction* txn, unsigned char** buffer) {
    if (!txn) {
        *buffer = NULL;
        return 0;
    }

    size_t size = sizeof(TW_InternalTransaction);
    *buffer = malloc(size);
    if (!*buffer) return 0;

    memcpy(*buffer, txn, size);
    return size;
}

TW_InternalTransaction* TW_InternalTransaction_deserialize(const unsigned char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size < sizeof(TW_InternalTransaction)) return NULL;

    TW_InternalTransaction* txn = malloc(sizeof(TW_InternalTransaction));
    if (!txn) return NULL;

    memcpy(txn, buffer, sizeof(TW_InternalTransaction));
    return txn;
}

/** Clears the transaction memory (no dynamic fields to free). */
void tw_destroy_internal_transaction(TW_InternalTransaction* txn) {
    memset(txn, 0, sizeof(TW_InternalTransaction));
}