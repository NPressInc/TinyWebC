#include <string.h>
#include <time.h>
#include <stddef.h>  // For size_t
#include <stdint.h>
#include <openssl/sha.h>
#include "packages/keystore/keystore.h"
#include "internalTransaction.h"


void tw_create_internal_transaction(TW_InternalTransaction* txn, TW_InternalTransactionType type, 
                                   const unsigned char* sender, const unsigned char* recipients, 
                                   uint8_t recipient_count, const unsigned char* last_hash, 
                                   BlockPayload* payload, const unsigned char* signature) {
    txn->type = type;
    memcpy(txn->sender, sender, PUBKEY_SIZE);
    txn->timestamp = (uint64_t)time(NULL);
    txn->recipient_count = (recipient_count > MAX_PEERS) ? MAX_PEERS : recipient_count;
    if (recipients) {
        memcpy(txn->recipients, recipients, PUBKEY_SIZE * txn->recipient_count);
    } else {
        memset(txn->recipients, 0, PUBKEY_SIZE * MAX_PEERS);
    }
    memcpy(txn->last_hash, last_hash, HASH_SIZE);

    memcpy(txn->payload->block_payload, payload->block_payload, sizeof(BlockPayload));
    txn->payload_len = sizeof(BlockPayload);

    if (signature) {
        memcpy(txn->signature, signature, SIGNATURE_SIZE);
    } else {
        // Auto-sign if no signature provided
        unsigned char hash[HASH_SIZE];
        TW_InternalTransaction_hash(txn, hash);
        sign_message(hash, txn->signature);
    }
}


void TW_Transaction_add_signature(TW_InternalTransaction* txn){

    if (txn->signature) {
        return;
    }

    unsigned char txn_hash[SIGNATURE_SIZE];

    TW_Transaction_hash(txn, txn_hash);

    sign_message(txn_hash, txn->signature);
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

/** Computes the SHA-256 hash of the transaction (excluding signature) into hash_out. */
void TW_InternalTransaction_hash(TW_InternalTransaction* txn, unsigned char* hash_out) {
    if (!txn || !hash_out) return;

    unsigned char buffer[8192];  // Buffer for all fields except signature
    size_t offset = 0;

    // Hash all fields except signature
    memcpy(buffer + offset, &txn->type, sizeof(txn->type));
    offset += sizeof(txn->type);
    memcpy(buffer + offset, txn->sender, PUBKEY_SIZE);
    offset += PUBKEY_SIZE;
    memcpy(buffer + offset, &txn->timestamp, sizeof(txn->timestamp));
    offset += sizeof(txn->timestamp);
    memcpy(buffer + offset, txn->recipients, PUBKEY_SIZE * txn->recipient_count);
    offset += PUBKEY_SIZE * txn->recipient_count;
    memcpy(buffer + offset, txn->last_hash, HASH_SIZE);
    offset += HASH_SIZE;
    
    // Hash the payload based on type
    switch (txn->type) {
        case TW_INT_TXN_PROPOSE_BLOCK:
            memcpy(buffer + offset, &txn->payload.block_payload, sizeof(BlockPayload));
            offset += sizeof(BlockPayload);
            break;
        case TW_INT_MISC:
            memcpy(buffer + offset, &txn->payload.misc_payload, sizeof(MiscellaneousMessage));
            offset += sizeof(MiscellaneousMessage);
            break;
        default:
            // For other types, just hash whatever is in the payload up to payload_len
            memcpy(buffer + offset, &txn->payload, txn->payload_len);
            offset += txn->payload_len;
            break;
    }

    // Compute the hash
    SHA256(buffer, offset, hash_out);
}