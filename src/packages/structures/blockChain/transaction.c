#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include "transaction.h"
#include "packages/signing/signing.h"

/** Creates a transaction with pre-prepared data (no encryption here). */
TW_Transaction* TW_Transaction_create(TW_TransactionType type, const unsigned char* sender, 
                                     const unsigned char* recipients, uint8_t recipient_count, 
                                     const unsigned char* group_id, const EncryptedPayload* payload, 
                                     const unsigned char* signature) {
    TW_Transaction* tx = malloc(sizeof(TW_Transaction));
    if (!tx) return NULL;

    tx->type = type;
    memcpy(tx->sender, sender, PUBKEY_SIZE);
    tx->timestamp = time(NULL);
    tx->recipient_count = (recipient_count > MAX_RECIPIENTS) ? MAX_RECIPIENTS : recipient_count;
    if (recipients) {
        memcpy(tx->recipients, recipients, PUBKEY_SIZE * tx->recipient_count);
    } else {
        memset(tx->recipients, 0, PUBKEY_SIZE * MAX_RECIPIENTS);
    }
    memcpy(tx->group_id, group_id ? group_id : (const unsigned char*)"\0", GROUP_ID_SIZE);
    
    // Copy the entire EncryptedPayload struct
    if (payload) {
        memcpy(&tx->payload, payload, sizeof(EncryptedPayload));
    } else {
        memset(&tx->payload, 0, sizeof(EncryptedPayload));
    }

    if (signature) {
        memcpy(tx->signature, signature, SIGNATURE_SIZE);
    } else {
        memset(tx->signature, 0, SIGNATURE_SIZE);
    }

    return tx;
}

void TW_Transaction_add_signature(TW_Transaction* txn){

    char* txn_hash = malloc(SIGNATURE_SIZE);

    TW_Transaction_hash(txn, txn_hash);

    *txn->signature = sign_message(txn_hash);
}

/** Computes the SHA-256 hash of the transaction into hash_out. */
void TW_Transaction_hash(TW_Transaction* tx, unsigned char* hash_out) {
    if (!tx || !hash_out) return;

    unsigned char buffer[MAX_PAYLOAD_SIZE_EXTERNAL];
    size_t offset = 0;

    memcpy(buffer + offset, &tx->type, sizeof(tx->type));
    offset += sizeof(tx->type);
    memcpy(buffer + offset, tx->sender, PUBKEY_SIZE);
    offset += PUBKEY_SIZE;
    memcpy(buffer + offset, &tx->timestamp, sizeof(tx->timestamp));
    offset += sizeof(tx->timestamp);
    memcpy(buffer + offset, tx->recipients, PUBKEY_SIZE * tx->recipient_count);
    offset += PUBKEY_SIZE * tx->recipient_count;
    memcpy(buffer + offset, tx->group_id, GROUP_ID_SIZE);
    offset += GROUP_ID_SIZE;
    
    // Hash the EncryptedPayload
    memcpy(buffer + offset, &tx->payload, sizeof(EncryptedPayload));
    offset += sizeof(EncryptedPayload);

    SHA256(buffer, offset, hash_out);
}

/** Serializes the transaction to a byte array. */
size_t TW_Transaction_to_bytes(TW_Transaction* tx, unsigned char** buffer) {
    if (!tx) {
        *buffer = NULL;
        return 0;
    }

    size_t size = sizeof(TW_Transaction);
    *buffer = malloc(size);
    if (!*buffer) return 0;

    memcpy(*buffer, tx, size);
    return size;
}

TW_Transaction* TW_Transaction_deserialize(const unsigned char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size < sizeof(TW_Transaction)) return NULL;

    TW_Transaction* tx = malloc(sizeof(TW_Transaction));
    if (!tx) return NULL;

    memcpy(tx, buffer, sizeof(TW_Transaction));
    return tx;
}

/** Frees the memory allocated for the transaction. */
void TW_Transaction_destroy(TW_Transaction* tx) {
    if (!tx) return;
    free(tx);
}