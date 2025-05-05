#include <string.h>
#include <time.h>
#include <stddef.h> // For size_t
#include <stdint.h>
#include <openssl/sha.h>
#include "packages/keystore/keystore.h"
#include "internalTransaction.h"

TW_InternalTransaction *tw_create_internal_transaction(TW_InternalTransactionType type, const unsigned char *proposer_id,
                                                       TW_Block *block_data, unsigned char *chain_hash,
                                                       const unsigned char *sender, const unsigned char *block_hash,
                                                       const unsigned char *signature)
{
    TW_InternalTransaction *txn = malloc(sizeof(TW_InternalTransaction));
    if (!txn) return NULL;

    txn->type = type;
    memcpy(txn->sender, sender, PUBKEY_SIZE);
    txn->timestamp = (uint64_t)time(NULL);
    txn->proposer_id = *(uint32_t*)proposer_id;
    memcpy(txn->block_hash, block_hash, HASH_SIZE);
    memcpy(&txn->block_data, block_data, sizeof(TW_Block));
    memcpy(txn->chain_hash, chain_hash, HASH_SIZE);

    if (signature)
    {
        memcpy(txn->signature, signature, SIGNATURE_SIZE);
    }
    else
    {
        // Auto-sign if no signature provided
        unsigned char hash[HASH_SIZE];
        TW_InternalTransaction_hash(txn, hash);
        sign_message(hash, txn->signature);
    }

    return txn;
}

void TW_Internal_Transaction_add_signature(TW_InternalTransaction *txn)
{
    if (!txn) return;

    unsigned char hash[HASH_SIZE];
    TW_InternalTransaction_hash(txn, hash);
    sign_message(hash, txn->signature);
}

size_t TW_InternalTransaction_serialize(TW_InternalTransaction *txn, unsigned char **buffer)
{
    if (!txn)
    {
        *buffer = NULL;
        return 0;
    }

    size_t size = sizeof(TW_InternalTransaction);
    *buffer = malloc(size);
    if (!*buffer)
        return 0;

    memcpy(*buffer, txn, size);
    return size;
}

TW_InternalTransaction *TW_InternalTransaction_deserialize(const unsigned char *buffer, size_t buffer_size)
{
    if (!buffer || buffer_size < sizeof(TW_InternalTransaction))
        return NULL;

    TW_InternalTransaction *txn = malloc(sizeof(TW_InternalTransaction));
    if (!txn)
        return NULL;

    memcpy(txn, buffer, sizeof(TW_InternalTransaction));
    return txn;
}

/** Clears the transaction memory (no dynamic fields to free). */
void tw_destroy_internal_transaction(TW_InternalTransaction *txn)
{
    if (!txn) return;
    free(txn);
}

/** Computes the SHA-256 hash of the transaction (excluding signature) into hash_out. */
void TW_InternalTransaction_hash(TW_InternalTransaction *txn, unsigned char *hash_out)
{
    if (!txn || !hash_out)
        return;

    unsigned char buffer[8192]; // Buffer for all fields except signature
    size_t offset = 0;

    // Hash all fields except signature
    memcpy(buffer + offset, &txn->type, sizeof(txn->type));
    offset += sizeof(txn->type);
    memcpy(buffer + offset, txn->sender, PUBKEY_SIZE);
    offset += PUBKEY_SIZE;
    memcpy(buffer + offset, &txn->timestamp, sizeof(txn->timestamp));
    offset += sizeof(txn->timestamp);
    memcpy(buffer + offset, &txn->proposer_id, sizeof(txn->proposer_id));
    offset += sizeof(txn->proposer_id);
    memcpy(buffer + offset, txn->block_hash, HASH_SIZE);
    offset += HASH_SIZE;
    memcpy(buffer + offset, &txn->block_data, sizeof(TW_Block));
    offset += sizeof(TW_Block);
    memcpy(buffer + offset, txn->chain_hash, HASH_SIZE);
    offset += HASH_SIZE;

    // Compute the hash
    SHA256(buffer, offset, hash_out);
}