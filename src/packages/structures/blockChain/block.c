#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stddef.h>  // For size_t
#include <stdint.h>
#include <openssl/sha.h>
#include "block.h"
#include "transaction.h"
#include "internalTransaction.h"
#include "merkleTree.h"
#include "merkleTreeNode.h"

/** Creates a new Block with the given parameters. */
TW_Block* TW_Block_create(int32_t index, TW_Transaction** block_txns, int32_t txn_count, 
                        time_t timestamp, const unsigned char* previous_hash, const unsigned char* proposer_id) {
    TW_Block* block = malloc(sizeof(TW_Block));
    if (!block) return NULL;

    block->index = index;
    block->txn_count = (txn_count > MAX_TXNS) ? MAX_TXNS : txn_count;
    for (int32_t i = 0; i < block->txn_count; i++) {
        block->txns[i] = *block_txns[i];
    }
    block->timestamp = timestamp;
    memcpy(block->previous_hash, previous_hash ? previous_hash : (const unsigned char*)"\0", HASH_SIZE);
    memcpy(block->proposer_id, proposer_id ? proposer_id : (const unsigned char*)"\0", PROP_ID_SIZE);


    TW_MerkleTreeNode* node = TW_MerkleTree_buildTree(block_txns, txn_count, )

    memcpy(block->merkle_root_hash, merkle_root_hash ? merkle_root_hash : (const unsigned char*)"\0", HASH_SIZE);

    return block;
}


int TW_Block_getHash(TW_Block* block, unsigned char* hash_out) {
    if (!block || !hash_out) {
        if (hash_out) memset(hash_out, 0, HASH_SIZE);
        return;
    }

    size_t buffer_size = sizeof(block->index) + 
                         sizeof(block->timestamp) + 
                         HASH_SIZE + // previous_hash
                         HASH_SIZE + // merkle_root_hash
                         PROP_ID_SIZE;
    size_t offset = 0;

    // Allocate buffer
    unsigned char* buffer = malloc(buffer_size);
    if (!buffer) {
        memset(hash_out, 0, HASH_SIZE);
        return 0;
    }

    memcpy(buffer + offset, &block->index, sizeof(block->index));
    offset += sizeof(block->index);
    memcpy(buffer + offset, &block->timestamp, sizeof(block->timestamp));
    offset += sizeof(block->timestamp);
    memcpy(buffer + offset, block->previous_hash, HASH_SIZE);
    offset += HASH_SIZE;
    memcpy(buffer + offset, block->merkle_root_hash, HASH_SIZE);
    offset += HASH_SIZE;
    memcpy(buffer + offset, block->proposer_id, PROP_ID_SIZE);
    offset += PROP_ID_SIZE;
    

    SHA256(buffer, offset, hash_out);

    free(buffer);
    return 1;
}

/** Frees the memory allocated for the block. */
void TW_Block_destroy(TW_Block* block) {
    if (!block) return;
    free(block);
}

/** Serializes the block to a byte array. */
size_t TW_Block_serialize(TW_Block* block, unsigned char** buffer) {
    if (!block) {
        *buffer = NULL;
        return 0;
    }

    size_t total_size = sizeof(int32_t) +    // index
                        sizeof(int32_t) +    // txn_count
                        sizeof(uint8_t) +    // is_internal
                        sizeof(time_t) +     // timestamp
                        HASH_SIZE +          // previous_hash
                        PROP_ID_SIZE +       // proposer_id
                        HASH_SIZE;           // merkle_root_hash
    size_t* entry_sizes = malloc(block->txn_count * sizeof(size_t));
    if (!entry_sizes) {
        *buffer = NULL;
        return 0;
    }

    for (int32_t i = 0; i < block->txn_count; i++) {
        unsigned char* entry_buf;
        entry_sizes[i] = TW_Transaction_to_bytes(&block->txns[i], &entry_buf);
        total_size += sizeof(size_t) + entry_sizes[i];
        free(entry_buf);
    }

    unsigned char* ptr = *buffer;
    memcpy(ptr, &block->index, sizeof(int32_t));
    ptr += sizeof(int32_t);
    memcpy(ptr, &block->txn_count, sizeof(int32_t));
    ptr += sizeof(int32_t);
    memcpy(ptr, &block->timestamp, sizeof(time_t));
    ptr += sizeof(time_t);
    memcpy(ptr, block->previous_hash, HASH_SIZE);
    ptr += HASH_SIZE;
    memcpy(ptr, block->merkle_root_hash, HASH_SIZE);
    ptr += HASH_SIZE;
    memcpy(ptr, block->proposer_id, PROP_ID_SIZE);
    ptr += PROP_ID_SIZE;
    

    for (int32_t i = 0; i < block->txn_count; i++) {
        unsigned char* entry_buf;
        size_t entry_size;
        entry_size = TW_Transaction_to_bytes(&block->txns[i], &entry_buf);
        memcpy(ptr, &entry_size, sizeof(size_t));
        ptr += sizeof(size_t);
        memcpy(ptr, entry_buf, entry_size);
        ptr += entry_size;
        free(entry_buf);
    }
    free(entry_sizes);
    return total_size;
}

/** Deserializes a block from a byte array. */
TW_Block* TW_Block_deserialize(const unsigned char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size < sizeof(int32_t) * 2 + sizeof(uint8_t) + sizeof(time_t) + HASH_SIZE + PROP_ID_SIZE) {
        return NULL;
    }

    TW_Block* block = malloc(sizeof(TW_Block));
    if (!block) return NULL;

    const unsigned char* ptr = buffer;
    memcpy(&block->index, ptr, sizeof(int32_t));
    ptr += sizeof(int32_t);
    memcpy(&block->txn_count, ptr, sizeof(int32_t));
    ptr += sizeof(int32_t);
    memcpy(&block->timestamp, ptr, sizeof(time_t));
    ptr += sizeof(time_t);
    memcpy(block->previous_hash, ptr, HASH_SIZE);
    ptr += HASH_SIZE;
    memcpy(block->merkle_root_hash, ptr, HASH_SIZE);
    ptr += HASH_SIZE;
    memcpy(block->proposer_id, ptr, PROP_ID_SIZE);
    ptr += PROP_ID_SIZE;

    for (int32_t i = 0; i < block->txn_count; i++) {
        size_t entry_size;
        memcpy(&entry_size, ptr, sizeof(size_t));
        ptr += sizeof(size_t);
        if (ptr + entry_size > buffer + buffer_size) {
            free(block);
            return NULL;
        }

        TW_Transaction* txn = TW_Transaction_deserialize(ptr, entry_size);
        if (!txn) {
            free(block);
            return NULL;
        }
        block->txns[i] = *txn;
        free(txn);
        ptr += entry_size;
    }

    return block;
}