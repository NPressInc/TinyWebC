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
TW_Block* TW_Block_create(int32_t index, TW_BlockEntry* entries, int32_t entry_count, 
                          uint8_t is_internal, time_t timestamp, const unsigned char* previous_hash, 
                          const unsigned char* proposer_id, TW_MerkleTree* merkle_tree) {
    TW_Block* block = malloc(sizeof(TW_Block));
    if (!block) return NULL;

    block->index = index;
    block->entry_count = (entry_count > MAX_TXNS) ? MAX_TXNS : entry_count;
    block->is_internal = is_internal;
    for (int32_t i = 0; i < block->entry_count; i++) {
        block->entries[i] = entries[i];
    }
    block->timestamp = timestamp;
    memcpy(block->previous_hash, previous_hash ? previous_hash : (const unsigned char*)"\0", HASH_SIZE);
    memcpy(block->proposer_id, proposer_id ? proposer_id : (const unsigned char*)"\0", PROP_ID_SIZE);
    block->merkle_tree = merkle_tree;

    if (!merkle_tree) {
        TW_Block_buildMerkleTree(block);
    }

    return block;
}

/** Builds the Merkle Tree for the block based on its entries. */
void TW_Block_buildMerkleTree(TW_Block* block) {
    if (!block || block->entry_count == 0) {
        block->merkle_tree = NULL;
        return;
    }

    unsigned char** entry_data = malloc(block->entry_count * sizeof(unsigned char*));
    size_t* data_sizes = malloc(block->entry_count * sizeof(size_t));
    if (!entry_data || !data_sizes) {
        free(entry_data);
        free(data_sizes);
        block->merkle_tree = NULL;
        return;
    }

    for (int32_t i = 0; i < block->entry_count; i++) {
        if (block->is_internal) {
            data_sizes[i] = TW_InternalTransaction_serialize(&block->entries[i].int_txn, &entry_data[i]);
        } else {
            data_sizes[i] = TW_Transaction_to_bytes(&block->entries[i].txn, &entry_data[i]);
        }
        if (!entry_data[i]) {
            for (int32_t j = 0; j < i; j++) free(entry_data[j]);
            free(entry_data);
            free(data_sizes);
            block->merkle_tree = NULL;
            return;
        }
    }

    TW_MerkleTreeNode* root_node = TW_MerkleTreeNode_buildTree((const unsigned char**)entry_data, 
                                                               block->entry_count, data_sizes);
    unsigned char root_hash[HASH_SIZE];
    if (root_node) {
        memcpy(root_hash, TW_MerkleTreeNode_get_hash(root_node), HASH_SIZE);
    } else {
        memset(root_hash, 0, HASH_SIZE);
    }

    block->merkle_tree = TW_MerkleTree_create(root_node, block->entry_count, root_hash, UINT32_MAX);

    for (int32_t i = 0; i < block->entry_count; i++) {
        free(entry_data[i]);
    }
    free(entry_data);
    free(data_sizes);
}

void TW_Block_getHash(TW_Block* block, unsigned char* hash_out) {
    if (!block || !hash_out) {
        if (hash_out) memset(hash_out, 0, HASH_SIZE);
        return;
    }

    unsigned char buffer[128];
    size_t offset = 0;

    memcpy(buffer + offset, &block->index, sizeof(block->index));
    offset += sizeof(block->index);
    memcpy(buffer + offset, &block->timestamp, sizeof(block->timestamp));
    offset += sizeof(block->timestamp);
    memcpy(buffer + offset, block->previous_hash, HASH_SIZE);
    offset += HASH_SIZE;
    memcpy(buffer + offset, block->proposer_id, PROP_ID_SIZE);
    offset += PROP_ID_SIZE;
    if (block->merkle_tree) {
        const unsigned char* merkle_root = TW_MerkleTree_get_rootHash(block->merkle_tree);
        if (merkle_root) {
            memcpy(buffer + offset, merkle_root, HASH_SIZE);
            offset += HASH_SIZE;
        } else {
            memset(buffer + offset, 0, HASH_SIZE);
            offset += HASH_SIZE;
        }
    } else {
        memset(buffer + offset, 0, HASH_SIZE);
        offset += HASH_SIZE;
    }

    SHA256(buffer, offset, hash_out);
}

/** Frees the memory allocated for the block. */
void TW_Block_destroy(TW_Block* block) {
    if (!block) return;

    if (block->merkle_tree) {
        TW_MerkleTree_destroy(block->merkle_tree);
    }
    free(block);
}

/** Serializes the block to a byte array. */
size_t TW_Block_serialize(TW_Block* block, unsigned char** buffer) {
    if (!block) {
        *buffer = NULL;
        return 0;
    }

    size_t total_size = sizeof(int32_t) +    // index
                        sizeof(int32_t) +    // entry_count
                        sizeof(uint8_t) +    // is_internal
                        sizeof(time_t) +     // timestamp
                        HASH_SIZE +          // previous_hash
                        PROP_ID_SIZE;        // proposer_id
    size_t* entry_sizes = malloc(block->entry_count * sizeof(size_t));
    if (!entry_sizes) {
        *buffer = NULL;
        return 0;
    }

    for (int32_t i = 0; i < block->entry_count; i++) {
        unsigned char* entry_buf;
        if (block->is_internal) {
            entry_sizes[i] = TW_InternalTransaction_serialize(&block->entries[i].int_txn, &entry_buf);
        } else {
            entry_sizes[i] = TW_Transaction_to_bytes(&block->entries[i].txn, &entry_buf);
        }
        total_size += sizeof(size_t) + entry_sizes[i];
        free(entry_buf);
    }

    size_t merkle_size = 0;
    unsigned char* merkle_buf = NULL;
    if (block->merkle_tree) {
        merkle_size = TW_MerkleTree_serialize(block->merkle_tree, &merkle_buf);
        total_size += sizeof(size_t) + merkle_size;
    }

    *buffer = malloc(total_size);
    if (!*buffer) {
        free(entry_sizes);
        if (merkle_buf) free(merkle_buf);
        return 0;
    }

    unsigned char* ptr = *buffer;
    memcpy(ptr, &block->index, sizeof(int32_t));
    ptr += sizeof(int32_t);
    memcpy(ptr, &block->entry_count, sizeof(int32_t));
    ptr += sizeof(int32_t);
    memcpy(ptr, &block->is_internal, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    memcpy(ptr, &block->timestamp, sizeof(time_t));
    ptr += sizeof(time_t);
    memcpy(ptr, block->previous_hash, HASH_SIZE);
    ptr += HASH_SIZE;
    memcpy(ptr, block->proposer_id, PROP_ID_SIZE);
    ptr += PROP_ID_SIZE;

    for (int32_t i = 0; i < block->entry_count; i++) {
        unsigned char* entry_buf;
        size_t entry_size;
        if (block->is_internal) {
            entry_size = TW_InternalTransaction_serialize(&block->entries[i].int_txn, &entry_buf);
        } else {
            entry_size = TW_Transaction_to_bytes(&block->entries[i].txn, &entry_buf);
        }
        memcpy(ptr, &entry_size, sizeof(size_t));
        ptr += sizeof(size_t);
        memcpy(ptr, entry_buf, entry_size);
        ptr += entry_size;
        free(entry_buf);
    }

    if (block->merkle_tree) {
        memcpy(ptr, &merkle_size, sizeof(size_t));
        ptr += sizeof(size_t);
        memcpy(ptr, merkle_buf, merkle_size);
        ptr += merkle_size;
        free(merkle_buf);
    } else {
        size_t zero = 0;
        memcpy(ptr, &zero, sizeof(size_t));
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
    memcpy(&block->entry_count, ptr, sizeof(int32_t));
    ptr += sizeof(int32_t);
    memcpy(&block->is_internal, ptr, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    memcpy(&block->timestamp, ptr, sizeof(time_t));
    ptr += sizeof(time_t);
    memcpy(block->previous_hash, ptr, HASH_SIZE);
    ptr += HASH_SIZE;
    memcpy(block->proposer_id, ptr, PROP_ID_SIZE);
    ptr += PROP_ID_SIZE;

    for (int32_t i = 0; i < block->entry_count; i++) {
        size_t entry_size;
        memcpy(&entry_size, ptr, sizeof(size_t));
        ptr += sizeof(size_t);
        if (ptr + entry_size > buffer + buffer_size) {
            free(block);
            return NULL;
        }
        if (block->is_internal) {
            TW_InternalTransaction* int_txn = TW_InternalTransaction_deserialize(ptr, entry_size);
            if (!int_txn) {
                free(block);
                return NULL;
            }
            block->entries[i].int_txn = *int_txn;
            free(int_txn);
        } else {
            TW_Transaction* txn = TW_Transaction_deserialize(ptr, entry_size);
            if (!txn) {
                free(block);
                return NULL;
            }
            block->entries[i].txn = *txn;
            free(txn);
        }
        ptr += entry_size;
    }

    size_t merkle_size;
    memcpy(&merkle_size, ptr, sizeof(size_t));
    ptr += sizeof(size_t);
    if (merkle_size > 0) {
        if (ptr + merkle_size > buffer + buffer_size) {
            free(block);
            return NULL;
        }
        block->merkle_tree = TW_MerkleTree_deserialize(ptr, merkle_size);
        if (!block->merkle_tree) {
            free(block);
            return NULL;
        }
        ptr += merkle_size;
    } else {
        block->merkle_tree = NULL;
    }

    return block;
}