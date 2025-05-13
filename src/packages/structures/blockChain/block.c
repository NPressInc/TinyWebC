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


    //TW_MerkleTreeNode* node = TW_MerkleTree_buildTree(block_txns, txn_count, )

    char* merkle_root_hash = NULL;

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

size_t TW_Block_get_size(TW_Block* block) {
    if (!block) {
        return 0; // Invalid block
    }
    if (block->txn_count < 0 || (block->txn_count > 0 && (!block->txns || !block->txn_sizes))) {
        return 0; // Invalid transaction count or missing arrays
    }

    size_t size = 0;

    // Fixed-size fields
    size += sizeof(int32_t);        // index
    size += sizeof(int32_t);        // txn_count
    size += sizeof(time_t);         // timestamp
    size += HASH_SIZE;              // previous_hash
    size += PROP_ID_SIZE;           // proposer_id
    size += HASH_SIZE;              // merkle_root_hash

    // Size of txn_sizes array
    size += block->txn_count * sizeof(size_t); // txn_sizes array

    // Size of all transactions
    for (int32_t i = 0; i < block->txn_count; i++) {
        if (!block->txns[i]) {
            return 0; // Invalid transaction
        }
        size_t txn_size = TW_Transaction_get_size(block->txns[i]);
        if (txn_size == 0) {
            return 0; // Invalid transaction size
        }
        // Validate and update txn_sizes[i]
        if (block->txn_sizes[i] != txn_size) {
            block->txn_sizes[i] = txn_size;
        }
        size += block->txn_sizes[i]; // Add serialized size of each transaction
    }

    return size;
}

/** Serializes the block to a byte array. */
int TW_Block_serialize(TW_Block* block, unsigned char** buffer) {
    if (!block) {
        return 1;
    }

    unsigned char* ptr = *buffer;

    uint32_t index_net = htonl((uint32_t)block->index);
    memcpy(ptr, &index_net, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    
    // Serialize txn_count 
    uint32_t txn_count_net = htonl((uint32_t)block->txn_count);
    memcpy(ptr, &txn_count_net, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    
    // Serialize timestamp 
    uint64_t timestamp_net = htonll((uint64_t)block->timestamp);
    memcpy(ptr, timestamp_net, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    
    // Serialize previous_hash (no conversion needed)
    memcpy(ptr, block->previous_hash, HASH_SIZE);
    ptr += HASH_SIZE;

    // Serialize merkle_root_hash (no conversion needed)
    memcpy(ptr, block->merkle_root_hash, HASH_SIZE);
    ptr += HASH_SIZE;

    // Serialize proposer_id (no conversion needed)
    memcpy(ptr, block->proposer_id, PROP_ID_SIZE);
    ptr += PROP_ID_SIZE;

    for (int32_t i = 0; i < block->txn_count; i++) {
        int res = TW_Transaction_to_bytes(block->txns[i], &ptr);
        if(res != 0){
            printf("Failed to serialize transaction in block. \n");
            return 1;
        }
        ptr += block->txn_sizes[i];
    }

    *buffer = ptr; 

    return 0;
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
        block->txns[i] = txn;
        free(txn);
        ptr += entry_size;
    }

    return block;
}