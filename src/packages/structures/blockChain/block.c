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
#include "packages/utils/byteorder.h" // Include byteorder.h for htonll

/** Creates a new Block with the given parameters. */
TW_Block* TW_Block_create(int32_t index, TW_Transaction** block_txns, int32_t txn_count, 
                        time_t timestamp, const unsigned char* previous_hash, const unsigned char* proposer_id) {
    TW_Block* block = malloc(sizeof(TW_Block));
    if (!block) return NULL;

    block->index = index;
    block->txn_count = (txn_count > MAX_TXNS) ? MAX_TXNS : txn_count;
    
    // Allocate memory for transaction pointers
    block->txns = malloc(block->txn_count * sizeof(TW_Transaction*));
    if (!block->txns) {
        free(block);
        return NULL;
    }
    
    // Allocate memory for transaction sizes
    block->txn_sizes = malloc(block->txn_count * sizeof(size_t));
    if (!block->txn_sizes) {
        free(block->txns);
        free(block);
        return NULL;
    }
    
    // Copy transaction pointers
    for (int32_t i = 0; i < block->txn_count; i++) {
        block->txns[i] = block_txns[i]; // Just copy the pointer, not the content
    }
    
    block->timestamp = timestamp;
    
    // Handle previous_hash
    if (previous_hash) {
        memcpy(block->previous_hash, previous_hash, HASH_SIZE);
    } else {
        memset(block->previous_hash, 0, HASH_SIZE);
    }
    
    // Handle proposer_id
    if (proposer_id) {
        memcpy(block->proposer_id, proposer_id, PROP_ID_SIZE);
    } else {
        memset(block->proposer_id, 0, PROP_ID_SIZE);
    }

    // Initialize merkle_root_hash to zeros
    memset(block->merkle_root_hash, 0, HASH_SIZE);

    return block;
}

/** Builds the merkle tree for the block and sets the merkle_root_hash. */
void TW_Block_buildMerkleTree(TW_Block* block) {
    if (!block) return;
    
    // If no transactions, set merkle root to zero
    if (block->txn_count == 0) {
        memset(block->merkle_root_hash, 0, HASH_SIZE);
        return;
    }
    
    // Create transaction hashes array
    unsigned char** tx_hashes = malloc(sizeof(unsigned char*) * block->txn_count);
    if (!tx_hashes) return;
    
    size_t* hash_sizes = malloc(sizeof(size_t) * block->txn_count);
    if (!hash_sizes) {
        free(tx_hashes);
        return;
    }
    
    // Calculate hash for each transaction
    for (int32_t i = 0; i < block->txn_count; i++) {
        tx_hashes[i] = malloc(HASH_SIZE);
        if (!tx_hashes[i]) {
            // Cleanup on failure
            for (int32_t j = 0; j < i; j++) {
                free(tx_hashes[j]);
            }
            free(tx_hashes);
            free(hash_sizes);
            return;
        }
        TW_Transaction_hash(block->txns[i], tx_hashes[i]);
        hash_sizes[i] = HASH_SIZE;
    }
    
    // Build merkle tree and get root
    TW_MerkleTreeNode* root = TW_MerkleTree_buildTree((const unsigned char**)tx_hashes, block->txn_count, hash_sizes);
    
    if (root) {
        // Copy root hash to block
        memcpy(block->merkle_root_hash, root->hash, HASH_SIZE);
        // Note: We don't free the root node here as TW_MerkleTree_buildTree 
        // may return a node that's part of a larger tree structure
    } else {
        // If tree building failed, set to zero
        memset(block->merkle_root_hash, 0, HASH_SIZE);
    }
    
    // Cleanup transaction hashes
    for (int32_t i = 0; i < block->txn_count; i++) {
        free(tx_hashes[i]);
    }
    free(tx_hashes);
    free(hash_sizes);
}

int TW_Block_getHash(TW_Block* block, unsigned char* hash_out) {
    if (!block || !hash_out) {
        if (hash_out) memset(hash_out, 0, HASH_SIZE);
        return -1; // Return negative to indicate failure
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
        return -2; // Return negative to indicate failure
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
    return 0; // Return 0 to indicate success
}

/** Frees the memory allocated for the block. */
void TW_Block_destroy(TW_Block* block) {
    if (!block) return;
    
    // Free transactions
    if (block->txns) {
        for (int32_t i = 0; i < block->txn_count; i++) {
            if (block->txns[i]) {
                TW_Transaction_destroy(block->txns[i]);
            }
        }
        free(block->txns);
    }
    
    // Free transaction sizes array
    if (block->txn_sizes) {
        free(block->txn_sizes);
    }
    
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

    // Size of txn_sizes array - REMOVED since we don't actually serialize this
    // size += block->txn_count * sizeof(size_t);

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
size_t TW_Block_serialize(TW_Block* block, unsigned char** buffer) {
    if (!block) {
        return 0; // Return 0 to indicate failure
    }

    unsigned char* ptr = *buffer;
    size_t total_size = 0;

    // Serialize index
    uint32_t index_net = htonl((uint32_t)block->index);
    memcpy(ptr, &index_net, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    total_size += sizeof(uint32_t);
    
    // Serialize txn_count 
    uint32_t txn_count_net = htonl((uint32_t)block->txn_count);
    memcpy(ptr, &txn_count_net, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    total_size += sizeof(uint32_t);
    
    // Serialize timestamp 
    uint64_t timestamp_net = htonll((uint64_t)block->timestamp);
    memcpy(ptr, &timestamp_net, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    total_size += sizeof(uint64_t);
    
    // Serialize previous_hash (no conversion needed)
    memcpy(ptr, block->previous_hash, HASH_SIZE);
    ptr += HASH_SIZE;
    total_size += HASH_SIZE;

    // Serialize merkle_root_hash (no conversion needed)
    memcpy(ptr, block->merkle_root_hash, HASH_SIZE);
    ptr += HASH_SIZE;
    total_size += HASH_SIZE;

    // Serialize proposer_id (no conversion needed)
    memcpy(ptr, block->proposer_id, PROP_ID_SIZE);
    ptr += PROP_ID_SIZE;
    total_size += PROP_ID_SIZE;

    // Serialize transactions
    for (int32_t i = 0; i < block->txn_count; i++) {
        // We need to use TW_Transaction_serialize instead of TW_Transaction_to_bytes
        int res = TW_Transaction_serialize(block->txns[i], &ptr);
        if(res != 0) {
            printf("Failed to serialize transaction in block. \n");
            return 0; // Return 0 to indicate failure
        }
        
        // We don't need to increment total_size here because ptr is updated by the function
        // and the final size is calculated by the difference between the final and initial pointers
    }

    size_t actual_total = ptr - *buffer;
    *buffer = ptr; 
    return actual_total; // Return the total size serialized
}

/** Deserializes a block from a byte array. */
// Deep copy function for blocks (creates independent copy with own memory allocations)
TW_Block* TW_Block_copy(const TW_Block* source) {
    if (!source) return NULL;

    // Create a new block with the same properties
    TW_Block* copy = TW_Block_create(source->index, source->txns, source->txn_count,
                                     source->timestamp, source->previous_hash, source->proposer_id);
    if (!copy) return NULL;

    // Copy the merkle root hash
    memcpy(copy->merkle_root_hash, source->merkle_root_hash, HASH_SIZE);

    // Copy transaction sizes
    if (source->txn_sizes && copy->txn_sizes) {
        memcpy(copy->txn_sizes, source->txn_sizes, source->txn_count * sizeof(size_t));
    }

    return copy;
}

TW_Block* TW_Block_deserialize(const unsigned char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size < sizeof(int32_t) * 2 + sizeof(time_t) + HASH_SIZE*2 + PROP_ID_SIZE) {
        return NULL;
    }

    TW_Block* block = malloc(sizeof(TW_Block));
    if (!block) return NULL;
    memset(block, 0, sizeof(TW_Block)); // Initialize to zeros

    const unsigned char* ptr = buffer;
    
    // Deserialize index
    uint32_t index_net;
    memcpy(&index_net, ptr, sizeof(uint32_t));
    block->index = ntohl(index_net);
    ptr += sizeof(uint32_t);
    
    // Deserialize txn_count
    uint32_t txn_count_net;
    memcpy(&txn_count_net, ptr, sizeof(uint32_t));
    block->txn_count = ntohl(txn_count_net);
    ptr += sizeof(uint32_t);
    
    // Allocate memory for transaction pointers and sizes
    if (block->txn_count > 0) {
        block->txns = malloc(block->txn_count * sizeof(TW_Transaction*));
        if (!block->txns) {
            free(block);
            return NULL;
        }
        memset(block->txns, 0, block->txn_count * sizeof(TW_Transaction*));
        
        block->txn_sizes = malloc(block->txn_count * sizeof(size_t));
        if (!block->txn_sizes) {
            free(block->txns);
            free(block);
            return NULL;
        }
        memset(block->txn_sizes, 0, block->txn_count * sizeof(size_t));
    } else {
        block->txns = NULL;
        block->txn_sizes = NULL;
    }
    
    // Deserialize timestamp
    uint64_t timestamp_net;
    memcpy(&timestamp_net, ptr, sizeof(uint64_t));
    block->timestamp = ntohll(timestamp_net);
    ptr += sizeof(uint64_t);
    
    // Deserialize previous_hash
    memcpy(block->previous_hash, ptr, HASH_SIZE);
    ptr += HASH_SIZE;
    
    // Deserialize merkle_root_hash
    memcpy(block->merkle_root_hash, ptr, HASH_SIZE);
    ptr += HASH_SIZE;
    
    // Deserialize proposer_id
    memcpy(block->proposer_id, ptr, PROP_ID_SIZE);
    ptr += PROP_ID_SIZE;

    // Deserialize transactions
    for (int32_t i = 0; i < block->txn_count; i++) {
        // For each transaction, we need to deserialize it
        block->txns[i] = TW_Transaction_deserialize(ptr, buffer_size - (ptr - buffer));
        if (!block->txns[i]) {
            // Failed to deserialize, clean up and return NULL
            TW_Block_destroy(block);
            return NULL;
        }
        
        // Calculate transaction size
        block->txn_sizes[i] = TW_Transaction_get_size(block->txns[i]);
        ptr += block->txn_sizes[i];
        
        // Check if we've gone past the buffer
        if (ptr > buffer + buffer_size) {
            TW_Block_destroy(block);
            return NULL;
        }
    }

    return block;
}