#ifndef TW_MERKLE_TREE_H
#define TW_MERKLE_TREE_H

#include <stddef.h>  // For size_t
#include <stdint.h>
#include <openssl/sha.h>
#include "merkleTreeNode.h"

#define HASH_SIZE 32  // SHA-256 hash size

typedef struct TW_MerkleTree {
    TW_MerkleTreeNode* root_node;
    uint32_t size;
    unsigned char root_hash[HASH_SIZE];
    uint32_t depth;
    uint8_t leaf_count; // Max 255, fits 10s of family transactions
} TW_MerkleTree;

// Function prototypes
TW_MerkleTree* TW_MerkleTree_create(TW_MerkleTreeNode* root_node, uint32_t size, 
                                   const unsigned char* root_hash, uint32_t depth);
uint32_t TW_MerkleTree_findClosestSquare(uint32_t size);
TW_MerkleTreeNode* TW_MerkleTree_getNodeFromIndex(TW_MerkleTree* tree, uint32_t index);
void TW_MerkleTree_destroy(TW_MerkleTree* tree);
TW_MerkleTreeNode* TW_MerkleTree_buildTree(const unsigned char** transactions, 
                                               uint32_t transaction_count, size_t* data_sizes);
uint32_t TW_MerkleTree_get_size(TW_MerkleTree* tree);
uint32_t TW_MerkleTree_get_depth(TW_MerkleTree* tree);

TW_MerkleTree* TW_MerkleTree_deserialize(const unsigned char* buffer, size_t buffer_size);

size_t TW_MerkleTree_serialize(TW_MerkleTree* tree, unsigned char** buffer);

#endif