#ifndef TW_MERKLE_TREE_NODE_H
#define TW_MERKLE_TREE_NODE_H

#include <stddef.h>  // For size_t
#include <stdint.h>
#include <openssl/sha.h>

#define HASH_SIZE 32  // SHA-256 hash size

typedef struct TW_MerkleTreeNode {
    unsigned char hash[HASH_SIZE];  // Fixed-size hash of this node
    struct TW_MerkleTreeNode* left;  // Left child (NULL for leaf)
    struct TW_MerkleTreeNode* right; // Right child (NULL for leaf)
    uint8_t is_leaf;                // 1 if leaf, 0 if internal
} TW_MerkleTreeNode;

// Function prototypes
TW_MerkleTreeNode* TW_MerkleTreeNode_create_leaf(const unsigned char* data, size_t data_len);
TW_MerkleTreeNode* TW_MerkleTreeNode_create_internal(TW_MerkleTreeNode* left, TW_MerkleTreeNode* right);
void TW_MerkleTreeNode_destroy(TW_MerkleTreeNode* node);
const unsigned char* TW_MerkleTreeNode_get_hash(TW_MerkleTreeNode* node);
TW_MerkleTreeNode* TW_MerkleTreeNode_get_left(TW_MerkleTreeNode* node);
TW_MerkleTreeNode* TW_MerkleTreeNode_get_right(TW_MerkleTreeNode* node);

#endif