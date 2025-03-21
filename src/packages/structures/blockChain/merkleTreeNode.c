#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "merkleTreeNode.h"

/** Creates a leaf node from raw data, hashing it with SHA-256. */
TW_MerkleTreeNode* TW_MerkleTreeNode_create_leaf(const unsigned char* data, size_t data_len) {
    TW_MerkleTreeNode* node = malloc(sizeof(TW_MerkleTreeNode));
    if (!node) return NULL;

    node->is_leaf = 1;
    node->left = NULL;
    node->right = NULL;
    SHA256(data, data_len, node->hash); // Compute hash directly into fixed array

    return node;
}

/** Creates an internal node by combining the hashes of two child nodes. */
TW_MerkleTreeNode* TW_MerkleTreeNode_create_internal(TW_MerkleTreeNode* left, TW_MerkleTreeNode* right) {
    TW_MerkleTreeNode* node = malloc(sizeof(TW_MerkleTreeNode));
    if (!node) return NULL;

    node->is_leaf = 0;
    node->left = left;
    node->right = right;

    // Concatenate and hash child hashes
    unsigned char combined[HASH_SIZE * 2];
    if (left) memcpy(combined, left->hash, HASH_SIZE);
    if (right) memcpy(combined + HASH_SIZE, right->hash, HASH_SIZE);
    SHA256(combined, (left && right) ? HASH_SIZE * 2 : HASH_SIZE, node->hash);

    return node;
}

/** Frees the memory allocated for a Merkle Tree node and its children recursively. */
void TW_MerkleTreeNode_destroy(TW_MerkleTreeNode* node) {
    if (!node) return;
    TW_MerkleTreeNode_destroy(node->left);
    TW_MerkleTreeNode_destroy(node->right);
    free(node); // No dynamic fields to free (hash is fixed-size)
}

/** Returns the hash of the Merkle Tree node. */
const unsigned char* TW_MerkleTreeNode_get_hash(TW_MerkleTreeNode* node) {
    return node ? node->hash : NULL;
}

/** Returns the left child of the Merkle Tree node. */
TW_MerkleTreeNode* TW_MerkleTreeNode_get_left(TW_MerkleTreeNode* node) {
    return node ? node->left : NULL;
}

/** Returns the right child of the Merkle Tree node. */
TW_MerkleTreeNode* TW_MerkleTreeNode_get_right(TW_MerkleTreeNode* node) {
    return node ? node->right : NULL;
}