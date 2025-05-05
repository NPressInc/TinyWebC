#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>  // For size_t
#include <stdint.h>
#include <openssl/sha.h>
#include "merkleTree.h"
#include "merkleTreeNode.h"

/** Creates a new Merkle Tree with the given parameters. */
TW_MerkleTree* TW_MerkleTree_create(TW_MerkleTreeNode* root_node, uint32_t size, 
                                   const unsigned char* root_hash, uint32_t depth) {
    TW_MerkleTree* tree = malloc(sizeof(TW_MerkleTree));
    if (!tree) return NULL;

    tree->root_node = root_node;
    tree->size = size;
    if (root_hash) {
        memcpy(tree->root_hash, root_hash, HASH_SIZE);
    } else if (root_node) {
        memcpy(tree->root_hash, TW_MerkleTreeNode_get_hash(root_node), HASH_SIZE);
    } else {
        memset(tree->root_hash, 0, HASH_SIZE);
    }
    tree->depth = (depth == UINT32_MAX) ? TW_MerkleTree_findClosestSquare(size) : depth;
    tree->leaf_count = (uint8_t)(1 << tree->depth); // Cast safe, depth ≤ 7 for 255
    return tree;
}

/** Finds the smallest power of 2 >= size, returning the exponent. */
uint32_t TW_MerkleTree_findClosestSquare(uint32_t size) {
    uint32_t product = 1;
    uint32_t exponent = 0;
    while (product < size) {
        product *= 2;
        exponent++;
    }
    return exponent;
}

/** Converts index to binary navigation string for tree traversal. */
static void index_to_binary(uint32_t index, uint32_t depth, char* navigation) {
    for (uint32_t i = 0; i < depth; i++) {
        navigation[depth - 1 - i] = (index & (1 << i)) ? '1' : '0';
    }
    navigation[depth] = '\0';
}

/** Retrieves the transaction node at the given index. */
TW_MerkleTreeNode* TW_MerkleTree_getTransactionNodeFromIndex(TW_MerkleTree* tree, uint32_t index) {
    if (!tree || index >= tree->size) return NULL;

    char* navigation = calloc(tree->depth + 1, sizeof(char));
    if (!navigation) return NULL;
    index_to_binary(index, tree->depth, navigation);
    TW_MerkleTreeNode* curr_node = tree->root_node;
    for (uint32_t i = 0; i < tree->depth; i++) {
        if (!curr_node) break;
        curr_node = (navigation[i] == '0') ? TW_MerkleTreeNode_get_left(curr_node) 
                                          : TW_MerkleTreeNode_get_right(curr_node);
    }
    free(navigation);
    return curr_node;
}

/** Verifies the transaction hash at the given index, returns 1 if valid. */
int TW_MerkleTree_verifyTransactionHashByIndex(TW_MerkleTree* tree, uint32_t index, 
                                              unsigned char** result_value, size_t* result_size) {
    if (!tree || index >= tree->size) return 0;

    char* navigation = calloc(tree->depth + 1, sizeof(char));
    if (!navigation) return 0;
    index_to_binary(index, tree->depth, navigation);

    TW_MerkleTreeNode* curr_node = tree->root_node;
    unsigned char** neighbor_hashes = malloc(tree->depth * sizeof(unsigned char*));
    if (!neighbor_hashes) {
        free(navigation);
        return 0;
    }
    for (uint32_t i = 0; i < tree->depth; i++) neighbor_hashes[i] = NULL;

    // Traverse and collect neighbor hashes
    for (uint32_t i = 0; i < tree->depth; i++) {
        if (!curr_node) break;
        TW_MerkleTreeNode* neighbor = (navigation[i] == '0') ? TW_MerkleTreeNode_get_right(curr_node) 
                                                            : TW_MerkleTreeNode_get_left(curr_node);
        if (neighbor) neighbor_hashes[i] = (unsigned char*)TW_MerkleTreeNode_get_hash(neighbor);
        curr_node = (navigation[i] == '0') ? TW_MerkleTreeNode_get_left(curr_node) 
                                          : TW_MerkleTreeNode_get_right(curr_node);
    }

    if (!curr_node || !curr_node->is_leaf) {
        free(neighbor_hashes);
        free(navigation);
        *result_value = NULL;
        *result_size = 0;
        return 0;
    }

    // Reconstruct root hash from leaf hash and neighbors
    unsigned char current_hash[HASH_SIZE];
    memcpy(current_hash, TW_MerkleTreeNode_get_hash(curr_node), HASH_SIZE);
    for (int32_t i = tree->depth - 1; i >= 0; i--) {
        unsigned char combined[HASH_SIZE * 2];
        if (neighbor_hashes[i]) {
            if (navigation[i] == '0') {
                memcpy(combined, current_hash, HASH_SIZE);
                memcpy(combined + HASH_SIZE, neighbor_hashes[i], HASH_SIZE);
            } else {
                memcpy(combined, neighbor_hashes[i], HASH_SIZE);
                memcpy(combined + HASH_SIZE, current_hash, HASH_SIZE);
            }
        } else {
            memcpy(combined, current_hash, HASH_SIZE);
            memcpy(combined + HASH_SIZE, current_hash, HASH_SIZE); // Duplicate if no neighbor
        }
        SHA256(combined, HASH_SIZE * 2, current_hash);
    }

    int valid = (memcmp(current_hash, tree->root_hash, HASH_SIZE) == 0);
    free(neighbor_hashes);
    free(navigation);
    *result_value = NULL; // Data in SQLite, not stored here
    *result_size = 0;
    return valid;
}

/** Returns the root hash of the Merkle Tree. */
const unsigned char* TW_MerkleTree_get_rootHash(TW_MerkleTree* tree) {
    if (!tree) return NULL;
    return tree->root_hash; // Should always return the stored hash
}

/** Returns the number of transactions in the Merkle Tree. */
uint32_t TW_MerkleTree_get_size(TW_MerkleTree* tree) {
    return tree ? tree->size : 0;
}

/** Returns the depth of the Merkle Tree. */
uint32_t TW_MerkleTree_get_depth(TW_MerkleTree* tree) {
    return tree ? tree->depth : 0;
}

/** Frees the memory allocated for the Merkle Tree and its nodes. */
void TW_MerkleTree_destroy(TW_MerkleTree* tree) {
    if (!tree) return;
    if (tree->root_node) TW_MerkleTreeNode_destroy(tree->root_node);
    free(tree); // root_hash is fixed-size, no separate free
}

/** Builds a Merkle Tree from transaction byte data. */
TW_MerkleTreeNode* TW_MerkleTreeNode_buildTree(const unsigned char** transactions, 
                                              uint32_t transaction_count, size_t* data_sizes) {
    if (!transactions || transaction_count == 0) return NULL;

    uint32_t depth = TW_MerkleTree_findClosestSquare(transaction_count);
    uint32_t leaf_count = (uint8_t)(1 << depth);

    // Create leaf nodes
    TW_MerkleTreeNode** leaves = malloc(leaf_count * sizeof(TW_MerkleTreeNode*));
    if (!leaves) return NULL;

    for (uint32_t i = 0; i < leaf_count; i++) {
        uint32_t idx = (i < transaction_count) ? i : (transaction_count - 1);
        leaves[i] = TW_MerkleTreeNode_create_leaf(transactions[idx], data_sizes[idx]);
        if (!leaves[i]) {
            for (uint32_t j = 0; j < i; j++) TW_MerkleTreeNode_destroy(leaves[j]);
            free(leaves);
            return NULL;
        }
    }

    // Build tree bottom-up
    TW_MerkleTreeNode** current_level = leaves;
    uint32_t current_count = leaf_count;

    while (current_count > 1) {
        uint32_t parent_count = (current_count + 1) / 2;
        TW_MerkleTreeNode** parents = malloc(parent_count * sizeof(TW_MerkleTreeNode*));
        if (!parents) {
            for (uint32_t i = 0; i < current_count; i++) TW_MerkleTreeNode_destroy(current_level[i]);
            free(current_level);
            return NULL;
        }

        for (uint32_t i = 0; i < current_count; i += 2) {
            TW_MerkleTreeNode* left = current_level[i];
            TW_MerkleTreeNode* right = (i + 1 < current_count) ? current_level[i + 1] : left;
            parents[i / 2] = TW_MerkleTreeNode_create_internal(left, right);
            if (!parents[i / 2]) {
                for (uint32_t j = 0; j < i / 2; j++) TW_MerkleTreeNode_destroy(parents[j]);
                free(parents);
                for (uint32_t j = 0; j < current_count; j++) TW_MerkleTreeNode_destroy(current_level[j]);
                free(current_level);
                return NULL;
            }
        }

        free(current_level);
        current_level = parents;
        current_count = parent_count;
    }

    TW_MerkleTreeNode* root = current_level[0];
    free(current_level);
    return root;
}

size_t TW_MerkleTree_serialize(TW_MerkleTree* tree, unsigned char** buffer) {
    if (!tree) {
        *buffer = NULL;
        return 0;
    }

    size_t size = sizeof(uint32_t) +     // size
                  HASH_SIZE +            // root_hash
                  sizeof(uint32_t) +     // depth
                  sizeof(uint8_t);       // leaf_count
    *buffer = malloc(size);
    if (!*buffer) return 0;

    unsigned char* ptr = *buffer;
    memcpy(ptr, &tree->size, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, tree->root_hash, HASH_SIZE);
    ptr += HASH_SIZE;
    memcpy(ptr, &tree->depth, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(ptr, &tree->leaf_count, sizeof(uint8_t));

    return size; // Note: Doesn’t serialize nodes—assumes rebuilt from transactions
}

TW_MerkleTree* TW_MerkleTree_deserialize(const unsigned char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size < sizeof(uint32_t) + HASH_SIZE + sizeof(uint32_t) + sizeof(uint8_t)) return NULL;

    TW_MerkleTree* tree = malloc(sizeof(TW_MerkleTree));
    if (!tree) return NULL;

    const unsigned char* ptr = buffer;
    memcpy(&tree->size, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(tree->root_hash, ptr, HASH_SIZE);
    ptr += HASH_SIZE;
    memcpy(&tree->depth, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);
    memcpy(&tree->leaf_count, ptr, sizeof(uint8_t));
    tree->root_node = NULL; // Not serialized—rebuilt from transactions

    return tree;
}