#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "merkleTree.h"
#include "merkleTreeNode.h"

struct TW_MerkleTree {
    TW_MerkleTreeNode* rootNode;
    char* rootHash;
    int size; // Actual number of transactions
    int depth;
    int leaf_count; // Total leaves, including duplicates
};

/** Creates a new Merkle Tree with the given root node, size, and optional root hash. */
TW_MerkleTree* TW_MerkleTree_create(TW_MerkleTreeNode* rootNode, int size, const char* rootHash, int depth) {
    TW_MerkleTree* tree = malloc(sizeof(TW_MerkleTree));
    if (!tree) return NULL;

    tree->rootNode = rootNode;
    tree->size = size;
    if (rootHash) {
        tree->rootHash = strdup(rootHash);
    } else {
        tree->rootHash = strdup(TW_MerkleTreeNode_get_hashValue(rootNode));
    }
    tree->depth = (depth == -1) ? TW_MerkleTree_findClosestSquare(size) : depth;
    tree->leaf_count = 1 << tree->depth; // 2^depth
    return tree;
}

/** Finds the smallest power of 2 greater than or equal to size, returning the exponent. */
int TW_MerkleTree_findClosestSquare(int size) {
    int product = 1;
    int output = 0;
    while (product < size) {
        product *= 2;
        output++;
    }
    return output;
}

/** Helper function to convert an index to a binary navigation string for tree traversal. */
static void index_to_binary(int index, int depth, char* navigation) {
    for (int i = 0; i < depth; i++) {
        navigation[depth - 1 - i] = (index & (1 << i)) ? '1' : '0';
    }
    navigation[depth] = '\0';
}

/** Retrieves the transaction node at the given index by navigating the tree. */
TW_MerkleTreeNode* TW_MerkleTree_getTransactionNodeFromIndex(TW_MerkleTree* tree, int index) {
    if (!tree || index >= tree->size) return NULL;

    char* navigation = calloc(tree->depth + 1, sizeof(char));
    if (!navigation) return NULL;

    index_to_binary(index, tree->depth, navigation);
    TW_MerkleTreeNode* currNode = tree->rootNode;
    for (int i = 0; i < tree->depth; i++) {
        if (!currNode) break;
        currNode = (navigation[i] == '0') ? TW_MerkleTreeNode_get_left(currNode) : TW_MerkleTreeNode_get_right(currNode);
    }
    free(navigation);
    return currNode;
}

/** Verifies the transaction hash at the given index, returning 1 if valid, 0 otherwise. */
int TW_MerkleTree_verifyTransactionHashByIndex(TW_MerkleTree* tree, int index, char** result_value) {
    if (!tree || index >= tree->size || !result_value) return 0;
    
    // Initialize result value to NULL in case of early return
    *result_value = NULL;

    char* navigation = calloc(tree->depth + 1, sizeof(char));
    if (!navigation) return 0;

    index_to_binary(index, tree->depth, navigation);
    TW_MerkleTreeNode* currNode = tree->rootNode;
    
    // Allocate arrays for tracking hashes through traversal
    char** parentHashes = malloc(tree->depth * sizeof(char*));
    char** neighborHashes = malloc(tree->depth * sizeof(char*));
    char** valuesDebug = malloc(tree->depth * sizeof(char*));
    
    if (!parentHashes || !neighborHashes || !valuesDebug) {
        free(navigation);
        free(parentHashes);
        free(neighborHashes);
        free(valuesDebug);
        return 0;
    }

    // Initialize all pointers to NULL for safe cleanup
    for (int i = 0; i < tree->depth; i++) {
        parentHashes[i] = NULL;
        neighborHashes[i] = NULL;
        valuesDebug[i] = NULL;
    }

    // Traverse down the tree to the target leaf node
    for (int i = 0; i < tree->depth; i++) {
        if (!currNode) break;
        
        // Store the hash of the current node
        parentHashes[i] = strdup(TW_MerkleTreeNode_get_hashValue(currNode));
        
        // Store the value for debugging (if available)
        const char* value = TW_MerkleTreeNode_get_value(currNode);
        valuesDebug[i] = value ? strdup(value) : NULL;
        
        // Get the sibling node and its hash
        TW_MerkleTreeNode* neighbor = (navigation[i] == '0') ? 
            TW_MerkleTreeNode_get_right(currNode) : TW_MerkleTreeNode_get_left(currNode);
        neighborHashes[i] = neighbor ? strdup(TW_MerkleTreeNode_get_hashValue(neighbor)) : NULL;
        
        // Move to the next node according to the navigation path
        currNode = (navigation[i] == '0') ? 
            TW_MerkleTreeNode_get_left(currNode) : TW_MerkleTreeNode_get_right(currNode);
    }

    // Check if we found a valid leaf node
    if (!currNode) {
        // Clean up all allocated memory
        for (int i = 0; i < tree->depth; i++) {
            free(parentHashes[i]);
            free(neighborHashes[i]);
            free(valuesDebug[i]);
        }
        free(parentHashes);
        free(neighborHashes);
        free(valuesDebug);
        free(navigation);
        return 0;
    }

    // Get the value from the leaf node
    const char* currValue = TW_MerkleTreeNode_get_value(currNode);
    if (!currValue) {
        // Clean up all allocated memory
        for (int i = 0; i < tree->depth; i++) {
            free(parentHashes[i]);
            free(neighborHashes[i]);
            free(valuesDebug[i]);
        }
        free(parentHashes);
        free(neighborHashes);
        free(valuesDebug);
        free(navigation);
        return 0;
    }

    // Verify the leaf node's hash matches its value
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)currValue, strlen(currValue), hash);
    char computed_hash[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(computed_hash + i * 2, "%02x", hash[i]);
    }
    computed_hash[SHA256_DIGEST_LENGTH * 2] = '\0';
    
    // Set the result value regardless of verification outcome
    *result_value = strdup(currValue);
    
    // Check if the leaf node's hash matches its value
    if (strcmp(computed_hash, TW_MerkleTreeNode_get_hashValue(currNode)) != 0) {
        // Clean up all allocated memory
        for (int i = 0; i < tree->depth; i++) {
            free(parentHashes[i]);
            free(neighborHashes[i]);
            free(valuesDebug[i]);
        }
        free(parentHashes);
        free(neighborHashes);
        free(valuesDebug);
        free(navigation);
        return 0;
    }

    // Verify the path from leaf to root
    char* currentHash = strdup(TW_MerkleTreeNode_get_hashValue(currNode));
    int verification_result = 1; // Assume success until proven otherwise
    
    for (int i = tree->depth - 1; i >= 0 && verification_result; i--) {
        char* neighborHash = neighborHashes[i];
        char* tempNeighborHash = NULL;
        
        // If neighbor doesn't exist, use the current hash (for padding)
        if (!neighborHash) {
            tempNeighborHash = strdup(currentHash);
            neighborHash = tempNeighborHash;
        }
        
        // Concatenate the hashes in the correct order
        char* concatenatedHashes = malloc(strlen(currentHash) + strlen(neighborHash) + 1);
        if (!concatenatedHashes) {
            verification_result = 0;
        } else {
            strcpy(concatenatedHashes, (navigation[i] == '0') ? currentHash : neighborHash);
            strcat(concatenatedHashes, (navigation[i] == '0') ? neighborHash : currentHash);
            
            // Compute the hash of the concatenated hashes
            unsigned char hash_result[SHA256_DIGEST_LENGTH];
            SHA256((const unsigned char*)concatenatedHashes, strlen(concatenatedHashes), hash_result);
            char hash_str[SHA256_DIGEST_LENGTH * 2 + 1];
            for (int j = 0; j < SHA256_DIGEST_LENGTH; j++) {
                sprintf(hash_str + j * 2, "%02x", hash_result[j]);
            }
            hash_str[SHA256_DIGEST_LENGTH * 2] = '\0';
            
            // Verify the computed hash matches the stored parent hash
            if (strcmp(hash_str, parentHashes[i]) != 0) {
                verification_result = 0;
            } else {
                // Free the old current hash and replace it with the new one
                char* temp = currentHash;
                currentHash = strdup(hash_str);
                free(temp);
            }
            
            free(concatenatedHashes);
        }
        
        // Free temporary neighbor hash if created
        free(tempNeighborHash);
    }

    // Print the final root hash for debugging
    if (verification_result) {
        printf("Root Hash: %s\n", currentHash);
    }
    
    // Clean up all allocated memory
    free(currentHash);
    for (int i = 0; i < tree->depth; i++) {
        free(parentHashes[i]);
        free(neighborHashes[i]);
        free(valuesDebug[i]);
    }
    free(parentHashes);
    free(neighborHashes);
    free(valuesDebug);
    free(navigation);
    
    return verification_result;
}

/** Returns the root hash of the Merkle Tree. */
const char* TW_MerkleTree_get_rootHash(TW_MerkleTree* tree) {
    return tree ? tree->rootHash : NULL;
}

/** Returns the number of transactions in the Merkle Tree. */
int TW_MerkleTree_get_size(TW_MerkleTree* tree) {
    return tree ? tree->size : 0;
}

/** Returns the depth of the Merkle Tree. */
int TW_MerkleTree_get_depth(TW_MerkleTree* tree) {
    return tree ? tree->depth : 0;
}

/** Frees the memory allocated for the Merkle Tree and its nodes. */
void TW_MerkleTree_destroy(TW_MerkleTree* tree) {
    if (tree) {
        if (tree->rootNode) TW_MerkleTreeNode_destroy(tree->rootNode);
        free(tree->rootHash);
        free(tree);
    }
}