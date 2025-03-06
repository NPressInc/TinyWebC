#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "merkleTreeNode.h"

struct TW_MerkleTreeNode {
    char* value;
    char* hashValue;
    TW_MerkleTreeNode* left;
    TW_MerkleTreeNode* right;
};

TW_MerkleTreeNode* TW_MerkleTreeNode_create(const char* value, const char* hashValue) {
    TW_MerkleTreeNode* node = malloc(sizeof(TW_MerkleTreeNode));
    if (!node) return NULL;

    node->value = strdup(value);
    node->left = NULL;
    node->right = NULL;

    if (hashValue) {
        node->hashValue = strdup(hashValue);
    } else {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char*)value, strlen(value), hash);
        // Convert binary hash to hex string
        node->hashValue = malloc(SHA256_DIGEST_LENGTH * 2 + 1);
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            sprintf(node->hashValue + i * 2, "%02x", hash[i]);
        }
        node->hashValue[SHA256_DIGEST_LENGTH * 2] = '\0';
    }
    return node;
}

TW_MerkleTreeNode* TW_MerkleTreeNode_buildTree(const char** transactions, int transaction_count) {
    if (!transactions || transaction_count <= 0) return NULL;

    // Create leaf nodes
    TW_MerkleTreeNode** nodes = malloc(transaction_count * sizeof(TW_MerkleTreeNode*));
    if (!nodes) return NULL;

    for (int i = 0; i < transaction_count; i++) {
        nodes[i] = TW_MerkleTreeNode_create(transactions[i], NULL);
        if (!nodes[i]) {
            for (int j = 0; j < i; j++) TW_MerkleTreeNode_destroy(nodes[j]);
            free(nodes);
            return NULL;
        }
    }

    // Build tree iteratively
    while (transaction_count != 1) {
        int temp_count = (transaction_count + 1) / 2; // Ceiling division
        TW_MerkleTreeNode** temp = malloc(temp_count * sizeof(TW_MerkleTreeNode*));
        if (!temp) {
            for (int i = 0; i < transaction_count; i++) TW_MerkleTreeNode_destroy(nodes[i]);
            free(nodes);
            return NULL;
        }

        for (int i = 0; i < transaction_count; i += 2) {
            TW_MerkleTreeNode* node1 = nodes[i];
            TW_MerkleTreeNode* node2 = (i + 1 < transaction_count) ? nodes[i + 1] : nodes[i];
            char* concatenatedHash = malloc(strlen(node1->hashValue) + strlen(node2->hashValue) + 1);
            strcpy(concatenatedHash, node1->hashValue);
            strcat(concatenatedHash, node2->hashValue);

            TW_MerkleTreeNode* parent = TW_MerkleTreeNode_create(concatenatedHash, NULL);
            parent->left = node1;
            parent->right = node2;
            temp[i / 2] = parent;
            free(concatenatedHash);
        }

        for (int i = 0; i < transaction_count; i++) {
            if (i % 2 == 1) nodes[i] = NULL; // Avoid double-free
        }
        free(nodes);
        nodes = temp;
        transaction_count = temp_count;
    }

    TW_MerkleTreeNode* root = nodes[0];
    free(nodes);
    return root;
}

void TW_MerkleTreeNode_destroy_helper(TW_MerkleTreeNode* node, void** visited, int* visited_count, int* visited_capacity) {
    if (!node) return;
    
    // Check if this node has already been visited (freed)
    for (int i = 0; i < *visited_count; i++) {
        if (visited[i] == node) {
            // Node already processed, don't free it again
            return;
        }
    }
    
    // Add this node to the visited list
    if (*visited_count >= *visited_capacity) {
        // Expand the visited array if needed
        *visited_capacity *= 2;
        visited = realloc(visited, *visited_capacity * sizeof(void*));
    }
    visited[*visited_count] = node;
    (*visited_count)++;
    
    // Process children before freeing this node
    if (node->left) {
        TW_MerkleTreeNode_destroy_helper(node->left, visited, visited_count, visited_capacity);
        node->left = NULL;  // Prevent future access
    }
    
    if (node->right) {
        TW_MerkleTreeNode_destroy_helper(node->right, visited, visited_count, visited_capacity);
        node->right = NULL;  // Prevent future access
    }
    
    // Free the node's resources
    free(node->hashValue);
    free(node->value);
    free(node);
}

/**
 * Safely destroys a Merkle tree node and all its children.
 * Handles the case where nodes might be shared (DAG structure).
 */
void TW_MerkleTreeNode_destroy(TW_MerkleTreeNode* node) {
    if (!node) return;
    
    // Initialize the visited nodes tracker
    int initial_capacity = 100;  // Adjust based on expected tree size
    void** visited = malloc(initial_capacity * sizeof(void*));
    if (!visited) return;  // Memory allocation failure
    
    int visited_count = 0;
    int visited_capacity = initial_capacity;
    
    // Destroy the node tree safely
    TW_MerkleTreeNode_destroy_helper(node, visited, &visited_count, &visited_capacity);
    
    // Free the visited nodes tracker
    free(visited);
}

const char* TW_MerkleTreeNode_get_value(TW_MerkleTreeNode* node) {
    return node ? node->value : NULL;
}

const char* TW_MerkleTreeNode_get_hashValue(TW_MerkleTreeNode* node) {
    return node ? node->hashValue : NULL;
}

TW_MerkleTreeNode* TW_MerkleTreeNode_get_left(TW_MerkleTreeNode* node) {
    return node ? node->left : NULL;
}

TW_MerkleTreeNode* TW_MerkleTreeNode_get_right(TW_MerkleTreeNode* node) {
    return node ? node->right : NULL;
}