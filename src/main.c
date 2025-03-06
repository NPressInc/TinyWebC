// main.c
#include <stdio.h>
#include <string.h>
#include "packages/comm/blockChainQueryApi.h"
#include "packages/structures/merkleTree/merkleTreeNode.h"
#include "packages/structures/merkleTree/merkleTree.h"
#include <sodium.h>

void test_merkle_tree() {
    const char* transactions[] = {"tx1", "tx2", "tx3"}; // Unbalanced (3 transactions)
    TW_MerkleTreeNode* root = TW_MerkleTreeNode_buildTree(transactions, 3);
    if (root) {
        TW_MerkleTree* tree = TW_MerkleTree_create(root, 3, NULL, -1);
        if (tree) {
            TW_MerkleTreeNode* node = TW_MerkleTree_getTransactionNodeFromIndex(tree, 1);
            char* result = NULL;
            int valid = TW_MerkleTree_verifyTransactionHashByIndex(tree, 1, &result);
            printf("Merkle Tree Root Hash: %s\n", TW_MerkleTree_get_rootHash(tree));
            printf("Node value: %s, Valid: %d\n", result ? result : "NULL", valid);
            free(result);
            TW_MerkleTree_destroy(tree);
        } else {
            printf("Merkle Tree creation failed\n");
            TW_MerkleTreeNode_destroy(root);
        }
    } else {
        printf("Merkle Tree build failed\n");
    }
}

int main() {
    printf("Starting Tiny Web MerkleTree Test...\n");
    test_merkle_tree();
    printf("Test completed.\n");
    return 0;
}