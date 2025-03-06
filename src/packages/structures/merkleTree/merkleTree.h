#ifndef TW_MERKLE_TREE_H
#define TW_MERKLE_TREE_H

#include <openssl/sha.h>
#include "merkleTreeNode.h"

typedef struct TW_MerkleTree TW_MerkleTree;

TW_MerkleTree* TW_MerkleTree_create(TW_MerkleTreeNode* rootNode, int size, const char* rootHash, int depth);
int TW_MerkleTree_findClosestSquare(int size);
TW_MerkleTreeNode* TW_MerkleTree_getTransactionNodeFromIndex(TW_MerkleTree* tree, int index);
int TW_MerkleTree_verifyTransactionHashByIndex(TW_MerkleTree* tree, int index, char** result_value);
void TW_MerkleTree_destroy(TW_MerkleTree* tree);

const char* TW_MerkleTree_get_rootHash(TW_MerkleTree* tree);
int TW_MerkleTree_get_size(TW_MerkleTree* tree);
int TW_MerkleTree_get_depth(TW_MerkleTree* tree);

#endif