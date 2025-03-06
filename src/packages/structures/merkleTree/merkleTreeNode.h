#ifndef TW_MERKLE_TREE_NODE_H
#define TW_MERKLE_TREE_NODE_H

#include <openssl/sha.h>

typedef struct TW_MerkleTreeNode TW_MerkleTreeNode;

TW_MerkleTreeNode* TW_MerkleTreeNode_create(const char* value, const char* hashValue);
TW_MerkleTreeNode* TW_MerkleTreeNode_buildTree(const char** transactions, int transaction_count);
void TW_MerkleTreeNode_destroy(TW_MerkleTreeNode* node);

const char* TW_MerkleTreeNode_get_value(TW_MerkleTreeNode* node);
const char* TW_MerkleTreeNode_get_hashValue(TW_MerkleTreeNode* node);
TW_MerkleTreeNode* TW_MerkleTreeNode_get_left(TW_MerkleTreeNode* node);
TW_MerkleTreeNode* TW_MerkleTreeNode_get_right(TW_MerkleTreeNode* node);

#endif