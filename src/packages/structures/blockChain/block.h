#ifndef TW_BLOCK_H
#define TW_BLOCK_H

#include <stddef.h>  // For size_t
#include <stdint.h>
#include <time.h>      // For time_t
#include <openssl/sha.h> // For SHA256
#include "transaction.h" // Assume this exists for TW_Transaction
#include "merkleTree.h" // Assume this exists

#define HASH_SIZE 32   // SHA-256 hash size
#define MAX_TXNS 64    // Max transactions per block (adjustable)
#define PROP_ID_SIZE 16 // Fixed-size proposer ID (e.g., UUID)


typedef struct {
    int32_t index;
    TW_Transaction** txns;
    size_t* txn_sizes;
    int32_t txn_count;
    time_t timestamp;
    unsigned char previous_hash[HASH_SIZE];
    unsigned char proposer_id[PROP_ID_SIZE];
    unsigned char merkle_root_hash[HASH_SIZE];
} TW_Block;


// Function prototypes
TW_Block* TW_Block_create(int32_t index, TW_Transaction** block_txns, int32_t txn_count, 
    time_t timestamp, const unsigned char* previous_hash, const unsigned char* proposer_id);
void TW_Block_destroy(TW_Block* block);
void TW_Block_buildMerkleTree(TW_Block* block);
int TW_Block_getHash(TW_Block* block, unsigned char* hash_out);
size_t TW_Block_serialize(TW_Block* block, unsigned char** buffer); 
TW_Block* TW_Block_deserialize(const unsigned char* buffer, size_t buffer_size);

#endif