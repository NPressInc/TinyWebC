#ifndef TW_BLOCKCHAIN_H
#define TW_BLOCKCHAIN_H

#include <stddef.h>  // For size_t
#include <stdint.h>
#include "block.h"
#include "transaction.h"
#include "packages/encryption/encryption.h"

#define MAX_BLOCKS 1000000  // Arbitrary cap for in-memory chain, adjust as needed

typedef struct {
    TW_Block** blocks;  // Fixed-size array of block pointers
    size_t* block_sizes;
    uint32_t length;               // Current number of blocks
    unsigned char creator_pubkey[PUBKEY_SIZE]; // Creator's public key
} TW_BlockChain;

// Function prototypes
TW_BlockChain* TW_BlockChain_create(const unsigned char* creator_pubkey, TW_Block** chain, uint32_t length);
void TW_BlockChain_create_genesis_block(TW_BlockChain* blockchain, const unsigned char* creator_pubkey);
TW_Block* TW_BlockChain_get_last_block(TW_BlockChain* blockchain);
int TW_BlockChain_add_block(TW_BlockChain* blockchain, TW_Block* block);
size_t TW_BlockChain_get_size(const TW_BlockChain* chain);
int TW_BlockChain_serialize(TW_BlockChain* blockchain, unsigned char** buffer);
TW_BlockChain* TW_BlockChain_deserialize(const unsigned char* buffer, size_t buffer_size);
void TW_BlockChain_get_hash(TW_BlockChain* blockchain, unsigned char* hash_out);
void TW_BlockChain_get_block_hashes(TW_BlockChain* blockchain, unsigned char* hashes, uint32_t* count);
void TW_BlockChain_destroy(TW_BlockChain* blockchain);


#endif