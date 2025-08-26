#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>  // For size_t
#include <stdint.h>
#include <openssl/sha.h>
#include <arpa/inet.h>  // For htonl, ntohl
#include "blockchain.h"
#include "packages/utils/byteorder.h"  // For htonll, ntohll

/** Initializes a new blockchain. */
TW_BlockChain* TW_BlockChain_create(const unsigned char* creator_pubkey, TW_Block** blocks, uint32_t length) {
    TW_BlockChain* blockchain = malloc(sizeof(TW_BlockChain));
    if (!blockchain) return NULL;

    // Initialize all fields to zero
    memset(blockchain, 0, sizeof(TW_BlockChain));

    blockchain->length = (length > MAX_BLOCKS) ? MAX_BLOCKS : length;
    if (creator_pubkey) {
        memcpy(blockchain->creator_pubkey, creator_pubkey, PUBKEY_SIZE);
    } else {
        memset(blockchain->creator_pubkey, 0, PUBKEY_SIZE);
    }

    // Allocate memory for blocks and block_sizes
    blockchain->blocks = malloc(MAX_BLOCKS * sizeof(TW_Block*));
    if (!blockchain->blocks) {
        free(blockchain);
        return NULL;
    }
    memset(blockchain->blocks, 0, MAX_BLOCKS * sizeof(TW_Block*));
    
    blockchain->block_sizes = malloc(MAX_BLOCKS * sizeof(size_t));
    if (!blockchain->block_sizes) {
        free(blockchain->blocks);
        free(blockchain);
        return NULL;
    }
    memset(blockchain->block_sizes, 0, MAX_BLOCKS * sizeof(size_t));

    // Initialize blocks and block_sizes
    for (uint32_t i = 0; i < MAX_BLOCKS; i++) {
        blockchain->blocks[i] = (i < length && blocks) ? blocks[i] : NULL;
        blockchain->block_sizes[i] = 0;
    }

    // If no blocks provided and creator key exists, create genesis block
    if (blockchain->length == 0 && creator_pubkey) {
        TW_BlockChain_create_genesis_block(blockchain, creator_pubkey);
    }

    return blockchain;
}

/** Creates and adds a genesis block to the blockchain. */
void TW_BlockChain_create_genesis_block(TW_BlockChain* blockchain, const unsigned char* creator_pubkey) {
    if (!blockchain || blockchain->length >= MAX_BLOCKS || !creator_pubkey) return;

    // Dummy genesis transaction (no crypto, plaintext)
    unsigned char sender[PUBKEY_SIZE];
    memcpy(sender, creator_pubkey, PUBKEY_SIZE);

    // Create a genesis message
    unsigned char genesis_text[] = "Genesis Block";
    size_t text_len = sizeof(genesis_text) - 1; // Exclude null terminator

    // Create an encrypted payload
    EncryptedPayload* genesis_payload = encrypt_payload_multi(genesis_text, text_len, sender, 1);
    if (!genesis_payload) return;

    // Create a single transaction for the genesis block
    TW_Transaction** txns = malloc(sizeof(TW_Transaction*));
    if (!txns) {
        free_encrypted_payload(genesis_payload);
        return;
    }
    
    // Initialize to NULL first
    txns[0] = NULL;
    
    // Create the genesis transaction
    txns[0] = TW_Transaction_create(TW_TXN_SYSTEM_CONFIG, sender, sender, 1, NULL, genesis_payload, NULL);
    
    // The transaction now owns the payload
    genesis_payload = NULL;
    
    if (!txns[0]) {
        free(txns);
        return;
    }
    
    // Create zeroed hash for previous_hash
    unsigned char zero_hash[HASH_SIZE] = {0};
    
    // Create proposer_id
    unsigned char proposer_id[PROP_ID_SIZE] = {0};
    strncpy((char*)proposer_id, "genesis", PROP_ID_SIZE-1);

    // Create the genesis block
    TW_Block* genesis = TW_Block_create(0, txns, 1, time(NULL), zero_hash, proposer_id);

    // Add the block to the blockchain
    if (genesis) {
        // Build the merkle tree for the genesis block
        TW_Block_buildMerkleTree(genesis);
        
        blockchain->blocks[0] = genesis;
        blockchain->length = 1;
    } else {
        // If block creation failed, clean up the transaction
        TW_Transaction_destroy(txns[0]);
    }
    
    // Free the array but not the transaction 
    // (it's now managed by the block if the block was created successfully)
    free(txns);
}

/** Returns the last block in the chain. */
TW_Block* TW_BlockChain_get_last_block(TW_BlockChain* blockchain) {
    if (!blockchain || blockchain->length == 0) return NULL;
    return blockchain->blocks[blockchain->length - 1];
}

/** Adds a block to the chain. Returns 0 on success, negative on failure. */
int TW_BlockChain_add_block(TW_BlockChain* blockchain, TW_Block* block) {
    if (!blockchain || !block || blockchain->length >= MAX_BLOCKS) return -1;

    // Basic validation: check previous hash matches last block
    TW_Block* last_block = TW_BlockChain_get_last_block(blockchain);
    unsigned char last_hash[HASH_SIZE];
    if (last_block) {
        if (TW_Block_getHash(last_block, last_hash) != 0) {
            // Failed to get hash of last block
            return -2;
        }
        
        // Convert hashes to hex for comparison
        char expected_hex[HASH_SIZE * 2 + 1];
        char block_hex[HASH_SIZE * 2 + 1];
        
        for (int i = 0; i < HASH_SIZE; i++) {
            sprintf(&expected_hex[i * 2], "%02x", last_hash[i]);
            sprintf(&block_hex[i * 2], "%02x", block->previous_hash[i]);
        }
        
        if (memcmp(last_hash, block->previous_hash, HASH_SIZE) != 0) {
            // Hash mismatch, rejecting block
            return -3;
        }
    } else if (block->index != 0) {
        return -4; // First block must be index 0
    }

    blockchain->blocks[blockchain->length] = block;
    blockchain->length++;
    return 0;
}

/** Computes the hash of the entire chain (based on last block hash). */
void TW_BlockChain_get_hash(TW_BlockChain* blockchain, unsigned char* hash_out) {
    if (!blockchain || !hash_out || blockchain->length == 0) {
        memset(hash_out, 0, HASH_SIZE);
        return;
    }
    if (TW_Block_getHash(TW_BlockChain_get_last_block(blockchain), hash_out) != 0) {
        // If hash calculation fails, set to zero hash
        memset(hash_out, 0, HASH_SIZE);
    }
}

/** Retrieves an array of all block hashes. */
void TW_BlockChain_get_block_hashes(TW_BlockChain* blockchain, unsigned char* hashes, uint32_t* count) {
    if (!blockchain || !hashes || !count) {
        if (count) *count = 0;
        return;
    }

    *count = blockchain->length;
    for (uint32_t i = 0; i < blockchain->length; i++) {
        if (TW_Block_getHash(blockchain->blocks[i], hashes + i * HASH_SIZE) != 0) {
            // If hash calculation fails, set to zero hash
            memset(hashes + i * HASH_SIZE, 0, HASH_SIZE);
        }
    }
}

size_t TW_BlockChain_get_size(const TW_BlockChain* chain) {
    if (!chain) {
        return 0; // Invalid chain
    }
    
    // Start with the basic essential fields
    size_t size = 0;
    size += sizeof(uint32_t);            // length
    size += PUBKEY_SIZE;                 // creator_pubkey
    
    // Add size for block_sizes array
    size += chain->length * sizeof(size_t);
    
    // If no blocks, just return the size of the header
    if (chain->length == 0) {
        return size;
    }
    
    if (!chain->blocks) {
        return 0; // Invalid blocks array
    }
    
    // Add size for each block
    for (uint32_t i = 0; i < chain->length; i++) {
        if (!chain->blocks[i]) {
            return 0; // Invalid block
        }
        
        // Get the size of this block
        size_t block_size = TW_Block_get_size(chain->blocks[i]);
        
        if (block_size == 0) {
            return 0; // Invalid block size
        }
        
        // Add the block size to the total
        size += block_size;
    }
    
    return size;
}

/** Serializes the blockchain to a byte array (simplified, no Protobuf yet). */
int TW_BlockChain_serialize(TW_BlockChain* blockchain, unsigned char** buffer) {
    if (!blockchain || !buffer || !*buffer) {
        return 1; // Error
    }

    // Ensure block sizes are up to date
    for (uint32_t i = 0; i < blockchain->length; i++) {
        if (blockchain->blocks[i]) {
            blockchain->block_sizes[i] = TW_Block_get_size(blockchain->blocks[i]);
        }
    }

    unsigned char* ptr = *buffer;
    
    // Serialize length
    uint32_t length_net = htonl(blockchain->length);
    memcpy(ptr, &length_net, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    // Serialize creator_pubkey
    memcpy(ptr, blockchain->creator_pubkey, PUBKEY_SIZE);
    ptr += PUBKEY_SIZE;

    // Serialize block_sizes
    for (uint32_t i = 0; i < blockchain->length; i++) {
        size_t block_size_net = htonll(blockchain->block_sizes[i]);
        memcpy(ptr, &block_size_net, sizeof(size_t));
        ptr += sizeof(size_t);
    }

    // Serialize blocks
    for (uint32_t i = 0; i < blockchain->length; i++) {
        if (!blockchain->blocks[i]) {
            return 1; // Error - block is NULL
        }
        
        size_t result = TW_Block_serialize(blockchain->blocks[i], &ptr);
        if (result == 0) {
            return 1; // Error in serialization
        }
        
        // Update the block_sizes array with actual size if different
        if (blockchain->block_sizes[i] != result) {
            blockchain->block_sizes[i] = result;
        }
    }

    *buffer = ptr;
    return 0; // Success
}

TW_BlockChain* TW_BlockChain_deserialize(const unsigned char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size < sizeof(uint32_t)) {
        return NULL;
    }

    TW_BlockChain* blockchain = malloc(sizeof(TW_BlockChain));
    if (!blockchain) return NULL;
    memset(blockchain, 0, sizeof(TW_BlockChain)); // Initialize to zeros

    const unsigned char* ptr = buffer;

    // Deserialize length
    uint32_t length_net;
    memcpy(&length_net, ptr, sizeof(uint32_t));
    blockchain->length = ntohl(length_net);
    ptr += sizeof(uint32_t);

    // Deserialize creator_pubkey
    memcpy(blockchain->creator_pubkey, ptr, PUBKEY_SIZE);
    ptr += PUBKEY_SIZE;

    if (blockchain->length > MAX_BLOCKS) {
        free(blockchain);
        return NULL;
    }

    // Allocate memory for blocks and block_sizes
    blockchain->blocks = malloc(MAX_BLOCKS * sizeof(TW_Block*));
    if (!blockchain->blocks) {
        free(blockchain);
        return NULL;
    }
    memset(blockchain->blocks, 0, MAX_BLOCKS * sizeof(TW_Block*));
    
    blockchain->block_sizes = malloc(MAX_BLOCKS * sizeof(size_t));
    if (!blockchain->block_sizes) {
        free(blockchain->blocks);
        free(blockchain);
        return NULL;
    }
    memset(blockchain->block_sizes, 0, MAX_BLOCKS * sizeof(size_t));

    // Read block sizes
    size_t total_block_size = 0;
    for (uint32_t i = 0; i < blockchain->length; i++) {
        size_t block_size_net;
        memcpy(&block_size_net, ptr, sizeof(size_t));
        blockchain->block_sizes[i] = ntohll(block_size_net);
        ptr += sizeof(size_t);
        
        total_block_size += blockchain->block_sizes[i];
        if (ptr + blockchain->block_sizes[i] > buffer + buffer_size) {
            TW_BlockChain_destroy(blockchain);
            return NULL;
        }
    }
    
    // Calculate expected total size and validate
    size_t header_size = sizeof(uint32_t) + PUBKEY_SIZE + blockchain->length * sizeof(size_t);
    size_t expected_total = header_size + total_block_size;
    
    if (expected_total > buffer_size) {
        TW_BlockChain_destroy(blockchain);
        return NULL;
    }
    
    // Deserialize blocks
    for (uint32_t i = 0; i < blockchain->length; i++) {
        blockchain->blocks[i] = TW_Block_deserialize(ptr, blockchain->block_sizes[i]);
        if (!blockchain->blocks[i]) {
            TW_BlockChain_destroy(blockchain);
            return NULL;
        }
        ptr += blockchain->block_sizes[i];
    }

    return blockchain;
}

/** Frees the blockchain and its blocks. */
void TW_BlockChain_destroy(TW_BlockChain* blockchain) {
    if (!blockchain) return;
    
    if (blockchain->blocks) {
        for (uint32_t i = 0; i < blockchain->length; i++) {
            if (blockchain->blocks[i]) {
                TW_Block_destroy(blockchain->blocks[i]);
            }
        }
        free(blockchain->blocks);
    }
    
    if (blockchain->block_sizes) {
        free(blockchain->block_sizes);
    }
    
    free(blockchain);
}