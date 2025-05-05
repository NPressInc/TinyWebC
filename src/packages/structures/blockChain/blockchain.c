#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>  // For size_t
#include <stdint.h>
#include <openssl/sha.h>
#include "blockchain.h"

/** Initializes a new blockchain. */
TW_BlockChain* TW_BlockChain_create(const unsigned char* creator_pubkey, TW_Block** chain, uint32_t length) {
    TW_BlockChain* blockchain = malloc(sizeof(TW_BlockChain));
    if (!blockchain) return NULL;

    blockchain->length = (length > MAX_BLOCKS) ? MAX_BLOCKS : length;
    if (creator_pubkey) {
        memcpy(blockchain->creator_pubkey, creator_pubkey, PUBKEY_SIZE);
    } else {
        memset(blockchain->creator_pubkey, 0, PUBKEY_SIZE);
    }

    // Initialize blocks
    for (uint32_t i = 0; i < MAX_BLOCKS; i++) {
        blockchain->blocks[i] = (i < length && chain) ? chain[i] : NULL;
    }

    // If no chain provided and creator key exists, create genesis block
    if (blockchain->length == 0 && creator_pubkey) {
        TW_BlockChain_create_genesis_block(blockchain, creator_pubkey);
    }

    return blockchain;
}

/** Creates and adds a genesis block to the blockchain. */
void TW_BlockChain_create_genesis_block(TW_BlockChain* blockchain, const unsigned char* creator_pubkey) {
    if (!blockchain || blockchain->length >= MAX_BLOCKS) return;

    // Dummy genesis transaction (no crypto, plaintext)
    unsigned char sender[PUBKEY_SIZE];
    memcpy(sender, creator_pubkey, PUBKEY_SIZE);

    unsigned char* genesis_text = "genesis_text";

    EncryptedPayload* genesis_payload = encrypt_payload_multi(genesis_text, 13, sender, 1);

    TW_Transaction* txns[1];
    txns[0] = TW_Transaction_create(TW_TXN_MISC, sender, sender, 1, NULL, genesis_payload, NULL);

    free_encrypted_payload(genesis_payload);
    
    if (!txns) return;
    unsigned char zero_hash[HASH_SIZE] = {0};
    unsigned char proposer_id[PROP_ID_SIZE] = "genesis";

    TW_Block* genesis = TW_Block_create(0, txns, 1, time(NULL), zero_hash, proposer_id, NULL);

    if (genesis) {
        blockchain->blocks[0] = genesis;
        blockchain->length = 1;
    }
    
    TW_Transaction_destroy(txns[0]);
}

/** Returns the last block in the chain. */
TW_Block* TW_BlockChain_get_last_block(TW_BlockChain* blockchain) {
    if (!blockchain || blockchain->length == 0) return NULL;
    return blockchain->blocks[blockchain->length - 1];
}

/** Adds a block to the chain. Returns 1 on success, 0 on failure. */
int TW_BlockChain_add_block(TW_BlockChain* blockchain, TW_Block* block) {
    if (!blockchain || !block || blockchain->length >= MAX_BLOCKS) return 0;

    // Basic validation: check previous hash matches last block
    TW_Block* last = TW_BlockChain_get_last_block(blockchain);
    unsigned char last_hash[HASH_SIZE];
    if (last) {
        TW_Block_getHash(last, last_hash);
        if (memcmp(block->previous_hash, last_hash, HASH_SIZE) != 0) return 0;
    } else if (block->index != 0) {
        return 0; // First block must be index 0
    }

    blockchain->blocks[blockchain->length] = block;
    blockchain->length++;
    return 1;
}

/** Serializes the blockchain to a byte array (simplified, no Protobuf yet). */
size_t TW_BlockChain_serialize(TW_BlockChain* blockchain, unsigned char** buffer) {
    if (!blockchain) {
        *buffer = NULL;
        return 0;
    }

    // Calculate size: length + each block’s serialized size
    size_t total_size = sizeof(uint32_t); // For length
    size_t* block_sizes = malloc(blockchain->length * sizeof(size_t));
    if (!block_sizes) {
        *buffer = NULL;
        return 0;
    }

    for (uint32_t i = 0; i < blockchain->length; i++) {
        unsigned char* block_buf;
        block_sizes[i] = TW_Block_serialize(blockchain->blocks[i], &block_buf);
        total_size += sizeof(size_t) + block_sizes[i]; // Size prefix + block data
        free(block_buf);
    }

    *buffer = malloc(total_size);
    if (!*buffer) {
        free(block_sizes);
        return 0;
    }

    unsigned char* ptr = *buffer;
    memcpy(ptr, &blockchain->length, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    for (uint32_t i = 0; i < blockchain->length; i++) {
        unsigned char* block_buf;
        size_t block_size = TW_Block_serialize(blockchain->blocks[i], &block_buf);
        memcpy(ptr, &block_size, sizeof(size_t));
        ptr += sizeof(size_t);
        memcpy(ptr, block_buf, block_size);
        ptr += block_size;
        free(block_buf);
    }

    free(block_sizes);
    return total_size;
}

/** Computes the hash of the entire chain (based on last block hash). */
void TW_BlockChain_get_hash(TW_BlockChain* blockchain, unsigned char* hash_out) {
    if (!blockchain || !hash_out || blockchain->length == 0) {
        memset(hash_out, 0, HASH_SIZE);
        return;
    }
    TW_Block_getHash(TW_BlockChain_get_last_block(blockchain), hash_out);
}

/** Retrieves an array of all block hashes. */
void TW_BlockChain_get_block_hashes(TW_BlockChain* blockchain, unsigned char* hashes, uint32_t* count) {
    if (!blockchain || !hashes || !count) {
        if (count) *count = 0;
        return;
    }

    *count = blockchain->length;
    for (uint32_t i = 0; i < blockchain->length; i++) {
        TW_Block_getHash(blockchain->blocks[i], hashes + i * HASH_SIZE);
    }
}

TW_BlockChain* TW_BlockChain_deserialize(const unsigned char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size < sizeof(uint32_t)) return NULL;

    TW_BlockChain* blockchain = malloc(sizeof(TW_BlockChain));
    if (!blockchain) return NULL;

    const unsigned char* ptr = buffer;
    memcpy(&blockchain->length, ptr, sizeof(uint32_t));
    ptr += sizeof(uint32_t);

    if (blockchain->length > MAX_BLOCKS) {
        free(blockchain);
        return NULL;
    }

    for (uint32_t i = 0; i < blockchain->length; i++) {
        size_t block_size;
        memcpy(&block_size, ptr, sizeof(size_t));
        ptr += sizeof(size_t);
        if (ptr + block_size > buffer + buffer_size) {
            for (uint32_t j = 0; j < i; j++) TW_Block_destroy(blockchain->blocks[j]);
            free(blockchain);
            return NULL;
        }
        blockchain->blocks[i] = TW_Block_deserialize(ptr, block_size);
        if (!blockchain->blocks[i]) {
            for (uint32_t j = 0; j < i; j++) TW_Block_destroy(blockchain->blocks[j]);
            free(blockchain);
            return NULL;
        }
        ptr += block_size;
    }

    for (uint32_t i = blockchain->length; i < MAX_BLOCKS; i++) {
        blockchain->blocks[i] = NULL;
    }

    // Creator pubkey not serialized—set to zero (adjust if needed)
    memset(blockchain->creator_pubkey, 0, PUBKEY_SIZE);

    return blockchain;
}

/** Frees the blockchain and its blocks. */
void TW_BlockChain_destroy(TW_BlockChain* blockchain) {
    if (!blockchain) return;
    for (uint32_t i = 0; i < blockchain->length; i++) {
        TW_Block_destroy(blockchain->blocks[i]);
    }
    free(blockchain);
}