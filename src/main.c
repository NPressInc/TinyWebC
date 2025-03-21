#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packages/structures/blockChain/block.h"
#include "packages/structures/blockChain/transaction.h"
#include "packages/structures/blockChain/merkleTree.h"
#include "packages/structures/blockChain/blockchain.h"

int main() {
    unsigned char creator_pubkey[PUBKEY_SIZE] = "creator123456789012345678901234";
    unsigned char sender_pubkey[PUBKEY_SIZE] = "sender123456789012345678901234";
    unsigned char recip_pubkey[PUBKEY_SIZE] = "recipient12345678901234567890123";
    unsigned char signature[SIG_SIZE] = {0};

    TW_BlockChain* chain = TW_BlockChain_create(creator_pubkey, NULL, 0);
    if (!chain) {
        printf("Failed to create blockchain\n");
        return 1;
    }
    printf("Initial length (with genesis): %u\n", chain->length);

    TW_Block* genesis = TW_BlockChain_get_last_block(chain);
    unsigned char prev_hash[HASH_SIZE];
    TW_Block_getHash(genesis, prev_hash);

    char* message_base = "Message %d";
    TW_Block* blocks[3];
    unsigned char proposer_id[PROP_ID_SIZE] = "proposer123";

    for (int i = 0; i < 3; i++) {
        TW_BlockEntry entries[43]; // Reduced to 1 per block
        char msg[32];
        snprintf(msg, sizeof(msg), "Message %d-0", i);
        TW_Transaction* txn = TW_Transaction_create(TW_TXN_MESSAGE, sender_pubkey, recip_pubkey, 1, 
                                                   NULL, (unsigned char*)msg, strlen(msg), signature);
        if (!txn) {
            printf("Failed to create transaction %d-0\n", i);
            TW_BlockChain_destroy(chain);
            return 1;
        }
        entries[0].txn = *txn;
        TW_Transaction_destroy(txn);

        blocks[i] = TW_Block_create(i + 1, entries, 1, 0, time(NULL), prev_hash, proposer_id, NULL);
        if (!blocks[i] || !TW_BlockChain_add_block(chain, blocks[i])) {
            printf("Failed to add block %d\n", i);
            TW_BlockChain_destroy(chain);
            return 1;
        }

        TW_Block_getHash(blocks[i], prev_hash);
    }

    if (chain->length != 4) {
        printf("Length mismatch: expected 4, got %u\n", chain->length);
        TW_BlockChain_destroy(chain);
        return 1;
    }
    printf("Blockchain length: %u (correct)\n", chain->length);

    unsigned char* serialized;
    size_t serialized_size = TW_BlockChain_serialize(chain, &serialized);
    printf("Serialized blockchain size: %zu bytes\n", serialized_size);

    TW_BlockChain* deserialized_chain = TW_BlockChain_deserialize(serialized, serialized_size);
    if (!deserialized_chain) {
        printf("Failed to deserialize blockchain\n");
        free(serialized);
        TW_BlockChain_destroy(chain);
        return 1;
    }

    printf("Original blocks before hashing:\n");
    for (uint32_t i = 0; i < chain->length; i++) {
        TW_Block* b = chain->blocks[i];
        printf("Block %u (ptr: %p) - index: %d, timestamp: %ld, prev_hash: ", 
               i, (void*)b, b->index, b->timestamp);
        for (int j = 0; j < HASH_SIZE; j++) printf("%02x", b->previous_hash[j]);
        printf(", proposer: %s\n", b->proposer_id);
    }

    printf("Deserialized blocks before hashing:\n");
    for (uint32_t i = 0; i < deserialized_chain->length; i++) {
        TW_Block* b = deserialized_chain->blocks[i];
        printf("Block %u (ptr: %p) - index: %d, timestamp: %ld, prev_hash: ", 
               i, (void*)b, b->index, b->timestamp);
        for (int j = 0; j < HASH_SIZE; j++) printf("%02x", b->previous_hash[j]);
        printf(", proposer: %s\n", b->proposer_id);
    }

    for (uint32_t i = 0; i < deserialized_chain->length; i++) {
        TW_Block* b = deserialized_chain->blocks[i];
        const unsigned char* root = TW_MerkleTree_get_rootHash(b->merkle_tree);
        printf("Block %u merkle_root: ", i);
        for (int j = 0; j < HASH_SIZE; j++) printf("%02x", root[j]);
        printf("\n");
    }

    unsigned char orig_hashes[4 * HASH_SIZE];
    unsigned char deser_hashes[4 * HASH_SIZE];
    uint32_t orig_count, deser_count;
    TW_BlockChain_get_block_hashes(chain, &orig_hashes, &orig_count); // Pass array directly
    TW_BlockChain_get_block_hashes(deserialized_chain, &deser_hashes, &deser_count);

    printf("Original hash count: %u, Deserialized hash count: %u\n", orig_count, deser_count);

    printf("Original block hashes:\n");
    for (uint32_t i = 0; i < orig_count; i++) {
        printf("Block %u: ", i);
        for (int j = 0; j < HASH_SIZE; j++) printf("%02x", orig_hashes[i * HASH_SIZE + j]);
        printf("\n");
    }

    printf("Deserialized block hashes:\n");
    for (uint32_t i = 0; i < deser_count; i++) {
        printf("Block %u: ", i);
        for (int j = 0; j < HASH_SIZE; j++) printf("%02x", deser_hashes[i * HASH_SIZE + j]);
        printf("\n");
    }

    if (orig_count != deser_count || memcmp(orig_hashes, deser_hashes, orig_count * HASH_SIZE) != 0) {
        printf("Block hashes mismatch after deserialization\n");
        free(serialized);
        TW_BlockChain_destroy(chain);
        TW_BlockChain_destroy(deserialized_chain);
        return 1;
    }

    printf("Block hashes match after deserialization\n");

    free(serialized);
    TW_BlockChain_destroy(chain);
    TW_BlockChain_destroy(deserialized_chain);

    printf("Test completed successfully\n");
    return 0;
}