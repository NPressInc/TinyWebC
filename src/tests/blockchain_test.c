#include "string.h"
#include <math.h>

#include "blockchain_test.h" 
#include "packages/structures/blockChain/blockchain.h"
#include "packages/keystore/keystore.h"
#include "packages/structures/blockChain/transaction.h"
#include "packages/structures/blockChain/block.h"
#include "packages/encryption/encryption.h"
#include "packages/utils/print.h"
#include "packages/fileIO/blockchainIO.h"

#define NUM_BLOCKS 8640
#define TXNS_PER_BLOCK 1

// Helper function to create a block of transactions
static TW_Block* create_block_with_transactions(int block_index, const unsigned char* prev_hash, 
                                              const unsigned char* publicKey, const unsigned char* group_id) {
    TW_Transaction** transactions = malloc(sizeof(TW_Transaction*) * TXNS_PER_BLOCK);
    if (!transactions) return NULL;

    // Create transactions for this block
    for (int i = 0; i < TXNS_PER_BLOCK; i++) {
        // Create a unique message for each transaction
        char message[50];
        snprintf(message, sizeof(message), "Block %d, Transaction %d", block_index, i);
        
        // Encrypt the message
        EncryptedPayload* tx_payload = encrypt_payload_multi(
            (unsigned char*)message, strlen(message), 
            publicKey, 1);
            
        if (!tx_payload) {
            // Clean up previous transactions
            for (int j = 0; j < i; j++) {
                if (transactions[j]) TW_Transaction_destroy(transactions[j]);
            }
            free(transactions);
            return NULL;
        }
        
        // Create the transaction
        transactions[i] = TW_Transaction_create(
            TW_TXN_GROUP_MESSAGE, 
            publicKey, 
            publicKey, // Using the same key as recipient for testing
            1, 
            group_id, 
            tx_payload, 
            NULL);
            
        if (!transactions[i]) {
            // Clean up previous transactions and current payload
            free_encrypted_payload(tx_payload);
            for (int j = 0; j < i; j++) {
                if (transactions[j]) TW_Transaction_destroy(transactions[j]);
            }
            free(transactions);
            return NULL;
        }
    }

    // Create proposer_id
    unsigned char proposer_id[PROP_ID_SIZE] = {0};
    snprintf((char*)proposer_id, PROP_ID_SIZE-1, "block_%d", block_index);
    
    // Create the block
    TW_Block* block = TW_Block_create(block_index, transactions, TXNS_PER_BLOCK, time(NULL), prev_hash, proposer_id);
    
    // Free the transactions array (but not the transactions themselves, as they're now owned by the block)
    free(transactions);
    
    return block;
}

int blockchain_test_main(void) {
    printf("Running blockchain test...\n");

    // Starting with node functions
    if (keystore_init() == 0) {
        printf("Failed to initialize keystore\n");
        return 1;
    }

    if (keystore_load_private_key("node_key.bin", "testpass") == 0) {
        printf("Failed to load private key\n");
        return 1;
    }

    // Properly allocate memory for the keys
    unsigned char privkey[SIGN_SECRET_SIZE];
    unsigned char publicKey[SIGN_PUBKEY_SIZE];

    // Get the keys, checking for success
    if (!_keystore_get_private_key(privkey)) {
        printf("Failed to get private key\n");
        keystore_cleanup();
        return 1;
    }
    
    if (!keystore_get_public_key(publicKey)) {
        printf("Failed to get public key\n");
        keystore_cleanup();
        return 1;
    }

    printf("Loaded private key\n");

    // Create blockchain with proper parameters
    TW_BlockChain* blockchain = TW_BlockChain_create(privkey, NULL, 0);
    if (!blockchain) {
        printf("Failed to create blockchain\n");
        keystore_cleanup();
        return 1;
    }

    printf("Created blockchain\n");

    // Create group_id
    unsigned char group_id[GROUP_ID_SIZE] = {0};
    strncpy((char*)group_id, "test_group_id", GROUP_ID_SIZE-1);

    // Add blocks to the blockchain
    printf("Adding %d blocks with %d transactions each...\n", NUM_BLOCKS, TXNS_PER_BLOCK);
    
    unsigned char last_hash[HASH_SIZE];
    for (int i = 0; i < NUM_BLOCKS; i++) {
        // Get the hash of the last block
        TW_BlockChain_get_hash(blockchain, last_hash);
        
        // Create a new block
        TW_Block* new_block = create_block_with_transactions(i, last_hash, publicKey, group_id);
        if (!new_block) {
            printf("Failed to create block %d\n", i);
            TW_BlockChain_destroy(blockchain);
            keystore_cleanup();
            return 1;
        }
        
        // Add the block to the chain
        if (!TW_BlockChain_add_block(blockchain, new_block)) {
            printf("Failed to add block %d to chain\n", i);
            TW_Block_destroy(new_block);
            TW_BlockChain_destroy(blockchain);
            keystore_cleanup();
            return 1;
        }
        
        if (i % 100 == 0) {
            printf("Added block %d\n", i);
        }
    }

    // Get final blockchain hash
    TW_BlockChain_get_hash(blockchain, last_hash);
    print_hex("Final blockchain hash: ", last_hash, HASH_SIZE);

    // Test blockchain I/O
    printf("\nTesting blockchain I/O operations...\n");
    
    // Save blockchain to file
    if (!saveBlockChainToFile(blockchain)) {
        printf("Failed to save blockchain to file\n");
        TW_BlockChain_destroy(blockchain);
        keystore_cleanup();
        return 1;
    }
    printf("Successfully saved blockchain to file\n");
    
    // Read blockchain from file
    TW_BlockChain* loaded_blockchain = readBlockChainFromFile();
    if (!loaded_blockchain) {
        printf("Failed to read blockchain from file\n");
        TW_BlockChain_destroy(blockchain);
        keystore_cleanup();
        return 1;
    }
    printf("Successfully read blockchain from file\n");
    
    // Verify loaded blockchain
    printf("Verifying loaded blockchain...\n");
    
    // Check blockchain length
    if (loaded_blockchain->length != blockchain->length) {
        printf("Loaded blockchain length mismatch: expected %u, got %u\n", 
               blockchain->length, loaded_blockchain->length);
        TW_BlockChain_destroy(blockchain);
        TW_BlockChain_destroy(loaded_blockchain);
        keystore_cleanup();
        return 1;
    }
    printf("Blockchain length: %u blocks (verified)\n", loaded_blockchain->length);
    
    // Check that the hash of the loaded blockchain matches the original
    unsigned char loaded_hash[HASH_SIZE];
    TW_BlockChain_get_hash(loaded_blockchain, loaded_hash);
    if (memcmp(last_hash, loaded_hash, HASH_SIZE) != 0) {
        printf("Loaded blockchain hash mismatch\n");
        print_hex("Original hash: ", last_hash, HASH_SIZE);
        print_hex("Loaded hash  : ", loaded_hash, HASH_SIZE);
        TW_BlockChain_destroy(blockchain);
        TW_BlockChain_destroy(loaded_blockchain);
        keystore_cleanup();
        return 1;
    }
    print_hex("Loaded blockchain hash: ", loaded_hash, HASH_SIZE);
    printf("Hash verification: Passed\n");
    
    // If we got here, the I/O test passed
    printf("Blockchain I/O test: Passed\n");
    
    // Clean up I/O test resources
    TW_BlockChain_destroy(loaded_blockchain);

    // Clean up before returning
    TW_BlockChain_destroy(blockchain);
    keystore_cleanup();

    return 0;
}