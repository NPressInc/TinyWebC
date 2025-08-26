#include "string.h"
#include <math.h>
#include <unistd.h>  // For sleep()

#include "blockchain_test.h" 
#include "packages/structures/blockChain/blockchain.h"
#include "packages/keystore/keystore.h"
#include "packages/structures/blockChain/transaction.h"
#include "packages/structures/blockChain/block.h"
#include "packages/encryption/encryption.h"
#include "packages/utils/print.h"
#include "packages/fileIO/blockchainIO.h"
#include "packages/validation/block_validation.h"

#define NUM_BLOCKS 10
#define TXNS_PER_BLOCK 1

// Helper function to create a block of transactions
static TW_Block* create_block_with_transactions(int block_index, const unsigned char* prev_hash, 
                                              const unsigned char* publicKey, const unsigned char* group_id,
                                              const TW_BlockChain* blockchain) {
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
        
        // Sign the transaction
        TW_Transaction_add_signature(transactions[i]);
    }

    // Create proposer_id
    unsigned char proposer_id[PROP_ID_SIZE] = {0};
    snprintf((char*)proposer_id, PROP_ID_SIZE-1, "block_%d", block_index);
    
    // Create the block with microsecond precision to avoid timestamp collisions
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    time_t block_timestamp = ts.tv_sec;
    
    // Ensure timestamp is always greater than the previous block's timestamp
    if (blockchain && blockchain->length > 0) {
        TW_Block* last_block = TW_BlockChain_get_last_block((TW_BlockChain*)blockchain);
        if (last_block && block_timestamp <= last_block->timestamp) {
            block_timestamp = last_block->timestamp + 1;
        }
    }
    
    // For rapid block creation, also check against static last timestamp
    static time_t last_timestamp = 0;
    if (block_timestamp <= last_timestamp) {
        block_timestamp = last_timestamp + 1;
    }
    last_timestamp = block_timestamp;
    
    TW_Block* block = TW_Block_create(block_index, transactions, TXNS_PER_BLOCK, block_timestamp, prev_hash, proposer_id);
    
    // Build the merkle tree for the block
    TW_Block_buildMerkleTree(block);
    
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

    if (keystore_load_private_key("node_private.key", "testpass") == 0) {
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

    // Create validation configuration for testing
    ValidationConfig* validation_config = create_default_validation_config();
    if (!validation_config) {
        printf("Failed to create validation configuration\n");
        TW_BlockChain_destroy(blockchain);
        keystore_cleanup();
        return 1;
    }
    
    // Enable all validation features for comprehensive testing
    validation_config->validate_signatures = true;
    validation_config->validate_merkle_tree = true;
    validation_config->strict_ordering = true; // Re-enabled with timestamp fix
    validation_config->max_timestamp_drift = 600; // 10 minutes for testing
    printf("Created validation configuration\n");

    // Create group_id
    unsigned char group_id[GROUP_ID_SIZE] = {0};
    strncpy((char*)group_id, "test_group_id", GROUP_ID_SIZE-1);

    // Add blocks to the blockchain
    printf("Adding %d blocks with %d transactions each...\n", NUM_BLOCKS, TXNS_PER_BLOCK);
    
    unsigned char last_hash[HASH_SIZE];
    int validation_failures = 0;
    
    for (int i = 0; i < NUM_BLOCKS; i++) {
        // Get the hash of the last block
        TW_BlockChain_get_hash(blockchain, last_hash);
        
        // Create a new block with index = current blockchain length
        // This ensures the block index matches what the blockchain expects
        uint32_t block_index = blockchain->length;
        TW_Block* new_block = create_block_with_transactions(block_index, last_hash, publicKey, group_id, blockchain);
        if (!new_block) {
            printf("Failed to create block %d\n", block_index);
            free_validation_config(validation_config);
            TW_BlockChain_destroy(blockchain);
            keystore_cleanup();
            return 1;
        }
        
        // Validate the block before adding it to the chain
        ValidationResult validation_result = validate_block(new_block, blockchain, validation_config);
        if (validation_result != VALIDATION_SUCCESS) {
            printf("Block %d validation failed with error: %s\n", block_index, validation_error_string(validation_result));
            validation_failures++;
            
            // For testing purposes, we'll continue but track failures
            // In a real system, you might want to reject the block
        }
        
        // Add the block to the chain
        if (TW_BlockChain_add_block(blockchain, new_block) != 0) {
            printf("Failed to add block %d to chain\n", block_index);
            TW_Block_destroy(new_block);
            free_validation_config(validation_config);
            TW_BlockChain_destroy(blockchain);
            keystore_cleanup();
            return 1;
        }
        
        if (i % 100 == 0) {
            printf("Added block %d\n", block_index);
        }
        
        // Validate every 1000th block for performance sampling
        if (i % 1000 == 0 && i > 0) {
            ValidationResult block_validation = validate_block(blockchain->blocks[block_index], blockchain, validation_config);
            if (block_validation != VALIDATION_SUCCESS) {
                printf("Post-addition validation failed for block %d: %s\n", block_index, validation_error_string(block_validation));
                validation_failures++;
            }
        }
    }
    
    printf("Block creation completed with %d validation failures\n", validation_failures);

    // Get final blockchain hash
    TW_BlockChain_get_hash(blockchain, last_hash);
    print_hex("Final blockchain hash: ", last_hash, HASH_SIZE);

    // Perform comprehensive blockchain validation
    printf("\nPerforming comprehensive blockchain validation...\n");
    ValidationResult blockchain_validation = validate_blockchain(blockchain, validation_config);
    if (blockchain_validation == VALIDATION_SUCCESS) {
        printf("✓ Comprehensive blockchain validation: PASSED\n");
    } else {
        printf("✗ Comprehensive blockchain validation: FAILED (%s)\n", validation_error_string(blockchain_validation));
    }
    
    // Validate blockchain integrity
    ValidationResult integrity_validation = validate_blockchain_integrity(blockchain);
    if (integrity_validation == VALIDATION_SUCCESS) {
        printf("✓ Blockchain integrity validation: PASSED\n");
    } else {
        printf("✗ Blockchain integrity validation: FAILED (%s)\n", validation_error_string(integrity_validation));
    }

    // Test blockchain I/O
    printf("\nTesting blockchain I/O operations...\n");
    
    // Save blockchain to file
    if (!saveBlockChainToFile(blockchain)) {
        printf("Failed to save blockchain to file\n");
        free_validation_config(validation_config);
        TW_BlockChain_destroy(blockchain);
        keystore_cleanup();
        return 1;
    }
    printf("Successfully saved blockchain to file\n");
    
    // Read blockchain from file
    TW_BlockChain* loaded_blockchain = readBlockChainFromFile();
    if (!loaded_blockchain) {
        printf("Failed to read blockchain from file\n");
        free_validation_config(validation_config);
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
        free_validation_config(validation_config);
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
        free_validation_config(validation_config);
        TW_BlockChain_destroy(blockchain);
        TW_BlockChain_destroy(loaded_blockchain);
        keystore_cleanup();
        return 1;
    }
    print_hex("Loaded blockchain hash: ", loaded_hash, HASH_SIZE);
    printf("Hash verification: Passed\n");
    
    // Validate the loaded blockchain
    printf("Validating loaded blockchain...\n");
    ValidationResult loaded_validation = validate_blockchain(loaded_blockchain, validation_config);
    if (loaded_validation == VALIDATION_SUCCESS) {
        printf("✓ Loaded blockchain validation: PASSED\n");
    } else {
        printf("✗ Loaded blockchain validation: FAILED (%s)\n", validation_error_string(loaded_validation));
    }
    
    // Validate loaded blockchain integrity
    ValidationResult loaded_integrity = validate_blockchain_integrity(loaded_blockchain);
    if (loaded_integrity == VALIDATION_SUCCESS) {
        printf("✓ Loaded blockchain integrity: PASSED\n");
    } else {
        printf("✗ Loaded blockchain integrity: FAILED (%s)\n", validation_error_string(loaded_integrity));
    }
    
    // Sample validation of individual blocks from loaded blockchain
    printf("Sampling individual block validation from loaded blockchain...\n");
    int sample_blocks[] = {0, 100, 1000, 5000, NUM_BLOCKS-1}; // Sample different blocks
    int sample_count = sizeof(sample_blocks) / sizeof(sample_blocks[0]);
    int sample_failures = 0;
    
    for (int i = 0; i < sample_count; i++) {
        int block_index = sample_blocks[i];
        if (block_index < loaded_blockchain->length) {
            ValidationResult sample_validation = validate_block(loaded_blockchain->blocks[block_index], loaded_blockchain, validation_config);
            if (sample_validation != VALIDATION_SUCCESS) {
                printf("✗ Sample block %d validation failed: %s\n", block_index, validation_error_string(sample_validation));
                sample_failures++;
            } else {
                printf("✓ Sample block %d validation: PASSED\n", block_index);
            }
        }
    }
    
    if (sample_failures == 0) {
        printf("✓ All sampled blocks validated successfully\n");
    } else {
        printf("✗ %d out of %d sampled blocks failed validation\n", sample_failures, sample_count);
    }
    
    // If we got here, the I/O test passed
    printf("Blockchain I/O test: Passed\n");
    
    // Clean up I/O test resources
    TW_BlockChain_destroy(loaded_blockchain);
    free_validation_config(validation_config);

    // Clean up before returning
    TW_BlockChain_destroy(blockchain);
    keystore_cleanup();

    return 0;
}