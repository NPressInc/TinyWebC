#include "string.h"
#include <math.h>

#include "blockchain_test.h" 
#include "packages/structures/blockChain/blockchain.h"
#include "packages/keystore/keystore.h"
#include "packages/structures/blockChain/transaction.h"
#include "packages/structures/blockChain/block.h"
#include "packages/encryption/encryption.h"
#include "packages/utils/print.h"

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

    // Now making data that a client would produce
    TW_Transaction** transactions = malloc(sizeof(TW_Transaction*) * 10);
    if (!transactions) {
        printf("Failed to allocate memory for transactions\n");
        TW_BlockChain_destroy(blockchain);
        keystore_cleanup();
        return 1;
    }

    // Use allocated arrays for these instead of string literals
    unsigned char group_id[GROUP_ID_SIZE] = {0};
    strncpy((char*)group_id, "test_group_id", GROUP_ID_SIZE-1);

    // Create a deep copy of the encrypted payload for each transaction
    // This ensures each transaction has its own copy to free
    for (int i = 0; i < 10; i++) {
        // For each transaction, create a new encrypted payload
        const char* raw_payload = "test-message";
        size_t payload_len = strlen(raw_payload);
        
        // Encrypt with array of pointers to public keys
        EncryptedPayload* tx_payload = encrypt_payload_multi(
            (unsigned char*)raw_payload, payload_len, 
            publicKey, 1);
            
        if (!tx_payload) {
            printf("Failed to encrypt payload for transaction %d\n", i);
            // Clean up previous transactions
            for (int j = 0; j < i; j++) {
                if (transactions[j]) TW_Transaction_destroy(transactions[j]);
            }
            free(transactions);
            TW_BlockChain_destroy(blockchain);
            keystore_cleanup();
            return 1;
        }
        
        char label[50];
        snprintf(label, sizeof(label), "Encrypted payload for tx %d", i);
        print_hex(label, tx_payload->ciphertext, tx_payload->ciphertext_len);
        
        transactions[i] = TW_Transaction_create(
            TW_TXN_GROUP_MESSAGE, 
            publicKey, 
            publicKey, // Using the same key as recipient for testing
            1, 
            group_id, 
            tx_payload, 
            NULL);
            
        if (!transactions[i]) {
            printf("Failed to create transaction %d\n", i);
            // Clean up previous transactions and the current payload
            free_encrypted_payload(tx_payload);
            for (int j = 0; j < i; j++) {
                if (transactions[j]) TW_Transaction_destroy(transactions[j]);
            }
            free(transactions);
            TW_BlockChain_destroy(blockchain);
            keystore_cleanup();
            return 1;
        }
    }

    printf("Created transactions\n");

    // now with the transactions, we can simulate what a node would do
    unsigned char last_hash[HASH_SIZE];

    TW_BlockChain_get_hash(blockchain, last_hash);

    print_hex("blockchain hash: ", last_hash, HASH_SIZE);

    // Convert "test" to an unsigned char array for proposer_id
    unsigned char proposer_id[PROP_ID_SIZE] = {0};
    strncpy((char*)proposer_id, "test", PROP_ID_SIZE-1);
    
    TW_Block* test_block = TW_Block_create(1, transactions, 10, time(NULL), last_hash, proposer_id);

    TW_Block_getHash(test_block,last_hash);

    print_hex("test_block hash: ", last_hash, HASH_SIZE);

    TW_BlockChain_add_block(blockchain, test_block);

    TW_BlockChain_get_hash(blockchain, last_hash);

    print_hex("updated blockchain hash: ", last_hash, HASH_SIZE);

    // Test serialization and deserialization
    printf("\nTesting blockchain serialization and deserialization...\n");
    
    // Calculate the size needed for serialization
    size_t blockchain_size = TW_BlockChain_get_size(blockchain);
    if (blockchain_size == 0) {
        printf("Failed to calculate blockchain size\n");
        free(transactions);
        TW_BlockChain_destroy(blockchain);
        keystore_cleanup();
        return 1;
    }
    printf("Blockchain size: %zu bytes\n", blockchain_size);
    
    // Allocate memory for serialized data
    unsigned char* serialized_data = malloc(blockchain_size);
    if (!serialized_data) {
        printf("Failed to allocate memory for serialized data\n");
        free(transactions);
        TW_BlockChain_destroy(blockchain);
        keystore_cleanup();
        return 1;
    }
    
    // Pointer for tracking serialization progress
    unsigned char* ptr = serialized_data;
    
    // Serialize the blockchain
    int serialize_result = TW_BlockChain_serialize(blockchain, &ptr);
    if (serialize_result != 0) {
        printf("Failed to serialize blockchain\n");
        free(serialized_data);
        free(transactions);
        TW_BlockChain_destroy(blockchain);
        keystore_cleanup();
        return 1;
    }
    
    // Calculate actual bytes written
    size_t bytes_written = ptr - serialized_data;
    printf("Serialized blockchain: %zu bytes written\n", bytes_written);
    
    // For deserialization, use the actual written size
    if (bytes_written != blockchain_size) {
        blockchain_size = bytes_written;
    }
    
    // Deserialize the blockchain
    TW_BlockChain* deserialized = TW_BlockChain_deserialize(serialized_data, blockchain_size);
    if (!deserialized) {
        printf("Failed to deserialize blockchain\n");
        free(serialized_data);
        free(transactions);
        TW_BlockChain_destroy(blockchain);
        keystore_cleanup();
        return 1;
    }
    
    // Verify the deserialized blockchain has the same properties
    printf("Verifying deserialized blockchain...\n");
    
    // Check blockchain length
    if (deserialized->length != blockchain->length) {
        printf("Blockchain length mismatch: expected %u, got %u\n", 
               blockchain->length, deserialized->length);
        free(serialized_data);
        free(transactions);
        TW_BlockChain_destroy(blockchain);
        TW_BlockChain_destroy(deserialized);
        keystore_cleanup();
        return 1;
    }
    printf("Blockchain length: %u blocks (verified)\n", deserialized->length);
    
    // Check that the hash of the deserialized blockchain matches the original
    unsigned char deserialized_hash[HASH_SIZE];
    TW_BlockChain_get_hash(deserialized, deserialized_hash);
    if (memcmp(last_hash, deserialized_hash, HASH_SIZE) != 0) {
        printf("Blockchain hash mismatch\n");
        print_hex("Original hash   : ", last_hash, HASH_SIZE);
        print_hex("Deserialized hash: ", deserialized_hash, HASH_SIZE);
        free(serialized_data);
        free(transactions);
        TW_BlockChain_destroy(blockchain);
        TW_BlockChain_destroy(deserialized);
        keystore_cleanup();
        return 1;
    }
    print_hex("Deserialized blockchain hash: ", deserialized_hash, HASH_SIZE);
    printf("Hash verification: Passed\n");
    
    // If we got here, the test passed
    printf("Serialization/Deserialization test: Passed\n");
    
    // Clean up serialization test resources
    free(serialized_data);
    TW_BlockChain_destroy(deserialized);

    // Clean up before returning
    // Don't free the transactions here since they are owned by the block
    // and will be freed when the blockchain is destroyed
    free(transactions);
    TW_BlockChain_destroy(blockchain);
    keystore_cleanup();

    return 0;
}