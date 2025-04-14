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

    const unsigned char* recipient_pubkeys[1];
    recipient_pubkeys[0] = publicKey;

    const char* raw_payload = "test-message";
    size_t payload_len = strlen(raw_payload);

    // Encrypt with array of pointers to public keys
    EncryptedPayload* encrypted_payload = encrypt_payload_multi(
        (unsigned char*)raw_payload, payload_len, 
        recipient_pubkeys, 1);

    if (!encrypted_payload) {
        printf("Failed to encrypt payload\n");
        free(transactions);
        TW_BlockChain_destroy(blockchain);
        keystore_cleanup();
        return 1;
    }

    print_hex("Encrypted payload: ", encrypted_payload->ciphertext, encrypted_payload->ciphertext_len);

    for (int i = 0; i < 10; i++) {
        transactions[i] = TW_Transaction_create(
            TW_TXN_GROUP_MESSAGE, 
            publicKey, 
            publicKey, // Using the same key as recipient for testing
            1, 
            group_id, 
            encrypted_payload, 
            NULL);
            
        if (!transactions[i]) {
            printf("Failed to create transaction %d\n", i);
            // Clean up previous transactions
            for (int j = 0; j < i; j++) {
                if (transactions[j]) TW_Transaction_destroy(transactions[j]);
            }
            free(transactions);
            free_encrypted_payload(encrypted_payload);
            TW_BlockChain_destroy(blockchain);
            keystore_cleanup();
            return 1;
        }
    }

    printf("Created transactions\n");

    // now with the transactions, we can simulate what a node would do
    // Clean up before returning
    for (int i = 0; i < 10; i++) {
        if (transactions[i]) TW_Transaction_destroy(transactions[i]);
    }
    free(transactions);
    free_encrypted_payload(encrypted_payload);
    TW_BlockChain_destroy(blockchain);
    keystore_cleanup();

    return 0;
}