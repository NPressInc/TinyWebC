#include "blockchain_test.h" 
#include "packages/structures/blockChain/blockchain.h"
#include "packages/keystore/keystore.h"
#include "packages/structures/blockChain/transaction.h"
#include "packages/structures/blockChain/block.h"
#include "packages/encryption/encryption.h"
#include "packages/utils/print.h"

int blockchain_test_main(void) {

    printf("Running blockchain test...\n");

    //Starting with node functions

    if (keystore_init() == 0){
        printf("Failed to initialize keystore\n");
        return 1;
    }

    if (keystore_load_private_key("node_key.bin", "testpass") == 0){
        printf("Failed to generate keypair\n");
        return 1;
    }

    unsigned char* privkey;
    unsigned char* publicKey;

    _keystore_get_private_key(privkey);
    keystore_get_public_key(publicKey);

    printf("Loaded private key\n");

    TW_BlockChain* blockchain = TW_BlockChain_create(privkey, NULL, 0);

    printf("Created blockchain\n");

    //Now making data that a client would produce

    TW_InternalTransaction** transactions = malloc(sizeof(TW_Transaction*) * 10);

    unsigned char* group_id = "test_group_id";

    unsigned char* raw_payload = "test-message";

    EncryptedPayload* encrypted_payload = encrypt_payload_multi(
        raw_payload, strlen(raw_payload), publicKey, 1);

    print_hex("Encrypted payload: ",encrypted_payload->ciphertext, encrypted_payload->ciphertext_len);

    for( int i = 0; i < 10; i++){
        transactions[i] = TW_Transaction_create(TW_TXN_GROUP_MESSAGE, publicKey, publicKey, 1, group_id, encrypted_payload, NULL);
        TW_Transaction_add_signature(transactions[i]);
        char txn_hash[HASH_SIZE];
        TW_Transaction_hash(transactions[i], txn_hash);
        print_hex("txt hash: ",txn_hash, HASH_SIZE);
    }

    printf("Created transactions\n");

    // now with the transactions, we can simulate what a node would do

    

    return 0;
}