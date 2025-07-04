#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sodium.h>
#include <cjson/cJSON.h>
#include "packages/initialization/init.h"
#include "packages/sql/database.h"
#include "packages/encryption/encryption.h"
#include "packages/keystore/keystore.h"
#include "tests/init_network_test.h"

#define TEST_KEYSTORE_PATH "test_state/keys/"
#define TEST_BLOCKCHAIN_PATH "test_state/blockchain/"
#define TEST_DB_PATH "test_state/blockchain/test_blockchain.db"
#define TEST_PASSPHRASE "testpass"
#define TEST_BASE_PORT 9000
#define TEST_NODE_COUNT 2
#define TEST_USER_COUNT 4

void cleanup_test_dirs() {
    // Remove test files and directories (simple, not recursive)
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s %s", TEST_KEYSTORE_PATH, TEST_BLOCKCHAIN_PATH);
    system(cmd);
    
    // Also clean up any database files
    unlink(TEST_DB_PATH);
    unlink("test_state/blockchain/test_blockchain.db-wal");
    unlink("test_state/blockchain/test_blockchain.db-shm");
}

// Helper function to verify database was created and contains expected data
int verify_database_initialization(void) {
    printf("Verifying database initialization...\n");
    
    // Initialize database connection
    if (db_init(TEST_DB_PATH) != 0) {
        printf("❌ Failed to initialize database connection for verification\n");
        return 0;
    }
    
    // Check that database file exists
    FILE* db_file = fopen(TEST_DB_PATH, "r");
    if (!db_file) {
        printf("❌ Database file does not exist: %s\n", TEST_DB_PATH);
        db_close();
        return 0;
    }
    fclose(db_file);
    printf("✅ Database file exists: %s\n", TEST_DB_PATH);
    
    // Check blockchain info
    uint32_t block_count = 0;
    if (db_get_block_count(&block_count) != 0) {
        printf("❌ Failed to get block count from database\n");
        db_close();
        return 0;
    }
    
    if (block_count == 0) {
        printf("❌ Database contains no blocks\n");
        db_close();
        return 0;
    }
    printf("✅ Database contains %u blocks\n", block_count);
    
    // Check transaction count
    uint64_t transaction_count = 0;
    if (db_get_transaction_count(&transaction_count) != 0) {
        printf("❌ Failed to get transaction count from database\n");
        db_close();
        return 0;
    }
    
    if (transaction_count == 0) {
        printf("❌ Database contains no transactions\n");
        db_close();
        return 0;
    }
    printf("✅ Database contains %llu transactions\n", (unsigned long long)transaction_count);
    
    // Verify we have the expected number of transactions
    // Should be: users (4) + roles (4) + peers (2) + system (1) + filter (1) = 12 transactions
    uint64_t expected_transactions = TEST_USER_COUNT * 2 + TEST_NODE_COUNT + 2;
    if (transaction_count != expected_transactions) {
        printf("❌ Expected %llu transactions, found %llu\n", 
               (unsigned long long)expected_transactions, (unsigned long long)transaction_count);
        db_close();
        return 0;
    }
    printf("✅ Database contains expected number of transactions: %llu\n", (unsigned long long)transaction_count);
    
    // Check that we can query transactions by type
    TransactionRecord* user_transactions = NULL;
    size_t user_txn_count = 0;
    if (db_get_transactions_by_type(TW_TXN_USER_REGISTRATION, &user_transactions, &user_txn_count) != 0) {
        printf("❌ Failed to query user registration transactions\n");
        db_close();
        return 0;
    }
    
    if (user_txn_count != TEST_USER_COUNT) {
        printf("❌ Expected %u user registration transactions, found %zu\n", TEST_USER_COUNT, user_txn_count);
        db_free_transaction_records(user_transactions, user_txn_count);
        db_close();
        return 0;
    }
    printf("✅ Database contains %zu user registration transactions\n", user_txn_count);
    
    // Verify transaction recipients
    if (user_txn_count > 0) {
        char** recipients = NULL;
        size_t recipient_count = 0;
        if (db_get_recipients_for_transaction(user_transactions[0].transaction_id, &recipients, &recipient_count) != 0) {
            printf("❌ Failed to get recipients for first user transaction\n");
            db_free_transaction_records(user_transactions, user_txn_count);
            db_close();
            return 0;
        }
        
        size_t expected_recipients = TEST_NODE_COUNT + TEST_USER_COUNT;
        if (recipient_count != expected_recipients) {
            printf("❌ Expected %zu recipients for transaction, found %zu\n", expected_recipients, recipient_count);
            db_free_recipients(recipients, recipient_count);
            db_free_transaction_records(user_transactions, user_txn_count);
            db_close();
            return 0;
        }
        printf("✅ Transaction has expected number of recipients: %zu\n", recipient_count);
        
        db_free_recipients(recipients, recipient_count);
    }
    
    db_free_transaction_records(user_transactions, user_txn_count);
    db_close();
    
    printf("✅ Database verification completed successfully\n");
    return 1;
}

// Helper function to load Ed25519 private key and derive X25519 public key
unsigned char* load_key_and_get_x25519_pubkey(const char* key_path) {
    FILE* f = fopen(key_path, "rb");
    if (!f) {
        printf("Failed to open key file: %s\n", key_path);
        return NULL;
    }
    
    unsigned char ed25519_private[crypto_sign_SECRETKEYBYTES];
    if (fread(ed25519_private, 1, crypto_sign_SECRETKEYBYTES, f) != crypto_sign_SECRETKEYBYTES) {
        printf("Failed to read complete private key from: %s\n", key_path);
        fclose(f);
        return NULL;
    }
    fclose(f);
    
    // Extract Ed25519 public key from private key
    unsigned char ed25519_public[crypto_sign_PUBLICKEYBYTES];
    memcpy(ed25519_public, ed25519_private + crypto_sign_SECRETKEYBYTES - crypto_sign_PUBLICKEYBYTES, crypto_sign_PUBLICKEYBYTES);
    
    // Convert to X25519 public key
    unsigned char* x25519_public = malloc(crypto_box_PUBLICKEYBYTES);
    if (!x25519_public) {
        printf("Failed to allocate memory for X25519 public key\n");
        return NULL;
    }
    
    if (crypto_sign_ed25519_pk_to_curve25519(x25519_public, ed25519_public) != 0) {
        printf("Failed to convert Ed25519 to X25519 public key\n");
        free(x25519_public);
        return NULL;
    }
    
    return x25519_public;
}

// Helper function to convert X25519 private key and decrypt transaction
int test_transaction_decryption_with_key(cJSON* transaction, const char* key_path, const char* key_name) {
    // Load the Ed25519 private key
    FILE* f = fopen(key_path, "rb");
    if (!f) {
        printf("Failed to open key file: %s\n", key_path);
        return 0;
    }
    
    unsigned char ed25519_private[crypto_sign_SECRETKEYBYTES];
    if (fread(ed25519_private, 1, crypto_sign_SECRETKEYBYTES, f) != crypto_sign_SECRETKEYBYTES) {
        printf("Failed to read complete private key from: %s\n", key_path);
        fclose(f);
        return 0;
    }
    fclose(f);
    
    // Convert Ed25519 private key to X25519 private key
    unsigned char x25519_private[crypto_box_SECRETKEYBYTES];
    if (crypto_sign_ed25519_sk_to_curve25519(x25519_private, ed25519_private) != 0) {
        printf("Failed to convert Ed25519 to X25519 private key\n");
        return 0;
    }
    
    // Get X25519 public key for recipient matching
    unsigned char* x25519_public = load_key_and_get_x25519_pubkey(key_path);
    if (!x25519_public) {
        printf("Failed to derive X25519 public key for %s\n", key_name);
        return 0;
    }
    
    // Convert X25519 public key to hex string for comparison
    char public_key_hex[65];
    for (int i = 0; i < crypto_box_PUBLICKEYBYTES; i++) {
        sprintf(&public_key_hex[i * 2], "%02x", x25519_public[i]);
    }
    public_key_hex[64] = '\0';
    
    // Get the recipients array from transaction
    cJSON* recipients = cJSON_GetObjectItem(transaction, "recipients");
    if (!recipients || !cJSON_IsArray(recipients)) {
        printf("Transaction missing recipients array\n");
        free(x25519_public);
        return 0;
    }
    
    // Find our public key in the recipients list
    int recipient_index = -1;
    int num_recipients = cJSON_GetArraySize(recipients);
    for (int i = 0; i < num_recipients; i++) {
        cJSON* recipient = cJSON_GetArrayItem(recipients, i);
        if (cJSON_IsString(recipient)) {
            if (strcmp(recipient->valuestring, public_key_hex) == 0) {
                recipient_index = i;
                break;
            }
        }
    }
    
    if (recipient_index == -1) {
        printf("Key %s not found in recipients list\n", key_name);
        free(x25519_public);
        return 0;
    }
    
    // Get the payload
    cJSON* payload = cJSON_GetObjectItem(transaction, "payload");
    if (!payload) {
        printf("Transaction missing payload\n");
        free(x25519_public);
        return 0;
    }
    
    // Extract encrypted payload components
    cJSON* ephemeral_pubkey_json = cJSON_GetObjectItem(payload, "ephemeral_pubkey");
    cJSON* encrypted_keys_json = cJSON_GetObjectItem(payload, "encrypted_keys");
    cJSON* nonce_json = cJSON_GetObjectItem(payload, "nonce");
    cJSON* ciphertext_json = cJSON_GetObjectItem(payload, "ciphertext");
    
    if (!ephemeral_pubkey_json || !encrypted_keys_json || !nonce_json || !ciphertext_json) {
        printf("Transaction payload missing required fields\n");
        free(x25519_public);
        return 0;
    }
    
    // Convert hex strings to binary
    unsigned char ephemeral_pubkey[crypto_box_PUBLICKEYBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    
    // Convert ephemeral public key
    const char* ephemeral_hex = ephemeral_pubkey_json->valuestring;
    for (int i = 0; i < crypto_box_PUBLICKEYBYTES; i++) {
        sscanf(&ephemeral_hex[i * 2], "%2hhx", &ephemeral_pubkey[i]);
    }
    
    // Convert main nonce
    const char* nonce_hex = nonce_json->valuestring;
    for (int i = 0; i < crypto_secretbox_NONCEBYTES; i++) {
        sscanf(&nonce_hex[i * 2], "%2hhx", &nonce[i]);
    }
    
    // Get our encrypted key
    cJSON* encrypted_key_item = cJSON_GetArrayItem(encrypted_keys_json, recipient_index);
    if (!encrypted_key_item) {
        printf("Missing encrypted key for recipient index %d\n", recipient_index);
        free(x25519_public);
        return 0;
    }
    
    cJSON* encrypted_key_json = cJSON_GetObjectItem(encrypted_key_item, "encrypted_key");
    cJSON* key_nonce_json = cJSON_GetObjectItem(encrypted_key_item, "key_nonce");
    
    if (!encrypted_key_json || !key_nonce_json) {
        printf("Missing encrypted_key or key_nonce\n");
        free(x25519_public);
        return 0;
    }
    
    // Convert encrypted key and key nonce
    unsigned char encrypted_key[crypto_secretbox_KEYBYTES + crypto_box_MACBYTES];
    unsigned char key_nonce[crypto_box_NONCEBYTES];
    
    const char* encrypted_key_hex = encrypted_key_json->valuestring;
    for (int i = 0; i < (crypto_secretbox_KEYBYTES + crypto_box_MACBYTES); i++) {
        sscanf(&encrypted_key_hex[i * 2], "%2hhx", &encrypted_key[i]);
    }
    
    const char* key_nonce_hex = key_nonce_json->valuestring;
    for (int i = 0; i < crypto_box_NONCEBYTES; i++) {
        sscanf(&key_nonce_hex[i * 2], "%2hhx", &key_nonce[i]);
    }
    
    // Decrypt the symmetric key
    unsigned char symmetric_key[crypto_secretbox_KEYBYTES];
    if (crypto_box_open_easy(symmetric_key, encrypted_key, crypto_secretbox_KEYBYTES + crypto_box_MACBYTES,
                             key_nonce, ephemeral_pubkey, x25519_private) != 0) {
        printf("Failed to decrypt symmetric key for %s\n", key_name);
        free(x25519_public);
        return 0;
    }
    
    // Get ciphertext length and convert ciphertext
    cJSON* ciphertext_len_json = cJSON_GetObjectItem(payload, "ciphertext_len");
    if (!ciphertext_len_json) {
        printf("Missing ciphertext_len\n");
        free(x25519_public);
        return 0;
    }
    
    int ciphertext_len = ciphertext_len_json->valueint;
    unsigned char* ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        printf("Failed to allocate memory for ciphertext\n");
        free(x25519_public);
        return 0;
    }
    
    const char* ciphertext_hex = ciphertext_json->valuestring;
    for (int i = 0; i < ciphertext_len; i++) {
        sscanf(&ciphertext_hex[i * 2], "%2hhx", &ciphertext[i]);
    }
    
    // Decrypt the content
    unsigned char* decrypted_content = malloc(ciphertext_len - crypto_secretbox_MACBYTES);
    if (!decrypted_content) {
        printf("Failed to allocate memory for decrypted content\n");
        free(ciphertext);
        free(x25519_public);
        return 0;
    }
    
    if (crypto_secretbox_open_easy(decrypted_content, ciphertext, ciphertext_len, nonce, symmetric_key) != 0) {
        printf("Failed to decrypt content for %s\n", key_name);
        free(decrypted_content);
        free(ciphertext);
        free(x25519_public);
        return 0;
    }
    
    printf("✅ Successfully decrypted transaction for %s\n", key_name);
    
    // Cleanup
    free(decrypted_content);
    free(ciphertext);
    free(x25519_public);
    
    return 1;
}

int test_multi_recipient_initialization(void) {
    printf("Testing multi-recipient initialization...\n");
    
    // Initialize sodium
    if (sodium_init() < 0) {
        printf("Failed to initialize sodium\n");
        return 0;
    }
    
    // Load the blockchain JSON file
    FILE* f = fopen("test_state/blockchain/blockchain.json", "r");
    if (!f) {
        printf("Failed to open blockchain.json\n");
        return 0;
    }
    
    // Read the entire file
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* json_string = malloc(file_size + 1);
    if (!json_string) {
        printf("Failed to allocate memory for JSON\n");
        fclose(f);
        return 0;
    }
    
    fread(json_string, 1, file_size, f);
    json_string[file_size] = '\0';
    fclose(f);
    
    // Parse JSON
    cJSON* blockchain_json = cJSON_Parse(json_string);
    free(json_string);
    
    if (!blockchain_json) {
        printf("Failed to parse blockchain JSON\n");
        return 0;
    }
    
    // Get the blocks array
    cJSON* blocks = cJSON_GetObjectItem(blockchain_json, "blocks");
    if (!blocks || !cJSON_IsArray(blocks)) {
        printf("Missing blocks array in blockchain\n");
        cJSON_Delete(blockchain_json);
        return 0;
    }
    
    // Get the first block (initialization block)
    cJSON* first_block = cJSON_GetArrayItem(blocks, 0);
    if (!first_block) {
        printf("No blocks found in blockchain\n");
        cJSON_Delete(blockchain_json);
        return 0;
    }
    
    // Get the transactions array from the first block
    cJSON* transactions = cJSON_GetObjectItem(first_block, "transactions");
    if (!transactions || !cJSON_IsArray(transactions)) {
        printf("Missing transactions array in first block\n");
        cJSON_Delete(blockchain_json);
        return 0;
    }
    
    // Get the first transaction for testing
    cJSON* first_transaction = cJSON_GetArrayItem(transactions, 0);
    if (!first_transaction) {
        printf("No transactions found in first block\n");
        cJSON_Delete(blockchain_json);
        return 0;
    }
    
    // Verify the transaction has the expected number of recipients
    cJSON* recipients = cJSON_GetObjectItem(first_transaction, "recipients");
    if (!recipients || !cJSON_IsArray(recipients)) {
        printf("Transaction missing recipients array\n");
        cJSON_Delete(blockchain_json);
        return 0;
    }
    
    int num_recipients = cJSON_GetArraySize(recipients);
    int expected_recipients = TEST_NODE_COUNT + TEST_USER_COUNT; // 2 nodes + 4 users = 6
    
    if (num_recipients != expected_recipients) {
        printf("❌ Expected %d recipients, found %d\n", expected_recipients, num_recipients);
        cJSON_Delete(blockchain_json);
        return 0;
    }
    
    printf("✅ Transaction has correct number of recipients: %d\n", num_recipients);
    
    // Test decryption with each key
    int successful_decryptions = 0;
    
    // Test node keys
    for (int i = 0; i < TEST_NODE_COUNT; i++) {
        char key_path[256];
        snprintf(key_path, sizeof(key_path), "%snode_%d_key.bin", TEST_KEYSTORE_PATH, i);
        
        char key_name[64];
        snprintf(key_name, sizeof(key_name), "Node %d", i);
        
        if (test_transaction_decryption_with_key(first_transaction, key_path, key_name)) {
            successful_decryptions++;
        }
    }
    
    // Test user keys
    for (int i = 0; i < TEST_USER_COUNT; i++) {
        char key_path[256];
        snprintf(key_path, sizeof(key_path), "%suser_%d_key.bin", TEST_KEYSTORE_PATH, i);
        
        char key_name[64];
        snprintf(key_name, sizeof(key_name), "User %d", i);
        
        if (test_transaction_decryption_with_key(first_transaction, key_path, key_name)) {
            successful_decryptions++;
        }
    }
    
    cJSON_Delete(blockchain_json);
    
    if (successful_decryptions == expected_recipients) {
        printf("✅ Multi-recipient test PASSED: All %d keys successfully decrypted the transaction\n", successful_decryptions);
        return 1;
    } else {
        printf("❌ Multi-recipient test FAILED: Only %d out of %d keys successfully decrypted\n", successful_decryptions, expected_recipients);
        return 0;
    }
}

int init_network_test_main(void) {
    cleanup_test_dirs();
    mkdir("test_state", 0700);
    mkdir(TEST_KEYSTORE_PATH, 0700);
    mkdir(TEST_BLOCKCHAIN_PATH, 0700);

    // Initialize test database
    if (db_init(TEST_DB_PATH) != 0) {
        printf("Failed to initialize test database\n");
        return 1;
    }

    InitConfig config = {
        .keystore_path = TEST_KEYSTORE_PATH,
        .blockchain_path = TEST_BLOCKCHAIN_PATH,
        .database_path = TEST_DB_PATH,
        .passphrase = TEST_PASSPHRASE,
        .base_port = TEST_BASE_PORT,
        .node_count = TEST_NODE_COUNT,
        .user_count = TEST_USER_COUNT
    };

    // Close the database connection before running initialization
    // (since init.c will handle database initialization internally)
    db_close();

    int result = initialize_network(&config);
    assert(result == 0 && "Network initialization should succeed");

    // Check that binary blockchain file exists
    FILE* f = fopen("test_state/blockchain/blockchain.dat", "rb");
    assert(f && "Binary blockchain file should exist after initialization");
    if (f) fclose(f);

    // Check that JSON blockchain file exists
    FILE* json_f = fopen("test_state/blockchain/blockchain.json", "r");
    assert(json_f && "JSON blockchain file should exist after initialization");
    
    if (json_f) {
        // Read a bit of the JSON file to verify it contains data
        char buffer[256];
        size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, json_f);
        buffer[bytes_read] = '\0';
        fclose(json_f);
        
        // Basic verification that it looks like JSON
        assert(bytes_read > 0 && "JSON file should contain data");
        assert(strstr(buffer, "{") != NULL && "JSON file should contain JSON data");
        
        printf("JSON blockchain file verified: %zu bytes read\n", bytes_read);
        printf("JSON preview: %.100s%s\n", buffer, bytes_read > 100 ? "..." : "");
    }

    // Check that SQLite database file exists
    FILE* db_f = fopen(TEST_DB_PATH, "rb");
    assert(db_f && "SQLite database file should exist after initialization");
    if (db_f) {
        fclose(db_f);
        printf("SQLite database file verified: %s\n", TEST_DB_PATH);
    }

    // Verify database initialization and content
    if (!verify_database_initialization()) {
        printf("Database verification failed\n");
        return 1;
    }
    
    // Test multi-recipient encryption
    if (!test_multi_recipient_initialization()) {
        printf("Multi-recipient initialization test failed\n");
        return 1;
    }

    printf("init_network_test: PASSED\n");
    
    return 0;
} 