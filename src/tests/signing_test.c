#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <assert.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <errno.h>
#include "packages/keystore/keystore.h"
#include "packages/utils/print.h"
#include "packages/signing/signing.h"

static void ensure_directory(const char* path) {
    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
        fprintf(stderr, "Failed to create directory %s: %s\n", path, strerror(errno));
    }
}

int signing_test_main(void) {
    int tests_passed = 0;
    int tests_failed = 0;
    const char* test_message = "Hello, this is a test message for signing!";
    const size_t message_len = strlen(test_message);

    printf("Starting signing tests...\n");

    // Initialize keystore
    if (keystore_init() == 0) {
        printf("Failed to initialize keystore\n");
        return 1;
    }

    const char* key_dir = "test_state/keys";
    const char* key_path = "test_state/keys/node_0_private.key";

    unsigned char raw_private_key[SIGN_SECRET_SIZE];
    size_t bytes_read = 0;

    FILE* key_file = fopen(key_path, "rb");
    if (!key_file) {
        // Generate and persist a test key if it doesn't exist yet
        ensure_directory("test_state");
        ensure_directory(key_dir);

        if (!keystore_generate_keypair()) {
            printf("Failed to generate keypair for signing test\n");
            keystore_cleanup();
            return 1;
        }

        if (!_keystore_get_private_key(raw_private_key)) {
            printf("Failed to extract generated private key\n");
            keystore_cleanup();
            return 1;
        }

        key_file = fopen(key_path, "wb");
        if (!key_file) {
            printf("Failed to create key file\n");
            keystore_cleanup();
            return 1;
        }
        if (fwrite(raw_private_key, 1, SIGN_SECRET_SIZE, key_file) != SIGN_SECRET_SIZE) {
            printf("Failed to write private key\n");
            fclose(key_file);
            keystore_cleanup();
            return 1;
        }
        fclose(key_file);
        key_file = fopen(key_path, "rb");
        if (!key_file) {
            printf("Failed to reopen key file\n");
            keystore_cleanup();
            return 1;
        }
    }

    bytes_read = fread(raw_private_key, 1, SIGN_SECRET_SIZE, key_file);
    fclose(key_file);

    if (bytes_read != SIGN_SECRET_SIZE) {
        printf("Failed to read complete private key\n");
        keystore_cleanup();
        return 1;
    }

    if (!keystore_load_raw_ed25519_keypair(raw_private_key)) {
        printf("Failed to load raw private key\n");
        keystore_cleanup();
        return 1;
    }

    // Get the public key for verification
    unsigned char public_key[SIGN_PUBKEY_SIZE];
    if (!keystore_get_public_key(public_key)) {
        printf("Failed to get public key\n");
        keystore_cleanup();
        return 1;
    }

    // Hash the message first (this is what blockchain applications do)
    unsigned char message_hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)test_message, message_len, message_hash);

    // Test 1: Sign the message hash
    printf("Test 1: Sign message... ");
    unsigned char signature[SIGNATURE_SIZE];
    if (sign_message((const char*)message_hash, signature) == 0) {
        printf("✓ Passed\n");
        tests_passed++;
    } else {
        printf("✗ Failed\n");
        tests_failed++;
    }

    // Test 2: Verify the signature using the hash
    printf("Test 2: Verify signature... ");
    if (verify_signature(signature, message_hash, SHA256_DIGEST_LENGTH, public_key) == 0) {
        printf("✓ Passed\n");
        tests_passed++;
    } else {
        printf("✗ Failed\n");
        tests_failed++;
    }

    // Test 3: Verify with tampered message hash
    printf("Test 3: Verify tampered message... ");
    char tampered_message[message_len + 1];
    strcpy(tampered_message, test_message);
    tampered_message[0] = 'X'; // Tamper with the message
    
    unsigned char tampered_hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)tampered_message, message_len, tampered_hash);
    
    if (verify_signature(signature, tampered_hash, SHA256_DIGEST_LENGTH, public_key) != 0) {
        printf("✓ Passed (correctly rejected tampered message)\n");
        tests_passed++;
    } else {
        printf("✗ Failed (accepted tampered message)\n");
        tests_failed++;
    }

    // Cleanup
    keystore_cleanup();

    printf("\nSigning test summary:\n");
    printf("Total tests: 3\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
} 