#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <assert.h>
#include "packages/keystore/keystore.h"
#include "packages/utils/print.h"
#include "packages/signing/signing.h"

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

    // Load the existing key file instead of generating a new one
    if (!keystore_load_private_key("node_key.bin", "testpass")) {
        printf("Failed to load private key\n");
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

    // Test 1: Sign a message
    printf("Test 1: Sign message... ");
    unsigned char signature[SIGNATURE_SIZE];
    if (sign_message(test_message, signature) == 0) {
        printf("✓ Passed\n");
        tests_passed++;
    } else {
        printf("✗ Failed\n");
        tests_failed++;
    }

    // Test 2: Verify the signature
    printf("Test 2: Verify signature... ");
    if (verify_signature(signature, (unsigned char*)test_message, message_len, public_key) == 0) {
        printf("✓ Passed\n");
        tests_passed++;
    } else {
        printf("✗ Failed\n");
        tests_failed++;
    }

    // Test 3: Verify with tampered message
    printf("Test 3: Verify tampered message... ");
    char tampered_message[message_len + 1];
    strcpy(tampered_message, test_message);
    tampered_message[0] = 'X'; // Tamper with the message
    if (verify_signature(signature, (unsigned char*)tampered_message, message_len, public_key) != 0) {
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