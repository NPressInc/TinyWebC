#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "packages/keystore/keystore.h"
#include "tests/encryption_test.h"
#include "tests/signing_test.h"

// Declare the test functions
int encryption_test_main(void);
int signing_test_main(void);

int main(int argc, char* argv[]) {
    // Initialize libsodium once at the start
    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return 1;
    }

    // If no argument provided, run all tests
    if (argc < 2) {
        int tests_passed = 0;
        int tests_failed = 0;
        int total_tests = 2;

        printf("Running all tests...\n\n");

        // Run encryption tests
        printf("Running encryption tests...\n");
        if (encryption_test_main() == 0) {
            printf("✓ Encryption tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Encryption tests failed\n");
            tests_failed++;
        }
        keystore_cleanup();
        printf("\n");

        // Run signing tests
        printf("Running signing tests...\n");
        if (signing_test_main() == 0) {
            printf("✓ Signing tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Signing tests failed\n");
            tests_failed++;
        }
        keystore_cleanup();
        printf("\n");

        // Run blockchain tests
        printf("Running signing tests...\n");
        if (blockchain_test_main() == 0) {
            printf("✓ Blockchain tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Blockchain tests failed\n");
            tests_failed++;
        }
        keystore_cleanup();
        printf("\n");

        // Print summary
        printf("Test Summary:\n");
        printf("Total tests: %d\n", total_tests);
        printf("Passed: %d\n", tests_passed);
        printf("Failed: %d\n", tests_failed);

        return tests_failed > 0 ? 1 : 0;
    }
    
    // Run specific test based on argument
    if (strcmp(argv[1], "encryption") == 0) {
        printf("Running encryption test...\n");
        int result = encryption_test_main();
        keystore_cleanup();
        return result;
    }
    else if (strcmp(argv[1], "signing") == 0) {
        printf("Running signing test...\n");
        int result = signing_test_main();
        keystore_cleanup();
        return result;
    }
    else if (strcmp(argv[1], "signing") == 0) {
        printf("Running blockchain test...\n");
        int result = blockchain_test_main();
        keystore_cleanup();
        return result;
    }
    else {
        printf("Unknown test: %s\n", argv[1]);
        printf("Available tests: encryption, signing\n");
        return 1;
    }

    return 0;
} 