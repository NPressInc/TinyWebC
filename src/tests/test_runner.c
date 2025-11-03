#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "packages/keystore/keystore.h"
#include "tests/encryption_test.h"
#include "tests/signing_test.h"
#include "tests/mongoose_test.h"

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
        int total_tests = 3;

        printf("Running all gossip tests...\n\n");

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

        // Run mongoose tests
        printf("Running mongoose tests...\n");
        if (mongoose_test_main() == 1) {  // mongoose returns 1 for success
            printf("✓ Mongoose tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Mongoose tests failed\n");
            tests_failed++;
        }
        keystore_cleanup();
        printf("\n");

        printf("\n=== Test Summary ===\n");
        printf("Total Tests: %d\n", total_tests);
        printf("Passed: %d\n", tests_passed);
        printf("Failed: %d\n", tests_failed);
        printf("====================\n");

        return (tests_failed > 0) ? 1 : 0;
    } else {
        // Run specific test
        const char* test_name = argv[1];

        if (strcmp(test_name, "encryption") == 0) {
            return encryption_test_main();
        } else if (strcmp(test_name, "signing") == 0) {
            return signing_test_main();
        } else if (strcmp(test_name, "mongoose") == 0) {
            return (mongoose_test_main() == 1) ? 0 : 1;  // convert 1=success to 0=success
        } else {
            printf("Unknown test: %s\n", test_name);
            printf("Available tests: encryption, signing, mongoose\n");
            return 1;
        }
    }
} 