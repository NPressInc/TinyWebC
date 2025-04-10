#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>
#include "packages/keystore/keystore.h"
#include "tests/encryption_test.h"
#include "tests/signing_test.h"

// Declare the test functions
int encryption_test_main(void);
int signing_test_main(void);

int main() {
    int tests_passed = 0;
    int tests_failed = 0;
    int total_tests = 2; // encryption and signing tests

    printf("Running all tests...\n\n");

    // Initialize libsodium once at the start
    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return 1;
    }

    // Run encryption tests
    printf("Running encryption tests...\n");
    if (encryption_test_main() == 0) {
        printf("✓ Encryption tests passed\n");
        tests_passed++;
    } else {
        printf("✗ Encryption tests failed\n");
        tests_failed++;
    }
    keystore_cleanup();  // Clean up after encryption test
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
    keystore_cleanup();  // Clean up after signing test
    printf("\n");

    // Print summary
    printf("Test Summary:\n");
    printf("Total tests: %d\n", total_tests);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
} 