#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "packages/keystore/keystore.h"
#include "tests/test_init.h"
#include "tests/encryption_test.h"
#include "tests/signing_test.h"
#include "tests/mongoose_test.h"
#include "tests/gossip_store_test.h"
#include "tests/envelope_test.h"
#include "tests/gossip_validation_test.h"
#include "tests/api_protobuf_test.h"
#include "tests/envelope_dispatcher_test.h"
#include "tests/schema_test.h"
#include "tests/httpclient_test.h"
#include "tests/permissions_test.h"

int main(int argc, char* argv[]) {
    // Initialize libsodium once at the start
    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return 1;
    }

    // Initialize test environment (creates test_state with full network)
    printf("Initializing test environment...\n");
    if (test_init_environment() != 0) {
        printf("Failed to initialize test environment\n");
        return 1;
    }
    printf("\n");

        // If no argument provided, run all tests
    if (argc < 2) {
        int tests_passed = 0;
        int tests_failed = 0;
        int total_tests = 11;

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

        // Run gossip store tests
        printf("Running gossip store tests...\n");
        if (gossip_store_test_main() == 0) {
            printf("✓ Gossip store tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Gossip store tests failed\n");
            tests_failed++;
        }
        printf("\n");

        // Run envelope tests
        printf("Running envelope tests...\n");
        if (envelope_test_main() == 0) {
            printf("✓ Envelope tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Envelope tests failed\n");
            tests_failed++;
        }
        printf("\n");

        // Run gossip validation tests
        printf("Running gossip validation tests...\n");
        if (gossip_validation_test_main() == 0) {
            printf("✓ Gossip validation tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Gossip validation tests failed\n");
            tests_failed++;
        }
        printf("\n");

        // Run API protobuf tests
        printf("Running API protobuf tests...\n");
        if (api_protobuf_test_main() == 0) {
            printf("✓ API protobuf tests passed\n");
            tests_passed++;
        } else {
            printf("✗ API protobuf tests failed\n");
            tests_failed++;
        }
        printf("\n");

        // Run envelope dispatcher tests
        printf("Running envelope dispatcher tests...\n");
        if (envelope_dispatcher_test_main() == 0) {
            printf("✓ Envelope dispatcher tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Envelope dispatcher tests failed\n");
            tests_failed++;
        }
        printf("\n");

        // Run schema tests
        printf("Running schema tests...\n");
        if (schema_test_main() == 0) {
            printf("✓ Schema tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Schema tests failed\n");
            tests_failed++;
        }
        printf("\n");

        // Run httpClient tests
        printf("Running httpClient tests...\n");
        if (httpclient_test_main() == 0) {
            printf("✓ HttpClient tests passed\n");
            tests_passed++;
        } else {
            printf("✗ HttpClient tests failed\n");
            tests_failed++;
        }
        printf("\n");

        // Run permissions tests
        printf("Running permissions tests...\n");
        if (permissions_test_main() == 0) {
            printf("✓ Permissions tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Permissions tests failed\n");
            tests_failed++;
        }
        printf("\n");

        printf("\n=== Test Summary ===\n");
        printf("Total Tests: %d\n", total_tests);
        printf("Passed: %d\n", tests_passed);
        printf("Failed: %d\n", tests_failed);
        printf("====================\n");

        // Cleanup test environment
        test_cleanup_environment();

        return (tests_failed > 0) ? 1 : 0;
    } else {
        // Run specific test
        const char* test_name = argv[1];
        int result = 0;

        if (strcmp(test_name, "encryption") == 0) {
            result = encryption_test_main();
        } else if (strcmp(test_name, "signing") == 0) {
            result = signing_test_main();
        } else if (strcmp(test_name, "mongoose") == 0) {
            result = (mongoose_test_main() == 1) ? 0 : 1;  // convert 1=success to 0=success
        } else if (strcmp(test_name, "gossipdb") == 0) {
            result = gossip_store_test_main();
        } else if (strcmp(test_name, "envelope") == 0) {
            result = envelope_test_main();
        } else if (strcmp(test_name, "validation") == 0) {
            result = gossip_validation_test_main();
        } else if (strcmp(test_name, "apipb") == 0) {
            result = api_protobuf_test_main();
        } else if (strcmp(test_name, "dispatcher") == 0) {
            result = envelope_dispatcher_test_main();
        } else if (strcmp(test_name, "schema") == 0) {
            result = schema_test_main();
        } else if (strcmp(test_name, "httpclient") == 0) {
            result = httpclient_test_main();
        } else if (strcmp(test_name, "permissions") == 0) {
            result = permissions_test_main();
        } else {
            printf("Unknown test: %s\n", test_name);
            printf("Available tests: encryption, signing, mongoose, gossipdb, envelope, validation, apipb, dispatcher, schema, httpclient, permissions\n");
            test_cleanup_environment();
            return 1;
        }

        test_cleanup_environment();
        return result;
    }
} 