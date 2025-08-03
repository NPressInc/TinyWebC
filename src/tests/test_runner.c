#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "packages/keystore/keystore.h"
#include "tests/encryption_test.h"
#include "tests/signing_test.h"
#include "tests/blockchain_test.h"
#include "tests/init_network_test.h"
#include "tests/database_test.h"
#include "tests/mongoose_test.h"
#include "tests/http_client_test.h"
#include "tests/invitation_test.h"
#include "tests/access_request_test.h"
#include "tests/node_peer_management_test.h"


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
        int total_tests = 10;

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
        printf("Running blockchain tests...\n");
        if (blockchain_test_main() == 0) {
            printf("✓ Blockchain tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Blockchain tests failed\n");
            tests_failed++;
        }
        keystore_cleanup();
        printf("\n");

        // Run init network tests
        printf("Running init network tests...\n");
        if (init_network_test_main() == 0) {
            printf("✓ Init network tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Init network tests failed\n");
            tests_failed++;
        }
        keystore_cleanup();
        printf("\n");

        // Run database tests
        printf("Running database tests...\n");
        if (database_test_main() == 0) {
            printf("✓ Database tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Database tests failed\n");
            tests_failed++;
        }
        keystore_cleanup();
        printf("\n");

        // Run mongoose tests
        printf("Running mongoose tests...\n");
        if (mongoose_test_main() == 1) {
            printf("✓ Mongoose tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Mongoose tests failed\n");
            tests_failed++;
        }
        printf("\n");

        // Run HTTP client tests
        printf("Running HTTP client tests...\n");
        if (http_client_test_main() == 0) {
            printf("✓ HTTP client tests passed\n");
            tests_passed++;
        } else {
            printf("✗ HTTP client tests failed\n");
            tests_failed++;
        }
        keystore_cleanup();
        printf("\n");

        // Run invitation tests
        printf("Running invitation tests...\n");
        if (invitation_test_main() == 0) {
            printf("✓ Invitation tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Invitation tests failed\n");
            tests_failed++;
        }
        keystore_cleanup();
        printf("\n");

        // Run access request tests
        printf("Running access request tests...\n");
        if (access_request_test_main() == 0) {
            printf("✓ Access request tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Access request tests failed\n");
            tests_failed++;
        }
        keystore_cleanup();
        printf("\n");

        // Run node peer management tests
        printf("Running node peer management tests...\n");
        if (node_peer_management_test_main() == 0) {
            printf("✓ Node peer management tests passed\n");
            tests_passed++;
        } else {
            printf("✗ Node peer management tests failed\n");
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
    else if (strcmp(argv[1], "blockchain") == 0) {
        printf("Running blockchain test...\n");
        int result = blockchain_test_main();
        keystore_cleanup();
        return result;
    }
    else if (strcmp(argv[1], "init_network") == 0) {
        printf("Running init network test...\n");
        int result = init_network_test_main();
        keystore_cleanup();
        return result;
    }
    else if (strcmp(argv[1], "database") == 0) {
        printf("Running database test...\n");
        int result = database_test_main();
        keystore_cleanup();
        return result;
    }
    else if (strcmp(argv[1], "mongoose") == 0) {
        printf("Running mongoose test...\n");
        int result = mongoose_test_main();
        return result == 1 ? 0 : 1;  // Convert mongoose return value (1=success) to standard (0=success)
    }
    else if (strcmp(argv[1], "http_client") == 0) {
        printf("Running HTTP client test...\n");
        int result = http_client_test_main();
        keystore_cleanup();
        return result;
    }
    else if (strcmp(argv[1], "invitation") == 0) {
        printf("Running invitation test...\n");
        int result = invitation_test_main();
        keystore_cleanup();
        return result;
    }
    else if (strcmp(argv[1], "access_request") == 0) {
        printf("Running access request test...\n");
        int result = access_request_test_main();
        keystore_cleanup();
        return result;
    }
    else if (strcmp(argv[1], "node_peer_management") == 0) {
        printf("Running node peer management test...\n");
        int result = node_peer_management_test_main();
        keystore_cleanup();
        return result;
    }
    else {
        printf("Unknown test: %s\n", argv[1]);
        printf("Available tests: encryption, signing, blockchain, init_network, database, mongoose, http_client, invitation, access_request, node_peer_management\n");
        return 1;
    }

    return 0;
} 