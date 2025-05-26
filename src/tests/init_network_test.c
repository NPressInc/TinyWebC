#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <unistd.h>
#include "packages/initialization/init.h"
#include "tests/init_network_test.h"

#define TEST_KEYSTORE_PATH "test_state/keys/"
#define TEST_BLOCKCHAIN_PATH "test_state/blockchain/"
#define TEST_PASSPHRASE "testpass"
#define TEST_BASE_PORT 9000
#define TEST_NODE_COUNT 2
#define TEST_USER_COUNT 2

void cleanup_test_dirs() {
    // Remove test files and directories (simple, not recursive)
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s %s", TEST_KEYSTORE_PATH, TEST_BLOCKCHAIN_PATH);
    system(cmd);
}

int init_network_test_main(void) {
    cleanup_test_dirs();
    mkdir("test_state", 0700);
    mkdir(TEST_KEYSTORE_PATH, 0700);
    mkdir(TEST_BLOCKCHAIN_PATH, 0700);

    InitConfig config = {
        .keystore_path = TEST_KEYSTORE_PATH,
        .blockchain_path = TEST_BLOCKCHAIN_PATH,
        .passphrase = TEST_PASSPHRASE,
        .base_port = TEST_BASE_PORT,
        .node_count = TEST_NODE_COUNT,
        .user_count = TEST_USER_COUNT
    };

    int result = initialize_network(&config);
    assert(result == 0 && "Network initialization should succeed");

    // Check that binary blockchain file exists
    FILE* f = fopen("state/blockchain/blockchain.dat", "rb");
    assert(f && "Binary blockchain file should exist after initialization");
    if (f) fclose(f);

    // Check that JSON blockchain file exists
    FILE* json_f = fopen("state/blockchain/blockchain.json", "r");
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

    printf("init_network_test: PASSED\n");
    return 0;
} 