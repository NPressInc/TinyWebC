#include "tests/message_permissions_test.h"
#include "tests/test_init.h"
#include "packages/comm/message_permissions.h"
#include <stdio.h>
#include <string.h>

#define ASSERT_TEST(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s\n", msg); \
            return -1; \
        } \
    } while (0)

static int test_basic_permissions(void) {
    printf("Testing basic message permissions...\n");
    
    unsigned char sender[32], recipient[32];
    memset(sender, 0x11, 32);
    memset(recipient, 0x22, 32);
    
    // Current implementation returns true for everything, but we should test the API
    ASSERT_TEST(message_permissions_check(sender, recipient, NULL, 1) == true, "Should allow basic message");
    
    printf("  ✓ basic permissions passed\n");
    return 0;
}

int message_permissions_test_main(void) {
    printf("\n=== Message Permissions Tests ===\n");
    
    if (test_basic_permissions() != 0) return -1;
    
    printf("All Message Permissions tests passed!\n");
    return 0;
}


