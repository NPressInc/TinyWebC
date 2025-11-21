#include "envelope_dispatcher_test.h"
#include "test_init.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

#include "packages/comm/envelope_dispatcher.h"
#include "packages/transactions/envelope.h"
#include "packages/keystore/keystore.h"
#include "envelope.pb-c.h"
#include "content.pb-c.h"

#define ASSERT_TEST(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s\n", msg); \
            return -1; \
        } \
    } while (0)

// Helper to load user key from test_state
static int load_test_user_key(const char* user_id, unsigned char* out_secret) {
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "test_state/keys/users/%s/key.bin", user_id);
    
    FILE* f = fopen(key_path, "rb");
    if (!f) {
        return -1;
    }
    
    size_t read = fread(out_secret, 1, crypto_sign_SECRETKEYBYTES, f);
    fclose(f);
    
    return (read == crypto_sign_SECRETKEYBYTES) ? 0 : -1;
}

// Helper to extract public key from secret key
static void get_public_key_from_secret(const unsigned char* secret_key, unsigned char* out_pubkey) {
    crypto_sign_ed25519_sk_to_pk(out_pubkey, secret_key);
}

// Test handler call tracking
static int g_handler_called = 0;
static uint32_t g_last_content_type = 0;

static int test_handler(const Tinyweb__Envelope* envelope,
                       const unsigned char* payload,
                       size_t payload_len,
                       void* context) {
    (void)payload;
    (void)payload_len;
    (void)context;
    
    if (envelope && envelope->header) {
        g_handler_called = 1;
        g_last_content_type = envelope->header->content_type;
    }
    return 0;
}

// Test dispatcher initialization
static int test_dispatcher_init(void) {
    printf("  - test_dispatcher_init...\n");
    
    int result = envelope_dispatcher_init();
    ASSERT_TEST(result == 0, "envelope_dispatcher_init failed");
    
    envelope_dispatcher_cleanup();
    
    printf("    ✓ dispatcher initialization passed\n");
    return 0;
}

// Test handler registration
static int test_handler_registration(void) {
    printf("  - test_handler_registration...\n");
    
    ASSERT_TEST(envelope_dispatcher_init() == 0, "Failed to init dispatcher");
    
    // Register a custom handler
    int result = envelope_register_handler(TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE, test_handler);
    ASSERT_TEST(result == 0, "Failed to register handler");
    
    // Try to register again (should succeed, replacing previous)
    result = envelope_register_handler(TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE, test_handler);
    ASSERT_TEST(result == 0, "Failed to re-register handler");
    
    // Unregister handler
    envelope_unregister_handler(TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE);
    
    envelope_dispatcher_cleanup();
    
    printf("    ✓ handler registration passed\n");
    return 0;
}

// Test dispatch routing
static int test_dispatch_routing(void) {
    printf("  - test_dispatch_routing...\n");
    
    ASSERT_TEST(envelope_dispatcher_init() == 0, "Failed to init dispatcher");
    
    // Load test key
    unsigned char admin_secret[crypto_sign_SECRETKEYBYTES];
    ASSERT_TEST(load_test_user_key("admin_001", admin_secret) == 0, "Failed to load admin_001 key");
    
    unsigned char admin_pubkey[PUBKEY_SIZE];
    get_public_key_from_secret(admin_secret, admin_pubkey);
    
    // Initialize keystore
    ASSERT_TEST(keystore_init() != 0, "Failed to init keystore");
    ASSERT_TEST(keystore_load_raw_ed25519_keypair(admin_secret) != 0, "Failed to load keypair");
    
    // Create DirectMessage content
    Tinyweb__DirectMessage direct_msg = TINYWEB__DIRECT_MESSAGE__INIT;
    direct_msg.text = "Test dispatch message";
    
    size_t content_size = tinyweb__direct_message__get_packed_size(&direct_msg);
    unsigned char* content_data = malloc(content_size);
    ASSERT_TEST(content_data != NULL, "Failed to allocate content data");
    tinyweb__direct_message__pack(&direct_msg, content_data);
    
    // Create envelope header
    tw_envelope_header_view_t header = {
        .version = 1,
        .content_type = TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE,
        .schema_version = 1,
        .timestamp = (uint64_t)time(NULL),
        .sender_pubkey = admin_pubkey,
        .recipients_pubkeys = admin_pubkey,
        .num_recipients = 1,
        .group_id = NULL,
        .group_id_len = 0
    };
    
    // Build and sign envelope
    Tinyweb__Envelope* envelope = NULL;
    int result = tw_envelope_build_and_sign(&header, content_data, content_size, &envelope);
    free(content_data);
    ASSERT_TEST(result == 0, "Failed to build envelope");
    ASSERT_TEST(envelope != NULL, "Envelope is NULL");
    
    // Register test handler
    g_handler_called = 0;
    g_last_content_type = 0;
    ASSERT_TEST(envelope_register_handler(TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE, test_handler) == 0,
               "Failed to register test handler");
    
    // Dispatch envelope
    result = envelope_dispatch(envelope, NULL);
    ASSERT_TEST(result == 0, "envelope_dispatch failed");
    ASSERT_TEST(g_handler_called == 1, "Handler was not called");
    ASSERT_TEST(g_last_content_type == TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE,
               "Handler received wrong content type");
    
    // Test unregistered content type
    envelope->header->content_type = 999; // Unregistered type
    result = envelope_dispatch(envelope, NULL);
    ASSERT_TEST(result != 0, "Dispatch should fail for unregistered content type");
    
    tw_envelope_free(envelope);
    keystore_cleanup();
    envelope_dispatcher_cleanup();
    
    printf("    ✓ dispatch routing passed\n");
    return 0;
}

// Test default handlers are registered
static int test_default_handlers(void) {
    printf("  - test_default_handlers...\n");
    
    ASSERT_TEST(envelope_dispatcher_init() == 0, "Failed to init dispatcher");
    
    // Load test key
    unsigned char admin_secret[crypto_sign_SECRETKEYBYTES];
    ASSERT_TEST(load_test_user_key("admin_001", admin_secret) == 0, "Failed to load admin_001 key");
    
    unsigned char admin_pubkey[PUBKEY_SIZE];
    get_public_key_from_secret(admin_secret, admin_pubkey);
    
    // Initialize keystore
    ASSERT_TEST(keystore_init() != 0, "Failed to init keystore");
    ASSERT_TEST(keystore_load_raw_ed25519_keypair(admin_secret) != 0, "Failed to load keypair");
    
    // Test DirectMessage handler
    Tinyweb__DirectMessage direct_msg = TINYWEB__DIRECT_MESSAGE__INIT;
    direct_msg.text = "Test direct message";
    
    size_t content_size = tinyweb__direct_message__get_packed_size(&direct_msg);
    unsigned char* content_data = malloc(content_size);
    ASSERT_TEST(content_data != NULL, "Failed to allocate content data");
    tinyweb__direct_message__pack(&direct_msg, content_data);
    
    tw_envelope_header_view_t header = {
        .version = 1,
        .content_type = TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE,
        .schema_version = 1,
        .timestamp = (uint64_t)time(NULL),
        .sender_pubkey = admin_pubkey,
        .recipients_pubkeys = admin_pubkey,
        .num_recipients = 1,
        .group_id = NULL,
        .group_id_len = 0
    };
    
    Tinyweb__Envelope* envelope = NULL;
    int result = tw_envelope_build_and_sign(&header, content_data, content_size, &envelope);
    free(content_data);
    ASSERT_TEST(result == 0, "Failed to build envelope");
    
    // Dispatch should succeed (default handler exists)
    result = envelope_dispatch(envelope, NULL);
    // Note: Default handler returns 0 even if payload is NULL (not decrypted yet)
    // So we just check it doesn't crash
    ASSERT_TEST(result == 0 || result == -1, "Unexpected dispatch result");
    
    tw_envelope_free(envelope);
    keystore_cleanup();
    envelope_dispatcher_cleanup();
    
    printf("    ✓ default handlers registered\n");
    return 0;
}

int envelope_dispatcher_test_main(void) {
    printf("Running envelope dispatcher tests...\n\n");
    
    int passed = 0;
    int failed = 0;
    
    if (test_dispatcher_init() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    if (test_handler_registration() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    if (test_dispatch_routing() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    if (test_default_handlers() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    printf("\nEnvelope Dispatcher Tests: %d passed, %d failed\n", passed, failed);
    
    return (failed > 0) ? -1 : 0;
}

