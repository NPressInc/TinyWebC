#include "gossip_validation_test.h"
#include "test_init.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

#include "packages/validation/gossip_validation.h"
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

// Helper to create a valid test envelope
static Tinyweb__Envelope* create_test_envelope(uint64_t timestamp, size_t payload_size) {
    // Load admin_001 key from test_state
    char key_path[512];
    snprintf(key_path, sizeof(key_path), "test_state/keys/users/admin_001/key.bin");
    
    FILE* f = fopen(key_path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open key file: %s\n", key_path);
        return NULL;
    }
    
    unsigned char secret_key[crypto_sign_SECRETKEYBYTES];
    size_t read = fread(secret_key, 1, sizeof(secret_key), f);
    fclose(f);
    
    if (read != sizeof(secret_key)) {
        fprintf(stderr, "Failed to read complete key\n");
        return NULL;
    }
    
    // Initialize keystore with the loaded key
    if (keystore_init() != 0) {
        fprintf(stderr, "Failed to init keystore\n");
        return NULL;
    }
    
    if (keystore_load_raw_ed25519_keypair(secret_key) != 0) {
        fprintf(stderr, "Failed to load keypair into keystore\n");
        keystore_cleanup();
        return NULL;
    }
    
    unsigned char admin_pubkey[PUBKEY_SIZE];
    if (keystore_get_public_key(admin_pubkey) != 0) {
        fprintf(stderr, "Failed to get public key\n");
        keystore_cleanup();
        return NULL;
    }
    
    // Create test payload
    unsigned char* payload = malloc(payload_size);
    if (!payload) {
        keystore_cleanup();
        return NULL;
    }
    memset(payload, 'A', payload_size);
    
    // Create header
    tw_envelope_header_view_t header = {
        .version = 1,
        .content_type = TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE,
        .schema_version = 1,
        .timestamp = timestamp,
        .sender_pubkey = admin_pubkey,
        .recipients_pubkeys = admin_pubkey,
        .num_recipients = 1,
        .group_id = NULL,
        .group_id_len = 0
    };
    
    // Build envelope
    Tinyweb__Envelope* envelope = NULL;
    int result = tw_envelope_build_and_sign(&header, payload, payload_size, &envelope);
    free(payload);
    keystore_cleanup();
    
    return (result == 0) ? envelope : NULL;
}

// Test 1: Valid envelope should pass validation
static int test_validate_valid_envelope(void) {
    printf("  - test_validate_valid_envelope...\n");
    
    GossipValidationConfig config = {
        .max_clock_skew_seconds = 300,      // 5 minutes
        .message_ttl_seconds = 86400,        // 24 hours
        .max_payload_bytes = 1024 * 1024     // 1 MB
    };
    
    uint64_t now = (uint64_t)time(NULL);
    Tinyweb__Envelope* envelope = create_test_envelope(now, 100);
    ASSERT_TEST(envelope != NULL, "Failed to create test envelope");
    
    GossipValidationResult result = gossip_validate_envelope(envelope, &config, now);
    ASSERT_TEST(result == GOSSIP_VALIDATION_OK, 
                "Valid envelope failed validation");
    
    tw_envelope_free(envelope);
    printf("    ✓ valid envelope passed\n");
    return 0;
}

// Test 2: Envelope with future timestamp within skew should pass
static int test_validate_future_timestamp_within_skew(void) {
    printf("  - test_validate_future_timestamp_within_skew...\n");
    
    GossipValidationConfig config = {
        .max_clock_skew_seconds = 300,
        .message_ttl_seconds = 86400,
        .max_payload_bytes = 1024 * 1024
    };
    
    uint64_t now = (uint64_t)time(NULL);
    uint64_t future = now + 200; // 200 seconds in future (within 300s skew)
    
    Tinyweb__Envelope* envelope = create_test_envelope(future, 100);
    ASSERT_TEST(envelope != NULL, "Failed to create test envelope");
    
    GossipValidationResult result = gossip_validate_envelope(envelope, &config, now);
    ASSERT_TEST(result == GOSSIP_VALIDATION_OK,
                "Future timestamp within skew should pass");
    
    tw_envelope_free(envelope);
    printf("    ✓ future timestamp within skew passed\n");
    return 0;
}

// Test 3: Envelope with future timestamp beyond skew should fail
static int test_validate_future_timestamp_beyond_skew(void) {
    printf("  - test_validate_future_timestamp_beyond_skew...\n");
    
    GossipValidationConfig config = {
        .max_clock_skew_seconds = 300,
        .message_ttl_seconds = 86400,
        .max_payload_bytes = 1024 * 1024
    };
    
    uint64_t now = (uint64_t)time(NULL);
    uint64_t future = now + 400; // 400 seconds in future (beyond 300s skew)
    
    Tinyweb__Envelope* envelope = create_test_envelope(future, 100);
    ASSERT_TEST(envelope != NULL, "Failed to create test envelope");
    
    GossipValidationResult result = gossip_validate_envelope(envelope, &config, now);
    ASSERT_TEST(result == GOSSIP_VALIDATION_ERROR_TIMESTAMP,
                "Future timestamp beyond skew should fail");
    
    tw_envelope_free(envelope);
    printf("    ✓ future timestamp beyond skew rejected\n");
    return 0;
}

// Test 4: Old envelope within TTL should pass
static int test_validate_old_timestamp_within_ttl(void) {
    printf("  - test_validate_old_timestamp_within_ttl...\n");
    
    GossipValidationConfig config = {
        .max_clock_skew_seconds = 300,
        .message_ttl_seconds = 86400,
        .max_payload_bytes = 1024 * 1024
    };
    
    uint64_t now = (uint64_t)time(NULL);
    uint64_t past = now - 3600; // 1 hour ago (within 24h TTL)
    
    Tinyweb__Envelope* envelope = create_test_envelope(past, 100);
    ASSERT_TEST(envelope != NULL, "Failed to create test envelope");
    
    GossipValidationResult result = gossip_validate_envelope(envelope, &config, now);
    ASSERT_TEST(result == GOSSIP_VALIDATION_OK,
                "Old timestamp within TTL should pass");
    
    tw_envelope_free(envelope);
    printf("    ✓ old timestamp within TTL passed\n");
    return 0;
}

// Test 5: Expired envelope beyond TTL should fail
static int test_validate_expired_beyond_ttl(void) {
    printf("  - test_validate_expired_beyond_ttl...\n");
    
    GossipValidationConfig config = {
        .max_clock_skew_seconds = 300,
        .message_ttl_seconds = 86400,
        .max_payload_bytes = 1024 * 1024
    };
    
    uint64_t now = (uint64_t)time(NULL);
    uint64_t past = now - 90000; // 25 hours ago (beyond 24h TTL + 5min skew)
    
    Tinyweb__Envelope* envelope = create_test_envelope(past, 100);
    ASSERT_TEST(envelope != NULL, "Failed to create test envelope");
    
    GossipValidationResult result = gossip_validate_envelope(envelope, &config, now);
    ASSERT_TEST(result == GOSSIP_VALIDATION_ERROR_TIMESTAMP,
                "Expired envelope should fail");
    
    tw_envelope_free(envelope);
    printf("    ✓ expired envelope rejected\n");
    return 0;
}

// Test 6: Envelope at exact TTL boundary should pass
static int test_validate_at_ttl_boundary(void) {
    printf("  - test_validate_at_ttl_boundary...\n");
    
    GossipValidationConfig config = {
        .max_clock_skew_seconds = 300,
        .message_ttl_seconds = 86400,
        .max_payload_bytes = 1024 * 1024
    };
    
    uint64_t now = (uint64_t)time(NULL);
    uint64_t past = now - (86400 + 300); // Exactly at TTL + skew boundary
    
    Tinyweb__Envelope* envelope = create_test_envelope(past, 100);
    ASSERT_TEST(envelope != NULL, "Failed to create test envelope");
    
    GossipValidationResult result = gossip_validate_envelope(envelope, &config, now);
    ASSERT_TEST(result == GOSSIP_VALIDATION_OK,
                "Envelope at TTL boundary should pass");
    
    tw_envelope_free(envelope);
    printf("    ✓ envelope at TTL boundary passed\n");
    return 0;
}

// Test 7: Oversized payload should fail
static int test_validate_oversized_payload(void) {
    printf("  - test_validate_oversized_payload...\n");
    
    GossipValidationConfig config = {
        .max_clock_skew_seconds = 300,
        .message_ttl_seconds = 86400,
        .max_payload_bytes = 1024  // Only 1KB allowed
    };
    
    uint64_t now = (uint64_t)time(NULL);
    Tinyweb__Envelope* envelope = create_test_envelope(now, 2000); // 2KB payload
    ASSERT_TEST(envelope != NULL, "Failed to create test envelope");
    
    GossipValidationResult result = gossip_validate_envelope(envelope, &config, now);
    ASSERT_TEST(result == GOSSIP_VALIDATION_ERROR_PAYLOAD,
                "Oversized payload should fail");
    
    tw_envelope_free(envelope);
    printf("    ✓ oversized payload rejected\n");
    return 0;
}

// Test 8: Payload at size limit should pass
static int test_validate_at_size_limit(void) {
    printf("  - test_validate_at_size_limit...\n");
    
    GossipValidationConfig config = {
        .max_clock_skew_seconds = 300,
        .message_ttl_seconds = 86400,
        .max_payload_bytes = 1024
    };
    
    uint64_t now = (uint64_t)time(NULL);
    // Note: encrypted payload will be larger than plaintext due to MAC
    Tinyweb__Envelope* envelope = create_test_envelope(now, 800); // Leave room for crypto overhead
    ASSERT_TEST(envelope != NULL, "Failed to create test envelope");
    
    GossipValidationResult result = gossip_validate_envelope(envelope, &config, now);
    ASSERT_TEST(result == GOSSIP_VALIDATION_OK,
                "Payload at size limit should pass");
    
    tw_envelope_free(envelope);
    printf("    ✓ payload at size limit passed\n");
    return 0;
}

// Test 9: Null envelope should fail
static int test_validate_null_envelope(void) {
    printf("  - test_validate_null_envelope...\n");
    
    GossipValidationConfig config = {
        .max_clock_skew_seconds = 300,
        .message_ttl_seconds = 86400,
        .max_payload_bytes = 1024 * 1024
    };
    
    uint64_t now = (uint64_t)time(NULL);
    
    GossipValidationResult result = gossip_validate_envelope(NULL, &config, now);
    ASSERT_TEST(result == GOSSIP_VALIDATION_ERROR_NULL,
                "Null envelope should fail");
    
    printf("    ✓ null envelope rejected\n");
    return 0;
}

// Test 10: Null config should fail
static int test_validate_null_config(void) {
    printf("  - test_validate_null_config...\n");
    
    uint64_t now = (uint64_t)time(NULL);
    Tinyweb__Envelope* envelope = create_test_envelope(now, 100);
    ASSERT_TEST(envelope != NULL, "Failed to create test envelope");
    
    GossipValidationResult result = gossip_validate_envelope(envelope, NULL, now);
    ASSERT_TEST(result == GOSSIP_VALIDATION_ERROR_NULL,
                "Null config should fail");
    
    tw_envelope_free(envelope);
    printf("    ✓ null config rejected\n");
    return 0;
}

// Test 11: Invalid signature should fail
static int test_validate_invalid_signature(void) {
    printf("  - test_validate_invalid_signature...\n");
    
    GossipValidationConfig config = {
        .max_clock_skew_seconds = 300,
        .message_ttl_seconds = 86400,
        .max_payload_bytes = 1024 * 1024
    };
    
    uint64_t now = (uint64_t)time(NULL);
    Tinyweb__Envelope* envelope = create_test_envelope(now, 100);
    ASSERT_TEST(envelope != NULL, "Failed to create test envelope");
    
    // Tamper with the signature
    if (envelope->signature.data && envelope->signature.len > 0) {
        envelope->signature.data[0] ^= 0xFF;
    }
    
    GossipValidationResult result = gossip_validate_envelope(envelope, &config, now);
    ASSERT_TEST(result == GOSSIP_VALIDATION_ERROR_SIGNATURE,
                "Invalid signature should fail");
    
    tw_envelope_free(envelope);
    printf("    ✓ invalid signature rejected\n");
    return 0;
}

// Test 12: TTL calculation
static int test_validation_expiration_calculation(void) {
    printf("  - test_validation_expiration_calculation...\n");
    
    GossipValidationConfig config = {
        .max_clock_skew_seconds = 300,
        .message_ttl_seconds = 1000,
        .max_payload_bytes = 1024 * 1024
    };
    
    uint64_t timestamp = 5000;
    Tinyweb__Envelope* envelope = create_test_envelope(timestamp, 100);
    ASSERT_TEST(envelope != NULL, "Failed to create test envelope");
    
    // Override timestamp for test
    envelope->header->timestamp = timestamp;
    
    uint64_t expiration = gossip_validation_expiration(envelope, &config);
    ASSERT_TEST(expiration == timestamp + config.message_ttl_seconds,
                "TTL calculation incorrect");
    
    tw_envelope_free(envelope);
    printf("    ✓ TTL calculation correct\n");
    return 0;
}

int gossip_validation_test_main(void) {
    printf("\n=== Gossip Validation Tests ===\n");
    
    int passed = 0;
    int failed = 0;
    int total = 12;
    
    // Run all tests
    if (test_validate_valid_envelope() == 0) passed++; else failed++;
    if (test_validate_future_timestamp_within_skew() == 0) passed++; else failed++;
    if (test_validate_future_timestamp_beyond_skew() == 0) passed++; else failed++;
    if (test_validate_old_timestamp_within_ttl() == 0) passed++; else failed++;
    if (test_validate_expired_beyond_ttl() == 0) passed++; else failed++;
    if (test_validate_at_ttl_boundary() == 0) passed++; else failed++;
    if (test_validate_oversized_payload() == 0) passed++; else failed++;
    if (test_validate_at_size_limit() == 0) passed++; else failed++;
    if (test_validate_null_envelope() == 0) passed++; else failed++;
    if (test_validate_null_config() == 0) passed++; else failed++;
    if (test_validate_invalid_signature() == 0) passed++; else failed++;
    if (test_validation_expiration_calculation() == 0) passed++; else failed++;
    
    printf("\nGossip Validation Tests: %d passed, %d failed\n", passed, failed);
    
    if (failed > 0) {
        printf("✗ Gossip validation tests failed\n");
        return 1;
    }
    
    printf("✓ All gossip validation tests passed\n");
    return 0;
}
