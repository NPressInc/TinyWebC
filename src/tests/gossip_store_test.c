#include "tests/gossip_store_test.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <sodium.h>

#include "packages/sql/database_gossip.h"
#include "packages/sql/schema.h"
#include "packages/sql/gossip_peers.h"
#include "packages/transactions/envelope.h"
#include "envelope.pb-c.h"

#define ASSERT_OR_FAIL(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[gossip_store_test] %s\n", msg); \
            return -1; \
        } \
    } while (0)

static void ensure_directory_exists(const char* path) {
    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
        fprintf(stderr, "Failed to create directory %s: %s\n", path, strerror(errno));
    }
}

static void cleanup_path_recursive(const char* path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
    system(cmd);
}

static int test_gossip_seen_cache(void) {
    printf("  - testing gossip_seen cache lifecycle...\n");

    ensure_directory_exists("test_state");
    const char* db_path = "test_state/gossip_seen_test.db";
    remove(db_path);
    
    // Ensure any existing DB is closed before opening a new one
    if (db_is_initialized()) {
        db_close();
    }

    ASSERT_OR_FAIL(db_init_gossip(db_path) == 0, "db_init_gossip failed");
    ASSERT_OR_FAIL(gossip_store_init() == 0, "gossip_store_init failed");

    unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE];
    for (size_t i = 0; i < GOSSIP_SEEN_DIGEST_SIZE; ++i) {
        digest[i] = (unsigned char)(i + 1);
    }

    int seen = 0;
    ASSERT_OR_FAIL(gossip_store_has_seen(digest, &seen) == 0, "has_seen initial query failed");
    ASSERT_OR_FAIL(seen == 0, "digest unexpectedly marked as seen");

    uint64_t now = (uint64_t)time(NULL);
    ASSERT_OR_FAIL(gossip_store_mark_seen(digest, now + 5) == 0, "mark_seen failed");

    seen = 0;
    ASSERT_OR_FAIL(gossip_store_has_seen(digest, &seen) == 0, "has_seen after mark failed");
    ASSERT_OR_FAIL(seen == 1, "digest was not recorded as seen");

    ASSERT_OR_FAIL(gossip_store_cleanup(now + 10) == 0, "cleanup failed");

    seen = 1;
    ASSERT_OR_FAIL(gossip_store_has_seen(digest, &seen) == 0, "has_seen after cleanup failed");
    ASSERT_OR_FAIL(seen == 0, "digest was not expired by cleanup");

    ASSERT_OR_FAIL(db_close() == 0, "db_close failed");
    remove(db_path);

    printf("    ✓ gossip_seen cache working\n");
    return 0;
}

static int test_envelope_storage(void) {
    printf("  - testing envelope storage and retrieval...\n");

    ensure_directory_exists("test_state");
    const char* db_path = "test_state/envelope_store_test.db";
    remove(db_path);
    
    // Ensure any existing DB is closed before opening a new one
    if (db_is_initialized()) {
        db_close();
    }

    ASSERT_OR_FAIL(db_init_gossip(db_path) == 0, "db_init_gossip failed");
    ASSERT_OR_FAIL(gossip_store_init() == 0, "gossip_store_init failed");

    // Create test envelope data
    unsigned char test_sender[PUBKEY_SIZE];
    memset(test_sender, 0xAA, PUBKEY_SIZE);
    
    unsigned char test_envelope_data[100];
    memset(test_envelope_data, 0xBB, sizeof(test_envelope_data));

    uint64_t now = (uint64_t)time(NULL);
    uint64_t expires_at = now + 3600;

    // Create dummy envelope for storage test
    Tinyweb__Envelope envelope = TINYWEB__ENVELOPE__INIT;
    Tinyweb__EnvelopeHeader header = TINYWEB__ENVELOPE_HEADER__INIT;
    envelope.header = &header;
    header.version = 1;
    header.content_type = 100;
    header.schema_version = 1;
    header.timestamp = now;
    header.sender_pubkey.len = PUBKEY_SIZE;
    header.sender_pubkey.data = test_sender;
    
    envelope.payload_nonce.len = 24;
    envelope.payload_nonce.data = test_envelope_data; // Dummy nonce
    envelope.ephemeral_pubkey.len = PUBKEY_SIZE;
    envelope.ephemeral_pubkey.data = test_sender; // Dummy ephemeral
    envelope.payload_ciphertext.len = sizeof(test_envelope_data);
    envelope.payload_ciphertext.data = test_envelope_data;
    envelope.signature.len = 64;
    unsigned char dummy_sig[64] = {0};
    envelope.signature.data = dummy_sig;

    // Save envelope (no recipients for this test)
    ASSERT_OR_FAIL(gossip_store_save_envelope(&envelope, expires_at) == 0, "gossip_store_save_envelope failed");

    // Fetch recent envelopes
    GossipStoredEnvelope* envelopes = NULL;
    size_t count = 0;
    ASSERT_OR_FAIL(gossip_store_fetch_recent_envelopes(10, &envelopes, &count) == 0, 
                   "fetch_recent_envelopes failed");
    ASSERT_OR_FAIL(count == 1, "expected 1 envelope");
    ASSERT_OR_FAIL(envelopes[0].version == 1, "version mismatch");
    ASSERT_OR_FAIL(envelopes[0].content_type == 100, "content_type mismatch");
    ASSERT_OR_FAIL(envelopes[0].schema_version == 1, "schema_version mismatch");
    ASSERT_OR_FAIL(envelopes[0].timestamp == now, "timestamp mismatch");
    ASSERT_OR_FAIL(memcmp(envelopes[0].sender, test_sender, PUBKEY_SIZE) == 0, "sender mismatch");
    ASSERT_OR_FAIL(envelopes[0].envelope_size == sizeof(test_envelope_data), "envelope_size mismatch");

    gossip_store_free_envelopes(envelopes, count);

    // Test cleanup
    ASSERT_OR_FAIL(gossip_store_cleanup(expires_at + 1) == 0, "cleanup failed");

    envelopes = NULL;
    count = 0;
    ASSERT_OR_FAIL(gossip_store_fetch_recent_envelopes(10, &envelopes, &count) == 0,
                   "fetch after cleanup failed");
    ASSERT_OR_FAIL(count == 0, "envelope not cleaned up");

    if (envelopes) {
        gossip_store_free_envelopes(envelopes, count);
    }

    ASSERT_OR_FAIL(db_close() == 0, "db_close failed");
    remove(db_path);

    printf("    ✓ envelope storage working\n");
    return 0;
}

int gossip_store_test_main(void) {
    int failures = 0;

    printf("=== Gossip Store Tests ===\n");

    if (test_gossip_seen_cache() != 0) {
        failures++;
    }

    if (test_envelope_storage() != 0) {
        failures++;
    }

    if (failures == 0) {
        printf("✓ All gossip store tests passed\n");
    } else {
        printf("✗ %d test(s) failed\n", failures);
    }

    return (failures == 0) ? 0 : -1;
}
