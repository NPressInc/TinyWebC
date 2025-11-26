#include "envelope_test.h"
#include "test_init.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

#include "packages/transactions/envelope.h"
#include "packages/encryption/encryption.h"
#include "packages/keystore/keystore.h"
#include "packages/sql/database_gossip.h"
#include "packages/sql/schema.h"
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
        fprintf(stderr, "Failed to open key file: %s\n", key_path);
        return -1;
    }
    
    size_t read = fread(out_secret, 1, crypto_sign_SECRETKEYBYTES, f);
    fclose(f);
    
    if (read != crypto_sign_SECRETKEYBYTES) {
        fprintf(stderr, "Failed to read complete key from %s\n", key_path);
        return -1;
    }
    
    return 0;
}

// Helper to extract public key from secret key
static void get_public_key_from_secret(const unsigned char* secret_key, unsigned char* out_pubkey) {
    crypto_sign_ed25519_sk_to_pk(out_pubkey, secret_key);
}

int test_envelope_create_sign_verify(void) {
    printf("  - test_envelope_create_sign_verify...\n");

    // Load admin_001 key
    unsigned char admin_secret[crypto_sign_SECRETKEYBYTES];
    ASSERT_TEST(load_test_user_key("admin_001", admin_secret) == 0, 
                "Failed to load admin_001 key");

    unsigned char admin_pubkey[PUBKEY_SIZE];
    get_public_key_from_secret(admin_secret, admin_pubkey);

    // Initialize keystore with the loaded key
    ASSERT_TEST(keystore_init() == 0, "Failed to init keystore");
    ASSERT_TEST(keystore_load_raw_ed25519_keypair(admin_secret) == 0, 
                "Failed to load keypair into keystore");

    // Create simple direct message content
    Tinyweb__DirectMessage direct_msg = TINYWEB__DIRECT_MESSAGE__INIT;
    direct_msg.text = "Hello from envelope test";

    // Serialize the content
    size_t content_size = tinyweb__direct_message__get_packed_size(&direct_msg);
    uint8_t* content_data = malloc(content_size);
    ASSERT_TEST(content_data != NULL, "Failed to allocate content buffer");
    tinyweb__direct_message__pack(&direct_msg, content_data);

    // Create header view for envelope (sender is also a recipient)
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
    ASSERT_TEST(result == 0, "Failed to build and sign envelope");
    ASSERT_TEST(envelope != NULL, "Envelope is NULL");

    // Verify envelope signature
    result = tw_envelope_verify(envelope);
    ASSERT_TEST(result == 0, "Envelope signature verification failed");

    // Cleanup
    tw_envelope_free(envelope);
    keystore_cleanup();

    printf("    ✓ envelope create/sign/verify passed\n");
    return 0;
}

int test_envelope_multi_recipient_encryption(void) {
    printf("  - test_envelope_multi_recipient_encryption...\n");

    // Load admin_001 and admin_002 keys
    unsigned char admin1_secret[crypto_sign_SECRETKEYBYTES];
    unsigned char admin2_secret[crypto_sign_SECRETKEYBYTES];
    
    ASSERT_TEST(load_test_user_key("admin_001", admin1_secret) == 0,
                "Failed to load admin_001 key");
    ASSERT_TEST(load_test_user_key("admin_002", admin2_secret) == 0,
                "Failed to load admin_002 key");

    unsigned char admin1_pubkey[PUBKEY_SIZE];
    unsigned char admin2_pubkey[PUBKEY_SIZE];
    get_public_key_from_secret(admin1_secret, admin1_pubkey);
    get_public_key_from_secret(admin2_secret, admin2_pubkey);

    // Initialize keystore with admin1's key (sender)
    ASSERT_TEST(keystore_init() == 0, "Failed to init keystore");
    ASSERT_TEST(keystore_load_raw_ed25519_keypair(admin1_secret) == 0, 
                "Failed to load keypair into keystore");

    // Prepare recipient array
    unsigned char recipients[2 * PUBKEY_SIZE];
    memcpy(recipients, admin1_pubkey, PUBKEY_SIZE);
    memcpy(recipients + PUBKEY_SIZE, admin2_pubkey, PUBKEY_SIZE);

    // Create content
    const char* message = "Secret message for two admins";
    size_t message_len = strlen(message) + 1;

    // Create header view with recipients
    tw_envelope_header_view_t header = {
        .version = 1,
        .content_type = TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE,
        .schema_version = 1,
        .timestamp = (uint64_t)time(NULL),
        .sender_pubkey = admin1_pubkey,
        .recipients_pubkeys = recipients,
        .num_recipients = 2,
        .group_id = NULL,
        .group_id_len = 0
    };

    // Build encrypted envelope
    Tinyweb__Envelope* envelope = NULL;
    int result = tw_envelope_build_and_sign(&header, (unsigned char*)message, message_len, &envelope);

    ASSERT_TEST(result == 0, "Failed to build encrypted envelope");
    ASSERT_TEST(envelope != NULL, "Envelope is NULL");
    ASSERT_TEST(envelope->n_keywraps == 2, "Expected 2 key wraps");

    // Verify signature
    ASSERT_TEST(tw_envelope_verify(envelope) == 0, "Signature verification failed");

    // Verify envelope structure is correct
    ASSERT_TEST(envelope->ephemeral_pubkey.len == crypto_box_PUBLICKEYBYTES,
                "Invalid ephemeral pubkey size");
    ASSERT_TEST(envelope->payload_nonce.len == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
                "Invalid payload nonce size");
    ASSERT_TEST(envelope->payload_ciphertext.len > 0, 
                "Payload ciphertext is empty");

    // Cleanup
    tw_envelope_free(envelope);
    keystore_cleanup();

    printf("    ✓ multi-recipient encryption passed\n");
    return 0;
}

int test_envelope_serialization(void) {
    printf("  - test_envelope_serialization...\n");

    // Load admin key
    unsigned char admin_secret[crypto_sign_SECRETKEYBYTES];
    ASSERT_TEST(load_test_user_key("admin_001", admin_secret) == 0,
                "Failed to load admin_001 key");

    unsigned char admin_pubkey[PUBKEY_SIZE];
    get_public_key_from_secret(admin_secret, admin_pubkey);

    // Initialize keystore
    ASSERT_TEST(keystore_init() == 0, "Failed to init keystore");
    ASSERT_TEST(keystore_load_raw_ed25519_keypair(admin_secret) == 0, 
                "Failed to load keypair into keystore");

    // Create content
    const char* message = "Test message for serialization";
    size_t message_len = strlen(message) + 1;

    // Create header view (sender is also a recipient)
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

    // Build envelope
    Tinyweb__Envelope* envelope = NULL;
    int result = tw_envelope_build_and_sign(&header, (unsigned char*)message, message_len, &envelope);
    ASSERT_TEST(result == 0, "Failed to build envelope");
    ASSERT_TEST(envelope != NULL, "Envelope is NULL");

    // Serialize
    unsigned char* envelope_data1 = NULL;
    size_t envelope_size1 = 0;
    result = tw_envelope_serialize(envelope, &envelope_data1, &envelope_size1);
    ASSERT_TEST(result == 0, "Failed to serialize envelope");

    // Deserialize
    Tinyweb__Envelope* envelope2 = tw_envelope_deserialize(envelope_data1, envelope_size1);
    ASSERT_TEST(envelope2 != NULL, "Failed to deserialize envelope");

    // Serialize again
    unsigned char* envelope_data2 = NULL;
    size_t envelope_size2 = 0;
    result = tw_envelope_serialize(envelope2, &envelope_data2, &envelope_size2);
    ASSERT_TEST(result == 0, "Failed to serialize envelope2");

    // Sizes should match
    ASSERT_TEST(envelope_size1 == envelope_size2, "Serialization size mismatch");

    // Content should match
    ASSERT_TEST(memcmp(envelope_data1, envelope_data2, envelope_size1) == 0,
                "Serialized data mismatch");

    // Cleanup
    tw_envelope_free(envelope);
    tw_envelope_free(envelope2);
    free(envelope_data1);
    free(envelope_data2);
    keystore_cleanup();

    printf("    ✓ serialization round-trip passed\n");
    return 0;
}

int test_envelope_gossip_storage(void) {
    printf("  - test_envelope_gossip_storage...\n");

    // Initialize database
    const char* db_path = test_get_db_path();
    ASSERT_TEST(db_init_gossip(db_path) == 0, "Failed to init database");
    ASSERT_TEST(gossip_store_init() == 0, "Failed to init gossip store");

    // Load admin key
    unsigned char admin_secret[crypto_sign_SECRETKEYBYTES];
    ASSERT_TEST(load_test_user_key("admin_001", admin_secret) == 0,
                "Failed to load admin_001 key");

    unsigned char admin_pubkey[PUBKEY_SIZE];
    get_public_key_from_secret(admin_secret, admin_pubkey);

    // Initialize keystore
    ASSERT_TEST(keystore_init() == 0, "Failed to init keystore");
    ASSERT_TEST(keystore_load_raw_ed25519_keypair(admin_secret) == 0, 
                "Failed to load keypair into keystore");

    // Create envelope
    const char* message = "Test message for storage";
    size_t message_len = strlen(message) + 1;

    uint64_t timestamp = (uint64_t)time(NULL);
    
    // Create header view (sender is also a recipient)
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
    int result = tw_envelope_build_and_sign(&header, (unsigned char*)message, message_len, &envelope);
    ASSERT_TEST(result == 0, "Failed to build envelope");

    // Serialize for storage
    unsigned char* envelope_data = NULL;
    size_t envelope_size = 0;
    result = tw_envelope_serialize(envelope, &envelope_data, &envelope_size);
    ASSERT_TEST(result == 0, "Failed to serialize envelope");

    // Save to database
    uint64_t expires_at = timestamp + 3600;
    result = gossip_store_save_envelope(
        1,  // version
        TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE,
        1,  // schema_version
        admin_pubkey,
        timestamp,
        envelope_data,
        envelope_size,
        expires_at
    );

    ASSERT_TEST(result == 0, "Failed to save envelope");

    // Retrieve from database
    GossipStoredEnvelope* envelopes = NULL;
    size_t count = 0;

    result = gossip_store_fetch_recent_envelopes(10, &envelopes, &count);
    ASSERT_TEST(result == 0, "Failed to fetch envelopes");
    ASSERT_TEST(count >= 1, "No envelopes retrieved");

    // Verify retrieved envelope
    int found = 0;
    for (size_t i = 0; i < count; ++i) {
        if (memcmp(envelopes[i].sender, admin_pubkey, PUBKEY_SIZE) == 0 &&
            envelopes[i].envelope_size == envelope_size) {
            found = 1;
            ASSERT_TEST(envelopes[i].version == 1, "Version mismatch");
            ASSERT_TEST(envelopes[i].content_type == TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE,
                        "Content type mismatch");
            break;
        }
    }

    ASSERT_TEST(found == 1, "Stored envelope not found");

    // Cleanup
    gossip_store_free_envelopes(envelopes, count);
    tw_envelope_free(envelope);
    free(envelope_data);
    keystore_cleanup();
    db_close();

    printf("    ✓ gossip storage passed\n");
    return 0;
}

int envelope_test_main(void) {
    printf("\n=== Envelope Tests ===\n");

    int passed = 0;
    int failed = 0;

    if (test_envelope_create_sign_verify() == 0) {
        passed++;
    } else {
        failed++;
    }

    if (test_envelope_multi_recipient_encryption() == 0) {
        passed++;
    } else {
        failed++;
    }

    if (test_envelope_serialization() == 0) {
        passed++;
    } else {
        failed++;
    }

    if (test_envelope_gossip_storage() == 0) {
        passed++;
    } else {
        failed++;
    }

    printf("\nEnvelope Tests: %d passed, %d failed\n", passed, failed);
    return (failed == 0) ? 0 : 1;
}

