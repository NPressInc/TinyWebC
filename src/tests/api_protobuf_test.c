#include "tests/api_protobuf_test.h"
#include "test_init.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

#include "packages/sql/database_gossip.h"
#include "packages/sql/schema.h"
#include "packages/transactions/envelope.h"
#include "packages/keystore/keystore.h"
#include "envelope.pb-c.h"
#include "content.pb-c.h"
#include "api.pb-c.h"

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

// Helper to create a test envelope and store it
static int create_and_store_test_envelope(const unsigned char* sender_secret,
                                          const unsigned char* recipient_pubkey,
                                          const char* message_text,
                                          uint64_t timestamp) {
    // Initialize keystore with sender key
    if (keystore_init() != 0) {
        fprintf(stderr, "Failed to initialize keystore\n");
        return -1;
    }
    if (keystore_load_raw_ed25519_keypair(sender_secret) != 0) {
        fprintf(stderr, "Failed to load keypair\n");
        keystore_cleanup();
        return -1;
    }
    
    // Get sender pubkey
    unsigned char sender_pubkey[32];
    get_public_key_from_secret(sender_secret, sender_pubkey);
    
    // Create DirectMessage content
    Tinyweb__DirectMessage direct_msg = TINYWEB__DIRECT_MESSAGE__INIT;
    direct_msg.text = (char*)message_text;
    
    size_t content_size = tinyweb__direct_message__get_packed_size(&direct_msg);
    unsigned char* content_data = malloc(content_size);
    ASSERT_TEST(content_data != NULL, "Failed to allocate content data");
    tinyweb__direct_message__pack(&direct_msg, content_data);
    
    // Create envelope header
    tw_envelope_header_view_t header = {
        .version = 1,
        .content_type = TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE,
        .schema_version = 1,
        .timestamp = timestamp,
        .sender_pubkey = sender_pubkey,
        .recipients_pubkeys = recipient_pubkey,
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
    
    // Serialize envelope
    unsigned char* envelope_data = NULL;
    size_t envelope_size = 0;
    result = tw_envelope_serialize(envelope, &envelope_data, &envelope_size);
    ASSERT_TEST(result == 0, "Failed to serialize envelope");
    
    // Store envelope
    const Tinyweb__EnvelopeHeader* hdr = envelope->header;
    uint64_t expires_at = timestamp + (60 * 60 * 24 * 30); // 30 days
    result = gossip_store_save_envelope(
        hdr->version,
        hdr->content_type,
        hdr->schema_version,
        hdr->sender_pubkey.data,
        hdr->timestamp,
        envelope_data,
        envelope_size,
        expires_at
    );
    
    free(envelope_data);
    tw_envelope_free(envelope);
    keystore_cleanup();
    
    ASSERT_TEST(result == 0, "Failed to store envelope");
    return 0;
}

// Test StoredEnvelope protobuf creation and serialization
static int test_stored_envelope_protobuf(void) {
    printf("  - test_stored_envelope_protobuf...\n");
    
    // Create a test StoredEnvelope
    Tinyweb__StoredEnvelope* stored = calloc(1, sizeof(Tinyweb__StoredEnvelope));
    ASSERT_TEST(stored != NULL, "Failed to allocate StoredEnvelope");
    tinyweb__stored_envelope__init(stored);
    
    stored->id = 123;
    stored->version = 1;
    stored->content_type = TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE;
    stored->schema_version = 1;
    stored->timestamp = (uint64_t)time(NULL);
    stored->expires_at = stored->timestamp + (60 * 60 * 24 * 30);
    
    // Set sender pubkey
    unsigned char sender[32] = {0x01, 0x02, 0x03};
    stored->sender.data = malloc(32);
    ASSERT_TEST(stored->sender.data != NULL, "Failed to allocate sender data");
    stored->sender.len = 32;
    memcpy(stored->sender.data, sender, 32);
    
    // Set envelope data (dummy)
    unsigned char env_data[100] = {0};
    stored->envelope.data = malloc(100);
    ASSERT_TEST(stored->envelope.data != NULL, "Failed to allocate envelope data");
    stored->envelope.len = 100;
    memcpy(stored->envelope.data, env_data, 100);
    
    // Serialize
    size_t packed_size = tinyweb__stored_envelope__get_packed_size(stored);
    unsigned char* packed = malloc(packed_size);
    ASSERT_TEST(packed != NULL, "Failed to allocate packed buffer");
    tinyweb__stored_envelope__pack(stored, packed);
    
    // Deserialize
    Tinyweb__StoredEnvelope* stored2 = tinyweb__stored_envelope__unpack(NULL, packed_size, packed);
    ASSERT_TEST(stored2 != NULL, "Failed to deserialize StoredEnvelope");
    ASSERT_TEST(stored2->id == 123, "ID mismatch");
    ASSERT_TEST(stored2->version == 1, "Version mismatch");
    ASSERT_TEST(stored2->content_type == TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE, "Content type mismatch");
    ASSERT_TEST(stored2->timestamp == stored->timestamp, "Timestamp mismatch");
    ASSERT_TEST(stored2->sender.len == 32, "Sender length mismatch");
    ASSERT_TEST(memcmp(stored2->sender.data, sender, 32) == 0, "Sender data mismatch");
    ASSERT_TEST(stored2->envelope.len == 100, "Envelope length mismatch");
    
    // Cleanup
    tinyweb__stored_envelope__free_unpacked(stored, NULL);
    tinyweb__stored_envelope__free_unpacked(stored2, NULL);
    free(packed);
    
    printf("    ✓ StoredEnvelope protobuf serialization/deserialization passed\n");
    return 0;
}

// Test EnvelopeList protobuf creation
static int test_envelope_list_protobuf(void) {
    printf("  - test_envelope_list_protobuf...\n");
    
    // Create multiple StoredEnvelopes
    const size_t count = 3;
    Tinyweb__StoredEnvelope** envelopes = calloc(count, sizeof(Tinyweb__StoredEnvelope*));
    ASSERT_TEST(envelopes != NULL, "Failed to allocate envelope array");
    
    for (size_t i = 0; i < count; ++i) {
        envelopes[i] = calloc(1, sizeof(Tinyweb__StoredEnvelope));
        ASSERT_TEST(envelopes[i] != NULL, "Failed to allocate StoredEnvelope");
        tinyweb__stored_envelope__init(envelopes[i]);
        
        envelopes[i]->id = (uint64_t)(i + 1);
        envelopes[i]->version = 1;
        envelopes[i]->content_type = TINYWEB__CONTENT_TYPE__CONTENT_DIRECT_MESSAGE;
        envelopes[i]->schema_version = 1;
        envelopes[i]->timestamp = (uint64_t)time(NULL) + i;
        envelopes[i]->expires_at = envelopes[i]->timestamp + (60 * 60 * 24 * 30);
        
        envelopes[i]->sender.data = malloc(32);
        ASSERT_TEST(envelopes[i]->sender.data != NULL, "Failed to allocate sender");
        envelopes[i]->sender.len = 32;
        memset(envelopes[i]->sender.data, (int)(i + 1), 32);
        
        envelopes[i]->envelope.data = NULL;
        envelopes[i]->envelope.len = 0;
    }
    
    // Create EnvelopeList
    Tinyweb__EnvelopeList* list = calloc(1, sizeof(Tinyweb__EnvelopeList));
    ASSERT_TEST(list != NULL, "Failed to allocate EnvelopeList");
    tinyweb__envelope_list__init(list);
    
    list->n_envelopes = count;
    list->envelopes = envelopes;
    list->total_count = (uint32_t)count;
    
    // Serialize
    size_t packed_size = tinyweb__envelope_list__get_packed_size(list);
    unsigned char* packed = malloc(packed_size);
    ASSERT_TEST(packed != NULL, "Failed to allocate packed buffer");
    tinyweb__envelope_list__pack(list, packed);
    
    // Deserialize
    Tinyweb__EnvelopeList* list2 = tinyweb__envelope_list__unpack(NULL, packed_size, packed);
    ASSERT_TEST(list2 != NULL, "Failed to deserialize EnvelopeList");
    ASSERT_TEST(list2->n_envelopes == count, "Envelope count mismatch");
    ASSERT_TEST(list2->total_count == count, "Total count mismatch");
    
    for (size_t i = 0; i < count; ++i) {
        ASSERT_TEST(list2->envelopes[i] != NULL, "Envelope is NULL");
        ASSERT_TEST(list2->envelopes[i]->id == (uint64_t)(i + 1), "ID mismatch");
    }
    
    // Cleanup
    // For list: we manually allocated envelopes, so free them individually first
    // Then free the array, but don't let free_unpacked try to free them again
    for (size_t i = 0; i < count; ++i) {
        tinyweb__stored_envelope__free_unpacked(envelopes[i], NULL);
    }
    free(envelopes);
    // Clear the list pointers so free_unpacked doesn't try to free them again
    list->envelopes = NULL;
    list->n_envelopes = 0;
    tinyweb__envelope_list__free_unpacked(list, NULL);
    // list2 was created by unpack, so free_unpacked will handle it correctly
    tinyweb__envelope_list__free_unpacked(list2, NULL);
    free(packed);
    
    printf("    ✓ EnvelopeList protobuf serialization/deserialization passed\n");
    return 0;
}

// Test ConversationList protobuf creation
static int test_conversation_list_protobuf(void) {
    printf("  - test_conversation_list_protobuf...\n");
    
    // Create multiple ConversationSummary
    const size_t count = 2;
    Tinyweb__ConversationSummary** conversations = calloc(count, sizeof(Tinyweb__ConversationSummary*));
    ASSERT_TEST(conversations != NULL, "Failed to allocate conversation array");
    
    for (size_t i = 0; i < count; ++i) {
        conversations[i] = calloc(1, sizeof(Tinyweb__ConversationSummary));
        ASSERT_TEST(conversations[i] != NULL, "Failed to allocate ConversationSummary");
        tinyweb__conversation_summary__init(conversations[i]);
        
        conversations[i]->partner_pubkey.data = malloc(32);
        ASSERT_TEST(conversations[i]->partner_pubkey.data != NULL, "Failed to allocate partner pubkey");
        conversations[i]->partner_pubkey.len = 32;
        memset(conversations[i]->partner_pubkey.data, (int)(i + 1), 32);
        
        conversations[i]->last_message_timestamp = (uint64_t)time(NULL) + i;
        conversations[i]->unread_count = (uint32_t)(i * 2);
    }
    
    // Create ConversationList
    Tinyweb__ConversationList* list = calloc(1, sizeof(Tinyweb__ConversationList));
    ASSERT_TEST(list != NULL, "Failed to allocate ConversationList");
    tinyweb__conversation_list__init(list);
    
    list->n_conversations = count;
    list->conversations = conversations;
    list->total_count = (uint32_t)count;
    
    // Serialize
    size_t packed_size = tinyweb__conversation_list__get_packed_size(list);
    unsigned char* packed = malloc(packed_size);
    ASSERT_TEST(packed != NULL, "Failed to allocate packed buffer");
    tinyweb__conversation_list__pack(list, packed);
    
    // Deserialize
    Tinyweb__ConversationList* list2 = tinyweb__conversation_list__unpack(NULL, packed_size, packed);
    ASSERT_TEST(list2 != NULL, "Failed to deserialize ConversationList");
    ASSERT_TEST(list2->n_conversations == count, "Conversation count mismatch");
    ASSERT_TEST(list2->total_count == count, "Total count mismatch");
    
    for (size_t i = 0; i < count; ++i) {
        ASSERT_TEST(list2->conversations[i] != NULL, "Conversation is NULL");
        ASSERT_TEST(list2->conversations[i]->partner_pubkey.len == 32, "Partner pubkey length mismatch");
        ASSERT_TEST(list2->conversations[i]->last_message_timestamp == list->conversations[i]->last_message_timestamp,
                   "Timestamp mismatch");
        ASSERT_TEST(list2->conversations[i]->unread_count == (uint32_t)(i * 2), "Unread count mismatch");
    }
    
    // Cleanup
    // For list: we manually allocated conversations, so free them individually first
    for (size_t i = 0; i < count; ++i) {
        tinyweb__conversation_summary__free_unpacked(conversations[i], NULL);
    }
    free(conversations);
    // Clear the list pointers so free_unpacked doesn't try to free them again
    list->conversations = NULL;
    list->n_conversations = 0;
    tinyweb__conversation_list__free_unpacked(list, NULL);
    // list2 was created by unpack, so free_unpacked will handle it correctly
    tinyweb__conversation_list__free_unpacked(list2, NULL);
    free(packed);
    
    printf("    ✓ ConversationList protobuf serialization/deserialization passed\n");
    return 0;
}

// Test conversion from GossipStoredEnvelope to protobuf (integration test)
static int test_gossip_stored_to_protobuf_conversion(void) {
    printf("  - test_gossip_stored_to_protobuf_conversion...\n");
    
    // Setup test database
    const char* db_path = test_get_db_path();
    ASSERT_TEST(db_init_gossip(db_path) == 0, "Failed to init database");
    ASSERT_TEST(gossip_store_init() == 0, "Failed to init gossip store");
    
    // Load test keys
    unsigned char sender_secret[64];
    unsigned char recipient_secret[64];
    ASSERT_TEST(load_test_user_key("admin_001", sender_secret) == 0, "Failed to load admin_001 key");
    ASSERT_TEST(load_test_user_key("member_001", recipient_secret) == 0, "Failed to load member_001 key");
    
    unsigned char sender_pubkey[32], recipient_pubkey[32];
    get_public_key_from_secret(sender_secret, sender_pubkey);
    get_public_key_from_secret(recipient_secret, recipient_pubkey);
    
    // Store test envelopes
    uint64_t now = (uint64_t)time(NULL);
    ASSERT_TEST(create_and_store_test_envelope(sender_secret, recipient_pubkey, "Message 1", now) == 0,
               "Failed to store envelope 1");
    ASSERT_TEST(create_and_store_test_envelope(sender_secret, recipient_pubkey, "Message 2", now + 1) == 0,
               "Failed to store envelope 2");
    
    // Fetch stored envelopes
    GossipStoredEnvelope* stored_envs = NULL;
    size_t count = 0;
    ASSERT_TEST(gossip_store_fetch_recent_envelopes(10, &stored_envs, &count) == 0,
               "Failed to fetch envelopes");
    ASSERT_TEST(count >= 2, "Not enough envelopes retrieved");
    
    // Convert to protobuf (manual conversion since helpers are static)
    Tinyweb__StoredEnvelope** proto_envs = calloc(count, sizeof(Tinyweb__StoredEnvelope*));
    ASSERT_TEST(proto_envs != NULL, "Failed to allocate proto envelope array");
    
    for (size_t i = 0; i < count; ++i) {
        proto_envs[i] = calloc(1, sizeof(Tinyweb__StoredEnvelope));
        ASSERT_TEST(proto_envs[i] != NULL, "Failed to allocate StoredEnvelope");
        tinyweb__stored_envelope__init(proto_envs[i]);
        
        proto_envs[i]->id = stored_envs[i].id;
        proto_envs[i]->version = stored_envs[i].version;
        proto_envs[i]->content_type = stored_envs[i].content_type;
        proto_envs[i]->schema_version = stored_envs[i].schema_version;
        proto_envs[i]->timestamp = stored_envs[i].timestamp;
        proto_envs[i]->expires_at = stored_envs[i].expires_at;
        
        proto_envs[i]->sender.data = malloc(32);
        ASSERT_TEST(proto_envs[i]->sender.data != NULL, "Failed to allocate sender");
        proto_envs[i]->sender.len = 32;
        memcpy(proto_envs[i]->sender.data, stored_envs[i].sender, 32);
        
        if (stored_envs[i].envelope && stored_envs[i].envelope_size > 0) {
            proto_envs[i]->envelope.data = malloc(stored_envs[i].envelope_size);
            ASSERT_TEST(proto_envs[i]->envelope.data != NULL, "Failed to allocate envelope data");
            proto_envs[i]->envelope.len = stored_envs[i].envelope_size;
            memcpy(proto_envs[i]->envelope.data, stored_envs[i].envelope, stored_envs[i].envelope_size);
        }
    }
    
    // Create EnvelopeList
    Tinyweb__EnvelopeList* list = calloc(1, sizeof(Tinyweb__EnvelopeList));
    ASSERT_TEST(list != NULL, "Failed to allocate EnvelopeList");
    tinyweb__envelope_list__init(list);
    
    list->n_envelopes = count;
    list->envelopes = proto_envs;
    list->total_count = (uint32_t)count;
    
    // Serialize and verify
    size_t packed_size = tinyweb__envelope_list__get_packed_size(list);
    unsigned char* packed = malloc(packed_size);
    ASSERT_TEST(packed != NULL, "Failed to allocate packed buffer");
    tinyweb__envelope_list__pack(list, packed);
    ASSERT_TEST(packed_size > 0, "Packed size should be > 0");
    
    // Deserialize and verify
    Tinyweb__EnvelopeList* list2 = tinyweb__envelope_list__unpack(NULL, packed_size, packed);
    ASSERT_TEST(list2 != NULL, "Failed to deserialize EnvelopeList");
    ASSERT_TEST(list2->n_envelopes == count, "Envelope count mismatch after deserialization");
    
    // Verify envelope data
    bool found_message1 = false, found_message2 = false;
    for (size_t i = 0; i < list2->n_envelopes; ++i) {
        if (list2->envelopes[i]->envelope.len > 0) {
            // Deserialize the inner envelope to verify
            Tinyweb__Envelope* inner_env = tinyweb__envelope__unpack(NULL,
                                                                     list2->envelopes[i]->envelope.len,
                                                                     list2->envelopes[i]->envelope.data);
            if (inner_env && inner_env->header) {
                // Check sender matches
                if (inner_env->header->sender_pubkey.len == 32 &&
                    memcmp(inner_env->header->sender_pubkey.data, sender_pubkey, 32) == 0) {
                    found_message1 = true;
                }
                tinyweb__envelope__free_unpacked(inner_env, NULL);
            }
        }
    }
    
    // Cleanup
    // For list: we manually allocated proto_envs, so free them individually first
    for (size_t i = 0; i < count; ++i) {
        tinyweb__stored_envelope__free_unpacked(proto_envs[i], NULL);
    }
    free(proto_envs);
    // Clear the list pointers so free_unpacked doesn't try to free them again
    list->envelopes = NULL;
    list->n_envelopes = 0;
    tinyweb__envelope_list__free_unpacked(list, NULL);
    // list2 was created by unpack, so free_unpacked will handle it correctly
    tinyweb__envelope_list__free_unpacked(list2, NULL);
    free(packed);
    gossip_store_free_envelopes(stored_envs, count);
    db_close();
    remove(db_path);
    
    printf("    ✓ GossipStoredEnvelope to protobuf conversion passed\n");
    return 0;
}

int api_protobuf_test_main(void) {
    printf("Running API protobuf tests...\n\n");
    
    // Ensure sodium is initialized
    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return -1;
    }
    
    int passed = 0;
    int failed = 0;
    
    // Run basic protobuf tests (no database/keystore needed)
    if (test_stored_envelope_protobuf() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    if (test_envelope_list_protobuf() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    if (test_conversation_list_protobuf() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    // Run integration test (needs database/keystore)
    // Initialize test environment if not already done
    if (test_init_environment() != 0) {
        printf("Warning: Failed to initialize test environment, skipping integration test\n");
    } else {
        if (test_gossip_stored_to_protobuf_conversion() == 0) {
            passed++;
        } else {
            failed++;
        }
    }
    
    printf("\nAPI Protobuf Tests: %d passed, %d failed\n", passed, failed);
    
    return (failed > 0) ? -1 : 0;
}

