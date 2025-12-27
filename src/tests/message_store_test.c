#include "tests/message_store_test.h"
#include "tests/test_init.h"
#include "packages/sql/message_store.h"
#include "packages/sql/database_gossip.h"
#include "packages/sql/schema.h"
#include "message.pb-c.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>

#define ASSERT_TEST(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL: %s\n", msg); \
            return -1; \
        } \
    } while (0)

static Tinyweb__Message* create_test_message(const unsigned char sender[32], const unsigned char recipient[32]) {
    Tinyweb__Message* msg = malloc(sizeof(Tinyweb__Message));
    tinyweb__message__init(msg);
    
    Tinyweb__MessageHeader* hdr = malloc(sizeof(Tinyweb__MessageHeader));
    tinyweb__message_header__init(hdr);
    hdr->version = 1;
    hdr->timestamp = (uint64_t)time(NULL);
    hdr->sender_pubkey.len = 32;
    hdr->sender_pubkey.data = malloc(32);
    memcpy(hdr->sender_pubkey.data, sender, 32);
    
    hdr->n_recipients_pubkey = 1;
    hdr->recipients_pubkey = malloc(sizeof(ProtobufCBinaryData));
    hdr->recipients_pubkey[0].len = 32;
    hdr->recipients_pubkey[0].data = malloc(32);
    memcpy(hdr->recipients_pubkey[0].data, recipient, 32);
    
    msg->header = hdr;
    
    msg->payload_nonce.len = 24;
    msg->payload_nonce.data = malloc(24);
    memset(msg->payload_nonce.data, 0x01, 24);
    
    msg->ephemeral_pubkey.len = 32;
    msg->ephemeral_pubkey.data = malloc(32);
    memset(msg->ephemeral_pubkey.data, 0x02, 32);
    
    msg->payload_ciphertext.len = 16;
    msg->payload_ciphertext.data = malloc(16);
    memset(msg->payload_ciphertext.data, 0x03, 16);
    
    msg->n_keywraps = 1;
    msg->keywraps = malloc(sizeof(Tinyweb__MessageRecipientKeyWrap*));
    msg->keywraps[0] = malloc(sizeof(Tinyweb__MessageRecipientKeyWrap));
    tinyweb__message_recipient_key_wrap__init(msg->keywraps[0]);
    msg->keywraps[0]->recipient_pubkey.len = 32;
    msg->keywraps[0]->recipient_pubkey.data = malloc(32);
    memcpy(msg->keywraps[0]->recipient_pubkey.data, recipient, 32);
    msg->keywraps[0]->key_nonce.len = 24;
    msg->keywraps[0]->key_nonce.data = malloc(24);
    memset(msg->keywraps[0]->key_nonce.data, 0x04, 24);
    msg->keywraps[0]->wrapped_key.len = 32;
    msg->keywraps[0]->wrapped_key.data = malloc(32);
    memset(msg->keywraps[0]->wrapped_key.data, 0x05, 32);
    
    msg->signature.len = 64;
    msg->signature.data = malloc(64);
    memset(msg->signature.data, 0x06, 64);
    
    return msg;
}

static int test_save_and_fetch_recent(void) {
    printf("Testing message_store_save and fetch_recent...\n");
    
    unsigned char sender[32], recipient[32];
    memset(sender, 0x11, 32);
    memset(recipient, 0x22, 32);
    
    Tinyweb__Message* msg = create_test_message(sender, recipient);
    uint64_t expires_at = (uint64_t)time(NULL) + 3600;
    
    ASSERT_TEST(message_store_save(msg, expires_at) == 0, "Failed to save message");
    
    Tinyweb__Message** fetched = NULL;
    size_t count = 0;
    ASSERT_TEST(message_store_fetch_recent(recipient, 10, &fetched, &count) == 0, "Failed to fetch recent messages");
    ASSERT_TEST(count == 1, "Expected 1 message");
    ASSERT_TEST(fetched[0]->header->sender_pubkey.len == 32, "Sender pubkey len mismatch");
    ASSERT_TEST(memcmp(fetched[0]->header->sender_pubkey.data, sender, 32) == 0, "Sender pubkey mismatch");
    
    message_store_free_messages(fetched, count);
    tinyweb__message__free_unpacked(msg, NULL);
    
    printf("  ✓ save and fetch_recent passed\n");
    return 0;
}

static int test_fetch_conversation(void) {
    printf("Testing message_store_fetch_conversation...\n");
    
    unsigned char user1[32], user2[32];
    memset(user1, 0x33, 32);
    memset(user2, 0x44, 32);
    
    // User 1 to User 2
    Tinyweb__Message* msg1 = create_test_message(user1, user2);
    ASSERT_TEST(message_store_save(msg1, time(NULL) + 3600) == 0, "Save msg1 failed");
    
    // User 2 to User 1
    Tinyweb__Message* msg2 = create_test_message(user2, user1);
    ASSERT_TEST(message_store_save(msg2, time(NULL) + 3600) == 0, "Save msg2 failed");
    
    Tinyweb__Message** fetched = NULL;
    size_t count = 0;
    ASSERT_TEST(message_store_fetch_conversation(user1, user2, 10, &fetched, &count) == 0, "Fetch conversation failed");
    ASSERT_TEST(count == 2, "Expected 2 messages in conversation");
    
    message_store_free_messages(fetched, count);
    tinyweb__message__free_unpacked(msg1, NULL);
    tinyweb__message__free_unpacked(msg2, NULL);
    
    printf("  ✓ fetch_conversation passed\n");
    return 0;
}

static int test_deduplication(void) {
    printf("Testing message deduplication...\n");
    
    unsigned char sender[32], recipient[32];
    memset(sender, 0x55, 32);
    memset(recipient, 0x66, 32);
    
    Tinyweb__Message* msg = create_test_message(sender, recipient);
    unsigned char digest[32];
    ASSERT_TEST(message_store_compute_digest(msg, digest) == 0, "Compute digest failed");
    
    int seen = 0;
    ASSERT_TEST(message_store_has_seen(digest, &seen) == 0, "has_seen initial failed");
    ASSERT_TEST(seen == 0, "Should not have seen message yet");
    
    uint64_t expires_at = time(NULL) + 3600;
    ASSERT_TEST(message_store_mark_seen(digest, expires_at) == 0, "mark_seen failed");
    
    ASSERT_TEST(message_store_has_seen(digest, &seen) == 0, "has_seen after mark failed");
    ASSERT_TEST(seen == 1, "Should have seen message now");
    
    tinyweb__message__free_unpacked(msg, NULL);
    printf("  ✓ deduplication passed\n");
    return 0;
}

int message_store_test_main(void) {
    printf("\n=== Message Store Tests ===\n");
    
    // The test runner calls test_init_environment() which creates the DB
    // and initializes the schemas. We just need to open the database handle
    // for this test's thread.
    const char* db_path = test_get_db_path();
    
    // Check if database is already initialized (e.g., from another test)
    if (!db_is_initialized()) {
        if (db_init_gossip(db_path) != 0) {
            fprintf(stderr, "Failed to initialize database: %s\n", db_path);
            return -1;
        }
    }
    
    // The schema should already be initialized by test_init_environment()
    // No need to call gossip_store_init() or message_store_init() again
    
    if (test_save_and_fetch_recent() != 0) return -1;
    if (test_fetch_conversation() != 0) return -1;
    if (test_deduplication() != 0) return -1;
    
    printf("All Message Store tests passed!\n");
    return 0;
}

