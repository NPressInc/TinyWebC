#include "tests/message_api_test.h"
#include "tests/test_init.h"
#include "packages/comm/messagesApi.h"
#include "packages/comm/gossipApi.h"
#include "packages/sql/message_store.h"
#include "packages/sql/database_gossip.h"
#include "packages/keystore/keystore.h"
#include "packages/signing/signing.h"
#include "message.pb-c.h"
#include "external/mongoose/mongoose.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>
#include <openssl/sha.h>

#define ASSERT_TEST(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s\n", msg); \
            return -1; \
        } \
    } while (0)

// Helper to create and sign a Message protobuf
static Tinyweb__Message* create_signed_message(const unsigned char sender_sk[64], const unsigned char recipient_pk[32]) {
    unsigned char sender_pk[32];
    crypto_sign_ed25519_sk_to_pk(sender_pk, sender_sk);

    Tinyweb__Message* msg = malloc(sizeof(Tinyweb__Message));
    tinyweb__message__init(msg);
    
    Tinyweb__MessageHeader* hdr = malloc(sizeof(Tinyweb__MessageHeader));
    tinyweb__message_header__init(hdr);
    hdr->version = 1;
    hdr->timestamp = (uint64_t)time(NULL);
    hdr->sender_pubkey.len = 32;
    hdr->sender_pubkey.data = malloc(32);
    memcpy(hdr->sender_pubkey.data, sender_pk, 32);
    
    hdr->n_recipients_pubkey = 1;
    hdr->recipients_pubkey = malloc(sizeof(ProtobufCBinaryData));
    hdr->recipients_pubkey[0].len = 32;
    hdr->recipients_pubkey[0].data = malloc(32);
    memcpy(hdr->recipients_pubkey[0].data, recipient_pk, 32);
    
    msg->header = hdr;
    
    msg->payload_nonce.len = 24;
    msg->payload_nonce.data = malloc(24);
    memset(msg->payload_nonce.data, 0xAA, 24);
    
    msg->ephemeral_pubkey.len = 32;
    msg->ephemeral_pubkey.data = malloc(32);
    memset(msg->ephemeral_pubkey.data, 0xBB, 32);
    
    msg->payload_ciphertext.len = 32;
    msg->payload_ciphertext.data = malloc(32);
    memset(msg->payload_ciphertext.data, 0xCC, 32);
    
    // We need to sign this. The digest logic must match message_validation.c
    // SHA256(domain || version || timestamp || sender || recipients_count || recipients || group_id_len || group_id || payload_hash)
    
    unsigned char payload_hash[32];
    SHA256(msg->payload_ciphertext.data, msg->payload_ciphertext.len, payload_hash);
    
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    static const unsigned char domain[] = { 'T','W','M','E','S','S','A','G','E','\0' };
    SHA256_Update(&ctx, domain, sizeof(domain));
    SHA256_Update(&ctx, &hdr->version, 4);
    SHA256_Update(&ctx, &hdr->timestamp, 8);
    SHA256_Update(&ctx, hdr->sender_pubkey.data, 32);
    uint32_t n_recp = 1;
    SHA256_Update(&ctx, &n_recp, 4);
    SHA256_Update(&ctx, hdr->recipients_pubkey[0].data, 32);
    uint32_t group_id_len = 0;
    SHA256_Update(&ctx, &group_id_len, 4);
    SHA256_Update(&ctx, payload_hash, 32);
    
    unsigned char digest[32];
    SHA256_Final(digest, &ctx);
    
    msg->signature.len = 64;
    msg->signature.data = malloc(64);
    crypto_sign_detached(msg->signature.data, NULL, digest, 32, sender_sk);
    
    return msg;
}

static int test_submit_message_endpoint(void) {
    printf("Testing POST /messages/submit...\n");
    
    unsigned char sender_sk[64], sender_pk[32], recipient_pk[32];
    crypto_sign_keypair(sender_pk, sender_sk);
    memset(recipient_pk, 0xEE, 32);
    
    Tinyweb__Message* msg = create_signed_message(sender_sk, recipient_pk);
    size_t packed_len = tinyweb__message__get_packed_size(msg);
    unsigned char* packed = malloc(packed_len);
    tinyweb__message__pack(msg, packed);
    
    // Create a mock Mongoose connection and message
    struct mg_connection c;
    memset(&c, 0, sizeof(c));
    struct mg_http_message hm;
    memset(&hm, 0, sizeof(hm));
    hm.method = mg_str("POST");
    hm.uri = mg_str("/messages/submit");
    hm.body = mg_str_n((const char*)packed, packed_len);
    
    // Note: In a real test we'd need to mock mg_http_reply or check DB
    // For now, we'll verify the handler logic returns true
    ASSERT_TEST(messages_api_handler(&c, &hm) == true, "Handler should handle /messages/submit");
    
    // Verify it's in the DB
    Tinyweb__Message** fetched = NULL;
    size_t count = 0;
    ASSERT_TEST(message_store_fetch_recent(recipient_pk, 10, &fetched, &count) == 0, "Fetch failed");
    ASSERT_TEST(count >= 1, "Message not stored in DB");
    
    message_store_free_messages(fetched, count);
    free(packed);
    tinyweb__message__free_unpacked(msg, NULL);
    
    printf("  ✓ /messages/submit passed\n");
    return 0;
}

int message_api_test_main(void) {
    printf("\n=== Message API Tests ===\n");
    
    if (db_init_gossip(test_get_db_path()) != 0) return -1;
    if (message_store_init() != 0) return -1;
    
    if (test_submit_message_endpoint() != 0) return -1;
    
    printf("All Message API tests passed!\n");
    return 0;
}


