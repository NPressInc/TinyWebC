#include "message_validation.h"
#include "message.pb-c.h"
#include "packages/signing/signing.h"
#include "packages/utils/logger.h"
#include <time.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdlib.h>

#define MAX_MESSAGE_SIZE (1024 * 1024) // 1MB limit for now
#define CLOCK_SKEW_WINDOW 60 // 60 seconds for replay protection
#define MESSAGE_TTL (7 * 24 * 60 * 60) // 7 days default TTL

// Internal helper: Compute digest for signing (matches Frontend logic)
// SHA256(domain || raw_header_fields || SHA256(ciphertext))
static int compute_message_signing_digest(const Tinyweb__Message* msg, unsigned char out_hash[SHA256_DIGEST_LENGTH]) {
    if (!msg || !msg->header || !msg->payload_ciphertext.data) return -1;

    const Tinyweb__MessageHeader* hdr = msg->header;

    // 1. Hash ciphertext first
    unsigned char payload_hash[SHA256_DIGEST_LENGTH];
    SHA256(msg->payload_ciphertext.data, msg->payload_ciphertext.len, payload_hash);

    // 2. Compute digest from raw header data
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    
    // Domain separator (matches frontend approach)
    static const unsigned char domain[] = { 'T','W','M','E','S','S','A','G','E','\0' };
    SHA256_Update(&ctx, domain, sizeof(domain));
    
    // Header fields in canonical order:
    // 1. version (uint32, 4 bytes, little-endian)
    uint32_t version = hdr->version;
    SHA256_Update(&ctx, (unsigned char*)&version, sizeof(version));
    
    // 2. timestamp (uint64, 8 bytes, little-endian)
    uint64_t timestamp = hdr->timestamp;
    SHA256_Update(&ctx, (unsigned char*)&timestamp, sizeof(timestamp));
    
    // 3. sender_pubkey (32 bytes)
    if (hdr->sender_pubkey.len != 32) return -1;
    SHA256_Update(&ctx, hdr->sender_pubkey.data, 32);
    
    // 4. recipients_pubkey (count + data for each)
    uint32_t num_recipients = (uint32_t)hdr->n_recipients_pubkey;
    SHA256_Update(&ctx, (unsigned char*)&num_recipients, sizeof(num_recipients));
    for (size_t i = 0; i < hdr->n_recipients_pubkey; i++) {
        if (hdr->recipients_pubkey[i].len != 32) return -1;
        SHA256_Update(&ctx, hdr->recipients_pubkey[i].data, 32);
    }
    
    // 5. group_id (length + data, or empty)
    uint32_t group_id_len = (uint32_t)hdr->group_id.len;
    if (group_id_len > 64) return -1; // Sanity check
    SHA256_Update(&ctx, (unsigned char*)&group_id_len, sizeof(group_id_len));
    if (group_id_len > 0) {
        SHA256_Update(&ctx, hdr->group_id.data, group_id_len);
    }
    
    // 6. Payload hash
    SHA256_Update(&ctx, payload_hash, sizeof(payload_hash));
    
    SHA256_Final(out_hash, &ctx);
    return 0;
}

MessageValidationResult message_validate(const Tinyweb__Message* message) {
    if (!message || !message->header) return MESSAGE_VALIDATION_INVALID_FORMAT;

    // 1. Check timestamp (Replay protection: must be within 60s window)
    uint64_t now = (uint64_t)time(NULL);
    uint64_t msg_ts = message->header->timestamp;

    if (msg_ts > now + CLOCK_SKEW_WINDOW) {
        return MESSAGE_VALIDATION_FUTURE_TIMESTAMP;
    }
    if (msg_ts < now - CLOCK_SKEW_WINDOW) {
        return MESSAGE_VALIDATION_EXPIRED;
    }

    // 2. Check payload size
    if (message->payload_ciphertext.len > MAX_MESSAGE_SIZE) {
        return MESSAGE_VALIDATION_TOO_LARGE;
    }

    // 3. Verify Ed25519 signature
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (compute_message_signing_digest(message, digest) != 0) {
        logger_error("message_val", "Failed to compute message signing digest");
        return MESSAGE_VALIDATION_ERROR;
    }

    if (message->signature.len != 64) return MESSAGE_VALIDATION_INVALID_SIGNATURE;
    
    const unsigned char* pk = message->header->sender_pubkey.data;
    if (verify_signature(message->signature.data, digest, sizeof(digest), pk) != 0) {
        return MESSAGE_VALIDATION_INVALID_SIGNATURE;
    }

    return MESSAGE_VALIDATION_OK;
}

uint64_t message_validation_get_expiration(const Tinyweb__Message* message) {
    if (!message || !message->header) return 0;
    return message->header->timestamp + MESSAGE_TTL;
}

const char* message_validation_result_to_string(MessageValidationResult result) {
    switch (result) {
        case MESSAGE_VALIDATION_OK: return "OK";
        case MESSAGE_VALIDATION_INVALID_SIGNATURE: return "Invalid signature";
        case MESSAGE_VALIDATION_EXPIRED: return "Message expired (outside 60s window)";
        case MESSAGE_VALIDATION_FUTURE_TIMESTAMP: return "Message from the future";
        case MESSAGE_VALIDATION_TOO_LARGE: return "Message too large";
        case MESSAGE_VALIDATION_INVALID_FORMAT: return "Invalid message format";
        default: return "Unknown validation error";
    }
}

