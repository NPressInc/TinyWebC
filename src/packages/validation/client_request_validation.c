#include "client_request_validation.h"
#include "client_request.pb-c.h"
#include "packages/signing/signing.h"
#include "packages/utils/logger.h"
#include <time.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdlib.h>

#define MAX_CLIENT_REQUEST_SIZE (1024 * 1024) // 1MB limit for now
#define CLOCK_SKEW_WINDOW 60 // 60 seconds for replay protection
#define CLIENT_REQUEST_TTL (7 * 24 * 60 * 60) // 7 days default TTL (same as messages)

// Internal helper: Compute digest for signing (similar to message signing)
// SHA256(domain || raw_header_fields || SHA256(ciphertext))
static int compute_client_request_signing_digest(const Tinyweb__ClientRequest* req, unsigned char out_hash[SHA256_DIGEST_LENGTH]) {
    if (!req || !req->header || !req->payload_ciphertext.data) return -1;

    const Tinyweb__ClientRequestHeader* hdr = req->header;

    // 1. Hash ciphertext first
    unsigned char payload_hash[SHA256_DIGEST_LENGTH];
    SHA256(req->payload_ciphertext.data, req->payload_ciphertext.len, payload_hash);

    // 2. Compute digest from raw header data
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    
    // Domain separator (matches frontend approach for client requests)
    static const unsigned char domain[] = { 'T','W','C','L','I','E','N','T','R','E','Q','\0' };
    SHA256_Update(&ctx, domain, sizeof(domain));
    
    // Header fields in canonical order:
    // 1. version (uint32, 4 bytes, little-endian)
    uint32_t version = hdr->version;
    SHA256_Update(&ctx, (unsigned char*)&version, sizeof(version));
    
    // 2. content_type (uint32, 4 bytes, little-endian)
    uint32_t content_type = hdr->content_type;
    SHA256_Update(&ctx, (unsigned char*)&content_type, sizeof(content_type));
    
    // 3. schema_version (uint32, 4 bytes, little-endian)
    uint32_t schema_version = hdr->schema_version;
    SHA256_Update(&ctx, (unsigned char*)&schema_version, sizeof(schema_version));
    
    // 4. timestamp (uint64, 8 bytes, little-endian)
    uint64_t timestamp = hdr->timestamp;
    SHA256_Update(&ctx, (unsigned char*)&timestamp, sizeof(timestamp));
    
    // 5. sender_pubkey (32 bytes)
    if (hdr->sender_pubkey.len != 32) return -1;
    SHA256_Update(&ctx, hdr->sender_pubkey.data, 32);
    
    // 6. recipients_pubkey (count + data for each)
    uint32_t num_recipients = (uint32_t)hdr->n_recipients_pubkey;
    SHA256_Update(&ctx, (unsigned char*)&num_recipients, sizeof(num_recipients));
    for (size_t i = 0; i < hdr->n_recipients_pubkey; i++) {
        if (hdr->recipients_pubkey[i].len != 32) return -1;
        SHA256_Update(&ctx, hdr->recipients_pubkey[i].data, 32);
    }
    
    // 7. group_id (length + data, or empty)
    uint32_t group_id_len = (uint32_t)hdr->group_id.len;
    if (group_id_len > 64) return -1; // Sanity check
    SHA256_Update(&ctx, (unsigned char*)&group_id_len, sizeof(group_id_len));
    if (group_id_len > 0) {
        SHA256_Update(&ctx, hdr->group_id.data, group_id_len);
    }
    
    // 8. Payload hash
    SHA256_Update(&ctx, payload_hash, sizeof(payload_hash));
    
    SHA256_Final(out_hash, &ctx);
    return 0;
}

ClientRequestValidationResult client_request_validate(const Tinyweb__ClientRequest* request) {
    if (!request || !request->header) return CLIENT_REQUEST_VALIDATION_INVALID_FORMAT;

    // 1. Check timestamp (Replay protection: must be within 60s window)
    uint64_t now = (uint64_t)time(NULL);
    uint64_t req_ts = request->header->timestamp;

    if (req_ts > now + CLOCK_SKEW_WINDOW) {
        return CLIENT_REQUEST_VALIDATION_FUTURE_TIMESTAMP;
    }
    if (req_ts < now - CLOCK_SKEW_WINDOW) {
        return CLIENT_REQUEST_VALIDATION_EXPIRED;
    }

    // 2. Check payload size
    if (request->payload_ciphertext.len > MAX_CLIENT_REQUEST_SIZE) {
        return CLIENT_REQUEST_VALIDATION_TOO_LARGE;
    }

    // 3. Verify Ed25519 signature
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (compute_client_request_signing_digest(request, digest) != 0) {
        logger_error("client_request_val", "Failed to compute client request signing digest");
        return CLIENT_REQUEST_VALIDATION_ERROR;
    }

    if (request->signature.len != 64) return CLIENT_REQUEST_VALIDATION_INVALID_SIGNATURE;
    
    const unsigned char* pk = request->header->sender_pubkey.data;
    if (verify_signature(request->signature.data, digest, sizeof(digest), pk) != 0) {
        return CLIENT_REQUEST_VALIDATION_INVALID_SIGNATURE;
    }

    return CLIENT_REQUEST_VALIDATION_OK;
}

ClientRequestValidationResult client_request_validate_recipients(const Tinyweb__ClientRequest* request) {
    if (!request || !request->header) return CLIENT_REQUEST_VALIDATION_INVALID_FORMAT;

    const Tinyweb__ClientRequestHeader* hdr = request->header;
    
    // Check that we have at least one recipient
    if (hdr->n_recipients_pubkey == 0) {
        return CLIENT_REQUEST_VALIDATION_INVALID_RECIPIENTS;
    }
    
    // Check that all recipients in header have corresponding keywraps
    if (request->n_keywraps != hdr->n_recipients_pubkey) {
        logger_error("client_request_val", "Recipient count mismatch: header has %zu, keywraps has %zu",
                     hdr->n_recipients_pubkey, request->n_keywraps);
        return CLIENT_REQUEST_VALIDATION_INVALID_RECIPIENTS;
    }
    
    // Verify each recipient in header has a matching keywrap
    for (size_t i = 0; i < hdr->n_recipients_pubkey; i++) {
        const unsigned char* recipient_pubkey = hdr->recipients_pubkey[i].data;
        bool found = false;
        
        for (size_t j = 0; j < request->n_keywraps; j++) {
            const Tinyweb__ClientRequestKeyWrap* wrap = request->keywraps[j];
            if (wrap && wrap->recipient_pubkey.len == 32 &&
                memcmp(recipient_pubkey, wrap->recipient_pubkey.data, 32) == 0) {
                found = true;
                break;
            }
        }
        
        if (!found) {
            logger_error("client_request_val", "Recipient %zu in header has no matching keywrap", i);
            return CLIENT_REQUEST_VALIDATION_INVALID_RECIPIENTS;
        }
    }
    
    return CLIENT_REQUEST_VALIDATION_OK;
}

uint64_t client_request_get_expiration(const Tinyweb__ClientRequest* request) {
    if (!request || !request->header) return 0;
    return request->header->timestamp + CLIENT_REQUEST_TTL;
}

const char* client_request_validation_result_to_string(ClientRequestValidationResult result) {
    switch (result) {
        case CLIENT_REQUEST_VALIDATION_OK: return "OK";
        case CLIENT_REQUEST_VALIDATION_INVALID_SIGNATURE: return "Invalid signature";
        case CLIENT_REQUEST_VALIDATION_EXPIRED: return "Request expired (outside 60s window)";
        case CLIENT_REQUEST_VALIDATION_FUTURE_TIMESTAMP: return "Request from the future";
        case CLIENT_REQUEST_VALIDATION_TOO_LARGE: return "Request too large";
        case CLIENT_REQUEST_VALIDATION_INVALID_FORMAT: return "Invalid request format";
        case CLIENT_REQUEST_VALIDATION_INVALID_RECIPIENTS: return "Invalid recipients (missing keywraps)";
        case CLIENT_REQUEST_VALIDATION_ERROR:
        default: return "Unknown validation error";
    }
}

