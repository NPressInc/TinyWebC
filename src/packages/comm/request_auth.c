#include "request_auth.h"
#include "packages/sql/permissions.h"
#include "packages/signing/signing.h"
#include "packages/utils/logger.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/sha.h>
#include <sodium.h>

#define REQUEST_TIMESTAMP_WINDOW 300 // 5 minutes for request validity
#define MAX_HEADER_VALUE 256

// Extract header value (case-insensitive)
static int get_header_value(struct mg_http_message* hm, const char* header_name, char* out, size_t out_len) {
    struct mg_str* hdr = mg_http_get_header(hm, header_name);
    if (!hdr || hdr->len == 0) {
        return -1;
    }
    size_t copy_len = hdr->len < out_len - 1 ? hdr->len : out_len - 1;
    memcpy(out, hdr->buf, copy_len);
    out[copy_len] = '\0';
    return 0;
}

// Compute request signing digest
// Signs: method + uri + query + timestamp + pubkey
static int compute_request_digest(struct mg_http_message* hm, const char* timestamp, 
                                   const unsigned char* pubkey, unsigned char out_hash[SHA256_DIGEST_LENGTH]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    
    // Domain separator for request signing
    static const unsigned char domain[] = { 'T','W','R','E','Q','U','E','S','T','\0' };
    SHA256_Update(&ctx, domain, sizeof(domain));
    
    // 1. HTTP method
    SHA256_Update(&ctx, (unsigned char*)hm->method.buf, hm->method.len);
    
    // 2. URI path
    SHA256_Update(&ctx, (unsigned char*)hm->uri.buf, hm->uri.len);
    
    // 3. Query string (if present)
    if (hm->query.len > 0) {
        SHA256_Update(&ctx, (unsigned char*)hm->query.buf, hm->query.len);
    }
    
    // 4. Timestamp
    size_t ts_len = strlen(timestamp);
    SHA256_Update(&ctx, (unsigned char*)timestamp, ts_len);
    
    // 5. Public key
    SHA256_Update(&ctx, pubkey, 32);
    
    SHA256_Final(out_hash, &ctx);
    return 0;
}

RequestAuthResult validate_request_auth(struct mg_http_message* hm, unsigned char* out_pubkey) {
    if (!hm || !out_pubkey) {
        return REQUEST_AUTH_ERROR;
    }
    
    // 1. Extract and validate public key header
    char pubkey_hex[MAX_HEADER_VALUE];
    if (get_header_value(hm, "X-User-Pubkey", pubkey_hex, sizeof(pubkey_hex)) != 0) {
        return REQUEST_AUTH_MISSING_PUBKEY;
    }
    
    // Decode hex pubkey
    unsigned char pubkey[32];
    size_t bin_len = 0;
    if (sodium_hex2bin(pubkey, 32, pubkey_hex, strlen(pubkey_hex), NULL, &bin_len, NULL) != 0 || bin_len != 32) {
        return REQUEST_AUTH_INVALID_PUBKEY;
    }
    memcpy(out_pubkey, pubkey, 32);
    
    // 2. Extract and validate timestamp header
    char timestamp_str[MAX_HEADER_VALUE];
    if (get_header_value(hm, "X-Timestamp", timestamp_str, sizeof(timestamp_str)) != 0) {
        return REQUEST_AUTH_MISSING_TIMESTAMP;
    }
    
    uint64_t timestamp = (uint64_t)strtoull(timestamp_str, NULL, 10);
    uint64_t now = (uint64_t)time(NULL);
    
    // Check timestamp is within valid window (prevent replay attacks)
    if (timestamp > now + 60) { // Allow 60s clock skew
        return REQUEST_AUTH_FUTURE_TIMESTAMP;
    }
    if (timestamp < now - REQUEST_TIMESTAMP_WINDOW) {
        return REQUEST_AUTH_EXPIRED_TIMESTAMP;
    }
    
    // 3. Extract signature header
    char signature_hex[MAX_HEADER_VALUE];
    if (get_header_value(hm, "X-Signature", signature_hex, sizeof(signature_hex)) != 0) {
        return REQUEST_AUTH_MISSING_SIGNATURE;
    }
    
    // Decode hex signature (64 bytes for Ed25519)
    unsigned char signature[64];
    bin_len = 0;
    if (sodium_hex2bin(signature, 64, signature_hex, strlen(signature_hex), NULL, &bin_len, NULL) != 0 || bin_len != 64) {
        return REQUEST_AUTH_INVALID_SIGNATURE;
    }
    
    // 4. Compute request digest
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (compute_request_digest(hm, timestamp_str, pubkey, digest) != 0) {
        return REQUEST_AUTH_ERROR;
    }
    
    // Debug: log what we're verifying
    char method_buf[16] = {0};
    char uri_buf[256] = {0};
    char query_buf[256] = {0};
    size_t method_len = hm->method.len < sizeof(method_buf) - 1 ? hm->method.len : sizeof(method_buf) - 1;
    size_t uri_len = hm->uri.len < sizeof(uri_buf) - 1 ? hm->uri.len : sizeof(uri_buf) - 1;
    size_t query_len = hm->query.len < sizeof(query_buf) - 1 ? hm->query.len : sizeof(query_buf) - 1;
    if (hm->method.buf && method_len > 0) memcpy(method_buf, hm->method.buf, method_len);
    if (hm->uri.buf && uri_len > 0) memcpy(uri_buf, hm->uri.buf, uri_len);
    if (hm->query.buf && query_len > 0) memcpy(query_buf, hm->query.buf, query_len);
    method_buf[method_len] = '\0';
    uri_buf[uri_len] = '\0';
    query_buf[query_len] = '\0';
    
    char pubkey_hex_dbg[65];
    sodium_bin2hex(pubkey_hex_dbg, sizeof(pubkey_hex_dbg), pubkey, 32);
    char digest_hex[65];
    sodium_bin2hex(digest_hex, sizeof(digest_hex), digest, SHA256_DIGEST_LENGTH);
    
    logger_info("request_auth", "Verifying signature: method='%s' uri='%s' query='%s' timestamp='%s' pubkey='%s' digest='%s'",
                method_buf, uri_buf, query_buf, timestamp_str, pubkey_hex_dbg, digest_hex);
    
    // 5. Verify signature
    if (verify_signature(signature, digest, sizeof(digest), pubkey) != 0) {
        logger_error("request_auth", "Signature verification failed");
        return REQUEST_AUTH_INVALID_SIGNATURE;
    }
    
    // 6. Verify user is registered
    if (!user_exists(pubkey)) {
        return REQUEST_AUTH_USER_NOT_REGISTERED;
    }
    
    return REQUEST_AUTH_OK;
}

const char* request_auth_error_string(RequestAuthResult result) {
    switch (result) {
        case REQUEST_AUTH_OK:
            return "OK";
        case REQUEST_AUTH_MISSING_PUBKEY:
            return "Missing X-User-Pubkey header";
        case REQUEST_AUTH_MISSING_SIGNATURE:
            return "Missing X-Signature header";
        case REQUEST_AUTH_MISSING_TIMESTAMP:
            return "Missing X-Timestamp header";
        case REQUEST_AUTH_INVALID_PUBKEY:
            return "Invalid public key format";
        case REQUEST_AUTH_INVALID_SIGNATURE:
            return "Invalid signature";
        case REQUEST_AUTH_USER_NOT_REGISTERED:
            return "User not registered";
        case REQUEST_AUTH_EXPIRED_TIMESTAMP:
            return "Request timestamp expired";
        case REQUEST_AUTH_FUTURE_TIMESTAMP:
            return "Request timestamp too far in future";
        case REQUEST_AUTH_ERROR:
        default:
            return "Authentication error";
    }
}

