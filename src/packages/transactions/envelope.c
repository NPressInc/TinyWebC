#include "envelope.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

#include "packages/keystore/keystore.h"
#include "packages/signing/signing.h"
#include "packages/utils/logger.h"

#include "envelope.pb-c.h"

static int compute_envelope_digest(const Tinyweb__EnvelopeHeader* hdr,
                                   const unsigned char* cipher,
                                   size_t cipher_len,
                                   unsigned char out_hash[SHA256_DIGEST_LENGTH]) {
    if (!hdr || !cipher) return -1;

    // Hash ciphertext first
    unsigned char payload_hash[SHA256_DIGEST_LENGTH];
    SHA256(cipher, cipher_len, payload_hash);

    // Compute digest from raw header data (not protobuf-serialized)
    // This matches the frontend approach and is cleaner
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    
    // Domain separator
    static const unsigned char domain[] = { 'T','W','E','N','V','E','L','O','P','E','\0' };
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
    uint32_t num_recipients = hdr->n_recipients_pubkey;
    SHA256_Update(&ctx, (unsigned char*)&num_recipients, sizeof(num_recipients));
    for (size_t i = 0; i < num_recipients; i++) {
        if (hdr->recipients_pubkey[i].len != 32) return -1;
        SHA256_Update(&ctx, hdr->recipients_pubkey[i].data, 32);
    }
    
    // 7. group_id (length + data, or empty)
    uint32_t group_id_len = hdr->group_id.len;
    SHA256_Update(&ctx, (unsigned char*)&group_id_len, sizeof(group_id_len));
    if (group_id_len > 0) {
        SHA256_Update(&ctx, hdr->group_id.data, group_id_len);
    }
    
    // 8. Payload hash
    SHA256_Update(&ctx, payload_hash, sizeof(payload_hash));
    
    SHA256_Final(out_hash, &ctx);
    return 0;
}

int tw_envelope_serialize(const Tinyweb__Envelope* env, unsigned char** out, size_t* out_len) {
    if (!env || !out || !out_len) return -1;
    size_t len = tinyweb__envelope__get_packed_size((Tinyweb__Envelope*)env);
    unsigned char* buf = malloc(len);
    if (!buf) return -1;
    tinyweb__envelope__pack((Tinyweb__Envelope*)env, buf);
    *out = buf;
    *out_len = len;
    return 0;
}

Tinyweb__Envelope* tw_envelope_deserialize(const unsigned char* buf, size_t len) {
    if (!buf || !len) return NULL;
    return tinyweb__envelope__unpack(NULL, len, buf);
}

void tw_envelope_free(Tinyweb__Envelope* env) {
    if (env) tinyweb__envelope__free_unpacked(env, NULL);
}

int tw_envelope_build_and_sign(const tw_envelope_header_view_t* view,
                               const unsigned char* plaintext,
                               size_t plaintext_len,
                               Tinyweb__Envelope** out_env) {
    if (!view || !plaintext || !out_env) return -1;

    // Allocate envelope
    Tinyweb__Envelope* env = calloc(1, sizeof(Tinyweb__Envelope));
    if (!env) return -1;
    tinyweb__envelope__init(env);

    // Allocate and populate header
    Tinyweb__EnvelopeHeader* hdr = calloc(1, sizeof(Tinyweb__EnvelopeHeader));
    if (!hdr) {
        free(env);
        return -1;
    }
    tinyweb__envelope_header__init(hdr);
    
    hdr->version = view->version;
    hdr->content_type = view->content_type;
    hdr->schema_version = view->schema_version;
    hdr->timestamp = view->timestamp;
    
    // Allocate and copy sender pubkey
    hdr->sender_pubkey.len = PUBKEY_SIZE;
    hdr->sender_pubkey.data = malloc(PUBKEY_SIZE);
    if (!hdr->sender_pubkey.data) {
        free(hdr);
        free(env);
        return -1;
    }
    memcpy(hdr->sender_pubkey.data, view->sender_pubkey, PUBKEY_SIZE);

    // Allocate and copy recipients_pubkey
    hdr->n_recipients_pubkey = view->num_recipients;
    hdr->recipients_pubkey = calloc(view->num_recipients, sizeof(ProtobufCBinaryData));
    if (!hdr->recipients_pubkey) {
        free(hdr->sender_pubkey.data);
        free(hdr);
        free(env);
        return -1;
    }
    for (size_t i = 0; i < view->num_recipients; ++i) {
        hdr->recipients_pubkey[i].len = PUBKEY_SIZE;
        hdr->recipients_pubkey[i].data = malloc(PUBKEY_SIZE);
        if (!hdr->recipients_pubkey[i].data) {
            for (size_t j = 0; j < i; ++j) free(hdr->recipients_pubkey[j].data);
            free(hdr->recipients_pubkey);
            free(hdr->sender_pubkey.data);
            free(hdr);
            free(env);
            return -1;
        }
        memcpy(hdr->recipients_pubkey[i].data, view->recipients_pubkeys + i * PUBKEY_SIZE, PUBKEY_SIZE);
    }

    // Copy group_id if provided
    if (view->group_id && view->group_id_len > 0) {
        hdr->group_id.len = view->group_id_len;
        hdr->group_id.data = malloc(view->group_id_len);
        if (!hdr->group_id.data) {
            for (size_t j = 0; j < view->num_recipients; ++j) free(hdr->recipients_pubkey[j].data);
            free(hdr->recipients_pubkey);
            free(hdr->sender_pubkey.data);
            free(hdr);
            free(env);
            return -1;
        }
        memcpy(hdr->group_id.data, view->group_id, view->group_id_len);
    } else {
        hdr->group_id.data = NULL;
        hdr->group_id.len = 0;
    }

    env->header = hdr;

    // Encrypt plaintext directly into envelope
    if (encrypt_envelope_payload(plaintext, plaintext_len,
                                 view->recipients_pubkeys, view->num_recipients,
                                 env) != 0) {
        if (hdr->group_id.data) free(hdr->group_id.data);
        for (size_t j = 0; j < view->num_recipients; ++j) free(hdr->recipients_pubkey[j].data);
        free(hdr->recipients_pubkey);
        free(hdr->sender_pubkey.data);
        free(hdr);
        free(env);
        return -1;
    }

    // Compute digest and sign
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (compute_envelope_digest(env->header, env->payload_ciphertext.data, env->payload_ciphertext.len, digest) != 0) {
        tinyweb__envelope__free_unpacked(env, NULL);
        return -1;
    }

    env->signature.len = SIGNATURE_SIZE;
    env->signature.data = malloc(SIGNATURE_SIZE);
    if (!env->signature.data) {
        tinyweb__envelope__free_unpacked(env, NULL);
        return -1;
    }

    if (sign_message((const char*)digest, env->signature.data) != 0) {
        tinyweb__envelope__free_unpacked(env, NULL);
        return -1;
    }

    *out_env = env;
    return 0;
}

int tw_envelope_verify(const Tinyweb__Envelope* env) {
    if (!env) return -1;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (compute_envelope_digest(env->header, env->payload_ciphertext.data, env->payload_ciphertext.len, digest) != 0) {
        logger_error("envelope", "Failed to compute envelope digest");
        return -1;
    }
    const unsigned char* pk = env->header->sender_pubkey.data;
    int result = verify_signature(env->signature.data, digest, sizeof(digest), pk);
    if (result != 0) {
        logger_error("envelope", "Signature verification failed: result=%d", result);
        logger_error("envelope", "Signature len=%zu, digest len=%zu, pubkey len=%zu", 
                    env->signature.len, sizeof(digest), env->header->sender_pubkey.len);
    }
    return result;
}

int tw_envelope_peek(const Tinyweb__Envelope* env,
                     const Tinyweb__EnvelopeHeader** out_hdr,
                     const unsigned char** out_cipher,
                     size_t* out_cipher_len) {
    if (!env || !out_hdr || !out_cipher || !out_cipher_len) return -1;
    *out_hdr = env->header;
    *out_cipher = env->payload_ciphertext.data;
    *out_cipher_len = env->payload_ciphertext.len;
    return 0;
}


