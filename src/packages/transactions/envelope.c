#include "envelope.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#include "packages/keystore/keystore.h"
#include "packages/signing/signing.h"

#include "envelope.pb-c.h"

static int compute_envelope_digest(const Tinyweb__EnvelopeHeader* hdr,
                                   const unsigned char* cipher,
                                   size_t cipher_len,
                                   unsigned char out_hash[SHA256_DIGEST_LENGTH]) {
    if (!hdr || !cipher) return -1;

    // Serialize header
    size_t hdr_len = tinyweb__envelope_header__get_packed_size((Tinyweb__EnvelopeHeader*)hdr);
    unsigned char* hdr_buf = malloc(hdr_len);
    if (!hdr_buf) return -1;
    tinyweb__envelope_header__pack((Tinyweb__EnvelopeHeader*)hdr, hdr_buf);

    unsigned char payload_hash[SHA256_DIGEST_LENGTH];
    SHA256(cipher, cipher_len, payload_hash);

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    static const unsigned char domain[] = { 'T','W','E','N','V','E','L','O','P','E','\0' };
    SHA256_Update(&ctx, domain, sizeof(domain));
    SHA256_Update(&ctx, hdr_buf, hdr_len);
    SHA256_Update(&ctx, payload_hash, sizeof(payload_hash));
    SHA256_Final(out_hash, &ctx);

    free(hdr_buf);
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

    // Encrypt using existing multi-recipient helper
    EncryptedPayload* ep = encrypt_payload_multi(plaintext, plaintext_len,
                                                 view->recipients_pubkeys,
                                                 view->num_recipients);
    if (!ep) return -1;

    // Allocate header
    Tinyweb__EnvelopeHeader* hdr = calloc(1, sizeof(Tinyweb__EnvelopeHeader));
    if (!hdr) { free_encrypted_payload(ep); return -1; }
    tinyweb__envelope_header__init(hdr);
    
    hdr->version = view->version;
    hdr->content_type = view->content_type;
    hdr->schema_version = view->schema_version;
    hdr->timestamp = view->timestamp;
    hdr->sender_pubkey.data = (uint8_t*)view->sender_pubkey;
    hdr->sender_pubkey.len = PUBKEY_SIZE;

    // recipients_pubkey repeated
    hdr->n_recipients_pubkey = view->num_recipients;
    hdr->recipients_pubkey = calloc(view->num_recipients, sizeof(ProtobufCBinaryData));
    if (!hdr->recipients_pubkey) { free(hdr); free_encrypted_payload(ep); return -1; }
    for (size_t i = 0; i < view->num_recipients; ++i) {
        hdr->recipients_pubkey[i].data = (uint8_t*)(view->recipients_pubkeys + i * PUBKEY_SIZE);
        hdr->recipients_pubkey[i].len = PUBKEY_SIZE;
    }

    if (view->group_id && view->group_id_len > 0) {
        hdr->group_id.data = (uint8_t*)view->group_id;
        hdr->group_id.len = view->group_id_len;
    } else {
        hdr->group_id.data = NULL; hdr->group_id.len = 0;
    }

    Tinyweb__Envelope* env = calloc(1, sizeof(Tinyweb__Envelope));
    if (!env) { free(hdr->recipients_pubkey); free(hdr); free_encrypted_payload(ep); return -1; }
    tinyweb__envelope__init(env);
    env->header = hdr;

    // Map encryption output into envelope fields
    env->payload_nonce.data = ep->nonce;
    env->payload_nonce.len = NONCE_SIZE;
    env->ephemeral_pubkey.data = ep->ephemeral_pubkey;
    env->ephemeral_pubkey.len = PUBKEY_SIZE;
    env->payload_ciphertext.data = ep->ciphertext;
    env->payload_ciphertext.len = ep->ciphertext_len;

    env->n_keywraps = ep->num_recipients;
    env->keywraps = calloc(env->n_keywraps, sizeof(Tinyweb__RecipientKeyWrap*));
    if (!env->keywraps) { free(hdr->recipients_pubkey); free(hdr); free_encrypted_payload(ep); free(env); return -1; }
    for (size_t i = 0; i < ep->num_recipients; ++i) {
        Tinyweb__RecipientKeyWrap* wrap = calloc(1, sizeof(Tinyweb__RecipientKeyWrap));
        tinyweb__recipient_key_wrap__init(wrap);
        wrap->recipient_pubkey.data = (uint8_t*)(view->recipients_pubkeys + i * PUBKEY_SIZE);
        wrap->recipient_pubkey.len = PUBKEY_SIZE;
        wrap->key_nonce.data = ep->key_nonces + (i * NONCE_SIZE);
        wrap->key_nonce.len = NONCE_SIZE;
        wrap->wrapped_key.data = ep->encrypted_keys + (i * ENCRYPTED_KEY_SIZE);
        wrap->wrapped_key.len = ENCRYPTED_KEY_SIZE;
        env->keywraps[i] = wrap;
    }

    // Compute digest and sign
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (compute_envelope_digest(env->header, env->payload_ciphertext.data, env->payload_ciphertext.len, digest) != 0) {
        for (size_t i = 0; i < env->n_keywraps; ++i) free(env->keywraps[i]);
        free(env->keywraps);
        free(hdr->recipients_pubkey);
        free(hdr);
        free_encrypted_payload(ep);
        free(env);
        return -1;
    }

    env->signature.len = SIGNATURE_SIZE;
    env->signature.data = malloc(SIGNATURE_SIZE);
    if (!env->signature.data) {
        for (size_t i = 0; i < env->n_keywraps; ++i) free(env->keywraps[i]);
        free(env->keywraps);
        free(hdr->recipients_pubkey);
        free(hdr);
        free_encrypted_payload(ep);
        free(env);
        return -1;
    }

    if (sign_message((const char*)digest, env->signature.data) != 0) {
        free(env->signature.data);
        for (size_t i = 0; i < env->n_keywraps; ++i) free(env->keywraps[i]);
        free(env->keywraps);
        free(hdr->recipients_pubkey);
        free(hdr);
        free_encrypted_payload(ep);
        free(env);
        return -1;
    }

    // Serialize and re-deserialize to get a clean copy
    unsigned char* ser = NULL; size_t ser_len = 0;
    if (tw_envelope_serialize(env, &ser, &ser_len) != 0) {
        free(env->signature.data);
        for (size_t i = 0; i < env->n_keywraps; ++i) free(env->keywraps[i]);
        free(env->keywraps);
        free(hdr->recipients_pubkey);
        free(hdr);
        free_encrypted_payload(ep);
        free(env);
        return -1;
    }

    Tinyweb__Envelope* packed = tw_envelope_deserialize(ser, ser_len);
    free(ser);

    for (size_t i = 0; i < env->n_keywraps; ++i) free(env->keywraps[i]);
    free(env->keywraps);
    free(hdr->recipients_pubkey);
    free(hdr);
    free_encrypted_payload(ep);
    free(env);

    if (!packed) return -1;
    *out_env = packed;
    return 0;
}

int tw_envelope_verify(const Tinyweb__Envelope* env) {
    if (!env) return -1;
    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (compute_envelope_digest(env->header, env->payload_ciphertext.data, env->payload_ciphertext.len, digest) != 0) {
        return -1;
    }
    const unsigned char* pk = env->header->sender_pubkey.data;
    return verify_signature(env->signature.data, digest, sizeof(digest), pk);
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


