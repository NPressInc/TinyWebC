#include "client_request_converter.h"
#include "client_request.pb-c.h"
#include "envelope.pb-c.h"
#include "packages/utils/logger.h"
#include <stdlib.h>
#include <string.h>

Tinyweb__Envelope* client_request_to_envelope(const Tinyweb__ClientRequest* request) {
    if (!request || !request->header) {
        logger_error("client_request_conv", "Invalid client request");
        return NULL;
    }

    const Tinyweb__ClientRequestHeader* req_hdr = request->header;

    // Allocate envelope
    Tinyweb__Envelope* envelope = calloc(1, sizeof(Tinyweb__Envelope));
    if (!envelope) {
        logger_error("client_request_conv", "Failed to allocate envelope");
        return NULL;
    }
    tinyweb__envelope__init(envelope);

    // Allocate and populate envelope header
    Tinyweb__EnvelopeHeader* env_hdr = calloc(1, sizeof(Tinyweb__EnvelopeHeader));
    if (!env_hdr) {
        free(envelope);
        logger_error("client_request_conv", "Failed to allocate envelope header");
        return NULL;
    }
    tinyweb__envelope_header__init(env_hdr);
    envelope->header = env_hdr;

    // Copy header fields from ClientRequestHeader to EnvelopeHeader
    env_hdr->version = req_hdr->version;
    env_hdr->content_type = req_hdr->content_type;  // Already contains CONTENT_LOCATION_UPDATE
    env_hdr->schema_version = req_hdr->schema_version;
    env_hdr->timestamp = req_hdr->timestamp;

    // Copy sender_pubkey
    if (req_hdr->sender_pubkey.len != 32) {
        tinyweb__envelope__free_unpacked(envelope, NULL);
        logger_error("client_request_conv", "Invalid sender_pubkey length");
        return NULL;
    }
    env_hdr->sender_pubkey.len = 32;
    env_hdr->sender_pubkey.data = malloc(32);
    if (!env_hdr->sender_pubkey.data) {
        tinyweb__envelope__free_unpacked(envelope, NULL);
        logger_error("client_request_conv", "Failed to allocate sender_pubkey");
        return NULL;
    }
    memcpy(env_hdr->sender_pubkey.data, req_hdr->sender_pubkey.data, 32);

    // Copy recipients_pubkey array
    if (req_hdr->n_recipients_pubkey > 0) {
        env_hdr->n_recipients_pubkey = req_hdr->n_recipients_pubkey;
        env_hdr->recipients_pubkey = calloc(req_hdr->n_recipients_pubkey, sizeof(ProtobufCBinaryData));
        if (!env_hdr->recipients_pubkey) {
            tinyweb__envelope__free_unpacked(envelope, NULL);
            logger_error("client_request_conv", "Failed to allocate recipients_pubkey array");
            return NULL;
        }

        for (size_t i = 0; i < req_hdr->n_recipients_pubkey; i++) {
            if (req_hdr->recipients_pubkey[i].len != 32) {
                tinyweb__envelope__free_unpacked(envelope, NULL);
                logger_error("client_request_conv", "Invalid recipient_pubkey length at index %zu", i);
                return NULL;
            }
            env_hdr->recipients_pubkey[i].len = 32;
            env_hdr->recipients_pubkey[i].data = malloc(32);
            if (!env_hdr->recipients_pubkey[i].data) {
                tinyweb__envelope__free_unpacked(envelope, NULL);
                logger_error("client_request_conv", "Failed to allocate recipient_pubkey at index %zu", i);
                return NULL;
            }
            memcpy(env_hdr->recipients_pubkey[i].data, req_hdr->recipients_pubkey[i].data, 32);
        }
    }

    // Copy group_id (optional)
    if (req_hdr->group_id.len > 0) {
        env_hdr->group_id.len = req_hdr->group_id.len;
        env_hdr->group_id.data = malloc(req_hdr->group_id.len);
        if (!env_hdr->group_id.data) {
            tinyweb__envelope__free_unpacked(envelope, NULL);
            logger_error("client_request_conv", "Failed to allocate group_id");
            return NULL;
        }
        memcpy(env_hdr->group_id.data, req_hdr->group_id.data, req_hdr->group_id.len);
    }

    // Copy payload_nonce
    if (request->payload_nonce.len != 24) {
        tinyweb__envelope__free_unpacked(envelope, NULL);
        logger_error("client_request_conv", "Invalid payload_nonce length");
        return NULL;
    }
    envelope->payload_nonce.len = 24;
    envelope->payload_nonce.data = malloc(24);
    if (!envelope->payload_nonce.data) {
        tinyweb__envelope__free_unpacked(envelope, NULL);
        logger_error("client_request_conv", "Failed to allocate payload_nonce");
        return NULL;
    }
    memcpy(envelope->payload_nonce.data, request->payload_nonce.data, 24);

    // Copy ephemeral_pubkey
    if (request->ephemeral_pubkey.len != 32) {
        tinyweb__envelope__free_unpacked(envelope, NULL);
        logger_error("client_request_conv", "Invalid ephemeral_pubkey length");
        return NULL;
    }
    envelope->ephemeral_pubkey.len = 32;
    envelope->ephemeral_pubkey.data = malloc(32);
    if (!envelope->ephemeral_pubkey.data) {
        tinyweb__envelope__free_unpacked(envelope, NULL);
        logger_error("client_request_conv", "Failed to allocate ephemeral_pubkey");
        return NULL;
    }
    memcpy(envelope->ephemeral_pubkey.data, request->ephemeral_pubkey.data, 32);

    // Copy payload_ciphertext
    if (request->payload_ciphertext.len == 0) {
        tinyweb__envelope__free_unpacked(envelope, NULL);
        logger_error("client_request_conv", "Empty payload_ciphertext");
        return NULL;
    }
    envelope->payload_ciphertext.len = request->payload_ciphertext.len;
    envelope->payload_ciphertext.data = malloc(request->payload_ciphertext.len);
    if (!envelope->payload_ciphertext.data) {
        tinyweb__envelope__free_unpacked(envelope, NULL);
        logger_error("client_request_conv", "Failed to allocate payload_ciphertext");
        return NULL;
    }
    memcpy(envelope->payload_ciphertext.data, request->payload_ciphertext.data, request->payload_ciphertext.len);

    // Convert ClientRequestKeyWrap array to RecipientKeyWrap array
    if (request->n_keywraps > 0) {
        envelope->n_keywraps = request->n_keywraps;
        envelope->keywraps = calloc(request->n_keywraps, sizeof(Tinyweb__RecipientKeyWrap*));
        if (!envelope->keywraps) {
            tinyweb__envelope__free_unpacked(envelope, NULL);
            logger_error("client_request_conv", "Failed to allocate keywraps array");
            return NULL;
        }

        for (size_t i = 0; i < request->n_keywraps; i++) {
            const Tinyweb__ClientRequestKeyWrap* req_wrap = request->keywraps[i];
            if (!req_wrap) {
                tinyweb__envelope__free_unpacked(envelope, NULL);
                logger_error("client_request_conv", "Null keywrap at index %zu", i);
                return NULL;
            }

            Tinyweb__RecipientKeyWrap* env_wrap = calloc(1, sizeof(Tinyweb__RecipientKeyWrap));
            if (!env_wrap) {
                tinyweb__envelope__free_unpacked(envelope, NULL);
                logger_error("client_request_conv", "Failed to allocate keywrap at index %zu", i);
                return NULL;
            }
            tinyweb__recipient_key_wrap__init(env_wrap);
            envelope->keywraps[i] = env_wrap;

            // Copy recipient_pubkey
            if (req_wrap->recipient_pubkey.len != 32) {
                tinyweb__envelope__free_unpacked(envelope, NULL);
                logger_error("client_request_conv", "Invalid keywrap recipient_pubkey length at index %zu", i);
                return NULL;
            }
            env_wrap->recipient_pubkey.len = 32;
            env_wrap->recipient_pubkey.data = malloc(32);
            if (!env_wrap->recipient_pubkey.data) {
                tinyweb__envelope__free_unpacked(envelope, NULL);
                logger_error("client_request_conv", "Failed to allocate keywrap recipient_pubkey at index %zu", i);
                return NULL;
            }
            memcpy(env_wrap->recipient_pubkey.data, req_wrap->recipient_pubkey.data, 32);

            // Copy key_nonce
            if (req_wrap->key_nonce.len != 24) {
                tinyweb__envelope__free_unpacked(envelope, NULL);
                logger_error("client_request_conv", "Invalid keywrap key_nonce length at index %zu", i);
                return NULL;
            }
            env_wrap->key_nonce.len = 24;
            env_wrap->key_nonce.data = malloc(24);
            if (!env_wrap->key_nonce.data) {
                tinyweb__envelope__free_unpacked(envelope, NULL);
                logger_error("client_request_conv", "Failed to allocate keywrap key_nonce at index %zu", i);
                return NULL;
            }
            memcpy(env_wrap->key_nonce.data, req_wrap->key_nonce.data, 24);

            // Copy wrapped_key
            if (req_wrap->wrapped_key.len == 0) {
                tinyweb__envelope__free_unpacked(envelope, NULL);
                logger_error("client_request_conv", "Empty keywrap wrapped_key at index %zu", i);
                return NULL;
            }
            env_wrap->wrapped_key.len = req_wrap->wrapped_key.len;
            env_wrap->wrapped_key.data = malloc(req_wrap->wrapped_key.len);
            if (!env_wrap->wrapped_key.data) {
                tinyweb__envelope__free_unpacked(envelope, NULL);
                logger_error("client_request_conv", "Failed to allocate keywrap wrapped_key at index %zu", i);
                return NULL;
            }
            memcpy(env_wrap->wrapped_key.data, req_wrap->wrapped_key.data, req_wrap->wrapped_key.len);
        }
    }

    // Copy signature
    if (request->signature.len != 64) {
        tinyweb__envelope__free_unpacked(envelope, NULL);
        logger_error("client_request_conv", "Invalid signature length");
        return NULL;
    }
    envelope->signature.len = 64;
    envelope->signature.data = malloc(64);
    if (!envelope->signature.data) {
        tinyweb__envelope__free_unpacked(envelope, NULL);
        logger_error("client_request_conv", "Failed to allocate signature");
        return NULL;
    }
    memcpy(envelope->signature.data, request->signature.data, 64);

    return envelope;
}

