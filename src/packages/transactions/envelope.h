#ifndef TW_ENVELOPE_H
#define TW_ENVELOPE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "packages/encryption/encryption.h"

// We include protobuf headers here (generated files)
#include "envelope.pb-c.h"

typedef enum {
    TW_CONTENT_DIRECT_MESSAGE = 1,
    TW_CONTENT_GROUP_MESSAGE = 2,
    TW_CONTENT_LOCATION_UPDATE = 3,
    TW_CONTENT_EMERGENCY_ALERT = 4
} tw_content_type_t;

typedef struct {
    uint32_t version;
    uint32_t content_type;
    uint32_t schema_version;
    uint64_t timestamp;
    const unsigned char* sender_pubkey; // 32 bytes
    const unsigned char* recipients_pubkeys; // array: num_recipients * 32
    size_t num_recipients;
    const unsigned char* group_id; // optional, can be NULL
    size_t group_id_len;
} tw_envelope_header_view_t;

// Serialization API
int tw_envelope_serialize(const Tinyweb__Envelope* env, unsigned char** out, size_t* out_len);
Tinyweb__Envelope* tw_envelope_deserialize(const unsigned char* buf, size_t len);
void tw_envelope_free(Tinyweb__Envelope* env);

// Construction helpers using existing encryption/signing
// Encrypts plaintext for recipients and signs the envelope
int tw_envelope_build_and_sign(const tw_envelope_header_view_t* header,
                               const unsigned char* plaintext,
                               size_t plaintext_len,
                               Tinyweb__Envelope** out_env);

// Verify signature and (optionally) decrypt payload if recipient keys are available
int tw_envelope_verify(const Tinyweb__Envelope* env);

// Extract ciphertext payload and header pointers for validation/storage
int tw_envelope_peek(const Tinyweb__Envelope* env,
                     const Tinyweb__EnvelopeHeader** out_hdr,
                     const unsigned char** out_cipher,
                     size_t* out_cipher_len);

#endif // TW_ENVELOPE_H

