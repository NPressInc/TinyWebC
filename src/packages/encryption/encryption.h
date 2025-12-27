#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <sodium.h>
#include "packages/keystore/keystore.h"
#include "envelope.pb-c.h"
// Forward declaration - will be included after message.pb-c.h is generated
struct Tinyweb__Message;
typedef struct Tinyweb__Message Tinyweb__Message;

#define PUBKEY_SIZE crypto_box_PUBLICKEYBYTES    /* 32 */
#define SECRET_SIZE crypto_box_SECRETKEYBYTES    /* 32 */
#define NONCE_SIZE crypto_box_NONCEBYTES         /* 24 */
#define MAC_SIZE crypto_box_MACBYTES             /* 16 */

// Maximum plaintext size is 2KB (2048 bytes)
#define MAX_PLAINTEXT_SIZE 2048
// Maximum ciphertext size: plaintext + MAC
#define MAX_CIPHERTEXT_SIZE (MAX_PLAINTEXT_SIZE + MAC_SIZE)
// Maximum number of recipients
#define MAX_RECIPIENTS 50
// Size of each encrypted symmetric key (key + MAC)
#define ENCRYPTED_KEY_SIZE (crypto_secretbox_KEYBYTES + MAC_SIZE)

// New API: Encrypt plaintext and populate envelope fields directly
// This replaces the old EncryptedPayload-based API
int encrypt_envelope_payload(
    const unsigned char* plaintext, size_t plaintext_len,
    const unsigned char* recipient_pubkeys, size_t num_recipients,
    Tinyweb__Envelope* envelope  // Envelope to populate (must be initialized)
);

// Decrypt envelope payload for current user
// Returns 0 on success, -1 on error
// Caller must free *plaintext with sodium_free()
int decrypt_envelope_payload(
    const Tinyweb__Envelope* envelope,
    unsigned char** plaintext, size_t* plaintext_len
);

// Message encryption API (compatible with Message protobuf structure)
// Encrypt plaintext and populate Message fields directly
// Structure is identical to encrypt_envelope_payload but works with Message
int encrypt_message_payload(
    const unsigned char* plaintext, size_t plaintext_len,
    const unsigned char* recipient_pubkeys, size_t num_recipients,
    Tinyweb__Message* message  // Message to populate (must be initialized)
);

// Decrypt message payload for current user
// Returns 0 on success, -1 on error
// Caller must free *plaintext with sodium_free()
int decrypt_message_payload(
    const Tinyweb__Message* message,
    unsigned char** plaintext, size_t* plaintext_len
);

#endif /* ENCRYPTION_H */