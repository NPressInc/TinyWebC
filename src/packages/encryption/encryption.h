#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <sodium.h>
#include "packages/keystore/keystore.h"

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

typedef struct {
    unsigned char* ciphertext;      // Encrypted message (2KB + MAC)
    size_t ciphertext_len;                              // Length of encrypted message
    unsigned char nonce[NONCE_SIZE];                    // Nonce for symmetric encryption
    unsigned char* encrypted_keys; // Encrypted symmetric keys (one per recipient) size is MAX_RECIPIENTS * ENCRYPTED_KEY_SIZE
    unsigned char* key_nonces; // Nonces for encrypted keys, size is MAX_RECIPIENTS * NONCE_SIZE
    unsigned char ephemeral_pubkey[PUBKEY_SIZE];        // Ephemeral public key
    size_t num_recipients;                             // Number of recipients (up to 25)
} EncryptedPayload;

EncryptedPayload* encrypt_payload_multi(const unsigned char* plaintext, size_t plaintext_len,
                                        const unsigned char* recipient_pubkeys, size_t num_recipients);

unsigned char *decrypt_payload(const EncryptedPayload *encrypted, const unsigned char *recipient_pubkeys);

void free_encrypted_payload(EncryptedPayload* payload);

size_t encrypted_payload_get_size(EncryptedPayload* payload);

int encrypted_payload_serialize(EncryptedPayload* payload, char** out_buffer);

EncryptedPayload* encrypted_payload_deserialize(char** buffer);

#endif /* ENCRYPTION_H */