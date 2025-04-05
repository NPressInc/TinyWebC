#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <sodium.h>

#define PUBKEY_SIZE crypto_box_PUBLICKEYBYTES    /* 32 */
#define SECRET_SIZE crypto_box_SECRETKEYBYTES    /* 32 */
#define NONCE_SIZE crypto_box_NONCEBYTES         /* 24 */
#define MAC_SIZE crypto_box_MACBYTES             /* 16 */

typedef struct {
    unsigned char* ciphertext;         // Encrypted message
    size_t ciphertext_len;             // Length of encrypted message
    unsigned char nonce[NONCE_SIZE];   // Nonce for symmetric encryption
    unsigned char* encrypted_keys;     // Array of encrypted symmetric keys (one per recipient)
    size_t encrypted_key_len;          // Length of each encrypted key
    unsigned char ephemeral_pubkey[PUBKEY_SIZE]; // Ephemeral public key
    size_t num_recipients;             // Number of recipients
} EncryptedPayload;

int generate_keypair(void);
int save_private_key(const char* filename, const char* passphrase);
int load_private_key(const char* filename, const char* passphrase);
EncryptedPayload* encrypt_payload_multi(const unsigned char* plaintext, size_t plaintext_len,
                                        const unsigned char** recipient_pubkeys, size_t num_recipients);

unsigned char *decrypt_payload(const EncryptedPayload *encrypted, size_t *plaintext_len,
                                const unsigned char *recipient_privkey, const unsigned char *recipient_publickey,
                                const unsigned char *recipient_pubkeys);

void free_encrypted_payload(EncryptedPayload* payload);
void cleanup_encryption(void);

#endif /* ENCRYPTION_H */