#include "encryption.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char node_privkey[SECRET_SIZE];
static unsigned char node_pubkey[PUBKEY_SIZE];
static int keypair_loaded = 0;

int generate_keypair(void)
{
    if (sodium_init() < 0)
    {
        fprintf(stderr, "Failed to init libsodium\n");
        return 0;
    }
    crypto_box_keypair(node_pubkey, node_privkey);
    keypair_loaded = 1;
    return 1;
}

int save_private_key(const char *filename, const char *passphrase)
{
    if (!keypair_loaded && !generate_keypair())
        return 0;

    unsigned char nonce[NONCE_SIZE];
    unsigned char key[SECRET_SIZE];
    unsigned char ciphertext[SECRET_SIZE + MAC_SIZE];
    unsigned char salt[crypto_pwhash_SALTBYTES]; // Generate random salt

    randombytes_buf(nonce, NONCE_SIZE);
    randombytes_buf(salt, crypto_pwhash_SALTBYTES); // Generate random salt

    if (crypto_pwhash(key, SECRET_SIZE, passphrase, strlen(passphrase), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0)
    {
        fprintf(stderr, "Failed to derive key from passphrase\n");
        return 0;
    }
    if (crypto_secretbox_easy(ciphertext, node_privkey, SECRET_SIZE, nonce, key) != 0)
    {
        fprintf(stderr, "Failed to encrypt private key\n");
        return 0;
    }

    FILE *fp = fopen(filename, "wb");
    if (!fp ||
        fwrite(salt, 1, crypto_pwhash_SALTBYTES, fp) != crypto_pwhash_SALTBYTES || // Write salt first
        fwrite(nonce, 1, NONCE_SIZE, fp) != NONCE_SIZE ||
        fwrite(ciphertext, 1, SECRET_SIZE + MAC_SIZE, fp) != SECRET_SIZE + MAC_SIZE)
    {
        fprintf(stderr, "Failed to write private key\n");
        if (fp)
            fclose(fp);
        return 0;
    }
    fclose(fp);
    return 1;
}

int load_private_key(const char *filename, const char *passphrase)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp)
    {
        fprintf(stderr, "Failed to open key file\n");
        return 0;
    }

    unsigned char nonce[NONCE_SIZE];
    unsigned char ciphertext[SECRET_SIZE + MAC_SIZE];
    unsigned char salt[crypto_pwhash_SALTBYTES]; // Read salt first

    if (fread(salt, 1, crypto_pwhash_SALTBYTES, fp) != crypto_pwhash_SALTBYTES ||
        fread(nonce, 1, NONCE_SIZE, fp) != NONCE_SIZE ||
        fread(ciphertext, 1, SECRET_SIZE + MAC_SIZE, fp) != SECRET_SIZE + MAC_SIZE)
    {
        fprintf(stderr, "Failed to read key file\n");
        fclose(fp);
        return 0;
    }
    fclose(fp);

    unsigned char key[SECRET_SIZE];
    if (crypto_pwhash(key, SECRET_SIZE, passphrase, strlen(passphrase), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0)
    {
        fprintf(stderr, "Failed to derive key from passphrase\n");
        return 0;
    }
    if (crypto_secretbox_open_easy(node_privkey, ciphertext, SECRET_SIZE + MAC_SIZE, nonce, key) != 0)
    {
        fprintf(stderr, "Failed to decrypt private key\n");
        return 0;
    }

    if (sodium_init() < 0 || crypto_scalarmult_base(node_pubkey, node_privkey) != 0)
    {
        fprintf(stderr, "Failed to derive public key\n");
        return 0;
    }
    keypair_loaded = 1;
    return 1;
}

EncryptedPayload *encrypt_payload_multi(const unsigned char *plaintext, size_t plaintext_len,
                                        const unsigned char **recipient_pubkeys, size_t num_recipients)
{
    if (!keypair_loaded || num_recipients == 0)
        return NULL;

    // Check if plaintext size exceeds the maximum allowed
    if (plaintext_len > MAX_PLAINTEXT_SIZE) {
        fprintf(stderr, "Plaintext size (%zu bytes) exceeds maximum allowed size (%d bytes)\n", 
                plaintext_len, MAX_PLAINTEXT_SIZE);
        return NULL;
    }

    // Check if number of recipients exceeds the maximum allowed
    if (num_recipients > MAX_RECIPIENTS) {
        fprintf(stderr, "Number of recipients (%zu) exceeds maximum allowed (%d)\n", 
                num_recipients, MAX_RECIPIENTS);
        return NULL;
    }

    EncryptedPayload *encrypted = malloc(sizeof(EncryptedPayload));
    if (!encrypted)
        return NULL;

    // Initialize fields
    encrypted->num_recipients = num_recipients;
    encrypted->encrypted_keys_len = ENCRYPTED_KEY_SIZE; // Size of each encrypted key

    // Generate ephemeral keypair
    unsigned char ephemeral_privkey[SECRET_SIZE];
    crypto_box_keypair(encrypted->ephemeral_pubkey, ephemeral_privkey);

    // Generate a random symmetric key
    unsigned char symmetric_key[crypto_secretbox_KEYBYTES];
    randombytes_buf(symmetric_key, crypto_secretbox_KEYBYTES);

    // Encrypt the plaintext with the symmetric key
    encrypted->ciphertext_len = plaintext_len + crypto_secretbox_MACBYTES;
    randombytes_buf(encrypted->nonce, NONCE_SIZE);
    if (crypto_secretbox_easy(encrypted->ciphertext, plaintext, plaintext_len,
                              encrypted->nonce, symmetric_key) != 0)
    {
        free(encrypted);
        return NULL;
    }

    // Encrypt the symmetric key for each recipient
    for (size_t i = 0; i < num_recipients; i++)
    {
        randombytes_buf(encrypted->key_nonces[i], NONCE_SIZE);
        if (crypto_box_easy(encrypted->encrypted_keys[i],
                            symmetric_key, crypto_secretbox_KEYBYTES,
                            encrypted->key_nonces[i],
                            recipient_pubkeys[i],
                            ephemeral_privkey) != 0)
        {
            free(encrypted);
            return NULL;
        }
    }

    // Clean up sensitive data
    sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
    sodium_memzero(ephemeral_privkey, SECRET_SIZE);

    return encrypted;
}

void free_encrypted_payload(EncryptedPayload *encrypted)
{
    if (encrypted)
    {
        free(encrypted);
    }
}

unsigned char *decrypt_payload(const EncryptedPayload *encrypted, size_t *plaintext_len,
                               const unsigned char *recipient_privkey, const unsigned char *recipient_publickey,
                               const unsigned char *recipient_pubkeys)
{
    if (!encrypted || !recipient_privkey || !recipient_publickey || !recipient_pubkeys)
    {
        fprintf(stderr, "Invalid encrypted payload or keys\n");
        return NULL;
    }

    // Check if ciphertext size exceeds the maximum allowed
    if (encrypted->ciphertext_len > MAX_CIPHERTEXT_SIZE) {
        fprintf(stderr, "Ciphertext size (%zu bytes) exceeds maximum allowed size (%d bytes)\n", 
                encrypted->ciphertext_len, MAX_CIPHERTEXT_SIZE);
        return NULL;
    }

    // Step 1: Find the index of the matching recipient public key
    size_t recipient_index = 0;
    int found = 0;
    for (size_t i = 0; i < encrypted->num_recipients; i++)
    {
        if (memcmp(recipient_publickey, &recipient_pubkeys[i * PUBKEY_SIZE], PUBKEY_SIZE) == 0)
        {
            recipient_index = i;
            found = 1;
            break;
        }
    }

    if (!found)
    {
        fprintf(stderr, "Recipient public key not found in the list\n");
        return NULL;
    }

    // Step 2: Decrypt the symmetric key using the recipient's private key at the matched index
    unsigned char symmetric_key[crypto_secretbox_KEYBYTES];
    if (crypto_box_open_easy(symmetric_key, encrypted->encrypted_keys[recipient_index], 
                             ENCRYPTED_KEY_SIZE,
                             encrypted->key_nonces[recipient_index], 
                             encrypted->ephemeral_pubkey, 
                             recipient_privkey) != 0)
    {
        fprintf(stderr, "Failed to decrypt symmetric key\n");
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        return NULL;
    }

    // Step 3: Decrypt the ciphertext using the symmetric key
    *plaintext_len = encrypted->ciphertext_len - crypto_secretbox_MACBYTES;
    unsigned char *plaintext = malloc(*plaintext_len);
    if (!plaintext)
    {
        fprintf(stderr, "Memory allocation failed\n");
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        return NULL;
    }

    if (crypto_secretbox_open_easy(plaintext, encrypted->ciphertext, encrypted->ciphertext_len,
                                   encrypted->nonce, symmetric_key) != 0)
    {
        fprintf(stderr, "Decryption of payload failed\n");
        free(plaintext);
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        return NULL;
    }

    // Clean up sensitive data
    sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
    return plaintext;
}

void cleanup_encryption(void)
{
    sodium_memzero(node_privkey, SECRET_SIZE);
    sodium_memzero(node_pubkey, PUBKEY_SIZE);
    keypair_loaded = 0;
}