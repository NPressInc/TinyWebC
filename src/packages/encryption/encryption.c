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
    unsigned char salt[crypto_pwhash_SALTBYTES];  // Generate random salt
    
    randombytes_buf(nonce, NONCE_SIZE);
    randombytes_buf(salt, crypto_pwhash_SALTBYTES);  // Generate random salt
    
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
        fwrite(salt, 1, crypto_pwhash_SALTBYTES, fp) != crypto_pwhash_SALTBYTES ||  // Write salt first
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
    unsigned char salt[crypto_pwhash_SALTBYTES];  // Read salt first
    
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

    EncryptedPayload *encrypted = malloc(sizeof(EncryptedPayload));
    if (!encrypted)
        return NULL;

    // Initialize fields
    encrypted->num_recipients = num_recipients;
    encrypted->encrypted_key_len = crypto_box_SEALBYTES; // Size of each encrypted key
    encrypted->encrypted_keys = malloc(encrypted->encrypted_key_len * num_recipients);
    encrypted->ciphertext = NULL;
    if (!encrypted->encrypted_keys)
    {
        free_encrypted_payload(encrypted);
        return NULL;
    }

    // Generate ephemeral keypair
    unsigned char ephemeral_privkey[SECRET_SIZE];
    crypto_box_keypair(encrypted->ephemeral_pubkey, ephemeral_privkey);

    // Generate a random symmetric key
    unsigned char symmetric_key[crypto_secretbox_KEYBYTES];
    randombytes_buf(symmetric_key, crypto_secretbox_KEYBYTES);

    // Encrypt the plaintext with the symmetric key
    encrypted->ciphertext_len = plaintext_len + crypto_secretbox_MACBYTES;
    encrypted->ciphertext = malloc(encrypted->ciphertext_len);
    if (!encrypted->ciphertext)
    {
        free_encrypted_payload(encrypted);
        return NULL;
    }
    randombytes_buf(encrypted->nonce, NONCE_SIZE);
    if (crypto_secretbox_easy(encrypted->ciphertext, plaintext, plaintext_len,
                              encrypted->nonce, symmetric_key) != 0)
    {
        free_encrypted_payload(encrypted);
        return NULL;
    }

    // Encrypt the symmetric key for each recipient
    for (size_t i = 0; i < num_recipients; i++)
    {
        if (crypto_box_easy(&encrypted->encrypted_keys[i * encrypted->encrypted_key_len],
                            symmetric_key, crypto_secretbox_KEYBYTES,
                            encrypted->nonce,
                            recipient_pubkeys[i],
                            ephemeral_privkey) != 0)
        {
            free_encrypted_payload(encrypted);
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
        if (encrypted->ciphertext)
            free(encrypted->ciphertext);
        if (encrypted->encrypted_keys)
            free(encrypted->encrypted_keys);
        free(encrypted);
    }
}

unsigned char *decrypt_payload(const EncryptedPayload *encrypted, size_t *plaintext_len,
                               const unsigned char *recipient_privkey, size_t recipient_index)
{
    if (!encrypted || recipient_index >= encrypted->num_recipients)
    {
        fprintf(stderr, "Invalid encrypted payload or recipient index\n");
        return NULL;
    }

    // Step 1: Decrypt the symmetric key using the recipient's private key
    unsigned char symmetric_key[crypto_secretbox_KEYBYTES];
    const unsigned char *encrypted_key = &encrypted->encrypted_keys[recipient_index * encrypted->encrypted_key_len];
    if (crypto_box_open_easy(symmetric_key, encrypted_key, encrypted->encrypted_key_len,
                             encrypted->nonce,
                             encrypted->ephemeral_pubkey,
                             recipient_privkey) != 0)
    {
        fprintf(stderr, "Failed to decrypt symmetric key\n");
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        return NULL;
    }

    // Step 2: Decrypt the ciphertext using the symmetric key
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