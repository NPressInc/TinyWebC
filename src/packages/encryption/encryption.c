#include "encryption.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packages/keystore/keystore.h"

int encrypt_envelope_payload(
    const unsigned char* plaintext, size_t plaintext_len,
    const unsigned char* recipient_pubkeys, size_t num_recipients,
    Tinyweb__Envelope* envelope)
{
    if (!plaintext || !envelope || num_recipients == 0) {
        fprintf(stderr, "encrypt_envelope_payload: invalid arguments\n");
        return -1;
    }

    if (!keystore_is_keypair_loaded()) {
        fprintf(stderr, "encrypt_envelope_payload: keypair not loaded\n");
        return -1;
    }

    // Check if plaintext size exceeds the maximum allowed
    if (plaintext_len > MAX_PLAINTEXT_SIZE) {
        fprintf(stderr, "Plaintext size (%zu bytes) exceeds maximum allowed size (%d bytes)\n", 
                plaintext_len, MAX_PLAINTEXT_SIZE);
        return -1;
    }

    // Check if number of recipients exceeds the maximum allowed
    if (num_recipients > MAX_RECIPIENTS) {
        fprintf(stderr, "Number of recipients (%zu) exceeds maximum allowed (%d)\n", 
                num_recipients, MAX_RECIPIENTS);
        return -1;
    }

    // Generate ephemeral keypair
    unsigned char ephemeral_pubkey[PUBKEY_SIZE];
    unsigned char ephemeral_privkey[SECRET_SIZE];
    crypto_box_keypair(ephemeral_pubkey, ephemeral_privkey);

    // Generate a random symmetric key
    unsigned char symmetric_key[crypto_secretbox_KEYBYTES];
    randombytes_buf(symmetric_key, crypto_secretbox_KEYBYTES);

    // Allocate and encrypt the plaintext with the symmetric key
    size_t ciphertext_len = plaintext_len + crypto_secretbox_MACBYTES;
    unsigned char* ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        sodium_memzero(ephemeral_privkey, SECRET_SIZE);
        return -1;
    }

    unsigned char nonce[NONCE_SIZE];
    randombytes_buf(nonce, NONCE_SIZE);
    
    if (crypto_secretbox_easy(ciphertext, plaintext, plaintext_len,
                              nonce, symmetric_key) != 0)
    {
        free(ciphertext);
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        sodium_memzero(ephemeral_privkey, SECRET_SIZE);
        return -1;
    }

    // Convert Ed25519 recipient public keys to X25519 for encryption
    // and encrypt the symmetric key for each recipient
    Tinyweb__RecipientKeyWrap** keywraps = calloc(num_recipients, sizeof(Tinyweb__RecipientKeyWrap*));
    if (!keywraps) {
        free(ciphertext);
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        sodium_memzero(ephemeral_privkey, SECRET_SIZE);
        return -1;
    }

    for (size_t i = 0; i < num_recipients; i++) {
        Tinyweb__RecipientKeyWrap* wrap = malloc(sizeof(Tinyweb__RecipientKeyWrap));
        if (!wrap) {
            // Cleanup on failure
            for (size_t j = 0; j < i; j++) {
                free(keywraps[j]->key_nonce.data);
                free(keywraps[j]->wrapped_key.data);
                free(keywraps[j]);
            }
            free(keywraps);
            free(ciphertext);
            sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
            sodium_memzero(ephemeral_privkey, SECRET_SIZE);
            return -1;
        }

        tinyweb__recipient_key_wrap__init(wrap);

        // Copy recipient pubkey (Ed25519)
        wrap->recipient_pubkey.len = PUBKEY_SIZE;
        wrap->recipient_pubkey.data = malloc(PUBKEY_SIZE);
        if (!wrap->recipient_pubkey.data) {
            free(wrap);
            for (size_t j = 0; j < i; j++) {
                free(keywraps[j]->recipient_pubkey.data);
                free(keywraps[j]->key_nonce.data);
                free(keywraps[j]->wrapped_key.data);
                free(keywraps[j]);
            }
            free(keywraps);
            free(ciphertext);
            sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
            sodium_memzero(ephemeral_privkey, SECRET_SIZE);
            return -1;
        }
        memcpy(wrap->recipient_pubkey.data, &recipient_pubkeys[i * PUBKEY_SIZE], PUBKEY_SIZE);

        // Convert Ed25519 public key to X25519 for encryption
        unsigned char x25519_pubkey[PUBKEY_SIZE];
        if (crypto_sign_ed25519_pk_to_curve25519(x25519_pubkey, &recipient_pubkeys[i * PUBKEY_SIZE]) != 0) {
            fprintf(stderr, "Failed to convert Ed25519 to X25519 for recipient %zu\n", i);
            free(wrap->recipient_pubkey.data);
            free(wrap);
            for (size_t j = 0; j < i; j++) {
                free(keywraps[j]->recipient_pubkey.data);
                free(keywraps[j]->key_nonce.data);
                free(keywraps[j]->wrapped_key.data);
                free(keywraps[j]);
            }
            free(keywraps);
            free(ciphertext);
            sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
            sodium_memzero(ephemeral_privkey, SECRET_SIZE);
            return -1;
        }

        // Generate nonce for this key wrap
        wrap->key_nonce.len = NONCE_SIZE;
        wrap->key_nonce.data = malloc(NONCE_SIZE);
        if (!wrap->key_nonce.data) {
            free(wrap->recipient_pubkey.data);
            free(wrap);
            for (size_t j = 0; j < i; j++) {
                free(keywraps[j]->recipient_pubkey.data);
                free(keywraps[j]->key_nonce.data);
                free(keywraps[j]->wrapped_key.data);
                free(keywraps[j]);
            }
            free(keywraps);
            free(ciphertext);
            sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
            sodium_memzero(ephemeral_privkey, SECRET_SIZE);
            return -1;
        }
        randombytes_buf(wrap->key_nonce.data, NONCE_SIZE);

        // Encrypt the symmetric key for this recipient
        wrap->wrapped_key.len = ENCRYPTED_KEY_SIZE;
        wrap->wrapped_key.data = malloc(ENCRYPTED_KEY_SIZE);
        if (!wrap->wrapped_key.data) {
            free(wrap->key_nonce.data);
            free(wrap->recipient_pubkey.data);
            free(wrap);
            for (size_t j = 0; j < i; j++) {
                free(keywraps[j]->recipient_pubkey.data);
                free(keywraps[j]->key_nonce.data);
                free(keywraps[j]->wrapped_key.data);
                free(keywraps[j]);
            }
            free(keywraps);
            free(ciphertext);
            sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
            sodium_memzero(ephemeral_privkey, SECRET_SIZE);
            return -1;
        }

        if (crypto_box_easy(wrap->wrapped_key.data,
                           symmetric_key, crypto_secretbox_KEYBYTES,
                           wrap->key_nonce.data,
                           x25519_pubkey,
                           ephemeral_privkey) != 0)
        {
            free(wrap->wrapped_key.data);
            free(wrap->key_nonce.data);
            free(wrap->recipient_pubkey.data);
            free(wrap);
            for (size_t j = 0; j < i; j++) {
                free(keywraps[j]->recipient_pubkey.data);
                free(keywraps[j]->key_nonce.data);
                free(keywraps[j]->wrapped_key.data);
                free(keywraps[j]);
            }
            free(keywraps);
            free(ciphertext);
            sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
            sodium_memzero(ephemeral_privkey, SECRET_SIZE);
            sodium_memzero(x25519_pubkey, PUBKEY_SIZE);
            return -1;
        }

        sodium_memzero(x25519_pubkey, PUBKEY_SIZE);
        keywraps[i] = wrap;
    }

    // Populate envelope fields
    envelope->payload_nonce.len = NONCE_SIZE;
    envelope->payload_nonce.data = malloc(NONCE_SIZE);
    if (!envelope->payload_nonce.data) {
        for (size_t j = 0; j < num_recipients; j++) {
            free(keywraps[j]->recipient_pubkey.data);
            free(keywraps[j]->key_nonce.data);
            free(keywraps[j]->wrapped_key.data);
            free(keywraps[j]);
        }
        free(keywraps);
        free(ciphertext);
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        sodium_memzero(ephemeral_privkey, SECRET_SIZE);
        return -1;
    }
    memcpy(envelope->payload_nonce.data, nonce, NONCE_SIZE);

    envelope->ephemeral_pubkey.len = PUBKEY_SIZE;
    envelope->ephemeral_pubkey.data = malloc(PUBKEY_SIZE);
    if (!envelope->ephemeral_pubkey.data) {
        free(envelope->payload_nonce.data);
        for (size_t j = 0; j < num_recipients; j++) {
            free(keywraps[j]->recipient_pubkey.data);
            free(keywraps[j]->key_nonce.data);
            free(keywraps[j]->wrapped_key.data);
            free(keywraps[j]);
        }
        free(keywraps);
        free(ciphertext);
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        sodium_memzero(ephemeral_privkey, SECRET_SIZE);
        return -1;
    }
    memcpy(envelope->ephemeral_pubkey.data, ephemeral_pubkey, PUBKEY_SIZE);

    envelope->payload_ciphertext.len = ciphertext_len;
    envelope->payload_ciphertext.data = ciphertext;  // Transfer ownership

    envelope->n_keywraps = num_recipients;
    envelope->keywraps = keywraps;  // Transfer ownership

    // Clean up sensitive data
    sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
    sodium_memzero(ephemeral_privkey, SECRET_SIZE);

    return 0;
}

int decrypt_envelope_payload(
    const Tinyweb__Envelope* envelope,
    unsigned char** plaintext, size_t* plaintext_len)
{
    if (!envelope || !plaintext || !plaintext_len) {
        fprintf(stderr, "decrypt_envelope_payload: invalid arguments\n");
        return -1;
    }

    if (!keystore_is_keypair_loaded()) {
        fprintf(stderr, "decrypt_envelope_payload: keypair not loaded\n");
        return -1;
    }

    // Get our public key (Ed25519)
    unsigned char our_ed25519_pubkey[PUBKEY_SIZE];
    if (keystore_get_encryption_public_key(our_ed25519_pubkey) != 0) {
        fprintf(stderr, "decrypt_envelope_payload: failed to get encryption public key\n");
        return -1;
    }

    // Get our private key (X25519)
    unsigned char our_x25519_privkey[SECRET_SIZE];
    if (_keystore_get_encryption_private_key(our_x25519_privkey) != 0) {
        fprintf(stderr, "decrypt_envelope_payload: failed to get encryption private key\n");
        return -1;
    }

    // Find our key wrap
    Tinyweb__RecipientKeyWrap* our_wrap = NULL;
    for (size_t i = 0; i < envelope->n_keywraps; i++) {
        if (envelope->keywraps[i]->recipient_pubkey.len == PUBKEY_SIZE &&
            memcmp(envelope->keywraps[i]->recipient_pubkey.data, our_ed25519_pubkey, PUBKEY_SIZE) == 0) {
            our_wrap = envelope->keywraps[i];
            break;
        }
    }

    if (!our_wrap) {
        fprintf(stderr, "decrypt_envelope_payload: not a recipient of this envelope\n");
        sodium_memzero(our_x25519_privkey, SECRET_SIZE);
        return -1;
    }

    // Decrypt the symmetric key
    unsigned char symmetric_key[crypto_secretbox_KEYBYTES];
    if (crypto_box_open_easy(symmetric_key,
                            our_wrap->wrapped_key.data, our_wrap->wrapped_key.len,
                            our_wrap->key_nonce.data,
                            envelope->ephemeral_pubkey.data,
                            our_x25519_privkey) != 0)
    {
        fprintf(stderr, "decrypt_envelope_payload: failed to decrypt symmetric key\n");
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        sodium_memzero(our_x25519_privkey, SECRET_SIZE);
        return -1;
    }

    // Check ciphertext size
    if (envelope->payload_ciphertext.len < crypto_secretbox_MACBYTES ||
        envelope->payload_ciphertext.len > MAX_CIPHERTEXT_SIZE) {
        fprintf(stderr, "decrypt_envelope_payload: invalid ciphertext size %zu\n",
                envelope->payload_ciphertext.len);
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        sodium_memzero(our_x25519_privkey, SECRET_SIZE);
        return -1;
    }

    // Decrypt the payload
    *plaintext_len = envelope->payload_ciphertext.len - crypto_secretbox_MACBYTES;
    *plaintext = malloc(*plaintext_len);
    if (!*plaintext) {
        fprintf(stderr, "decrypt_envelope_payload: memory allocation failed\n");
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        sodium_memzero(our_x25519_privkey, SECRET_SIZE);
        return -1;
    }

    if (crypto_secretbox_open_easy(*plaintext,
                                   envelope->payload_ciphertext.data,
                                   envelope->payload_ciphertext.len,
                                   envelope->payload_nonce.data,
                                   symmetric_key) != 0)
    {
        fprintf(stderr, "decrypt_envelope_payload: decryption failed\n");
        free(*plaintext);
        *plaintext = NULL;
        *plaintext_len = 0;
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        sodium_memzero(our_x25519_privkey, SECRET_SIZE);
        return -1;
    }

    // Clean up sensitive data
    sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
    sodium_memzero(our_x25519_privkey, SECRET_SIZE);

    return 0;
}
