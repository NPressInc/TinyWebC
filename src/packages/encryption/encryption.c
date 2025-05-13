#include "encryption.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "packages/keystore/keystore.h"
#include "packages/utils/byteorder.h"

EncryptedPayload *encrypt_payload_multi(const unsigned char *plaintext, size_t plaintext_len,
                                        const unsigned char *recipient_pubkeys, size_t num_recipients)
{
    if (!keystore_is_keypair_loaded() || num_recipients == 0)
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

    // Generate ephemeral keypair
    unsigned char ephemeral_privkey[SECRET_SIZE];
    crypto_box_keypair(encrypted->ephemeral_pubkey, ephemeral_privkey);

    // Generate a random symmetric key
    unsigned char symmetric_key[crypto_secretbox_KEYBYTES];
    randombytes_buf(symmetric_key, crypto_secretbox_KEYBYTES);

    // Encrypt the plaintext with the symmetric key
    encrypted->ciphertext_len = plaintext_len + crypto_secretbox_MACBYTES;

    encrypted->ciphertext = malloc(encrypted->ciphertext_len);

    randombytes_buf(encrypted->nonce, NONCE_SIZE);
    if (crypto_secretbox_easy(encrypted->ciphertext, plaintext, plaintext_len,
                              encrypted->nonce, symmetric_key) != 0)
    {
        free(encrypted->ciphertext);
        free(encrypted);
        return NULL;
    }

    // Encrypt the symmetric key for each recipient

    encrypted->key_nonces = malloc(NONCE_SIZE*num_recipients);
    encrypted->encrypted_keys = malloc(ENCRYPTED_KEY_SIZE*num_recipients);

    for (size_t i = 0; i < num_recipients; i++)
    {
        randombytes_buf(&encrypted->key_nonces[i], NONCE_SIZE);
        if (crypto_box_easy(&encrypted->encrypted_keys[i],
                            symmetric_key, crypto_secretbox_KEYBYTES,
                            &encrypted->key_nonces[i],
                            &recipient_pubkeys[i * PUBKEY_SIZE],
                            ephemeral_privkey) != 0)
        {
            
            free(encrypted->key_nonces);
            free(encrypted->encrypted_keys);
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
    if (!encrypted) return;
    
    if (encrypted->ciphertext) {
        free(encrypted->ciphertext);
        encrypted->ciphertext = NULL;
    }
    
    if (encrypted->key_nonces) {
        free(encrypted->key_nonces);
        encrypted->key_nonces = NULL;
    }
    
    if (encrypted->encrypted_keys) {
        free(encrypted->encrypted_keys);
        encrypted->encrypted_keys = NULL;
    }
    
    free(encrypted);
}

unsigned char *decrypt_payload(const EncryptedPayload *encrypted, const unsigned char *recipient_pubkeys)
{

    unsigned char recipient_publickey[PUBKEY_SIZE];
    keystore_get_encryption_public_key(recipient_publickey);

    unsigned char recipient_privkey[SECRET_SIZE];
    _keystore_get_encryption_private_key(recipient_privkey);

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
    if (crypto_box_open_easy(symmetric_key, &encrypted->encrypted_keys[recipient_index], 
                             ENCRYPTED_KEY_SIZE,
                             &encrypted->key_nonces[recipient_index], 
                             encrypted->ephemeral_pubkey, 
                             recipient_privkey) != 0)
    {
        fprintf(stderr, "Failed to decrypt symmetric key\n");
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        sodium_memzero(recipient_publickey, PUBKEY_SIZE);
        sodium_memzero(recipient_privkey, SECRET_SIZE);
        return NULL;
    }

    // Step 3: Decrypt the ciphertext using the symmetric key
    unsigned char *plaintext = malloc(encrypted->ciphertext_len - crypto_secretbox_MACBYTES);
    if (!plaintext)
    {
        fprintf(stderr, "Memory allocation failed\n");
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        sodium_memzero(recipient_publickey, PUBKEY_SIZE);
        sodium_memzero(recipient_privkey, SECRET_SIZE);
        return NULL;
    }

    if (crypto_secretbox_open_easy(plaintext, encrypted->ciphertext, encrypted->ciphertext_len,
                                   encrypted->nonce, symmetric_key) != 0)
    {
        fprintf(stderr, "Decryption of payload failed\n");
        free(plaintext);
        sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
        sodium_memzero(recipient_publickey, PUBKEY_SIZE);
        sodium_memzero(recipient_privkey, SECRET_SIZE);
        return NULL;
    }

    // Clean up sensitive data
    sodium_memzero(symmetric_key, crypto_secretbox_KEYBYTES);
    sodium_memzero(recipient_publickey, PUBKEY_SIZE);
    sodium_memzero(recipient_privkey, SECRET_SIZE);

    return plaintext;
}

size_t encrypted_payload_get_size(EncryptedPayload* payload){
    if (!payload || !payload->ciphertext) return 0;
    size_t mem_size = 0;

    mem_size += payload->ciphertext_len;
    mem_size += sizeof(size_t);
    mem_size += NONCE_SIZE;
    mem_size += payload->num_recipients * ENCRYPTED_KEY_SIZE;
    mem_size += payload->num_recipients * NONCE_SIZE;
    mem_size += PUBKEY_SIZE;
    mem_size += sizeof(size_t);

    return mem_size;
}


int encrypted_payload_serialize(EncryptedPayload* payload, unsigned char** out_buffer){

    if(!payload){
        printf("payload is empty \n");
        return 1;
    }
    if (!out_buffer) {
        printf("output buffer is NULL \n");
        return 1;
    }

    unsigned char* ptr = *out_buffer;

    // Convert num_recipients to network byte order and copy it
    size_t num_recipients_net = htonll(payload->num_recipients);
    memcpy(ptr, &num_recipients_net, sizeof(size_t));
    ptr += sizeof(size_t);

    // Convert ciphertext_len to network byte order and copy it
    size_t ciphertext_len_net = htonll(payload->ciphertext_len);
    memcpy(ptr, &ciphertext_len_net, sizeof(size_t));
    ptr += sizeof(size_t);

    // Copy ephemeral_pubkey
    memcpy(ptr, payload->ephemeral_pubkey, PUBKEY_SIZE);
    ptr += PUBKEY_SIZE;

    // Copy the nonce
    memcpy(ptr, payload->nonce, NONCE_SIZE);
    ptr += NONCE_SIZE;

    // Copy the ciphertext
    memcpy(ptr, payload->ciphertext, payload->ciphertext_len);
    ptr += payload->ciphertext_len;

    // Encrypt keys
    size_t key_bytes = payload->num_recipients * ENCRYPTED_KEY_SIZE;
    memcpy(ptr, payload->encrypted_keys, key_bytes);
    ptr += key_bytes;

    // Encrypt key nonces
    size_t nonce_bytes = payload->num_recipients * NONCE_SIZE;
    memcpy(ptr, payload->key_nonces, nonce_bytes);
    ptr += nonce_bytes;

    *out_buffer = ptr;

    return 0;
}

EncryptedPayload* encrypted_payload_deserialize(const char** buffer) {
    if (!buffer || !*buffer) {
        printf("Invalid buffer\n");
        return NULL;
    }

    const char* ptr = *buffer;

    // Allocate memory for the EncryptedPayload
    EncryptedPayload* payload = (EncryptedPayload*)malloc(sizeof(EncryptedPayload));
    if (!payload) {
        printf("Failed to allocate memory for EncryptedPayload\n");
        return NULL;
    }
    // Initialize to avoid undefined behavior
    memset(payload, 0, sizeof(EncryptedPayload));

    // Deserialize num_recipients (convert from network byte order)
    size_t num_recipients_net;
    memcpy(&num_recipients_net, ptr, sizeof(size_t));
    payload->num_recipients = ntohl(num_recipients_net);
    ptr += sizeof(size_t);

    // Deserialize ciphertext_len (convert from network byte order)
    size_t ciphertext_len_net;
    memcpy(&ciphertext_len_net, ptr, sizeof(size_t));
    payload->ciphertext_len = ntohl(ciphertext_len_net);
    ptr += sizeof(size_t);

    // Deserialize ephemeral_pubkey
    memcpy(payload->ephemeral_pubkey, ptr, PUBKEY_SIZE);
    ptr += PUBKEY_SIZE;

    // Deserialize the nonce
    memcpy(payload->nonce, ptr, NONCE_SIZE);
    ptr += NONCE_SIZE;

    // Deserialize the ciphertext
    if (payload->ciphertext_len > 0) {
        payload->ciphertext = (char*)malloc(payload->ciphertext_len);
        if (!payload->ciphertext) {
            printf("Failed to allocate memory for ciphertext\n");
            free(payload);
            return NULL;
        }
        memcpy(payload->ciphertext, ptr, payload->ciphertext_len);
        ptr += payload->ciphertext_len;
    } else {
        payload->ciphertext = NULL;
    }

    // Deserialize encrypted_keys
    if (payload->num_recipients > 0) {
        payload->encrypted_keys = (char*)malloc(payload->num_recipients * ENCRYPTED_KEY_SIZE);
        if (!payload->encrypted_keys) {
            printf("Failed to allocate memory for encrypted_keys\n");
            if (payload->ciphertext) {
                free(payload->ciphertext);
            }
            free(payload);
            return NULL;
        }
        memcpy(payload->encrypted_keys, ptr, payload->num_recipients * ENCRYPTED_KEY_SIZE);
        ptr += payload->num_recipients * ENCRYPTED_KEY_SIZE;
    } else {
        payload->encrypted_keys = NULL;
    }

    // Deserialize key_nonces
    if (payload->num_recipients > 0) {
        payload->key_nonces = (char*)malloc(payload->num_recipients * NONCE_SIZE);
        if (!payload->key_nonces) {
            printf("Failed to allocate memory for key_nonces\n");
            if (payload->ciphertext) {
                free(payload->ciphertext);
            }
            if (payload->encrypted_keys) {
                free(payload->encrypted_keys);
            }
            free(payload);
            return NULL;
        }
        memcpy(payload->key_nonces, ptr, payload->num_recipients * NONCE_SIZE);
        ptr += payload->num_recipients * NONCE_SIZE;
    } else {
        payload->key_nonces = NULL;
    }

    // Update the caller's buffer pointer
    *buffer = ptr;
    return payload;
}

