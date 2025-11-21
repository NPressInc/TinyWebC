#include "packages/encryption/encryption.h"
#include "packages/keystore/keystore.h"
#include "envelope.pb-c.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NUM_RECIPIENTS 3

static void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int encryption_test_main(int argc, char** argv) {
    (void)argc;
    (void)argv;

    printf("=== Encryption Test (Protobuf Envelope API) ===\n\n");

    // Initialize libsodium
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        return 1;
    }

    // Initialize keystore
    if (keystore_init() == 0) {
        fprintf(stderr, "Failed to initialize keystore\n");
        return 1;
    }

    // Generate sender's keypair
    if (keystore_generate_keypair() == 0) {
        fprintf(stderr, "Failed to generate sender keypair\n");
        keystore_cleanup();
        return 1;
    }

    // Get sender's public key
    unsigned char sender_pubkey[PUBKEY_SIZE];
    keystore_get_public_key(sender_pubkey);
    print_hex("Sender public key", sender_pubkey, PUBKEY_SIZE);

    // Generate recipient keypairs
    unsigned char recip_pubkeys[NUM_RECIPIENTS][PUBKEY_SIZE];
    
    printf("\nGenerating %d recipient keypairs:\n", NUM_RECIPIENTS);
    for (int i = 0; i < NUM_RECIPIENTS; i++) {
        crypto_sign_keypair(recip_pubkeys[i], (unsigned char[64]){0}); // Generate Ed25519 keypair
        printf("Recipient %d:\n", i);
        print_hex("  Public key", recip_pubkeys[i], PUBKEY_SIZE);
    }

    // Prepare all recipient public keys
    unsigned char all_pubkeys[NUM_RECIPIENTS * PUBKEY_SIZE];
    for (int i = 0; i < NUM_RECIPIENTS; i++) {
        memcpy(all_pubkeys + (i * PUBKEY_SIZE), recip_pubkeys[i], PUBKEY_SIZE);
    }

    // Test message
    const char* message = "Hello, World! This is a test message.";
    size_t msg_len = strlen(message) + 1;

    printf("\nTest message: %s\n", message);
    printf("Message length: %zu bytes\n\n", msg_len);

    // Create and initialize envelope
    Tinyweb__Envelope envelope;
    tinyweb__envelope__init(&envelope);

    // Encrypt plaintext directly into envelope
    printf("Encrypting message for %d recipients...\n", NUM_RECIPIENTS);
    if (encrypt_envelope_payload((unsigned char*)message, msg_len, 
                                  all_pubkeys, NUM_RECIPIENTS, &envelope) != 0) {
        printf("ERROR: Encryption failed\n");
        keystore_cleanup();
        return 1;
    }
    printf("SUCCESS: Encryption completed\n");

    print_hex("Ephemeral pubkey", envelope.ephemeral_pubkey.data, envelope.ephemeral_pubkey.len);
    print_hex("Payload nonce", envelope.payload_nonce.data, envelope.payload_nonce.len);
    printf("Payload ciphertext length: %zu bytes\n", envelope.payload_ciphertext.len);
    printf("Number of key wraps: %zu\n", envelope.n_keywraps);

    // Decrypt with sender's private key
    printf("\nDecrypting with sender's private key:\n");
    unsigned char* decrypted = NULL;
    size_t decrypted_len = 0;
    
    if (decrypt_envelope_payload(&envelope, &decrypted, &decrypted_len) != 0) {
        printf("INFO: Decryption failed (expected if sender is not in recipients list)\n");
    } else {
        if (strcmp((char*)decrypted, message) == 0) {
            printf("SUCCESS: Sender decryption verified: %s\n", decrypted);
        } else {
            printf("ERROR: Decryption mismatch\n");
        }
        free(decrypted);
    }

    // Test with oversized message
    printf("\nTesting with oversized message:\n");
    char* large_message = malloc(MAX_PLAINTEXT_SIZE + 1000);
    if (large_message) {
        memset(large_message, 'A', MAX_PLAINTEXT_SIZE + 1000);
        large_message[MAX_PLAINTEXT_SIZE + 999] = '\0';
        
        Tinyweb__Envelope large_envelope;
        tinyweb__envelope__init(&large_envelope);
        
        if (encrypt_envelope_payload((unsigned char*)large_message, 
                                     MAX_PLAINTEXT_SIZE + 1000,
                                     all_pubkeys, NUM_RECIPIENTS, &large_envelope) != 0) {
            printf("SUCCESS: Oversized message correctly rejected\n");
        } else {
            printf("ERROR: Oversized message was accepted\n");
            tinyweb__envelope__free_unpacked(&large_envelope, NULL);
        }
        
        free(large_message);
    }

    // Test with too many recipients
    printf("\nTesting with too many recipients:\n");
    Tinyweb__Envelope many_recip_envelope;
    tinyweb__envelope__init(&many_recip_envelope);
    
    unsigned char* too_many_keys = malloc((MAX_RECIPIENTS + 10) * PUBKEY_SIZE);
    if (too_many_keys) {
        memset(too_many_keys, 0, (MAX_RECIPIENTS + 10) * PUBKEY_SIZE);
        
        if (encrypt_envelope_payload((unsigned char*)message, msg_len,
                                     too_many_keys, MAX_RECIPIENTS + 10,
                                     &many_recip_envelope) != 0) {
            printf("SUCCESS: Too many recipients correctly rejected\n");
        } else {
            printf("ERROR: Too many recipients was accepted\n");
            tinyweb__envelope__free_unpacked(&many_recip_envelope, NULL);
        }
        
        free(too_many_keys);
    }

    // Cleanup - manually free allocated fields (envelope is stack-allocated)
    if (envelope.ephemeral_pubkey.data) free(envelope.ephemeral_pubkey.data);
    if (envelope.payload_nonce.data) free(envelope.payload_nonce.data);
    if (envelope.payload_ciphertext.data) free(envelope.payload_ciphertext.data);
    if (envelope.keywraps) {
        for (size_t i = 0; i < envelope.n_keywraps; i++) {
            if (envelope.keywraps[i]) {
                if (envelope.keywraps[i]->recipient_pubkey.data) {
                    free(envelope.keywraps[i]->recipient_pubkey.data);
                }
                if (envelope.keywraps[i]->wrapped_key.data) {
                    free(envelope.keywraps[i]->wrapped_key.data);
                }
                free(envelope.keywraps[i]);
            }
        }
        free(envelope.keywraps);
    }
    
    keystore_cleanup();
    
    printf("\n=== Encryption Test Complete ===\n");
    return 0;
}
