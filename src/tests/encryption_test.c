#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "packages/encryption/encryption.h"

void print_hex(const char* label, const unsigned char* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

int main() {

    printf("Starting Encryption Test");

    if (sodium_init() < 0) {
        printf("Sodium initialization failed\n");
        return 1;
    }

    // Generate and save sender's private key
    if (!save_private_key("node_key.bin", "testpass")) {
        printf("Failed to save private key\n");
        return 1;
    }
    printf("Private key generated and saved\n");

    if (!load_private_key("node_key.bin", "testpass")) {
        printf("Failed to load private key\n");
        return 1;
    }
    printf("Private key loaded\n");

    const char* message = "Hello, encrypted world!";
    size_t msg_len = strlen(message) + 1;
    print_hex("Original message", (unsigned char*)message, msg_len);

    // Generate multiple recipient keypairs (3 recipients)
    #define NUM_RECIPIENTS 3
    unsigned char recip_pubkeys[NUM_RECIPIENTS][PUBKEY_SIZE];
    unsigned char recip_privkeys[NUM_RECIPIENTS][SECRET_SIZE];
    const unsigned char* recip_pubkey_ptrs[NUM_RECIPIENTS];

    for (int i = 0; i < NUM_RECIPIENTS; i++) {
        crypto_box_keypair(recip_pubkeys[i], recip_privkeys[i]);
        recip_pubkey_ptrs[i] = recip_pubkeys[i];
        printf("Recipient %d:\n", i + 1);
        print_hex("  Public key", recip_pubkeys[i], PUBKEY_SIZE);
        print_hex("  Private key", recip_privkeys[i], SECRET_SIZE);
    }

    // Encrypt for multiple recipients
    EncryptedPayload* encrypted_multi = encrypt_payload_multi(
        (unsigned char*)message, 
        msg_len, 
        recip_pubkey_ptrs, 
        NUM_RECIPIENTS
    );
    
    if (!encrypted_multi) {
        printf("Multiple recipient encryption failed\n");
        cleanup_encryption();
        return 1;
    }
    printf("Multiple recipient encryption succeeded\n");
    print_hex("Ephemeral pubkey", encrypted_multi->ephemeral_pubkey, PUBKEY_SIZE);
    print_hex("Nonce", encrypted_multi->nonce, NONCE_SIZE);
    print_hex("Ciphertext", encrypted_multi->ciphertext, encrypted_multi->ciphertext_len);
    for (int i = 0; i < NUM_RECIPIENTS; i++) {
        printf("Encrypted key %d:\n", i + 1);
        print_hex("  Key", &encrypted_multi->encrypted_keys[i * encrypted_multi->encrypted_key_len], 
                  encrypted_multi->encrypted_key_len);
    }

    // Decrypt with each recipient's private key
    for (int i = 0; i < NUM_RECIPIENTS; i++) {
        size_t plaintext_len;
        unsigned char* decrypted = decrypt_payload(encrypted_multi, &plaintext_len, recip_privkeys[i], recip_pubkeys[i], &recip_pubkeys[0][0]);
        if (!decrypted) {
            printf("Decryption failed for recipient %d\n", i + 1);
            continue;
        }

        if (strcmp((char*)decrypted, message) != 0) {
            printf("Decryption mismatch for recipient %d\n", i + 1);
            print_hex("Decrypted", decrypted, plaintext_len);
            free(decrypted);
            continue;
        }

        printf("Recipient %d decryption verified: %s\n", i + 1, decrypted);
        print_hex("Decrypted", decrypted, plaintext_len);
        free(decrypted);
    }

    free_encrypted_payload(encrypted_multi);
    cleanup_encryption();
    printf("Test completed\n");
    return 0;
}