#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "packages/encryption/encryption.h"
#include "packages/keystore/keystore.h"
#include "packages/utils/print.h"

int encryption_test_main(void) {
    printf("Starting Encryption Test\n");

    // Initialize the keystore
    if (!keystore_init()) {
        printf("Keystore initialization failed\n");
        return 1;
    }

    // Generate and save sender's Ed25519 keypair
    if (!keystore_generate_keypair()) {
        printf("Keystore initialization failed\n");
        return 1;
    }

    if (!keystore_save_private_key("node_key.bin", "testpass")) {
        printf("Failed to save private key\n");
        return 1;
    }
    printf("Ed25519 private key generated and saved\n");

    // Get the sender's Ed25519 public key (for signing and identity)
    unsigned char sender_pubkey[SIGN_PUBKEY_SIZE];
    if (!keystore_get_public_key(sender_pubkey)) {
        printf("Failed to get sender's Ed25519 public key\n");
        return 1;
    }
    printf("Sender's Ed25519 public key (for signing and identity):\n");
    print_hex("  Public key", sender_pubkey, SIGN_PUBKEY_SIZE);

    // Get the sender's X25519 public key (for encryption)
    unsigned char sender_encryption_pubkey[PUBKEY_SIZE];
    if (!keystore_get_encryption_public_key(sender_encryption_pubkey)) {
        printf("Failed to get sender's X25519 public key\n");
        return 1;
    }
    printf("Sender's X25519 public key (for encryption):\n");
    print_hex("  Encryption public key", sender_encryption_pubkey, PUBKEY_SIZE);

    // Clear the loaded keypair
    keystore_cleanup();

    // Load the private key
    if (!keystore_load_private_key("node_key.bin", "testpass")) {
        printf("Failed to load private key\n");
        return 1;
    }
    printf("Ed25519 private key loaded\n");

    // Create a test message that's within the size limit
    const char* message = "This is a test message for encryption";
    size_t msg_len = strlen(message) + 1;
    printf("Message length: %zu bytes\n", msg_len);

    // Generate multiple recipient keypairs (3 recipients)
    #define NUM_RECIPIENTS 4  // Increased to include sender
    unsigned char recip_pubkeys[NUM_RECIPIENTS][PUBKEY_SIZE];
    unsigned char recip_privkeys[NUM_RECIPIENTS][SECRET_SIZE];
    
    // Create a continuous buffer for all public keys
    unsigned char all_pubkeys[NUM_RECIPIENTS * PUBKEY_SIZE];

    // First recipient is the sender (using X25519 key for encryption)
    memcpy(recip_pubkeys[0], sender_encryption_pubkey, PUBKEY_SIZE);
    memcpy(all_pubkeys, sender_encryption_pubkey, PUBKEY_SIZE);
    printf("Recipient 0 (Sender):\n");
    print_hex("  X25519 Public key", recip_pubkeys[0], PUBKEY_SIZE);

    // Generate the other recipients
    for (int i = 1; i < NUM_RECIPIENTS; i++) {
        crypto_box_keypair(recip_pubkeys[i], recip_privkeys[i]);
        memcpy(all_pubkeys + (i * PUBKEY_SIZE), recip_pubkeys[i], PUBKEY_SIZE);
        printf("Recipient %d:\n", i);
        print_hex("  Public key", recip_pubkeys[i], PUBKEY_SIZE);
        print_hex("  Private key", recip_privkeys[i], SECRET_SIZE);
    }

    // Encrypt for multiple recipients
    EncryptedPayload* encrypted_multi = encrypt_payload_multi(
        (unsigned char*)message, 
        msg_len, 
        all_pubkeys, 
        NUM_RECIPIENTS
    );
    
    if (!encrypted_multi) {
        printf("Multiple recipient encryption failed\n");
        keystore_cleanup();
        return 1;
    }
    printf("Multiple recipient encryption succeeded\n");
    print_hex("Ephemeral pubkey", encrypted_multi->ephemeral_pubkey, PUBKEY_SIZE);
    print_hex("Nonce", encrypted_multi->nonce, NONCE_SIZE);
    
    // Print encrypted keys for each recipient
    for (int i = 0; i < NUM_RECIPIENTS; i++) {
        printf("Encrypted key %d:\n", i);
        print_hex("  Key", encrypted_multi->encrypted_keys[i], ENCRYPTED_KEY_SIZE);
        print_hex("  Nonce", encrypted_multi->key_nonces[i], NONCE_SIZE);
    }

    // Decrypt with sender's private key
    printf("\nDecrypting with sender's private key:\n");
    unsigned char sender_privkey[SECRET_SIZE];
    if (!_keystore_get_encryption_private_key(sender_privkey)) {
        printf("Failed to get sender's X25519 private key\n");
        free_encrypted_payload(encrypted_multi);
        keystore_cleanup();
        return 1;
    }
    
    size_t plaintext_len;
    unsigned char* decrypted = decrypt_payload(encrypted_multi, &plaintext_len, 
                                              sender_privkey, 
                                              sender_encryption_pubkey, 
                                              all_pubkeys);
    if (!decrypted) {
        printf("Decryption failed for sender\n");
    } else {
        if (strcmp((char*)decrypted, message) != 0) {
            printf("Decryption mismatch for sender\n");
            print_hex("Decrypted", decrypted, plaintext_len);
            free(decrypted);
        } else {
            printf("Sender decryption verified: %s\n", decrypted);
            free(decrypted);
        }
    }

    // Decrypt with each recipient's private key
    for (int i = 1; i < NUM_RECIPIENTS; i++) {
        size_t plaintext_len;
        unsigned char* decrypted = decrypt_payload(encrypted_multi, &plaintext_len, 
                                                  recip_privkeys[i], 
                                                  recip_pubkeys[i], 
                                                  all_pubkeys);
        if (!decrypted) {
            printf("Decryption failed for recipient %d\n", i);
            continue;
        }

        if (strcmp((char*)decrypted, message) != 0) {
            printf("Decryption mismatch for recipient %d\n", i);
            print_hex("Decrypted", decrypted, plaintext_len);
            free(decrypted);
            continue;
        }

        printf("Recipient %d decryption verified: %s\n", i, decrypted);
        free(decrypted);
    }

    // Test with a message that exceeds the size limit
    printf("\nTesting with a message that exceeds the size limit:\n");
    char* large_message = malloc(MAX_PLAINTEXT_SIZE + 1000);
    if (large_message) {
        memset(large_message, 'A', MAX_PLAINTEXT_SIZE + 1000);
        large_message[MAX_PLAINTEXT_SIZE + 999] = '\0';
        
        EncryptedPayload* large_encrypted = encrypt_payload_multi(
            (unsigned char*)large_message, 
            MAX_PLAINTEXT_SIZE + 1000, 
            all_pubkeys, 
            NUM_RECIPIENTS
        );
        
        if (large_encrypted) {
            printf("ERROR: Encryption of oversized message succeeded when it should have failed\n");
            free_encrypted_payload(large_encrypted);
        } else {
            printf("SUCCESS: Encryption of oversized message correctly failed\n");
        }
        
        free(large_message);
    }

    free_encrypted_payload(encrypted_multi);
    keystore_cleanup();
    printf("Test completed\n");
    return 0;
}