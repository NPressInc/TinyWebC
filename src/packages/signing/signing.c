#include <string.h>
#include <sodium.h>
#include "packages/signing/signing.h"
#include "packages/keystore/keystore.h"

int sign_message(const char* message, unsigned char* signature_out) {
    // Check if a keypair is loaded
    if (!keystore_is_keypair_loaded()) {
        return -1;
    }

    // Get the Ed25519 private key from keystore
    unsigned char private_key[SIGN_SECRET_SIZE];
    if (!_keystore_get_private_key(private_key)) {
        return -1;
    }

    // Sign the message directly into the provided buffer
    size_t message_len = strlen(message);
    if (crypto_sign_detached(signature_out, NULL,
                           (unsigned char*)message, message_len,
                           private_key) != 0) {
        return -1;
    }

    return 0;  // Success
}

int verify_signature(const unsigned char* signature, const unsigned char* message, size_t message_len, const unsigned char* public_key){
    // Check if public key is provided
    if (!public_key) {
        return -1;
    }

    return crypto_sign_verify_detached(signature, message, message_len, public_key);
} 