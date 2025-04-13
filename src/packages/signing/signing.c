#include <string.h>
#include <sodium.h>
#include "packages/signing/signing.h"
#include "packages/keystore/keystore.h"

unsigned char* sign_message(const char* message) {
    // Check if a keypair is loaded
    if (!keystore_is_keypair_loaded()) {
        return NULL;
    }

    // Get the Ed25519 private key from keystore
    unsigned char private_key[SIGN_SECRET_SIZE];
    if (!_keystore_get_private_key(private_key)) {
        return NULL;
    }

    unsigned char* signature = malloc(crypto_sign_BYTES);

    // Sign the message
    if (crypto_sign_detached(signature, NULL,
                           (unsigned char*)message, SIGNED_MESSAGE_SIZE,
                           private_key) != 0) {
        return NULL;
    }

    return signature;
}

int verify_signature(const unsigned char* signature, const unsigned char* message, size_t message_len, const unsigned char* public_key){
    // Check if public key is provided
    if (!public_key) {
        return -1;
    }

    return crypto_sign_verify_detached(signature, message, message_len, public_key);
} 