#include <string.h>
#include <sodium.h>
#include "packages/signing/signing.h"
#include "packages/keystore/keystore.h"

int sign_message(const char* message, size_t message_len, SignedMessage* signed_msg) {
    // Check if message is too large
    if (message_len > MAX_SIGNED_MESSAGE_SIZE) {
        return -1;
    }

    // Check if a keypair is loaded
    if (!keystore_is_keypair_loaded()) {
        return -1;
    }

    // Get the private key from keystore
    unsigned char private_key[SECRET_SIZE];
    if (!_keystore_get_private_key(private_key)) {
        return -1;
    }

    // Copy the message to the signed message structure
    memcpy(signed_msg->message, message, message_len);
    signed_msg->message_len = message_len;

    // Sign the message
    if (crypto_sign_detached(signed_msg->signature, NULL,
                           (unsigned char*)message, message_len,
                           private_key) != 0) {
        return -1;
    }

    return 0;
}

int verify_signature(const SignedMessage* signed_msg) {
    // Check if a keypair is loaded
    if (!keystore_is_keypair_loaded()) {
        return -1;
    }

    // Get the public key from keystore
    unsigned char public_key[PUBKEY_SIZE];
    if (!keystore_get_public_key(public_key)) {
        return -1;
    }

    // Verify the signature
    if (crypto_sign_verify_detached(signed_msg->signature,
                                  signed_msg->message,
                                  signed_msg->message_len,
                                  public_key) != 0) {
        return -1;
    }

    return 0;
} 