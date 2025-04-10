#ifndef SIGNING_H
#define SIGNING_H

#include <stddef.h>
#include <sodium.h>

// Maximum size of a message that can be signed
#define MAX_SIGNED_MESSAGE_SIZE 1024

// Structure to hold a signed message
typedef struct {
    unsigned char message[MAX_SIGNED_MESSAGE_SIZE];
    size_t message_len;
    unsigned char signature[crypto_sign_BYTES];
} SignedMessage;

/**
 * Sign a message using the node's private key
 * 
 * @param message The message to sign
 * @param message_len Length of the message
 * @param signed_msg Output parameter to store the signed message
 * @return 0 on success, -1 on failure
 */
int sign_message(const char* message, size_t message_len, SignedMessage* signed_msg);

/**
 * Verify a signed message using the node's public key
 * 
 * @param signed_msg The signed message to verify
 * @return 0 if signature is valid, -1 if invalid
 */
int verify_signature(const SignedMessage* signed_msg);

#endif // SIGNING_H 