#ifndef SIGNING_H
#define SIGNING_H

#include <stddef.h>
#include <sodium.h>

// Maximum size of a message that can be signed
#define SIGNED_MESSAGE_SIZE 32
#define SIGNATURE_SIZE 64

/**
 * Sign a message using the node's private key
 * 
 * @param message The message to sign
 * @param message_len Length of the message
 * @param signed_msg Output parameter to store the signed message
 * @return 0 on success, -1 on failure
 */
int sign_message(const char* message, unsigned char* signature_out);
/**
 * Verify a signed message using a provided public key
 * 
 * @param signed_msg The signed message to verify
 * @param public_key The public key to use for verification
 * @return 0 if signature is valid, -1 if invalid
 */
int verify_signature(const unsigned char* signature, const unsigned char* message, size_t message_len, const unsigned char* public_key);

#endif // SIGNING_H 