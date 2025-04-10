#ifndef KEYSTORE_H
#define KEYSTORE_H

#include <sodium.h>

// Key sizes
#define PUBKEY_SIZE crypto_box_PUBLICKEYBYTES    /* 32 */
#define SECRET_SIZE crypto_box_SECRETKEYBYTES    /* 32 */

// Initialize the keystore and libsodium
int keystore_init(void);

// Generate a new keypair
int keystore_generate_keypair(void);

// Save the private key to a file (encrypted with passphrase)
int keystore_save_private_key(const char* filename, const char* passphrase);

// Load a private key from a file (decrypt with passphrase)
int keystore_load_private_key(const char* filename, const char* passphrase);

// Get the public key (for encryption or signing)
// Returns 1 on success, 0 on failure
int keystore_get_public_key(unsigned char* pubkey_out);

// Internal use only by encryption and signing modules
// These functions should only be called by trusted internal modules
int _keystore_get_private_key(unsigned char* privkey_out);
int _keystore_get_keypair(unsigned char* pubkey_out, unsigned char* privkey_out);

// Check if a keypair is currently loaded
int keystore_is_keypair_loaded(void);

// Clean up the keystore
void keystore_cleanup(void);

#endif /* KEYSTORE_H */ 