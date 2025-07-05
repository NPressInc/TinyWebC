#ifndef KEYSTORE_H
#define KEYSTORE_H

#include <sodium.h>

// Key sizes
#define SIGN_PUBKEY_SIZE crypto_sign_PUBLICKEYBYTES    /* 32 */
#define SIGN_SECRET_SIZE crypto_sign_SECRETKEYBYTES    /* 64 */
#define PUBKEY_SIZE crypto_box_PUBLICKEYBYTES          /* 32 */
#define SECRET_SIZE crypto_box_SECRETKEYBYTES          /* 32 */

// Initialize the keystore and libsodium
int keystore_init(void);

// Generate a new Ed25519 keypair
int keystore_generate_keypair(void);

// Save the Ed25519 private key to a file (encrypted with passphrase)
int keystore_save_private_key(const char* filename, const char* passphrase);

// Load an Ed25519 private key from a file (decrypt with passphrase)
int keystore_load_private_key(const char* filename, const char* passphrase);

// Load raw Ed25519 keypair directly into keystore (for internal use)
int keystore_load_raw_ed25519_keypair(const unsigned char* private_key, const unsigned char* x25519_public_key);

// Get the Ed25519 public key (for signing or as sender ID)
// Returns 1 on success, 0 on failure
int keystore_get_public_key(unsigned char* pubkey_out);

// Get the X25519 public key (converted from Ed25519, for encryption)
// Returns 1 on success, 0 on failure
int keystore_get_encryption_public_key(unsigned char* pubkey_out);

// Internal use only by encryption and signing modules
// These functions should only be called by trusted internal modules
int _keystore_get_private_key(unsigned char* privkey_out);
int _keystore_get_encryption_private_key(unsigned char* privkey_out);

// Check if a keypair is currently loaded
int keystore_is_keypair_loaded(void);

// Clean up the keystore
void keystore_cleanup(void);

#endif /* KEYSTORE_H */ 