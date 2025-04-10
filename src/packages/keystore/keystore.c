#include "keystore.h"
#include <stdio.h>
#include <string.h>

// Static storage for the node's keypair
static unsigned char node_privkey[SECRET_SIZE];
static unsigned char node_pubkey[PUBKEY_SIZE];
static int keypair_loaded = 0;

int keystore_init(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize sodium\n");
        return 0;
    }
    return 1;
}

int keystore_generate_keypair(void) {
    if (crypto_box_keypair(node_pubkey, node_privkey) != 0) {
        fprintf(stderr, "Failed to generate keypair\n");
        return 0;
    }
    keypair_loaded = 1;
    return 1;
}

int keystore_save_private_key(const char* filename, const char* passphrase) {
    if (!keypair_loaded) {
        fprintf(stderr, "No keypair loaded to save\n");
        return 0;
    }

    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char ciphertext[SECRET_SIZE + crypto_secretbox_MACBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];

    // Generate random nonce and salt
    randombytes_buf(nonce, sizeof nonce);
    randombytes_buf(salt, sizeof salt);

    // Derive key from passphrase
    if (crypto_pwhash(key, sizeof key,
                     passphrase, strlen(passphrase), salt,
                     crypto_pwhash_OPSLIMIT_INTERACTIVE,
                     crypto_pwhash_MEMLIMIT_INTERACTIVE,
                     crypto_pwhash_ALG_DEFAULT) != 0) {
        fprintf(stderr, "Failed to derive key from passphrase\n");
        return 0;
    }

    // Encrypt the private key
    if (crypto_secretbox_easy(ciphertext, node_privkey,
                             SECRET_SIZE, nonce, key) != 0) {
        sodium_memzero(key, sizeof key);
        fprintf(stderr, "Failed to encrypt private key\n");
        return 0;
    }

    // Write to file: salt, nonce, encrypted private key
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        sodium_memzero(key, sizeof key);
        fprintf(stderr, "Failed to open file for writing\n");
        return 0;
    }

    int success = (fwrite(salt, 1, sizeof salt, fp) == sizeof salt &&
                  fwrite(nonce, 1, sizeof nonce, fp) == sizeof nonce &&
                  fwrite(ciphertext, 1, sizeof ciphertext, fp) == sizeof ciphertext);

    fclose(fp);
    sodium_memzero(key, sizeof key);

    if (!success) {
        fprintf(stderr, "Failed to write to file\n");
        return 0;
    }

    return 1;
}

int keystore_load_private_key(const char* filename, const char* passphrase) {
    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char ciphertext[SECRET_SIZE + crypto_secretbox_MACBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];

    // Read from file
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open key file\n");
        return 0;
    }

    int success = (fread(salt, 1, sizeof salt, fp) == sizeof salt &&
                  fread(nonce, 1, sizeof nonce, fp) == sizeof nonce &&
                  fread(ciphertext, 1, sizeof ciphertext, fp) == sizeof ciphertext);

    fclose(fp);

    if (!success) {
        fprintf(stderr, "Failed to read from key file\n");
        return 0;
    }

    // Derive key from passphrase
    if (crypto_pwhash(key, sizeof key,
                     passphrase, strlen(passphrase), salt,
                     crypto_pwhash_OPSLIMIT_INTERACTIVE,
                     crypto_pwhash_MEMLIMIT_INTERACTIVE,
                     crypto_pwhash_ALG_DEFAULT) != 0) {
        fprintf(stderr, "Failed to derive key from passphrase\n");
        return 0;
    }

    // Decrypt the private key
    if (crypto_secretbox_open_easy(node_privkey, ciphertext,
                                 sizeof ciphertext, nonce, key) != 0) {
        sodium_memzero(key, sizeof key);
        fprintf(stderr, "Failed to decrypt private key\n");
        return 0;
    }

    sodium_memzero(key, sizeof key);

    // Derive public key from private key
    if (crypto_scalarmult_base(node_pubkey, node_privkey) != 0) {
        fprintf(stderr, "Failed to derive public key\n");
        return 0;
    }

    keypair_loaded = 1;
    return 1;
}

int keystore_get_public_key(unsigned char* pubkey_out) {
    if (!keypair_loaded) {
        fprintf(stderr, "No keypair loaded\n");
        return 0;
    }
    memcpy(pubkey_out, node_pubkey, PUBKEY_SIZE);
    return 1;
}

int _keystore_get_private_key(unsigned char* privkey_out) {
    if (!keypair_loaded) {
        fprintf(stderr, "No keypair loaded\n");
        return 0;
    }
    memcpy(privkey_out, node_privkey, SECRET_SIZE);
    return 1;
}

int _keystore_get_keypair(unsigned char* pubkey_out, unsigned char* privkey_out) {
    if (!keypair_loaded) {
        fprintf(stderr, "No keypair loaded\n");
        return 0;
    }
    memcpy(pubkey_out, node_pubkey, PUBKEY_SIZE);
    memcpy(privkey_out, node_privkey, SECRET_SIZE);
    return 1;
}

int keystore_is_keypair_loaded(void) {
    return keypair_loaded;
}

void keystore_cleanup(void) {
    sodium_memzero(node_privkey, SECRET_SIZE);
    sodium_memzero(node_pubkey, PUBKEY_SIZE);
    keypair_loaded = 0;
} 