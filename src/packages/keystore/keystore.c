#include "keystore.h"
#include "packages/utils/error.h"
#include "packages/utils/logger.h"
#include <stdio.h>
#include <string.h>
#include <pthread.h>

// Static storage for the node's Ed25519 keypair
static unsigned char sign_public_key[SIGN_PUBKEY_SIZE];
static unsigned char sign_secret_key[SIGN_SECRET_SIZE];
static int keypair_loaded = 0;
static pthread_mutex_t g_keystore_mutex = PTHREAD_MUTEX_INITIALIZER;

int keystore_init(void) {
    pthread_mutex_lock(&g_keystore_mutex);
    if (sodium_init() < 0) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_CRYPTO_ERROR, "keystore", __func__, __LINE__, "Failed to initialize libsodium");
        logger_error("keystore", "Failed to initialize libsodium");
        return -1;
    }
    pthread_mutex_unlock(&g_keystore_mutex);
    return 0;
}

int keystore_generate_keypair(void) {
    pthread_mutex_lock(&g_keystore_mutex);
    if (crypto_sign_keypair(sign_public_key, sign_secret_key) != 0) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_CRYPTO_ERROR, "keystore", __func__, __LINE__, "Failed to generate Ed25519 keypair");
        logger_error("keystore", "Failed to generate Ed25519 keypair");
        return -1;
    }
    keypair_loaded = 1;
    pthread_mutex_unlock(&g_keystore_mutex);
    return 0;
}

int keystore_save_private_key(const char* filename, const char* passphrase) {
    pthread_mutex_lock(&g_keystore_mutex);
    if (!keypair_loaded) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_INVALID_STATE, "keystore", __func__, __LINE__, "No keypair loaded to save");
        logger_error("keystore", "No keypair loaded to save");
        return -1;
    }

    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char ciphertext[SIGN_SECRET_SIZE + crypto_secretbox_MACBYTES];
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
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_CRYPTO_ERROR, "keystore", __func__, __LINE__, "Failed to derive key from passphrase");
        logger_error("keystore", "Failed to derive key from passphrase");
        return -1;
    }

    // Encrypt the private key
    if (crypto_secretbox_easy(ciphertext, sign_secret_key,
                             SIGN_SECRET_SIZE, nonce, key) != 0) {
        sodium_memzero(key, sizeof key);
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_CRYPTO_ERROR, "keystore", __func__, __LINE__, "Failed to encrypt private key");
        logger_error("keystore", "Failed to encrypt private key");
        return -1;
    }

    // Write to file: salt, nonce, encrypted private key
    FILE* fp = fopen(filename, "wb");
    if (!fp) {
        sodium_memzero(key, sizeof key);
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_IO_ERROR, "keystore", __func__, __LINE__, "Failed to open file for writing: %s", filename);
        logger_error("keystore", "Failed to open file for writing: %s", filename);
        return -1;
    }

    int success = (fwrite(salt, 1, sizeof salt, fp) == sizeof salt &&
                  fwrite(nonce, 1, sizeof nonce, fp) == sizeof nonce &&
                  fwrite(ciphertext, 1, sizeof ciphertext, fp) == sizeof ciphertext);

    fclose(fp);
    sodium_memzero(key, sizeof key);

    if (!success) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_IO_ERROR, "keystore", __func__, __LINE__, "Failed to write to file: %s", filename);
        logger_error("keystore", "Failed to write to file: %s", filename);
        return -1;
    }

    pthread_mutex_unlock(&g_keystore_mutex);
    return 0;
}

int keystore_load_private_key(const char* filename, const char* passphrase) {
    pthread_mutex_lock(&g_keystore_mutex);
    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char key[crypto_secretbox_KEYBYTES];
    unsigned char ciphertext[SIGN_SECRET_SIZE + crypto_secretbox_MACBYTES];
    unsigned char salt[crypto_pwhash_SALTBYTES];

    // Read from file
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_IO_ERROR, "keystore", __func__, __LINE__, "Failed to open key file: %s", filename);
        logger_error("keystore", "Failed to open key file: %s", filename);
        return -1;
    }

    int success = (fread(salt, 1, sizeof salt, fp) == sizeof salt &&
                  fread(nonce, 1, sizeof nonce, fp) == sizeof nonce &&
                  fread(ciphertext, 1, sizeof ciphertext, fp) == sizeof ciphertext);

    fclose(fp);

    if (!success) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_IO_ERROR, "keystore", __func__, __LINE__, "Failed to read from key file: %s", filename);
        logger_error("keystore", "Failed to read from key file: %s", filename);
        return -1;
    }

    // Derive key from passphrase
    if (crypto_pwhash(key, sizeof key,
                     passphrase, strlen(passphrase), salt,
                     crypto_pwhash_OPSLIMIT_INTERACTIVE,
                     crypto_pwhash_MEMLIMIT_INTERACTIVE,
                     crypto_pwhash_ALG_DEFAULT) != 0) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_CRYPTO_ERROR, "keystore", __func__, __LINE__, "Failed to derive key from passphrase");
        logger_error("keystore", "Failed to derive key from passphrase");
        return -1;
    }

    // Decrypt the private key
    if (crypto_secretbox_open_easy(sign_secret_key, ciphertext,
                                 sizeof ciphertext, nonce, key) != 0) {
        sodium_memzero(key, sizeof key);
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_CRYPTO_ERROR, "keystore", __func__, __LINE__, "Failed to decrypt private key (wrong passphrase?)");
        logger_error("keystore", "Failed to decrypt private key (wrong passphrase?)");
        return -1;
    }

    sodium_memzero(key, sizeof key);

    // Derive public key from private key
    if (crypto_sign_ed25519_sk_to_pk(sign_public_key, sign_secret_key) != 0) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_CRYPTO_ERROR, "keystore", __func__, __LINE__, "Failed to derive public key");
        logger_error("keystore", "Failed to derive public key");
        return -1;
    }

    keypair_loaded = 1;
    return 0;
}

int keystore_load_user_key(const char* base_keys_path, const char* user_id) {
    if (!base_keys_path || !user_id) {
        tw_error_create(TW_ERROR_NULL_POINTER, "keystore", __func__, __LINE__, "Null base_keys_path or user_id provided");
        logger_error("keystore", "Null base_keys_path or user_id provided");
        return -1;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/users/%s/key.bin", base_keys_path, user_id);

    FILE* f = fopen(key_path, "rb");
    if (!f) {
        tw_error_create(TW_ERROR_IO_ERROR, "keystore", __func__, __LINE__, "Failed to open key file: %s", key_path);
        logger_error("keystore", "Failed to open key file: %s", key_path);
        return -1;
    }

    size_t read = fread(sign_secret_key, 1, SIGN_SECRET_SIZE, f);
    fclose(f);

    if (read != SIGN_SECRET_SIZE) {
        tw_error_create(TW_ERROR_IO_ERROR, "keystore", __func__, __LINE__, "Failed to read complete key from %s (read %zu bytes, expected %d)", key_path, read, SIGN_SECRET_SIZE);
        logger_error("keystore", "Failed to read complete key from %s (read %zu bytes, expected %d)", key_path, read, SIGN_SECRET_SIZE);
        return -1;
    }

    // Extract public key from secret key
    crypto_sign_ed25519_sk_to_pk(sign_public_key, sign_secret_key);
    
    keypair_loaded = 1;
    pthread_mutex_unlock(&g_keystore_mutex);
    return 0;
}

int keystore_get_public_key(unsigned char* pubkey_out) {
    pthread_mutex_lock(&g_keystore_mutex);
    if (!keypair_loaded) {
        tw_error_create(TW_ERROR_INVALID_STATE, "keystore", __func__, __LINE__, "No keypair loaded");
        logger_error("keystore", "No keypair loaded");
        return -1;
    }
    if (!pubkey_out) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_NULL_POINTER, "keystore", __func__, __LINE__, "pubkey_out is NULL");
        logger_error("keystore", "pubkey_out is NULL");
        return -1;
    }
    memcpy(pubkey_out, sign_public_key, SIGN_PUBKEY_SIZE);
    pthread_mutex_unlock(&g_keystore_mutex);
    return 0;
}

int keystore_get_encryption_public_key(unsigned char* pubkey_out) {
    pthread_mutex_lock(&g_keystore_mutex);
    if (!keypair_loaded) {
        tw_error_create(TW_ERROR_INVALID_STATE, "keystore", __func__, __LINE__, "No keypair loaded");
        logger_error("keystore", "No keypair loaded");
        return -1;
    }
    if (!pubkey_out) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_NULL_POINTER, "keystore", __func__, __LINE__, "pubkey_out is NULL");
        logger_error("keystore", "pubkey_out is NULL");
        return -1;
    }
    // Convert Ed25519 public key to X25519
    if (crypto_sign_ed25519_pk_to_curve25519(pubkey_out, sign_public_key) != 0) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_CRYPTO_ERROR, "keystore", __func__, __LINE__, "Failed to convert Ed25519 to X25519 public key");
        logger_error("keystore", "Failed to convert Ed25519 to X25519 public key");
        return -1;
    }
    pthread_mutex_unlock(&g_keystore_mutex);
    return 0;
}

int _keystore_get_private_key(unsigned char* privkey_out) {
    pthread_mutex_lock(&g_keystore_mutex);
    if (!keypair_loaded) {
        tw_error_create(TW_ERROR_INVALID_STATE, "keystore", __func__, __LINE__, "No keypair loaded");
        logger_error("keystore", "No keypair loaded");
        return -1;
    }
    if (!privkey_out) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_NULL_POINTER, "keystore", __func__, __LINE__, "privkey_out is NULL");
        logger_error("keystore", "privkey_out is NULL");
        return -1;
    }
    memcpy(privkey_out, sign_secret_key, SIGN_SECRET_SIZE);
    pthread_mutex_unlock(&g_keystore_mutex);
    return 0;
}

int _keystore_get_encryption_private_key(unsigned char* privkey_out) {
    pthread_mutex_lock(&g_keystore_mutex);
    if (!keypair_loaded) {
        tw_error_create(TW_ERROR_INVALID_STATE, "keystore", __func__, __LINE__, "No keypair loaded");
        logger_error("keystore", "No keypair loaded");
        return -1;
    }
    if (!privkey_out) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_NULL_POINTER, "keystore", __func__, __LINE__, "privkey_out is NULL");
        logger_error("keystore", "privkey_out is NULL");
        return -1;
    }
    // Convert Ed25519 private key to X25519
    if (crypto_sign_ed25519_sk_to_curve25519(privkey_out, sign_secret_key) != 0) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_CRYPTO_ERROR, "keystore", __func__, __LINE__, "Failed to convert Ed25519 to X25519 private key");
        logger_error("keystore", "Failed to convert Ed25519 to X25519 private key");
        return -1;
    }
    pthread_mutex_unlock(&g_keystore_mutex);
    return 0;
}

int keystore_load_raw_ed25519_keypair(const unsigned char* private_key) {
    pthread_mutex_lock(&g_keystore_mutex);
    if (!private_key) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_NULL_POINTER, "keystore", __func__, __LINE__, "Invalid private key provided (NULL)");
        logger_error("keystore", "Invalid private key provided (NULL)");
        return -1;
    }
    
    // Copy the Ed25519 private key
    memcpy(sign_secret_key, private_key, SIGN_SECRET_SIZE);
    
    // Derive the Ed25519 public key from the private key
    if (crypto_sign_ed25519_sk_to_pk(sign_public_key, sign_secret_key) != 0) {
        pthread_mutex_unlock(&g_keystore_mutex);
        tw_error_create(TW_ERROR_CRYPTO_ERROR, "keystore", __func__, __LINE__, "Failed to derive Ed25519 public key");
        logger_error("keystore", "Failed to derive Ed25519 public key");
        return -1;
    }
    
    keypair_loaded = 1;
    pthread_mutex_unlock(&g_keystore_mutex);
    return 0;
}

int keystore_is_keypair_loaded(void) {
    pthread_mutex_lock(&g_keystore_mutex);
    int loaded = keypair_loaded;
    pthread_mutex_unlock(&g_keystore_mutex);
    return loaded;
}

void keystore_cleanup(void) {
    pthread_mutex_lock(&g_keystore_mutex);
    sodium_memzero(sign_secret_key, SIGN_SECRET_SIZE);
    sodium_memzero(sign_public_key, SIGN_PUBKEY_SIZE);
    keypair_loaded = 0;
    pthread_mutex_unlock(&g_keystore_mutex);
    pthread_mutex_destroy(&g_keystore_mutex);
} 