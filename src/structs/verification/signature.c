#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "signature.h"

struct TW_Signature {
    unsigned char* signed_message;
    size_t signed_message_len;
};

TW_Signature* TW_Signature_create(const unsigned char* signed_message, size_t signed_message_len) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialization failed\n");
        return NULL;
    }
    TW_Signature* sig = malloc(sizeof(TW_Signature));
    if (sig) {
        sig->signed_message = malloc(signed_message_len);
        if (sig->signed_message) {
            memcpy(sig->signed_message, signed_message, signed_message_len);
            sig->signed_message_len = signed_message_len;
        } else {
            free(sig);
            return NULL;
        }
    }
    return sig;
}

size_t TW_Signature_get_length(TW_Signature* sig) {
    return sig ? sig->signed_message_len : 0;
}

unsigned char* TW_Signature_serialize_to_bytes(TW_Signature* sig) {
    if (!sig) return NULL;
    unsigned char* result = malloc(sig->signed_message_len);
    if (result) {
        memcpy(result, sig->signed_message, sig->signed_message_len);
    }
    return result;
}

char* TW_Signature_serialize_to_string(TW_Signature* sig) {
    if (!sig) return NULL;
    unsigned char* bytes = TW_Signature_serialize_to_bytes(sig);
    if (!bytes) return NULL;
    size_t b64_len = sodium_base64_ENCODED_LEN(sig->signed_message_len, sodium_base64_VARIANT_ORIGINAL);
    char* b64_str = malloc(b64_len);
    if (b64_str) {
        sodium_bin2base64(b64_str, b64_len, bytes, sig->signed_message_len, sodium_base64_VARIANT_ORIGINAL);
    }
    free(bytes);
    return b64_str;
}

void TW_Signature_destroy(TW_Signature* sig) {
    if (sig) {
        if (sig->signed_message) free(sig->signed_message);
        free(sig);
    }
}

void TW_Signature_deserialize_from_string(const char* signedMessageb64String, unsigned char** serialized_message, unsigned char** signature) {
    if (!signedMessageb64String || !serialized_message || !signature) return;

    size_t b64_len = strlen(signedMessageb64String);
    size_t bin_maxlen = (b64_len / 4 * 3) + 4;
    unsigned char* decoded = malloc(bin_maxlen);
    if (!decoded) return;

    size_t bin_len = 0;
    const char* ignore = NULL;
    const char* b64_end = NULL;
    int variant = sodium_base64_VARIANT_ORIGINAL;

    if (sodium_base642bin(decoded, bin_maxlen, signedMessageb64String, b64_len, ignore, &bin_len, &b64_end, variant) == 0) {
        if (bin_len >= crypto_sign_BYTES) {
            *serialized_message = malloc(bin_len - crypto_sign_BYTES);
            *signature = malloc(crypto_sign_BYTES);
            if (*serialized_message && *signature) {
                memcpy(*serialized_message, decoded, bin_len - crypto_sign_BYTES);
                memcpy(*signature, decoded + (bin_len - crypto_sign_BYTES), crypto_sign_BYTES);
            }
        }
    }
    free(decoded);
}