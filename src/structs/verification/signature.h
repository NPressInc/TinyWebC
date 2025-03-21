#ifndef TW_SIGNATURE_H
#define TW_SIGNATURE_H

#include <stddef.h>  // For size_t
#include <stdint.h>

typedef struct TW_Signature TW_Signature;

TW_Signature* TW_Signature_create(const unsigned char* signed_message, size_t signed_message_len);
size_t TW_Signature_get_length(TW_Signature* sig); // New getter
unsigned char* TW_Signature_serialize_to_bytes(TW_Signature* sig);
char* TW_Signature_serialize_to_string(TW_Signature* sig);
void TW_Signature_destroy(TW_Signature* sig);
void TW_Signature_deserialize_from_string(const char* signedMessageb64String, unsigned char** serialized_message, unsigned char** signature);

#endif