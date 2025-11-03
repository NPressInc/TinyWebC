#ifndef TW_CODEC_H
#define TW_CODEC_H

#include <stddef.h>
#include <stdint.h>

typedef int (*tw_encode_fn)(const void* msg, unsigned char** out, size_t* out_len);
typedef void* (*tw_decode_fn)(const unsigned char* buf, size_t len);

int tw_codec_register(uint32_t content_type, uint32_t schema_version,
                      tw_encode_fn enc, tw_decode_fn dec);

int tw_codec_encode(uint32_t content_type, uint32_t schema_version,
                    const void* msg, unsigned char** out, size_t* out_len);

void* tw_codec_decode(uint32_t content_type, uint32_t schema_version,
                      const unsigned char* buf, size_t len);

#endif // TW_CODEC_H

