#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "compression.h"
#include <lz4.h>

// Maximum compression level for LZ4
#define LZ4_COMPRESSION_LEVEL 9

bool compress_data(const unsigned char* data, size_t data_size, 
                  unsigned char** compressed_data, size_t* compressed_size) {
    if (!data || !data_size || !compressed_data || !compressed_size) {
        return false;
    }

    // Calculate maximum possible compressed size
    int max_compressed_size = LZ4_compressBound(data_size);
    if (max_compressed_size <= 0) {
        return false;
    }

    // Allocate memory for compressed data plus size header
    *compressed_data = malloc(max_compressed_size + sizeof(size_t));
    if (!*compressed_data) {
        return false;
    }

    // Store original size at the start
    memcpy(*compressed_data, &data_size, sizeof(size_t));

    // Compress the data after the size header
    int compressed_bytes = LZ4_compress_fast(
        (const char*)data,
        (char*)(*compressed_data + sizeof(size_t)),
        data_size,
        max_compressed_size,
        LZ4_COMPRESSION_LEVEL
    );

    if (compressed_bytes <= 0) {
        free(*compressed_data);
        *compressed_data = NULL;
        return false;
    }

    // Resize the buffer to the actual compressed size plus size header
    unsigned char* resized = realloc(*compressed_data, compressed_bytes + sizeof(size_t));
    if (!resized) {
        free(*compressed_data);
        *compressed_data = NULL;
        return false;
    }

    *compressed_data = resized;
    *compressed_size = compressed_bytes + sizeof(size_t);
    return true;
}

bool decompress_data(const unsigned char* compressed_data, size_t compressed_size,
                    unsigned char** decompressed_data, size_t* decompressed_size) {
    if (!compressed_data || !compressed_size || !decompressed_data || !decompressed_size) {
        return false;
    }

    // For LZ4, we need to know the original size
    // We'll read it from the start of the compressed data
    if (compressed_size < sizeof(size_t)) {
        return false;
    }

    // Extract the original size from the start of the compressed data
    memcpy(decompressed_size, compressed_data, sizeof(size_t));
    compressed_data += sizeof(size_t);
    compressed_size -= sizeof(size_t);

    // Allocate memory for decompressed data
    *decompressed_data = malloc(*decompressed_size);
    if (!*decompressed_data) {
        return false;
    }

    // Decompress the data
    int decompressed_bytes = LZ4_decompress_safe(
        (const char*)compressed_data,
        (char*)*decompressed_data,
        compressed_size,
        *decompressed_size
    );

    if (decompressed_bytes < 0) {
        free(*decompressed_data);
        *decompressed_data = NULL;
        return false;
    }

    return true;
} 