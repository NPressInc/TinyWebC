#ifndef COMPRESSION_H
#define COMPRESSION_H

#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Compresses binary data using LZ4 compression
 * 
 * @param data Pointer to the data to compress
 * @param data_size Size of the input data in bytes
 * @param compressed_data Pointer to store the compressed data (will be allocated)
 * @param compressed_size Pointer to store the size of compressed data
 * @return true if compression was successful, false otherwise
 */
bool compress_data(const unsigned char* data, size_t data_size, 
                  unsigned char** compressed_data, size_t* compressed_size);

/**
 * @brief Decompresses binary data that was compressed with LZ4
 * 
 * @param compressed_data Pointer to the compressed data
 * @param compressed_size Size of the compressed data in bytes
 * @param decompressed_data Pointer to store the decompressed data (will be allocated)
 * @param decompressed_size Pointer to store the size of decompressed data
 * @return true if decompression was successful, false otherwise
 */
bool decompress_data(const unsigned char* compressed_data, size_t compressed_size,
                    unsigned char** decompressed_data, size_t* decompressed_size);

#endif // COMPRESSION_H 