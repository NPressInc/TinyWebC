#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "blockchainIO.h"
#include "packages/structures/blockChain/blockchain.h"
#include "compression.h"

#define BLOCKCHAIN_DIR "state/blockchain"
#define BLOCKCHAIN_FILENAME BLOCKCHAIN_DIR "/blockchain.dat"

// Helper function to ensure directory exists
static bool ensure_directory_exists(const char* path) {
    struct stat st = {0};
    if (stat(path, &st) == -1) {
        // Directory doesn't exist, create it
        #ifdef _WIN32
            if (_mkdir(path) == -1) {
        #else
            if (mkdir(path, 0700) == -1) {
        #endif
                printf("Failed to create directory: %s\n", path);
                return false;
            }
    }
    return true;
}

bool saveBlockChainToFile(TW_BlockChain* blockChain) {
    if (!blockChain) return false;

    // Ensure state/blockchain directory exists
    if (!ensure_directory_exists(BLOCKCHAIN_DIR)) {
        return false;
    }

    // Serialize blockchain
    size_t serializedSize = TW_BlockChain_get_size(blockChain);
    if (serializedSize == 0) return false;

    unsigned char* serializedData = malloc(serializedSize);
    if (!serializedData) return false;

    unsigned char* ptr = serializedData;
    if (TW_BlockChain_serialize(blockChain, &ptr) != 0) {
        free(serializedData);
        return false;
    }

    // Compress the serialized data
    unsigned char* compressedData;
    size_t compressedSize;
    if (!compress_data(serializedData, serializedSize, &compressedData, &compressedSize)) {
        free(serializedData);
        return false;
    }
    free(serializedData); // Free the uncompressed data

    // Write to file
    FILE* file = fopen(BLOCKCHAIN_FILENAME, "wb");
    if (!file) {
        free(compressedData);
        return false;
    }

    // Write original size first, then compressed size, then compressed data
    size_t written = fwrite(&serializedSize, sizeof(size_t), 1, file);
    if (written != 1) {
        fclose(file);
        free(compressedData);
        return false;
    }

    written = fwrite(&compressedSize, sizeof(size_t), 1, file);
    if (written != 1) {
        fclose(file);
        free(compressedData);
        return false;
    }

    written = fwrite(compressedData, 1, compressedSize, file);
    fclose(file);
    free(compressedData);

    if (written != compressedSize) {
        return false;
    }

    printf("Saved BlockChain To File! (Original size: %zu bytes, Compressed size: %zu bytes)\n", 
           serializedSize, compressedSize);
    return true;
}

TW_BlockChain* readBlockChainFromFile(void) {
    // Open and read file
    FILE* file = fopen(BLOCKCHAIN_FILENAME, "rb");
    if (!file) {
        printf("Failed to open file: %s\n", BLOCKCHAIN_FILENAME);
        return NULL;
    }

    // Read original size first
    size_t originalSize;
    size_t read = fread(&originalSize, sizeof(size_t), 1, file);
    if (read != 1) {
        fclose(file);
        return NULL;
    }

    // Read compressed size
    size_t compressedSize;
    read = fread(&compressedSize, sizeof(size_t), 1, file);
    if (read != 1) {
        fclose(file);
        return NULL;
    }

    // Read compressed data
    unsigned char* compressedData = malloc(compressedSize);
    if (!compressedData) {
        fclose(file);
        return NULL;
    }

    read = fread(compressedData, 1, compressedSize, file);
    fclose(file);

    if (read != compressedSize) {
        free(compressedData);
        return NULL;
    }

    // Decompress the data
    unsigned char* serializedData;
    size_t serializedSize;
    if (!decompress_data(compressedData, compressedSize, &serializedData, &serializedSize)) {
        free(compressedData);
        return NULL;
    }
    free(compressedData);

    // Verify the decompressed size matches the original size
    if (serializedSize != originalSize) {
        printf("Size mismatch: expected %zu bytes, got %zu bytes\n", originalSize, serializedSize);
        free(serializedData);
        return NULL;
    }

    // Deserialize to BlockChain
    TW_BlockChain* blockChain = TW_BlockChain_deserialize(serializedData, serializedSize);
    free(serializedData);

    if (blockChain) {
        printf("Loaded blockchain (Original size: %zu bytes, Compressed size: %zu bytes)\n", 
               originalSize, compressedSize);
    }

    return blockChain;
}
