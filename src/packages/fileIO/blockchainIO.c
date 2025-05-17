#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "blockchainIO.h"
#include "packages/structures/blockChain/blockchain.h"

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

    uint8_t* serializedData = malloc(serializedSize);
    if (!serializedData) return false;

    unsigned char* ptr = serializedData;
    if (TW_BlockChain_serialize(blockChain, &ptr) != 0) {
        free(serializedData);
        return false;
    }

    // Write to file
    FILE* file = fopen(BLOCKCHAIN_FILENAME, "wb");
    if (!file) {
        free(serializedData);
        return false;
    }

    // Write size first, then data
    size_t written = fwrite(&serializedSize, sizeof(size_t), 1, file);
    if (written != 1) {
        fclose(file);
        free(serializedData);
        return false;
    }

    written = fwrite(serializedData, 1, serializedSize, file);
    fclose(file);
    free(serializedData);

    if (written != serializedSize) {
        return false;
    }

    printf("Saved BlockChain To File!\n");
    return true;
}

TW_BlockChain* readBlockChainFromFile(void) {
    // Open and read file
    FILE* file = fopen(BLOCKCHAIN_FILENAME, "rb");
    if (!file) {
        printf("Failed to open file: %s\n", BLOCKCHAIN_FILENAME);
        return NULL;
    }

    // Read size first
    size_t serializedSize;
    size_t read = fread(&serializedSize, sizeof(size_t), 1, file);
    if (read != 1) {
        fclose(file);
        return NULL;
    }

    // Read serialized data
    uint8_t* serializedData = malloc(serializedSize);
    if (!serializedData) {
        fclose(file);
        return NULL;
    }

    read = fread(serializedData, 1, serializedSize, file);
    fclose(file);

    if (read != serializedSize) {
        free(serializedData);
        return NULL;
    }

    // Deserialize to BlockChain
    TW_BlockChain* blockChain = TW_BlockChain_deserialize(serializedData, serializedSize);
    free(serializedData);

    if (blockChain) {
        printf("Loaded it\n");
    }

    return blockChain;
}
