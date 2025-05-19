#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "blockchainIO.h"
#include "packages/structures/blockChain/blockchain.h"
#include "compression.h"
#include <cjson/cJSON.h>
#include "packages/structures/blockChain/block.h"
#include "packages/structures/blockChain/transaction.h"

#define BLOCKCHAIN_DIR "state/blockchain"
#define BLOCKCHAIN_FILENAME BLOCKCHAIN_DIR "/blockchain.dat"
#define BLOCKCHAIN_JSON_FILENAME BLOCKCHAIN_DIR "/blockchain.json"

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

bool writeBlockChainToJson(TW_BlockChain* blockChain) {
    if (!blockChain) {
        return false;
    }

    // Create root JSON object
    cJSON* root = cJSON_CreateObject();
    if (!root) {
        return false;
    }

    // Add creator public key
    char creator_hex[PUBKEY_SIZE * 2 + 1];
    for (int i = 0; i < PUBKEY_SIZE; i++) {
        sprintf(creator_hex + (i * 2), "%02x", blockChain->creator_pubkey[i]);
    }
    cJSON_AddStringToObject(root, "creator_public_key", creator_hex);

    // Add blockchain length
    cJSON_AddNumberToObject(root, "length", blockChain->length);

    // Create blocks array
    cJSON* blocks_array = cJSON_CreateArray();
    if (!blocks_array) {
        cJSON_Delete(root);
        return false;
    }
    cJSON_AddItemToObject(root, "blocks", blocks_array);

    // Add each block
    for (uint32_t i = 0; i < blockChain->length; i++) {
        TW_Block* block = blockChain->blocks[i];
        if (!block) continue;

        cJSON* block_obj = cJSON_CreateObject();
        if (!block_obj) continue;

        // Add block index
        cJSON_AddNumberToObject(block_obj, "index", block->index);

        // Add timestamp
        cJSON_AddNumberToObject(block_obj, "timestamp", block->timestamp);

        // Add previous hash
        char prev_hash_hex[HASH_SIZE * 2 + 1];
        for (int j = 0; j < HASH_SIZE; j++) {
            sprintf(prev_hash_hex + (j * 2), "%02x", block->previous_hash[j]);
        }
        cJSON_AddStringToObject(block_obj, "previous_hash", prev_hash_hex);

        // Add proposer ID
        char proposer_hex[PROP_ID_SIZE * 2 + 1];
        for (int j = 0; j < PROP_ID_SIZE; j++) {
            sprintf(proposer_hex + (j * 2), "%02x", block->proposer_id[j]);
        }
        cJSON_AddStringToObject(block_obj, "proposer_id", proposer_hex);

        // Add merkle root hash
        char merkle_hex[HASH_SIZE * 2 + 1];
        for (int j = 0; j < HASH_SIZE; j++) {
            sprintf(merkle_hex + (j * 2), "%02x", block->merkle_root_hash[j]);
        }
        cJSON_AddStringToObject(block_obj, "merkle_root_hash", merkle_hex);

        // Create transactions array
        cJSON* txns_array = cJSON_CreateArray();
        if (!txns_array) {
            cJSON_Delete(block_obj);
            continue;
        }
        cJSON_AddItemToObject(block_obj, "transactions", txns_array);

        // Add each transaction
        for (int32_t j = 0; j < block->txn_count; j++) {
            TW_Transaction* tx = block->txns[j];
            if (!tx) continue;

            cJSON* tx_obj = cJSON_CreateObject();
            if (!tx_obj) continue;

            // Add transaction type
            cJSON_AddNumberToObject(tx_obj, "type", tx->type);

            // Add sender
            char sender_hex[PUBKEY_SIZE * 2 + 1];
            for (int k = 0; k < PUBKEY_SIZE; k++) {
                sprintf(sender_hex + (k * 2), "%02x", tx->sender[k]);
            }
            cJSON_AddStringToObject(tx_obj, "sender", sender_hex);

            // Add timestamp
            cJSON_AddNumberToObject(tx_obj, "timestamp", tx->timestamp);

            // Add recipients
            cJSON* recipients_array = cJSON_CreateArray();
            if (!recipients_array) {
                cJSON_Delete(tx_obj);
                continue;
            }
            cJSON_AddItemToObject(tx_obj, "recipients", recipients_array);

            for (uint8_t k = 0; k < tx->recipient_count; k++) {
                char recipient_hex[PUBKEY_SIZE * 2 + 1];
                for (int l = 0; l < PUBKEY_SIZE; l++) {
                    sprintf(recipient_hex + (l * 2), "%02x", tx->recipients[k * PUBKEY_SIZE + l]);
                }
                cJSON_AddItemToArray(recipients_array, cJSON_CreateString(recipient_hex));
            }

            // Add group ID
            char group_hex[GROUP_ID_SIZE * 2 + 1];
            for (int k = 0; k < GROUP_ID_SIZE; k++) {
                sprintf(group_hex + (k * 2), "%02x", tx->group_id[k]);
            }
            cJSON_AddStringToObject(tx_obj, "group_id", group_hex);

            // Add signature
            char sig_hex[SIGNATURE_SIZE * 2 + 1];
            for (int k = 0; k < SIGNATURE_SIZE; k++) {
                sprintf(sig_hex + (k * 2), "%02x", tx->signature[k]);
            }
            cJSON_AddStringToObject(tx_obj, "signature", sig_hex);

            cJSON_AddItemToArray(txns_array, tx_obj);
        }

        cJSON_AddItemToArray(blocks_array, block_obj);
    }

    // Convert to string with indentation
    char* json_str = cJSON_Print(root);
    if (!json_str) {
        cJSON_Delete(root);
        return false;
    }

    // Write to file
    FILE* file = fopen(BLOCKCHAIN_JSON_FILENAME, "w");
    if (!file) {
        free(json_str);
        cJSON_Delete(root);
        return false;
    }

    fprintf(file, "%s", json_str);
    fclose(file);

    // Cleanup
    free(json_str);
    cJSON_Delete(root);

    printf("Blockchain saved as JSON to %s\n", BLOCKCHAIN_JSON_FILENAME);
    return true;
}
