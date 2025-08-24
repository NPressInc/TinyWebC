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
#include "packages/utils/statePaths.h"

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
    return saveBlockChainToFileWithPath(blockChain, BLOCKCHAIN_DIR);
}

bool saveBlockChainToFileWithPath(TW_BlockChain* blockChain, const char* blockchain_dir) {
    if (!blockChain || !blockchain_dir) return false;

    // Ensure directory exists
    if (!ensure_directory_exists(blockchain_dir)) {
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

    // Build filename using the provided directory
    char blockchain_filename[512];
    snprintf(blockchain_filename, sizeof(blockchain_filename), "%s/blockchain.dat", blockchain_dir);

    // Write to file
    FILE* file = fopen(blockchain_filename, "wb");
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

TW_BlockChain* readBlockChainFromFileWithPath(const char* blockchain_dir) {
    if (!blockchain_dir) {
        return readBlockChainFromFile();  // Fallback to default path
    }
    
    // Build the full filename with provided directory
    char blockchain_filename[512];
    snprintf(blockchain_filename, sizeof(blockchain_filename), "%s/blockchain.dat", blockchain_dir);
    
    // Open and read file
    FILE* file = fopen(blockchain_filename, "rb");
    if (!file) {
        printf("Failed to open file: %s\n", blockchain_filename);
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
        printf("Loaded blockchain from %s (Original size: %zu bytes, Compressed size: %zu bytes)\n", 
               blockchain_filename, originalSize, compressedSize);
    }

    return blockChain;
}

bool writeBlockChainToJson(TW_BlockChain* blockChain) {
    return writeBlockChainToJsonWithPath(blockChain, BLOCKCHAIN_DIR);
}

bool writeBlockChainToJsonWithPath(TW_BlockChain* blockChain, const char* blockchain_dir) {
    if (!blockChain || !blockchain_dir) {
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

            // Add encrypted payload if it exists
            if (tx->payload && tx->payload_size > 0) {
                cJSON* payload_obj = cJSON_CreateObject();
                if (payload_obj) {
                    // Add payload size
                    cJSON_AddNumberToObject(payload_obj, "size", tx->payload_size);
                    
                    // Add ephemeral public key
                    char ephemeral_hex[PUBKEY_SIZE * 2 + 1];
                    for (int k = 0; k < PUBKEY_SIZE; k++) {
                        sprintf(ephemeral_hex + (k * 2), "%02x", tx->payload->ephemeral_pubkey[k]);
                    }
                    cJSON_AddStringToObject(payload_obj, "ephemeral_pubkey", ephemeral_hex);
                    
                    // Add nonce
                    char nonce_hex[NONCE_SIZE * 2 + 1];
                    for (int k = 0; k < NONCE_SIZE; k++) {
                        sprintf(nonce_hex + (k * 2), "%02x", tx->payload->nonce[k]);
                    }
                    cJSON_AddStringToObject(payload_obj, "nonce", nonce_hex);
                    
                    // Add encrypted ciphertext
                    if (tx->payload->ciphertext && tx->payload->ciphertext_len > 0) {
                        char* encrypted_hex = malloc(tx->payload->ciphertext_len * 2 + 1);
                        if (encrypted_hex) {
                            for (size_t k = 0; k < tx->payload->ciphertext_len; k++) {
                                sprintf(encrypted_hex + (k * 2), "%02x", tx->payload->ciphertext[k]);
                            }
                            cJSON_AddStringToObject(payload_obj, "ciphertext", encrypted_hex);
                            free(encrypted_hex);
                        }
                        cJSON_AddNumberToObject(payload_obj, "ciphertext_len", tx->payload->ciphertext_len);
                    }
                    
                    // Add recipient count and encrypted keys
                    cJSON_AddNumberToObject(payload_obj, "num_recipients", tx->payload->num_recipients);
                    
                    if (tx->payload->encrypted_keys && tx->payload->num_recipients > 0) {
                        cJSON* keys_array = cJSON_CreateArray();
                        if (keys_array) {
                            for (size_t k = 0; k < tx->payload->num_recipients; k++) {
                                cJSON* key_obj = cJSON_CreateObject();
                                if (key_obj) {
                                    // Add encrypted key
                                    char key_hex[ENCRYPTED_KEY_SIZE * 2 + 1];
                                    for (int l = 0; l < ENCRYPTED_KEY_SIZE; l++) {
                                        sprintf(key_hex + (l * 2), "%02x", tx->payload->encrypted_keys[k * ENCRYPTED_KEY_SIZE + l]);
                                    }
                                    cJSON_AddStringToObject(key_obj, "encrypted_key", key_hex);
                                    
                                    // Add key nonce
                                    char key_nonce_hex[NONCE_SIZE * 2 + 1];
                                    for (int l = 0; l < NONCE_SIZE; l++) {
                                        sprintf(key_nonce_hex + (l * 2), "%02x", tx->payload->key_nonces[k * NONCE_SIZE + l]);
                                    }
                                    cJSON_AddStringToObject(key_obj, "key_nonce", key_nonce_hex);
                                    
                                    cJSON_AddItemToArray(keys_array, key_obj);
                                }
                            }
                            cJSON_AddItemToObject(payload_obj, "encrypted_keys", keys_array);
                        }
                    }
                    
                    cJSON_AddItemToObject(tx_obj, "payload", payload_obj);
                }
            }

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

    // Build JSON filename using the provided directory
    char blockchain_json_filename[512];
    snprintf(blockchain_json_filename, sizeof(blockchain_json_filename), "%s/blockchain.json", blockchain_dir);

    // Write to file
    FILE* file = fopen(blockchain_json_filename, "w");
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

    printf("Blockchain saved as JSON to %s\n", blockchain_json_filename);
    return true;
}

// ===== BLOCKCHAIN DATA MANAGER IMPLEMENTATION =====

// Global configuration
static TW_DataRetentionConfig g_retention_config = {
    .critical_days = 0,      // Keep forever
    .important_days = 120,   // 4 months
    .operational_days = 30   // 1 month
};

static TW_ReloadStats g_last_stats = {0};

int TW_BlockchainDataManager_init(const TW_DataRetentionConfig* config) {
    if (config) {
        g_retention_config = *config;
    }
    printf("🔧 Blockchain Data Manager initialized\n");
    printf("   Critical data: %u days (0=forever)\n", g_retention_config.critical_days);  
    printf("   Important data: %u days\n", g_retention_config.important_days);
    printf("   Operational data: %u days\n", g_retention_config.operational_days);
    return 0;
}

bool TW_is_critical_transaction_type(TW_TransactionType type) {
    switch (type) {
        // Network Foundation - Always Critical
        case TW_TXN_USER_REGISTRATION:
        case TW_TXN_ROLE_ASSIGNMENT:
        case TW_TXN_SYSTEM_CONFIG:
        
        // Group Management - Critical for Network Structure
        case TW_TXN_GROUP_CREATE:
        case TW_TXN_GROUP_UPDATE:
        case TW_TXN_GROUP_MEMBER_ADD:
        case TW_TXN_GROUP_MEMBER_REMOVE:
        
        // Permission System - Critical for Security
        case TW_TXN_PERMISSION_EDIT:
        case TW_TXN_PARENTAL_CONTROL:
            return true;
            
        default:
            return false;
    }
}

bool TW_is_important_transaction_type(TW_TransactionType type) {
    switch (type) {
        // Communication - Important for Recent History
        case TW_TXN_MESSAGE:
        case TW_TXN_GROUP_MESSAGE:
        
        // Safety & Monitoring - Important for Recent Activity
        case TW_TXN_LOCATION_UPDATE:
        case TW_TXN_EMERGENCY_ALERT:
        case TW_TXN_CONTENT_FILTER:
        
        // Educational Content - Important for Progress Tracking
        case TW_TXN_EDUCATIONAL_RESOURCE_ADD:
        case TW_TXN_CHALLENGE_COMPLETE:
        case TW_TXN_BOOK_ADD_TO_LIBRARY:
        
        // Family Management - Important for Recent Activity
        case TW_TXN_CHORE_ASSIGN:
        case TW_TXN_CHORE_COMPLETE:
        case TW_TXN_REWARD_DISTRIBUTE:
        
        // Community Activity - Important for Recent Engagement
        case TW_TXN_EVENT_CREATE:
        case TW_TXN_EVENT_INVITE:
        case TW_TXN_EVENT_RSVP:
        case TW_TXN_COMMUNITY_POST_CREATE:
            return true;
            
        default:
            return false;
    }
}

TW_DataImportance TW_BlockchainDataManager_classify_transaction(const TW_Transaction* tx) {
    if (!tx) return DATA_EPHEMERAL;
    
    if (TW_is_critical_transaction_type(tx->type)) {
        return DATA_CRITICAL;
    }
    
    if (TW_is_important_transaction_type(tx->type)) {
        return DATA_IMPORTANT;
    }
    
    // Operational transactions (keep for shorter time)
    switch (tx->type) {
        case TW_TXN_MEDIA_DOWNLOAD:
        case TW_TXN_CONTENT_ACCESS_UPDATE:
        case TW_TXN_CREATION_UPLOAD:
        case TW_TXN_USAGE_POLICY_UPDATE:
        case TW_TXN_GEOFENCE_CREATE:
        case TW_TXN_GEOFENCE_CONFIG_UPDATE:
            return DATA_OPERATIONAL;
        
        // Ephemeral transactions (don't persist)
        case TW_TXN_VOICE_CALL_REQ:
        case TW_TXN_VIDEO_CALL_REQ:
        case TW_TXN_GAME_SESSION_START:
        case TW_TXN_GAME_PERMISSION_UPDATE:
        default:
            return DATA_EPHEMERAL;
    }
}

bool TW_BlockchainDataManager_should_load_transaction(const TW_Transaction* tx, 
                                                     TW_DataImportance importance,
                                                     time_t cutoff_time) {
    if (!tx) return false;
    
    switch (importance) {
        case DATA_CRITICAL:
            // Critical transactions: keep forever or until configured limit
            if (g_retention_config.critical_days == 0) return true;
            return (time_t)tx->timestamp >= cutoff_time - (g_retention_config.critical_days * 24 * 3600);
            
        case DATA_IMPORTANT:
            return (time_t)tx->timestamp >= cutoff_time - (g_retention_config.important_days * 24 * 3600);
            
        case DATA_OPERATIONAL:
            return (time_t)tx->timestamp >= cutoff_time - (g_retention_config.operational_days * 24 * 3600);
            
        case DATA_EPHEMERAL:
        default:
            return false; // Never load ephemeral data
    }
}

size_t TW_calculate_database_size(void) {
    // TODO: This should use node-specific database path when node context is available
    return TW_calculate_database_size_with_path("state/blockchain/blockchain.db");
}

size_t TW_calculate_database_size_with_path(const char* db_path) {
    struct stat st;
    if (stat(db_path, &st) == 0) {
        return st.st_size;
    }
    return 0;
}

int TW_BlockchainDataManager_reload_from_blockchain(TW_BlockChain* blockchain,
                                                   TW_ProgressCallback progress_cb,
                                                   TW_ReloadStats* stats_out) {
    if (!blockchain) return -1;
    
    // Initialize statistics 
    TW_ReloadStats stats = {0};
    stats.database_size_before = TW_calculate_database_size();
    
    time_t start_time = time(NULL);
    time_t cutoff_time = time(NULL);
    
    printf("🔄 Starting blockchain data reload...\n");
    printf("📊 Blockchain length: %u blocks\n", blockchain->length);
    printf("🗄️  Database size before: %zu bytes (%.2f MB)\n", 
           stats.database_size_before, stats.database_size_before / 1024.0 / 1024.0);
    
    // Clear existing database (except schema)
    if (progress_cb) progress_cb(0, blockchain->length, "Clearing database...");
    
    // Clear tables but keep schema
    if (db_is_initialized()) {
        sqlite3* db = db_get_handle();
        if (db && sqlite3_exec(db, 
                        "DELETE FROM transactions; DELETE FROM blocks; DELETE FROM transaction_recipients;", 
                        NULL, NULL, NULL) != SQLITE_OK) {
            printf("❌ Failed to clear database tables\n");
            return -1;
        }
        printf("✅ Database tables cleared\n");
    }
    
    // Process blockchain from newest to oldest for efficiency
    for (uint32_t i = 0; i < blockchain->length; i++) {
        TW_Block* block = blockchain->blocks[i];
        if (!block) continue;
        
        stats.blocks_processed++;
        
        if (progress_cb && (i % 10 == 0 || i == blockchain->length - 1)) {
            char status[64];
            snprintf(status, sizeof(status), "Processing block %u/%u", i + 1, blockchain->length);
            progress_cb(i + 1, blockchain->length, status);
        }
        
        // Always sync the block itself to database
        if (db_add_block(block, i) != 0) {
            printf("⚠️ Warning: Failed to sync block %u to database\n", i);
            continue;
        }
        
        // Process transactions in the block
        for (int32_t tx_idx = 0; tx_idx < block->txn_count; tx_idx++) {
            TW_Transaction* tx = block->txns[tx_idx];
            if (!tx) continue;
            
            TW_DataImportance importance = TW_BlockchainDataManager_classify_transaction(tx);
            
            if (TW_BlockchainDataManager_should_load_transaction(tx, importance, cutoff_time)) {
                // Transaction should be loaded
                stats.transactions_loaded++;
                
                switch (importance) {
                    case DATA_CRITICAL:     stats.critical_transactions++; break;
                    case DATA_IMPORTANT:    stats.important_transactions++; break;
                    case DATA_OPERATIONAL:  stats.operational_transactions++; break;
                    case DATA_EPHEMERAL:    break; // Won't reach here
                }
                
                // Transaction already synced by db_add_block
            } else {
                stats.transactions_skipped++;
            }
        }
    }
    
    stats.database_size_after = TW_calculate_database_size();
    stats.processing_time_seconds = difftime(time(NULL), start_time);
    
    // Store statistics
    g_last_stats = stats;
    if (stats_out) *stats_out = stats;
    
    // Print summary
    printf("\n📈 Blockchain Reload Complete!\n");
    printf("⏱️  Processing time: %.2f seconds\n", stats.processing_time_seconds);
    printf("🗃️  Blocks processed: %u\n", stats.blocks_processed);
    printf("📝 Transactions loaded: %u\n", stats.transactions_loaded);
    printf("   └─ Critical: %u\n", stats.critical_transactions);
    printf("   └─ Important: %u\n", stats.important_transactions);  
    printf("   └─ Operational: %u\n", stats.operational_transactions);
    printf("🚫 Transactions skipped: %u\n", stats.transactions_skipped);
    printf("💾 Database size: %zu → %zu bytes (%.2f MB)\n", 
           stats.database_size_before, stats.database_size_after,
           stats.database_size_after / 1024.0 / 1024.0);
    
    if (stats.database_size_after < stats.database_size_before) {
        size_t saved = stats.database_size_before - stats.database_size_after;
        printf("💡 Space saved: %zu bytes (%.2f MB, %.1f%% reduction)\n", 
               saved, saved / 1024.0 / 1024.0,
               (saved * 100.0) / stats.database_size_before);
    }
    
    return 0;
}

bool TW_BlockchainDataManager_needs_reload(TW_BlockChain* blockchain) {
    if (!blockchain || !db_is_initialized()) return true;
    
    // Quick consistency check
    uint32_t db_block_count = 0;
    if (db_get_block_count(&db_block_count) != 0) return true;
    
    // If blockchain has more blocks than database, we need reload
    if (blockchain->length > db_block_count) {
        printf("🔍 Reload needed: Blockchain has %u blocks, database has %u\n", 
               blockchain->length, db_block_count);
        return true;
    }
    
    return false;
}

const TW_DataRetentionConfig* TW_BlockchainDataManager_get_config(void) {
    return &g_retention_config;
}

int TW_BlockchainDataManager_set_config(const TW_DataRetentionConfig* config) {
    if (!config) return -1;
    g_retention_config = *config;
    printf("🔧 Data retention configuration updated\n");
    return 0;
}

const TW_ReloadStats* TW_BlockchainDataManager_get_last_stats(void) {
    return &g_last_stats;
}

const char* TW_data_importance_to_string(TW_DataImportance importance) {
    switch (importance) {
        case DATA_CRITICAL:     return "Critical";
        case DATA_IMPORTANT:    return "Important";
        case DATA_OPERATIONAL:  return "Operational";
        case DATA_EPHEMERAL:    return "Ephemeral";
        default:                return "Unknown";
    }
}

void TW_BlockchainDataManager_cleanup(void) {
    printf("🧹 Blockchain Data Manager cleanup complete\n");
}
