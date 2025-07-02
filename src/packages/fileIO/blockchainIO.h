#ifndef BLOCKCHAIN_IO_H
#define BLOCKCHAIN_IO_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include "packages/structures/blockChain/blockchain.h"
#include "packages/structures/blockChain/transaction.h"
#include "packages/sql/database.h"

// Save blockchain to a file
// Returns true if successful, false otherwise
bool saveBlockChainToFile(TW_BlockChain* blockChain);

// Save blockchain to a file with custom path
// Returns true if successful, false otherwise
bool saveBlockChainToFileWithPath(TW_BlockChain* blockChain, const char* blockchain_dir);

// Read blockchain from a file
// Returns pointer to newly allocated BlockChain if successful, NULL otherwise
// Caller is responsible for freeing the returned BlockChain
TW_BlockChain* readBlockChainFromFile(void);

bool writeBlockChainToJson(TW_BlockChain* blockChain);

// Write blockchain to JSON with custom path
bool writeBlockChainToJsonWithPath(TW_BlockChain* blockChain, const char* blockchain_dir);

// ===== BLOCKCHAIN DATA MANAGER =====

// Data importance classification for efficient loading
typedef enum {
    DATA_CRITICAL,      // Always keep (permissions, users, network config, system settings)
    DATA_IMPORTANT,     // Keep for specified days (messages, invitations, location updates) 
    DATA_OPERATIONAL,   // Keep for short term (media requests, temporary settings)
    DATA_EPHEMERAL     // Don't persist (call requests, temporary states)
} TW_DataImportance;

// Configuration for data retention
typedef struct {
    uint32_t critical_days;      // Days to keep critical data (0 = forever)
    uint32_t important_days;     // Days to keep important data (default: 120)
    uint32_t operational_days;   // Days to keep operational data (default: 30)
} TW_DataRetentionConfig;

// Progress callback for long operations
typedef void (*TW_ProgressCallback)(uint32_t current, uint32_t total, const char* status);

// Statistics from reload operation
typedef struct {
    uint32_t blocks_processed;
    uint32_t transactions_loaded;
    uint32_t transactions_skipped;
    uint32_t critical_transactions;
    uint32_t important_transactions;
    uint32_t operational_transactions;
    double processing_time_seconds;
    size_t database_size_before;
    size_t database_size_after;
} TW_ReloadStats;

// Main functions
/**
 * Initialize blockchain data manager with retention configuration
 */
int TW_BlockchainDataManager_init(const TW_DataRetentionConfig* config);

/**
 * Classify transaction importance based on type and content
 */
TW_DataImportance TW_BlockchainDataManager_classify_transaction(const TW_Transaction* tx);

/**
 * Check if transaction should be loaded based on age and importance
 */
bool TW_BlockchainDataManager_should_load_transaction(const TW_Transaction* tx, 
                                                     TW_DataImportance importance,
                                                     time_t cutoff_time);

/**
 * Reload database from blockchain with progress tracking
 * This is the main function that implements the measured approach
 */
int TW_BlockchainDataManager_reload_from_blockchain(TW_BlockChain* blockchain,
                                                   TW_ProgressCallback progress_cb,
                                                   TW_ReloadStats* stats_out);

/**
 * Fast check if database needs reloading (detect corruption/inconsistency)
 */
bool TW_BlockchainDataManager_needs_reload(TW_BlockChain* blockchain);

/**
 * Get current retention configuration
 */
const TW_DataRetentionConfig* TW_BlockchainDataManager_get_config(void);

/**
 * Update retention configuration
 */
int TW_BlockchainDataManager_set_config(const TW_DataRetentionConfig* config);

/**
 * Get statistics from last reload operation
 */
const TW_ReloadStats* TW_BlockchainDataManager_get_last_stats(void);

/**
 * Cleanup and shutdown
 */
void TW_BlockchainDataManager_cleanup(void);

// Utility functions for transaction importance classification
/**
 * Check if transaction type is network-critical (always needed)
 */
bool TW_is_critical_transaction_type(TW_TransactionType type);

/**
 * Check if transaction type is important for daily operations
 */
bool TW_is_important_transaction_type(TW_TransactionType type);

/**
 * Get human-readable name for data importance level
 */
const char* TW_data_importance_to_string(TW_DataImportance importance);

/**
 * Calculate database size before and after operations
 */
size_t TW_calculate_database_size(void);

/**
 * Calculate database size with custom path
 */
size_t TW_calculate_database_size_with_path(const char* db_path);

#endif // BLOCKCHAIN_IO_H
