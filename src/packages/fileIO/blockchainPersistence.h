#ifndef BLOCKCHAIN_PERSISTENCE_H
#define BLOCKCHAIN_PERSISTENCE_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "packages/structures/blockChain/blockchain.h"
#include "packages/sql/database.h"

// Two-phase commit result codes
typedef enum {
    PERSISTENCE_SUCCESS = 0,
    PERSISTENCE_ERROR_NULL_POINTER = -1,
    PERSISTENCE_ERROR_INVALID_STATE = -2,
    PERSISTENCE_ERROR_FILE_WRITE_FAILED = -3,
    PERSISTENCE_ERROR_DB_WRITE_FAILED = -4,
    PERSISTENCE_ERROR_TRANSACTION_FAILED = -5,
    PERSISTENCE_ERROR_ROLLBACK_FAILED = -6,
    PERSISTENCE_ERROR_RECOVERY_FAILED = -7,
    PERSISTENCE_ERROR_INCONSISTENT_STATE = -8,
    PERSISTENCE_ERROR_VALIDATION_FAILED = -9
} PersistenceResult;

// Recovery strategy options
typedef enum {
    RECOVERY_STRATEGY_PREFER_NEWER = 0,    // Choose the data source with more recent data
    RECOVERY_STRATEGY_PREFER_FILE = 1,     // Always prefer blockchain file
    RECOVERY_STRATEGY_PREFER_DB = 2,       // Always prefer database
    RECOVERY_STRATEGY_MANUAL = 3           // Require manual intervention
} RecoveryStrategy;

// Data source comparison result
typedef enum {
    DATA_SOURCE_FILE_NEWER = 0,
    DATA_SOURCE_DB_NEWER = 1,
    DATA_SOURCE_EQUIVALENT = 2,
    DATA_SOURCE_CONFLICT = 3
} DataSourceComparison;

// Persistence state metadata
typedef struct {
    uint32_t blockchain_length;
    uint64_t last_block_timestamp;
    time_t last_file_save;
    time_t last_db_sync;
    uint32_t file_version;      // For atomic file operations
    bool transaction_active;
    char checksum[65];          // SHA256 hex string
} PersistenceMetadata;

// Recovery statistics
typedef struct {
    uint32_t blocks_recovered;
    uint32_t transactions_recovered;
    uint32_t conflicts_resolved;
    DataSourceComparison comparison_result;
    RecoveryStrategy strategy_used;
    double recovery_time_seconds;
    size_t data_size_recovered;
} RecoveryStats;

// === CORE PERSISTENCE FUNCTIONS ===

/**
 * Initialize the blockchain persistence manager
 * Sets up metadata tracking and validates initial state
 */
PersistenceResult blockchain_persistence_init(const char* blockchain_path, const char* db_path);

/**
 * Atomically persist a new block using two-phase commit
 * This is the main function to use for all block persistence
 */
PersistenceResult blockchain_persistence_commit_block(TW_BlockChain* blockchain, TW_Block* block);

/**
 * Atomically persist the entire blockchain using two-phase commit
 * Used during initial sync or after recovery
 */
PersistenceResult blockchain_persistence_commit_full_blockchain(TW_BlockChain* blockchain);

/**
 * Cleanup and shutdown the persistence manager
 */
void blockchain_persistence_cleanup(void);

// === RECOVERY AND VALIDATION FUNCTIONS ===

/**
 * Detect if blockchain file and database are out of sync
 * Returns true if recovery is needed
 */
bool blockchain_persistence_needs_recovery(void);

/**
 * Compare blockchain file and database to determine which is more recent/complete
 */
DataSourceComparison blockchain_persistence_compare_sources(PersistenceMetadata* file_meta, 
                                                           PersistenceMetadata* db_meta);

/**
 * Automatically recover from inconsistent state using specified strategy
 */
PersistenceResult blockchain_persistence_auto_recovery(RecoveryStrategy strategy, 
                                                      RecoveryStats* stats_out);

/**
 * Load blockchain from the most reliable source after comparison
 */
TW_BlockChain* blockchain_persistence_load_with_recovery(RecoveryStrategy strategy, 
                                                        RecoveryStats* stats_out);

/**
 * Validate blockchain integrity across both storage systems
 */
PersistenceResult blockchain_persistence_validate_integrity(TW_BlockChain* blockchain);

// === METADATA AND UTILITY FUNCTIONS ===

/**
 * Get current persistence metadata for debugging/monitoring
 */
const PersistenceMetadata* blockchain_persistence_get_metadata(void);

/**
 * Get recovery statistics from last recovery operation
 */
const RecoveryStats* blockchain_persistence_get_last_recovery_stats(void);

/**
 * Calculate checksum for blockchain data integrity
 */
PersistenceResult blockchain_persistence_calculate_checksum(TW_BlockChain* blockchain, char* checksum_out);

/**
 * Get human-readable error message for persistence result
 */
const char* blockchain_persistence_error_string(PersistenceResult result);

// === TWO-PHASE COMMIT IMPLEMENTATION ===

/**
 * Phase 1: Prepare - validate and stage changes without committing
 */
PersistenceResult blockchain_persistence_prepare_commit(TW_BlockChain* blockchain);

/**
 * Phase 2: Commit - atomically apply all staged changes
 */
PersistenceResult blockchain_persistence_finalize_commit(void);

/**
 * Rollback - undo any staged changes if commit fails
 */
PersistenceResult blockchain_persistence_rollback_commit(void);

// === ADVANCED RECOVERY FUNCTIONS ===

/**
 * Repair database from blockchain file
 */
PersistenceResult blockchain_persistence_repair_database_from_file(RecoveryStats* stats_out);

/**
 * Repair blockchain file from database
 */
PersistenceResult blockchain_persistence_repair_file_from_database(RecoveryStats* stats_out);

/**
 * Create backup before making changes
 */
PersistenceResult blockchain_persistence_create_backup(const char* backup_suffix);

/**
 * Restore from backup if recovery fails
 */
PersistenceResult blockchain_persistence_restore_backup(const char* backup_suffix);

#endif // BLOCKCHAIN_PERSISTENCE_H 