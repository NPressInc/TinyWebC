#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sodium.h>
#include "blockchainPersistence.h"
#include "blockchainIO.h"
#include "packages/sql/database.h"
#include "packages/utils/print.h"
#include "packages/PBFT/pbftNode.h"
#include "packages/structures/blockChain/block.h"
#include "packages/structures/blockChain/transaction.h"

// Missing constants if not defined elsewhere
#ifndef MAX_RECIPIENTS
#define MAX_RECIPIENTS 50
#endif

#ifndef PROP_ID_SIZE
#define PROP_ID_SIZE 16
#endif

// Global persistence state
static struct {
    bool is_initialized;
    char blockchain_path[512];
    char db_path[512];
    char temp_file_path[512];
    PersistenceMetadata metadata;
    PersistenceMetadata staged_metadata;
    RecoveryStats last_recovery_stats;
    bool transaction_active;
    
    // Two-phase commit state
    FILE* staged_file;
    sqlite3* db_transaction;
    bool file_prepared;
    bool db_prepared;
} g_persistence_ctx = {0};

// === UTILITY FUNCTIONS ===

const char* blockchain_persistence_error_string(PersistenceResult result) {
    switch (result) {
        case PERSISTENCE_SUCCESS: return "Success";
        case PERSISTENCE_ERROR_NULL_POINTER: return "Null pointer error";
        case PERSISTENCE_ERROR_INVALID_STATE: return "Invalid persistence state";
        case PERSISTENCE_ERROR_FILE_WRITE_FAILED: return "File write failed";
        case PERSISTENCE_ERROR_DB_WRITE_FAILED: return "Database write failed";
        case PERSISTENCE_ERROR_TRANSACTION_FAILED: return "Transaction failed";
        case PERSISTENCE_ERROR_ROLLBACK_FAILED: return "Rollback failed";
        case PERSISTENCE_ERROR_RECOVERY_FAILED: return "Recovery failed";
        case PERSISTENCE_ERROR_INCONSISTENT_STATE: return "Inconsistent data state";
        case PERSISTENCE_ERROR_VALIDATION_FAILED: return "Validation failed";
        default: return "Unknown error";
    }
}

static bool file_exists(const char* path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static time_t get_file_mtime(const char* path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return st.st_mtime;
    }
    return 0;
}

static PersistenceResult calculate_blockchain_checksum(TW_BlockChain* blockchain, char* checksum_out) {
    if (!blockchain || !checksum_out) return PERSISTENCE_ERROR_NULL_POINTER;
    
    // Create a hash of the blockchain state
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    
    // Hash the blockchain length
    crypto_hash_sha256_update(&state, (unsigned char*)&blockchain->length, sizeof(blockchain->length));
    
    // Hash each block's hash
    for (uint32_t i = 0; i < blockchain->length; i++) {
        if (blockchain->blocks[i]) {
            unsigned char block_hash[32];
            if (TW_Block_getHash(blockchain->blocks[i], block_hash) == 1) {
                crypto_hash_sha256_update(&state, block_hash, sizeof(block_hash));
            }
        }
    }
    
    unsigned char hash[32];
    crypto_hash_sha256_final(&state, hash);
    
    // Convert to hex string
    for (int i = 0; i < 32; i++) {
        sprintf(checksum_out + (i * 2), "%02x", hash[i]);
    }
    checksum_out[64] = '\0';
    
    return PERSISTENCE_SUCCESS;
}

static PersistenceResult load_metadata_from_file(const char* blockchain_path, PersistenceMetadata* meta) {
    if (!blockchain_path || !meta) return PERSISTENCE_ERROR_NULL_POINTER;
    
    memset(meta, 0, sizeof(PersistenceMetadata));
    
    // Load blockchain to get metadata
    TW_BlockChain* blockchain = readBlockChainFromFile();
    if (!blockchain) {
        return PERSISTENCE_ERROR_FILE_WRITE_FAILED;
    }
    
    meta->blockchain_length = blockchain->length;
    meta->last_file_save = get_file_mtime(blockchain_path);
    meta->file_version = 1; // TODO: implement proper versioning
    
    if (blockchain->length > 0 && blockchain->blocks[blockchain->length - 1]) {
        meta->last_block_timestamp = blockchain->blocks[blockchain->length - 1]->timestamp;
    }
    
    PersistenceResult result = calculate_blockchain_checksum(blockchain, meta->checksum);
    TW_BlockChain_destroy(blockchain);
    
    return result;
}

static PersistenceResult load_metadata_from_db(PersistenceMetadata* meta) {
    if (!meta) return PERSISTENCE_ERROR_NULL_POINTER;
    
    memset(meta, 0, sizeof(PersistenceMetadata));
    
    if (!db_is_initialized()) {
        return PERSISTENCE_ERROR_DB_WRITE_FAILED;
    }
    
    // Get block count
    uint32_t block_count = 0;
    if (db_get_block_count(&block_count) != 0) {
        return PERSISTENCE_ERROR_DB_WRITE_FAILED;
    }
    
    meta->blockchain_length = block_count;
    meta->last_db_sync = time(NULL); // Approximate
    
    // Get last block timestamp if available
    if (block_count > 0) {
        sqlite3* db = db_get_handle();
        if (db) {
            sqlite3_stmt* stmt;
            const char* sql = "SELECT MAX(timestamp) FROM blocks;";
            if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
                if (sqlite3_step(stmt) == SQLITE_ROW) {
                    meta->last_block_timestamp = sqlite3_column_int64(stmt, 0);
                }
                sqlite3_finalize(stmt);
            }
        }
    }
    
    // Note: Database checksum calculation would require loading all blocks
    // For now, we'll calculate it when needed
    strcpy(meta->checksum, "pending");
    
    return PERSISTENCE_SUCCESS;
}

// === CORE PERSISTENCE FUNCTIONS ===

PersistenceResult blockchain_persistence_init(const char* blockchain_file, const char* db_file) {
    if (!blockchain_file || !db_file) return PERSISTENCE_ERROR_NULL_POINTER;
    
    printf("✅ Blockchain persistence manager initialized\n");
    printf("   File path: %s\n", blockchain_file);
    printf("   Database path: %s\n", db_file);
    
    // Store paths
    strncpy(g_persistence_ctx.blockchain_path, blockchain_file, sizeof(g_persistence_ctx.blockchain_path) - 1);
    strncpy(g_persistence_ctx.db_path, db_file, sizeof(g_persistence_ctx.db_path) - 1);
    
    // Create temp file path
    snprintf(g_persistence_ctx.temp_file_path, sizeof(g_persistence_ctx.temp_file_path), 
             "%s.tmp", blockchain_file);
    
    // Initialize metadata
    memset(&g_persistence_ctx.metadata, 0, sizeof(g_persistence_ctx.metadata));
    memset(&g_persistence_ctx.staged_metadata, 0, sizeof(g_persistence_ctx.staged_metadata));
    
    g_persistence_ctx.is_initialized = true;
    g_persistence_ctx.transaction_active = false;
    g_persistence_ctx.file_prepared = false;
    g_persistence_ctx.db_prepared = false;
    
    return PERSISTENCE_SUCCESS;
}

void blockchain_persistence_cleanup(void) {
    if (!g_persistence_ctx.is_initialized) return;
    
    // Clean up any active transaction
    if (g_persistence_ctx.transaction_active) {
        printf("⚠️ Warning: Cleaning up active transaction during shutdown\n");
        blockchain_persistence_rollback_commit();
    }
    
    // Remove temp files
    if (file_exists(g_persistence_ctx.temp_file_path)) {
        unlink(g_persistence_ctx.temp_file_path);
    }
    
    memset(&g_persistence_ctx, 0, sizeof(g_persistence_ctx));
    printf("✅ Blockchain persistence manager cleaned up\n");
}

// === TWO-PHASE COMMIT IMPLEMENTATION ===

PersistenceResult blockchain_persistence_prepare_commit(TW_BlockChain* blockchain) {
    if (!g_persistence_ctx.is_initialized || !blockchain) {
        return PERSISTENCE_ERROR_NULL_POINTER;
    }
    
    if (g_persistence_ctx.transaction_active) {
        return PERSISTENCE_ERROR_INVALID_STATE;
    }
    
    g_persistence_ctx.transaction_active = true;
    g_persistence_ctx.file_prepared = false;
    g_persistence_ctx.db_prepared = false;
    
    // PHASE 1A: Prepare file write
    // Create directory for temp file if needed
    char temp_dir[512];
    strncpy(temp_dir, g_persistence_ctx.temp_file_path, sizeof(temp_dir) - 1);
    temp_dir[sizeof(temp_dir) - 1] = '\0';
    
    char* last_slash = strrchr(temp_dir, '/');
    if (last_slash) {
        *last_slash = '\0';
    } else {
        strcpy(temp_dir, ".");
    }
    
    // Serialize and save to temporary file
    if (!saveBlockChainToFileWithPath(blockchain, temp_dir)) {
        printf("❌ Failed to write blockchain to temporary file\n");
        blockchain_persistence_rollback_commit();
        return PERSISTENCE_ERROR_FILE_WRITE_FAILED;
    }
    
    // Rename the temporary blockchain.dat to our specific temp file
    char temp_blockchain_path[512];
    snprintf(temp_blockchain_path, sizeof(temp_blockchain_path), "%s/blockchain.dat", temp_dir);
    
    if (rename(temp_blockchain_path, g_persistence_ctx.temp_file_path) != 0) {
        printf("❌ Failed to rename temporary file\n");
        blockchain_persistence_rollback_commit();
        return PERSISTENCE_ERROR_FILE_WRITE_FAILED;
    }
    
    // Verify the temp file
    FILE* temp_file = fopen(g_persistence_ctx.temp_file_path, "rb");
    if (!temp_file) {
        printf("❌ Failed to open temporary file for verification\n");
        blockchain_persistence_rollback_commit();
        return PERSISTENCE_ERROR_VALIDATION_FAILED;
    }
    
    // Verify the file has reasonable size
    fseek(temp_file, 0, SEEK_END);
    long file_size = ftell(temp_file);
    fclose(temp_file);
    
    if (file_size < 16) { // Minimum size for a valid blockchain file
        printf("❌ Temporary file is too small to be valid\n");
        blockchain_persistence_rollback_commit();
        return PERSISTENCE_ERROR_VALIDATION_FAILED;
    }
    
    g_persistence_ctx.file_prepared = true;
    
    // PHASE 1B: Prepare database write
    if (!db_is_initialized()) {
        // Skip database preparation if not available
        return PERSISTENCE_SUCCESS;
    }
    
    sqlite3* db = db_get_handle();
    if (!db) {
        printf("❌ Failed to get database handle\n");
        blockchain_persistence_rollback_commit();
        return PERSISTENCE_ERROR_DB_WRITE_FAILED;
    }
    
    // Begin database transaction
    if (sqlite3_exec(db, "BEGIN IMMEDIATE;", NULL, NULL, NULL) != SQLITE_OK) {
        printf("❌ Failed to begin database transaction\n");
        blockchain_persistence_rollback_commit();
        return PERSISTENCE_ERROR_DB_WRITE_FAILED;
    }
    
    // Add only new blocks to database within the transaction
    uint32_t existing_db_blocks = 0;
    if (db_get_block_count(&existing_db_blocks) == 0) {
        // Only add blocks that are newer than what's in the database
        for (uint32_t i = existing_db_blocks; i < blockchain->length; i++) {
            if (db_add_block(blockchain->blocks[i], i) != 0) {
                printf("❌ Failed to add block %u to database transaction\n", i);
                blockchain_persistence_rollback_commit();
                return PERSISTENCE_ERROR_DB_WRITE_FAILED;
            }
        }
        
        if (blockchain->length > existing_db_blocks) {
            printf("   Adding %u new blocks to database (blocks %u-%u)\n", 
                   blockchain->length - existing_db_blocks, existing_db_blocks, blockchain->length - 1);
        }
    } else {
        // If we can't get block count, add all blocks (fallback behavior)
        for (uint32_t i = 0; i < blockchain->length; i++) {
            if (db_add_block(blockchain->blocks[i], i) != 0) {
                printf("❌ Failed to add block %u to database transaction\n", i);
                blockchain_persistence_rollback_commit();
                return PERSISTENCE_ERROR_DB_WRITE_FAILED;
            }
        }
    }
    
    g_persistence_ctx.db_prepared = true;
    return PERSISTENCE_SUCCESS;
}

PersistenceResult blockchain_persistence_finalize_commit(void) {
    if (!g_persistence_ctx.is_initialized || !g_persistence_ctx.transaction_active) {
        return PERSISTENCE_ERROR_INVALID_STATE;
    }
    
    // PHASE 2A: Commit file changes
    if (g_persistence_ctx.file_prepared) {
        if (rename(g_persistence_ctx.temp_file_path, g_persistence_ctx.blockchain_path) != 0) {
            printf("❌ Failed to commit file changes\n");
            blockchain_persistence_rollback_commit();
            return PERSISTENCE_ERROR_FILE_WRITE_FAILED;
        }
    }
    
    // PHASE 2B: Commit database transaction
    if (g_persistence_ctx.db_prepared && db_is_initialized()) {
        sqlite3* db = db_get_handle();
        if (db) {
            if (sqlite3_exec(db, "COMMIT;", NULL, NULL, NULL) != SQLITE_OK) {
                printf("❌ Failed to commit database transaction\n");
                blockchain_persistence_rollback_commit();
                return PERSISTENCE_ERROR_DB_WRITE_FAILED;
            }
        }
    }
    
    // Reset transaction state
    g_persistence_ctx.transaction_active = false;
    g_persistence_ctx.file_prepared = false;
    g_persistence_ctx.db_prepared = false;
    
    return PERSISTENCE_SUCCESS;
}

PersistenceResult blockchain_persistence_rollback_commit(void) {
    if (!g_persistence_ctx.is_initialized) {
        return PERSISTENCE_ERROR_INVALID_STATE;
    }
    
    // Rollback file changes
    if (g_persistence_ctx.file_prepared) {
        unlink(g_persistence_ctx.temp_file_path); // Remove temp file
    }
    
    // Rollback database transaction
    if (g_persistence_ctx.db_prepared && db_is_initialized()) {
        sqlite3* db = db_get_handle();
        if (db) {
            if (sqlite3_exec(db, "ROLLBACK;", NULL, NULL, NULL) != SQLITE_OK) {
                printf("❌ Failed to rollback database transaction\n");
            }
        }
    }
    
    // Reset transaction state
    g_persistence_ctx.transaction_active = false;
    g_persistence_ctx.file_prepared = false;
    g_persistence_ctx.db_prepared = false;
    
    return PERSISTENCE_SUCCESS;
}

PersistenceResult blockchain_persistence_commit_block(TW_BlockChain* blockchain, TW_Block* block) {
    if (!g_persistence_ctx.is_initialized || !blockchain || !block) {
        return PERSISTENCE_ERROR_NULL_POINTER;
    }
    
    if (g_persistence_ctx.transaction_active) {
        printf("⚠️ Cannot commit block: transaction already active\n");
        return PERSISTENCE_ERROR_INVALID_STATE;
    }
    
    printf("🔄 Committing block %d using two-phase commit...\n", block->index);
    
    // TWO-PHASE COMMIT PROTOCOL
    
    // PHASE 1: PREPARE
    PersistenceResult prepare_result = blockchain_persistence_prepare_commit(blockchain);
    if (prepare_result != PERSISTENCE_SUCCESS) {
        printf("❌ Prepare phase failed: %s\n", blockchain_persistence_error_string(prepare_result));
        blockchain_persistence_rollback_commit();
        return prepare_result;
    }
    
    // PHASE 2: COMMIT
    PersistenceResult commit_result = blockchain_persistence_finalize_commit();
    if (commit_result != PERSISTENCE_SUCCESS) {
        printf("❌ Commit phase failed: %s\n", blockchain_persistence_error_string(commit_result));
        blockchain_persistence_rollback_commit();
        return commit_result;
    }
    
    printf("✅ Block %d committed successfully\n", block->index);
    return PERSISTENCE_SUCCESS;
}

PersistenceResult blockchain_persistence_commit_full_blockchain(TW_BlockChain* blockchain) {
    if (!blockchain) return PERSISTENCE_ERROR_NULL_POINTER;
    
    printf("🔄 Committing full blockchain using two-phase commit...\n");
    printf("   Blockchain length: %u blocks\n", blockchain->length);
    
    // Phase 1: Prepare (pass NULL for block to indicate full sync)
    PersistenceResult result = blockchain_persistence_prepare_commit(blockchain);
    if (result != PERSISTENCE_SUCCESS) {
        printf("❌ Failed to prepare full blockchain commit: %s\n", blockchain_persistence_error_string(result));
        return result;
    }
    
    // Phase 2: Commit
    result = blockchain_persistence_finalize_commit();
    if (result != PERSISTENCE_SUCCESS) {
        printf("❌ Failed to finalize full blockchain commit: %s\n", blockchain_persistence_error_string(result));
        // Attempt rollback
        blockchain_persistence_rollback_commit();
        return result;
    }
    
    printf("✅ Full blockchain committed successfully using two-phase commit\n");
    return PERSISTENCE_SUCCESS;
}

// === RECOVERY FUNCTIONS ===

bool blockchain_persistence_needs_recovery(void) {
    if (!g_persistence_ctx.is_initialized) return true;
    
    PersistenceMetadata file_meta, db_meta;
    
    // Load metadata from both sources
    PersistenceResult file_result = load_metadata_from_file(g_persistence_ctx.blockchain_path, &file_meta);
    PersistenceResult db_result = load_metadata_from_db(&db_meta);
    
    // If either source failed to load, we need recovery
    if (file_result != PERSISTENCE_SUCCESS || db_result != PERSISTENCE_SUCCESS) {
        printf("🔍 Recovery needed: Failed to load metadata from one or both sources\n");
        return true;
    }
    
    // Compare blockchain lengths
    if (file_meta.blockchain_length != db_meta.blockchain_length) {
        printf("🔍 Recovery needed: Length mismatch (file: %u, db: %u)\n", 
               file_meta.blockchain_length, db_meta.blockchain_length);
        return true;
    }
    
    // Compare timestamps if available
    if (file_meta.last_block_timestamp != db_meta.last_block_timestamp) {
        printf("🔍 Recovery needed: Timestamp mismatch (file: %lu, db: %lu)\n",
               file_meta.last_block_timestamp, db_meta.last_block_timestamp);
        return true;
    }
    
    printf("✅ No recovery needed: Sources are consistent\n");
    return false;
}

DataSourceComparison blockchain_persistence_compare_sources(PersistenceMetadata* file_meta, 
                                                           PersistenceMetadata* db_meta) {
    if (!file_meta || !db_meta) return DATA_SOURCE_CONFLICT;
    
    // Compare blockchain lengths first
    if (file_meta->blockchain_length > db_meta->blockchain_length) {
        printf("📊 File has more blocks (%u vs %u)\n", file_meta->blockchain_length, db_meta->blockchain_length);
        return DATA_SOURCE_FILE_NEWER;
    } else if (db_meta->blockchain_length > file_meta->blockchain_length) {
        printf("📊 Database has more blocks (%u vs %u)\n", db_meta->blockchain_length, file_meta->blockchain_length);
        return DATA_SOURCE_DB_NEWER;
    }
    
    // Same length, compare timestamps
    if (file_meta->last_block_timestamp > db_meta->last_block_timestamp) {
        printf("📊 File has newer timestamp (%lu vs %lu)\n", file_meta->last_block_timestamp, db_meta->last_block_timestamp);
        return DATA_SOURCE_FILE_NEWER;
    } else if (db_meta->last_block_timestamp > file_meta->last_block_timestamp) {
        printf("📊 Database has newer timestamp (%lu vs %lu)\n", db_meta->last_block_timestamp, file_meta->last_block_timestamp);
        return DATA_SOURCE_DB_NEWER;
    }
    
    // Check file modification times
    if (file_meta->last_file_save > db_meta->last_db_sync) {
        printf("📊 File was saved more recently\n");
        return DATA_SOURCE_FILE_NEWER;
    } else if (db_meta->last_db_sync > file_meta->last_file_save) {
        printf("📊 Database was synced more recently\n");
        return DATA_SOURCE_DB_NEWER;
    }
    
    printf("📊 Sources appear equivalent\n");
    return DATA_SOURCE_EQUIVALENT;
}

const PersistenceMetadata* blockchain_persistence_get_metadata(void) {
    if (!g_persistence_ctx.is_initialized) return NULL;
    return &g_persistence_ctx.metadata;
}

const RecoveryStats* blockchain_persistence_get_last_recovery_stats(void) {
    if (!g_persistence_ctx.is_initialized) return NULL;
    return &g_persistence_ctx.last_recovery_stats;
}

PersistenceResult blockchain_persistence_calculate_checksum(TW_BlockChain* blockchain, char* checksum_out) {
    return calculate_blockchain_checksum(blockchain, checksum_out);
}

// === RECOVERY IMPLEMENTATION ===

PersistenceResult blockchain_persistence_auto_recovery(RecoveryStrategy strategy, RecoveryStats* stats_out) {
    if (!g_persistence_ctx.is_initialized) return PERSISTENCE_ERROR_INVALID_STATE;
    
    printf("🔄 Starting automatic blockchain recovery...\n");
    
    time_t start_time = time(NULL);
    RecoveryStats stats = {0};
    
    // Load blockchain from file
    TW_BlockChain* file_blockchain = NULL;
    uint32_t file_blocks = 0;
    
    if (file_exists(g_persistence_ctx.blockchain_path)) {
        file_blockchain = readBlockChainFromFile();
        if (file_blockchain) {
            file_blocks = file_blockchain->length;
        }
    }
    
    // Get database block count
    uint32_t db_blocks = 0;
    if (db_is_initialized()) {
        db_get_block_count(&db_blocks);
    }
    
    printf("📊 Blockchain state: File=%u blocks, Database=%u blocks\n", file_blocks, db_blocks);
    
    PersistenceResult result = PERSISTENCE_SUCCESS;
    
    // Determine recovery action based on strategy
    if (db_blocks > file_blocks) {
        printf("🔄 Database has more blocks, repairing file from database...\n");
        result = blockchain_persistence_repair_file_from_database(&stats);
    } else if (file_blocks > db_blocks) {
        printf("🔄 File has more blocks, syncing to database...\n");
        if (file_blockchain) {
            result = blockchain_persistence_commit_full_blockchain(file_blockchain);
            if (result == PERSISTENCE_SUCCESS) {
                stats.blocks_recovered = file_blocks - db_blocks;
            }
        } else {
            result = PERSISTENCE_ERROR_RECOVERY_FAILED;
        }
    } else {
        printf("✅ File and database are in sync\n");
    }
    
    // Record recovery stats
    stats.recovery_time_seconds = (double)(time(NULL) - start_time);
    g_persistence_ctx.last_recovery_stats = stats;
    
    if (stats_out) {
        *stats_out = stats;
    }
    
    if (file_blockchain) {
        TW_BlockChain_destroy(file_blockchain);
    }
    
    if (result == PERSISTENCE_SUCCESS) {
        printf("✅ Recovery completed successfully in %.0f seconds\n", stats.recovery_time_seconds);
    } else {
        printf("❌ Recovery failed: %s\n", blockchain_persistence_error_string(result));
    }
    
    return result;
}

TW_BlockChain* blockchain_persistence_load_with_recovery(RecoveryStrategy strategy, RecoveryStats* stats_out) {
    if (!g_persistence_ctx.is_initialized) return NULL;
    
    // Check if recovery is needed
    if (!blockchain_persistence_needs_recovery()) {
        printf("📂 Loading blockchain (no recovery needed)...\n");
        return readBlockChainFromFile();
    }
    
    // Perform recovery
    printf("🔄 Recovery needed, attempting automatic recovery...\n");
    PersistenceResult result = blockchain_persistence_auto_recovery(strategy, stats_out);
    if (result != PERSISTENCE_SUCCESS) {
        printf("❌ Recovery failed, cannot load blockchain\n");
        return NULL;
    }
    
    // Load the recovered blockchain
    printf("📂 Loading recovered blockchain...\n");
    return readBlockChainFromFile();
}

PersistenceResult blockchain_persistence_repair_database_from_file(RecoveryStats* stats_out) {
    if (!g_persistence_ctx.is_initialized) return PERSISTENCE_ERROR_INVALID_STATE;
    
    printf("🔧 Repairing database from blockchain file...\n");
    
    // Load blockchain from file
    TW_BlockChain* blockchain = readBlockChainFromFile();
    if (!blockchain) {
        printf("❌ Failed to load blockchain from file\n");
        return PERSISTENCE_ERROR_FILE_WRITE_FAILED;
    }
    
    printf("   Loaded blockchain with %u blocks\n", blockchain->length);
    
    // Clear database and resync
    if (db_is_initialized()) {
        sqlite3* db = db_get_handle();
        if (db) {
            // Clear existing data
            const char* clear_sql = 
                "DELETE FROM transaction_recipients; "
                "DELETE FROM transactions; "
                "DELETE FROM blocks; "
                "DELETE FROM blockchain_info;";
            
            int rc = sqlite3_exec(db, clear_sql, NULL, NULL, NULL);
            if (rc != SQLITE_OK) {
                printf("❌ Failed to clear database: %s\n", sqlite3_errmsg(db));
                TW_BlockChain_destroy(blockchain);
                return PERSISTENCE_ERROR_DB_WRITE_FAILED;
            }
            printf("✅ Database cleared\n");
        }
    }
    
    // Use our two-phase commit to sync the blockchain
    PersistenceResult result = blockchain_persistence_commit_full_blockchain(blockchain);
    
    if (result == PERSISTENCE_SUCCESS && stats_out) {
        stats_out->blocks_recovered = blockchain->length;
        
        // Count transactions
        uint32_t total_transactions = 0;
        for (uint32_t i = 0; i < blockchain->length; i++) {
            if (blockchain->blocks[i]) {
                total_transactions += blockchain->blocks[i]->txn_count;
            }
        }
        stats_out->transactions_recovered = total_transactions;
    }
    
    TW_BlockChain_destroy(blockchain);
    
    if (result == PERSISTENCE_SUCCESS) {
        printf("✅ Database repaired from blockchain file\n");
    }
    
    return result;
}

PersistenceResult blockchain_persistence_repair_file_from_database(RecoveryStats* stats_out) {
    if (!g_persistence_ctx.is_initialized) return PERSISTENCE_ERROR_INVALID_STATE;
    
    printf("🔧 Repairing blockchain file from database...\n");
    
    if (!db_is_initialized()) {
        printf("❌ Database not initialized\n");
        return PERSISTENCE_ERROR_DB_WRITE_FAILED;
    }
    
    // Get block count from database
    uint32_t db_block_count = 0;
    if (db_get_block_count(&db_block_count) != 0) {
        printf("❌ Failed to get block count from database\n");
        return PERSISTENCE_ERROR_DB_WRITE_FAILED;
    }
    
    printf("   Database contains %u blocks\n", db_block_count);
    
    if (db_block_count == 0) {
        printf("⚠️ Database is empty, nothing to repair\n");
        return PERSISTENCE_SUCCESS;
    }
    
    // Create a backup of the current file before repair
    time_t now = time(NULL);
    char backup_suffix[32];
    strftime(backup_suffix, sizeof(backup_suffix), "backup_%Y%m%d_%H%M%S", localtime(&now));
    
    if (file_exists(g_persistence_ctx.blockchain_path)) {
        printf("💾 Creating backup before repair...\n");
        PersistenceResult backup_result = blockchain_persistence_create_backup(backup_suffix);
        if (backup_result != PERSISTENCE_SUCCESS) {
            printf("⚠️ Warning: Failed to create backup, continuing anyway\n");
        }
    }
    
    // Start reconstruction
    printf("🔄 Reconstructing blockchain from database blocks...\n");
    
    // Get database handle
    sqlite3* db = db_get_handle();
    if (!db) {
        printf("❌ Failed to get database handle\n");
        return PERSISTENCE_ERROR_DB_WRITE_FAILED;
    }
    
    // Query to get all blocks ordered by block_index
    const char* blocks_sql = 
        "SELECT block_index, timestamp, previous_hash, merkle_root_hash, "
        "proposer_id, transaction_count, block_hash "
        "FROM blocks ORDER BY block_index;";
    
    sqlite3_stmt* blocks_stmt;
    int rc = sqlite3_prepare_v2(db, blocks_sql, -1, &blocks_stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("❌ Failed to prepare blocks query: %s\n", sqlite3_errmsg(db));
        return PERSISTENCE_ERROR_DB_WRITE_FAILED;
    }
    
    // Create a new blockchain structure
    TW_BlockChain* reconstructed_blockchain = NULL;
    uint32_t blocks_processed = 0;
    uint32_t blocks_verified = 0;
    uint32_t transactions_recovered = 0;
    
    // Process each block in sequential order to maintain chain integrity
    while (sqlite3_step(blocks_stmt) == SQLITE_ROW) {
        uint32_t block_index = sqlite3_column_int(blocks_stmt, 0);
        uint64_t timestamp = sqlite3_column_int64(blocks_stmt, 1);
        const char* prev_hash_hex = (const char*)sqlite3_column_text(blocks_stmt, 2);
        const char* merkle_hash_hex = (const char*)sqlite3_column_text(blocks_stmt, 3);
        const char* proposer_hex = (const char*)sqlite3_column_text(blocks_stmt, 4);
        uint32_t txn_count = sqlite3_column_int(blocks_stmt, 5);
        const char* block_hash_hex = (const char*)sqlite3_column_text(blocks_stmt, 6);
        
        blocks_processed++;
        
        // Show progress every 100 blocks
        if (block_index % 100 == 0 || block_index < 10) {
            printf("   Processing block %u...\n", block_index);
        }
        
        // Convert hex strings back to binary
        unsigned char prev_hash[32];
        unsigned char merkle_hash[32];
        unsigned char proposer_id[PROP_ID_SIZE]; // 16 bytes
        unsigned char expected_block_hash[32];
        
        if (pbft_node_hex_to_bytes(prev_hash_hex, prev_hash, 32) != 32 ||
            pbft_node_hex_to_bytes(merkle_hash_hex, merkle_hash, 32) != 32 ||
            pbft_node_hex_to_bytes(proposer_hex, proposer_id, PROP_ID_SIZE) != PROP_ID_SIZE ||
            pbft_node_hex_to_bytes(block_hash_hex, expected_block_hash, 32) != 32) {
            printf("❌ Failed to decode hex data for block %u\n", block_index);
            continue;
        }
        
        // Create block structure with correct parameters
        TW_Block* block = TW_Block_create(block_index, NULL, 0, timestamp, prev_hash, proposer_id);
        if (!block) {
            printf("❌ Failed to create block structure for block %u\n", block_index);
            continue;
        }
        
        // Set block properties
        memcpy(block->merkle_root_hash, merkle_hash, 32);
        
        // Allocate transaction array if needed
        if (txn_count > 0) {
            block->txns = malloc(sizeof(TW_Transaction*) * txn_count);
            if (!block->txns) {
                printf("❌ Failed to allocate transactions array for block %u\n", block_index);
                TW_Block_destroy(block);
                continue;
            }
            memset(block->txns, 0, sizeof(TW_Transaction*) * txn_count);
        }
        
        // Load transactions for this block
        const char* txns_sql = 
            "SELECT transaction_index, type, sender, timestamp, recipient_count, "
            "group_id, signature, encrypted_payload, payload_size "
            "FROM transactions WHERE block_index = ? ORDER BY transaction_index;";
        
        sqlite3_stmt* txns_stmt;
        rc = sqlite3_prepare_v2(db, txns_sql, -1, &txns_stmt, NULL);
        if (rc != SQLITE_OK) {
            printf("❌ Failed to prepare transactions query for block %u\n", block_index);
            TW_Block_destroy(block);
            continue;
        }
        
        sqlite3_bind_int(txns_stmt, 1, block_index);
        
        int32_t current_txn_count = 0;
        
        // Process transactions
        while (sqlite3_step(txns_stmt) == SQLITE_ROW && current_txn_count < txn_count) {
            uint32_t tx_index = sqlite3_column_int(txns_stmt, 0);
            int tx_type = sqlite3_column_int(txns_stmt, 1);
            const char* sender_hex = (const char*)sqlite3_column_text(txns_stmt, 2);
            uint64_t tx_timestamp = sqlite3_column_int64(txns_stmt, 3);
            uint8_t recipient_count = sqlite3_column_int(txns_stmt, 4);
            const char* group_id_hex = (const char*)sqlite3_column_text(txns_stmt, 5);
            const char* signature_hex = (const char*)sqlite3_column_text(txns_stmt, 6);
            const void* payload_blob = sqlite3_column_blob(txns_stmt, 7);
            int payload_size = sqlite3_column_int(txns_stmt, 8);
            
            // Create transaction structure
            TW_Transaction* tx = malloc(sizeof(TW_Transaction));
            if (!tx) continue;
            
            memset(tx, 0, sizeof(TW_Transaction));
            tx->type = tx_type;
            tx->timestamp = tx_timestamp;
            tx->recipient_count = recipient_count;
            
            // Decode hex fields
            if (pbft_node_hex_to_bytes(sender_hex, tx->sender, 32) != 32 ||
                pbft_node_hex_to_bytes(group_id_hex, tx->group_id, 16) != 16 ||
                pbft_node_hex_to_bytes(signature_hex, tx->signature, 64) != 64) {
                printf("⚠️ Warning: Failed to decode transaction %u in block %u\n", tx_index, block_index);
                free(tx);
                continue;
            }
            
            // Handle encrypted payload if present
            if (payload_blob && payload_size > 0) {
                // Note: This would require deserializing the encrypted payload
                // For now, we'll skip payload reconstruction as it's complex
                tx->payload = NULL;
                tx->payload_size = 0;
            }
            
            // Load recipients
            if (recipient_count > 0 && recipient_count <= MAX_RECIPIENTS) {
                tx->recipients = malloc(recipient_count * 32);
                if (tx->recipients) {
                    const char* recipients_sql = 
                        "SELECT recipient_pubkey FROM transaction_recipients "
                        "WHERE transaction_id = (SELECT id FROM transactions WHERE block_index = ? AND transaction_index = ?) "
                        "ORDER BY recipient_order;";
                    
                    sqlite3_stmt* recipients_stmt;
                    if (sqlite3_prepare_v2(db, recipients_sql, -1, &recipients_stmt, NULL) == SQLITE_OK) {
                        sqlite3_bind_int(recipients_stmt, 1, block_index);
                        sqlite3_bind_int(recipients_stmt, 2, tx_index);
                        
                        int recipient_idx = 0;
                        while (sqlite3_step(recipients_stmt) == SQLITE_ROW && recipient_idx < recipient_count) {
                            const char* recipient_hex = (const char*)sqlite3_column_text(recipients_stmt, 0);
                            if (pbft_node_hex_to_bytes(recipient_hex, tx->recipients + (recipient_idx * 32), 32) == 32) {
                                recipient_idx++;
                            }
                        }
                        sqlite3_finalize(recipients_stmt);
                    }
                }
            }
            
            // Add transaction to block's array
            if (tx_index < txn_count) {
                block->txns[tx_index] = tx;
                current_txn_count++;
                transactions_recovered++;
            } else {
                printf("⚠️ Warning: Transaction index %u out of range for block %u\n", tx_index, block_index);
                TW_Transaction_destroy(tx);
            }
        }
        
        sqlite3_finalize(txns_stmt);
        
        // Update the actual transaction count
        block->txn_count = current_txn_count;
        
        // Verify block hash
        unsigned char calculated_hash[32];
        if (TW_Block_getHash(block, calculated_hash) == 1) {
            if (memcmp(calculated_hash, expected_block_hash, 32) == 0) {
                blocks_verified++;
                if (block_index % 100 == 0 || block_index < 10) {
                    printf("   ✅ Block %u hash verified\n", block_index);
                }
            } else {
                printf("❌ Block %u hash mismatch!\n", block_index);
            }
        } else {
            printf("❌ Failed to calculate hash for block %u\n", block_index);
        }
        
        // Create blockchain on first block or add subsequent blocks
        if (!reconstructed_blockchain) {
            // For block 0 (genesis), create blockchain with this block's proposer
            if (block_index == 0) {
                reconstructed_blockchain = TW_BlockChain_create(proposer_id, NULL, 0);
                if (!reconstructed_blockchain) {
                    printf("❌ Failed to create blockchain structure\n");
                    TW_Block_destroy(block);
                    break;
                }
                
                // For genesis block, we need to manually add it to avoid validation issues
                // since the blockchain expects specific genesis block properties
                if (reconstructed_blockchain->blocks) {
                    free(reconstructed_blockchain->blocks);
                }
                reconstructed_blockchain->blocks = malloc(sizeof(TW_Block*) * MAX_BLOCKS);
                if (!reconstructed_blockchain->blocks) {
                    printf("❌ Failed to allocate blocks array\n");
                    TW_Block_destroy(block);
                    TW_BlockChain_destroy(reconstructed_blockchain);
                    reconstructed_blockchain = NULL;
                    break;
                }
                
                // Initialize block sizes array
                if (reconstructed_blockchain->block_sizes) {
                    free(reconstructed_blockchain->block_sizes);
                }
                reconstructed_blockchain->block_sizes = malloc(sizeof(size_t) * MAX_BLOCKS);
                if (!reconstructed_blockchain->block_sizes) {
                    printf("❌ Failed to allocate block sizes array\n");
                    free(reconstructed_blockchain->blocks);
                    TW_Block_destroy(block);
                    TW_BlockChain_destroy(reconstructed_blockchain);
                    reconstructed_blockchain = NULL;
                    break;
                }
                
                reconstructed_blockchain->blocks[0] = block;
                reconstructed_blockchain->block_sizes[0] = TW_Block_get_size(block);
                reconstructed_blockchain->length = 1;
                printf("✅ Genesis block (block 0) added to reconstructed blockchain\n");
            } else {
                printf("⚠️ Skipping block %u - waiting for genesis block (block 0)\n", block_index);
                TW_Block_destroy(block);
            }
        } else {
            // Add subsequent blocks using the standard blockchain function
            if (TW_BlockChain_add_block(reconstructed_blockchain, block) == 1) {
                // Only log success for early blocks or every 100 blocks
                if (block_index % 100 == 0 || block_index < 10) {
                    printf("   ✅ Block %u added successfully\n", block_index);
                }
            } else {
                // Always log chain validation failures
                if (block_index < 10) {
                    printf("❌ Failed to add block %u (chain validation failed)\n", block_index);
                }
                TW_Block_destroy(block);
            }
        }
    }
    
    sqlite3_finalize(blocks_stmt);
    
    if (!reconstructed_blockchain) {
        printf("❌ Failed to reconstruct blockchain from database\n");
        return PERSISTENCE_ERROR_RECOVERY_FAILED;
    }
    
    printf("📊 Reconstruction complete:\n");
    printf("   Blocks processed: %u\n", blocks_processed);
    printf("   Blocks verified: %u\n", blocks_verified);
    printf("   Transactions recovered: %u\n", transactions_recovered);
    printf("   Final blockchain length: %u\n", reconstructed_blockchain->length);
    
    // Save the reconstructed blockchain using two-phase commit
    printf("💾 Saving reconstructed blockchain to file...\n");
    PersistenceResult save_result = blockchain_persistence_commit_full_blockchain(reconstructed_blockchain);
    
    if (save_result == PERSISTENCE_SUCCESS) {
        printf("✅ Blockchain file successfully repaired from database\n");
        
        if (stats_out) {
            stats_out->blocks_recovered = blocks_processed;
            stats_out->transactions_recovered = transactions_recovered;
        }
    } else {
        printf("❌ Failed to save reconstructed blockchain: %s\n", 
               blockchain_persistence_error_string(save_result));
        
        // Try to restore from backup
        if (file_exists(g_persistence_ctx.blockchain_path)) {
            printf("🔄 Attempting to restore from backup...\n");
            blockchain_persistence_restore_backup(backup_suffix);
        }
    }
    
    TW_BlockChain_destroy(reconstructed_blockchain);
    return save_result;
}

PersistenceResult blockchain_persistence_create_backup(const char* backup_suffix) {
    if (!g_persistence_ctx.is_initialized || !backup_suffix) return PERSISTENCE_ERROR_NULL_POINTER;
    
    printf("💾 Creating backup with suffix: %s\n", backup_suffix);
    
    // Create backup file path
    char backup_path[512];
    snprintf(backup_path, sizeof(backup_path), "%s.%s", g_persistence_ctx.blockchain_path, backup_suffix);
    
    // Copy blockchain file
    FILE* src = fopen(g_persistence_ctx.blockchain_path, "rb");
    if (!src) {
        printf("❌ Failed to open source file for backup\n");
        return PERSISTENCE_ERROR_FILE_WRITE_FAILED;
    }
    
    FILE* dst = fopen(backup_path, "wb");
    if (!dst) {
        printf("❌ Failed to create backup file\n");
        fclose(src);
        return PERSISTENCE_ERROR_FILE_WRITE_FAILED;
    }
    
    // Copy data
    char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
        if (fwrite(buffer, 1, bytes, dst) != bytes) {
            printf("❌ Failed to write backup data\n");
            fclose(src);
            fclose(dst);
            unlink(backup_path);
            return PERSISTENCE_ERROR_FILE_WRITE_FAILED;
        }
    }
    
    fclose(src);
    fclose(dst);
    
    printf("✅ Backup created: %s\n", backup_path);
    return PERSISTENCE_SUCCESS;
}

PersistenceResult blockchain_persistence_restore_backup(const char* backup_suffix) {
    if (!g_persistence_ctx.is_initialized || !backup_suffix) return PERSISTENCE_ERROR_NULL_POINTER;
    
    printf("🔄 Restoring from backup with suffix: %s\n", backup_suffix);
    
    // Create backup file path
    char backup_path[512];
    snprintf(backup_path, sizeof(backup_path), "%s.%s", g_persistence_ctx.blockchain_path, backup_suffix);
    
    if (!file_exists(backup_path)) {
        printf("❌ Backup file not found: %s\n", backup_path);
        return PERSISTENCE_ERROR_FILE_WRITE_FAILED;
    }
    
    // Copy backup file to main location
    if (rename(backup_path, g_persistence_ctx.blockchain_path) != 0) {
        printf("❌ Failed to restore backup: %s\n", strerror(errno));
        return PERSISTENCE_ERROR_FILE_WRITE_FAILED;
    }
    
    // Reload metadata
    PersistenceResult result = load_metadata_from_file(g_persistence_ctx.blockchain_path, &g_persistence_ctx.metadata);
    if (result != PERSISTENCE_SUCCESS) {
        printf("⚠️ Warning: Failed to reload metadata after restore\n");
    }
    
    printf("✅ Backup restored successfully\n");
    return PERSISTENCE_SUCCESS;
}

PersistenceResult blockchain_persistence_validate_integrity(TW_BlockChain* blockchain) {
    if (!blockchain) return PERSISTENCE_ERROR_NULL_POINTER;
    if (!g_persistence_ctx.is_initialized) return PERSISTENCE_ERROR_INVALID_STATE;
    
    printf("🔍 Validating blockchain integrity across storage systems...\n");
    
    // Calculate current blockchain checksum
    char current_checksum[65];
    PersistenceResult result = calculate_blockchain_checksum(blockchain, current_checksum);
    if (result != PERSISTENCE_SUCCESS) {
        return result;
    }
    
    // Compare with stored metadata checksum
    if (strlen(g_persistence_ctx.metadata.checksum) > 0 && 
        strcmp(current_checksum, g_persistence_ctx.metadata.checksum) != 0) {
        printf("⚠️ Checksum mismatch detected\n");
        printf("   Current: %.16s...\n", current_checksum);
        printf("   Stored:  %.16s...\n", g_persistence_ctx.metadata.checksum);
        return PERSISTENCE_ERROR_VALIDATION_FAILED;
    }
    
    // Validate blockchain length consistency
    if (g_persistence_ctx.metadata.blockchain_length != blockchain->length) {
        printf("⚠️ Length mismatch: metadata=%u, blockchain=%u\n", 
               g_persistence_ctx.metadata.blockchain_length, blockchain->length);
        return PERSISTENCE_ERROR_VALIDATION_FAILED;
    }
    
    // Check database consistency if available
    if (db_is_initialized()) {
        uint32_t db_block_count = 0;
        if (db_get_block_count(&db_block_count) == 0) {
            if (db_block_count != blockchain->length) {
                printf("⚠️ Database length mismatch: db=%u, blockchain=%u\n", 
                       db_block_count, blockchain->length);
                return PERSISTENCE_ERROR_INCONSISTENT_STATE;
            }
        }
    }
    
    printf("✅ Blockchain integrity validation passed\n");
    return PERSISTENCE_SUCCESS;
} 