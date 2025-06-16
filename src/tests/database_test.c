#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

#include "database_test.h"
#include "packages/sql/database.h"
#include "packages/sql/queries.h"
#include "packages/structures/blockChain/blockchain.h"
#include "packages/fileIO/blockchainIO.h"
#include "packages/keystore/keystore.h"

#define TEST_DB_PATH "test_state/blockchain/test_blockchain.db"
#define BLOCKCHAIN_FILE_PATH "state/blockchain/blockchain.dat"

// Helper function to remove test database files
static void cleanup_test_db(void) {
    unlink(TEST_DB_PATH);
    unlink("test_blockchain.db-wal");
    unlink("test_blockchain.db-shm");
}

// Helper function to check if blockchain file exists
static int check_blockchain_file_exists(void) {
    struct stat st;
    if (stat(BLOCKCHAIN_FILE_PATH, &st) == 0) {
        printf("Found blockchain file: %s (size: %ld bytes)\n", BLOCKCHAIN_FILE_PATH, st.st_size);
        return 1;
    }
    return 0;
}

// Test database initialization
static int test_db_initialization(void) {
    printf("Testing database initialization...\n");
    
    // Clean up any existing test database
    cleanup_test_db();
    
    // Initialize database
    if (db_init(TEST_DB_PATH) != 0) {
        printf("✗ Failed to initialize database\n");
        return 1;
    }
    
    // Check if database is initialized
    if (!db_is_initialized()) {
        printf("✗ Database not marked as initialized\n");
        db_close();
        return 1;
    }
    
    // Check if database file was created
    struct stat st;
    if (stat(TEST_DB_PATH, &st) != 0) {
        printf("✗ Database file was not created\n");
        db_close();
        return 1;
    }
    
    printf("✓ Database initialization successful\n");
    return 0;
}

// Test blockchain loading and syncing
static int test_blockchain_sync(void) {
    printf("Testing blockchain sync to database...\n");
    
    // Check if blockchain file exists
    if (!check_blockchain_file_exists()) {
        printf("✗ Blockchain file not found: %s\n", BLOCKCHAIN_FILE_PATH);
        printf("  Please run blockchain test first to create the blockchain file\n");
        return 1;
    }
    
    // Load blockchain from file
    printf("Loading blockchain from file...\n");
    TW_BlockChain* blockchain = readBlockChainFromFile();
    if (!blockchain) {
        printf("✗ Failed to load blockchain from file\n");
        return 1;
    }
    
    printf("✓ Loaded blockchain with %u blocks\n", blockchain->length);
    
    // Sync blockchain to database
    printf("Syncing blockchain to database...\n");
    clock_t start_time = clock();
    
    if (db_sync_blockchain(blockchain) != 0) {
        printf("✗ Failed to sync blockchain to database\n");
        TW_BlockChain_destroy(blockchain);
        return 1;
    }
    
    clock_t end_time = clock();
    double sync_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    printf("✓ Blockchain sync completed in %.2f seconds\n", sync_time);
    
    // Verify block count in database
    uint32_t db_block_count;
    if (db_get_block_count(&db_block_count) != 0) {
        printf("✗ Failed to get block count from database\n");
        TW_BlockChain_destroy(blockchain);
        return 1;
    }
    
    if (db_block_count != blockchain->length) {
        printf("✗ Block count mismatch: blockchain=%u, database=%u\n", 
               blockchain->length, db_block_count);
        TW_BlockChain_destroy(blockchain);
        return 1;
    }
    
    printf("✓ Block count verified: %u blocks\n", db_block_count);
    
    // Verify transaction count in database
    uint64_t db_tx_count;
    if (db_get_transaction_count(&db_tx_count) != 0) {
        printf("✗ Failed to get transaction count from database\n");
        TW_BlockChain_destroy(blockchain);
        return 1;
    }
    
    // Calculate expected transaction count
    uint64_t expected_tx_count = 0;
    for (uint32_t i = 0; i < blockchain->length; i++) {
        expected_tx_count += blockchain->blocks[i]->txn_count;
    }
    
    if (db_tx_count != expected_tx_count) {
        printf("✗ Transaction count mismatch: expected=%lu, database=%lu\n", 
               expected_tx_count, db_tx_count);
        TW_BlockChain_destroy(blockchain);
        return 1;
    }
    
    printf("✓ Transaction count verified: %lu transactions\n", db_tx_count);
    
    TW_BlockChain_destroy(blockchain);
    return 0;
}

// Test database queries
static int test_database_queries(void) {
    printf("Testing database queries...\n");
    
    // Test recent activity query
    TransactionRecord* records = NULL;
    size_t record_count = 0;
    
    if (query_recent_activity(10, &records, &record_count) != 0) {
        printf("✗ Failed to query recent activity\n");
        return 1;
    }
    
    printf("✓ Recent activity query returned %zu records\n", record_count);
    
    // Verify some basic properties of the records
    if (record_count > 0) {
        printf("  Sample record: Block %u, Transaction %u, Type %d\n",
               records[0].block_index, records[0].transaction_index, records[0].type);
        
        // Check if timestamps are reasonable (not zero and not in the future)
        time_t now = time(NULL);
        if (records[0].timestamp == 0 || records[0].timestamp > now + 3600) {
            printf("✗ Invalid timestamp in record: %lu\n", records[0].timestamp);
            db_free_transaction_records(records, record_count);
            return 1;
        }
    }
    
    db_free_transaction_records(records, record_count);
    
    // Test filtered query by type
    records = NULL;
    record_count = 0;
    
    if (query_transactions_by_type(TW_TXN_GROUP_MESSAGE, 5, &records, &record_count) != 0) {
        printf("✗ Failed to query filtered transactions\n");
        return 1;
    }
    
    printf("✓ Filtered query returned %zu records\n", record_count);
    
    // Verify filter was applied
    for (size_t i = 0; i < record_count; i++) {
        if (records[i].type != TW_TXN_GROUP_MESSAGE) {
            printf("✗ Filter not applied correctly: expected type %d, got %d\n",
                   TW_TXN_GROUP_MESSAGE, records[i].type);
            db_free_transaction_records(records, record_count);
            return 1;
        }
    }
    
    db_free_transaction_records(records, record_count);
    
    printf("✓ Database queries completed successfully\n");
    return 0;
}

// Test database performance and integrity
static int test_database_performance(void) {
    printf("Testing database performance and integrity...\n");
    
    // Test WAL checkpoint
    if (db_checkpoint_wal() != 0) {
        printf("✗ Failed to checkpoint WAL\n");
        return 1;
    }
    printf("✓ WAL checkpoint successful\n");
    
    // Get database statistics
    uint32_t block_count;
    uint64_t tx_count;
    
    if (db_get_block_count(&block_count) != 0 || db_get_transaction_count(&tx_count) != 0) {
        printf("✗ Failed to get database statistics\n");
        return 1;
    }
    
    printf("✓ Database statistics: %u blocks, %lu transactions\n", block_count, tx_count);
    
    // Test database file size
    struct stat st;
    if (stat(TEST_DB_PATH, &st) == 0) {
        printf("✓ Database file size: %ld bytes (%.2f MB)\n", 
               st.st_size, (double)st.st_size / (1024 * 1024));
    }
    
    return 0;
}

int database_test_main(void) {
    printf("=== Database Test Suite ===\n");
    
    int tests_passed = 0;
    int tests_failed = 0;
    
    // Test 1: Database initialization
    if (test_db_initialization() == 0) {
        tests_passed++;
        printf("✓ Database initialization test passed\n\n");
    } else {
        tests_failed++;
        printf("✗ Database initialization test failed\n\n");
        cleanup_test_db();
        return 1;
    }
    
    // Test 2: Blockchain sync
    if (test_blockchain_sync() == 0) {
        tests_passed++;
        printf("✓ Blockchain sync test passed\n\n");
    } else {
        tests_failed++;
        printf("✗ Blockchain sync test failed\n\n");
        db_close();
        cleanup_test_db();
        return 1;
    }
    
    // Test 3: Database queries
    if (test_database_queries() == 0) {
        tests_passed++;
        printf("✓ Database queries test passed\n\n");
    } else {
        tests_failed++;
        printf("✗ Database queries test failed\n\n");
        db_close();
        cleanup_test_db();
        return 1;
    }
    
    // Test 4: Performance and integrity
    if (test_database_performance() == 0) {
        tests_passed++;
        printf("✓ Database performance test passed\n\n");
    } else {
        tests_failed++;
        printf("✗ Database performance test failed\n\n");
        db_close();
        cleanup_test_db();
        return 1;
    }
    
    // Close database and cleanup
    db_close();
    //cleanup_test_db();
    
    // Print summary
    printf("=== Database Test Summary ===\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("Total tests: %d\n", tests_passed + tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
} 