# SQL Package for CTinyWeb

The SQL package provides a comprehensive SQLite-based database layer for the CTinyWeb blockchain project. It enables efficient querying, indexing, and caching of blockchain data for client applications.

## Features

### Core Functionality
- **SQLite Integration**: Full SQLite3 support with WAL mode for concurrent access
- **Blockchain Synchronization**: Automatic sync of blockchain data to database
- **Transaction Indexing**: Fast lookups by sender, recipient, type, timestamp, and block
- **Encrypted Payload Storage**: Secure storage of encrypted transaction payloads
- **Content Caching**: Optional caching of decrypted transaction content

### Performance Optimizations
- **WAL Mode**: Write-Ahead Logging for concurrent reads during writes
- **Optimized Indexes**: Strategic indexing for common query patterns
- **Memory Mapping**: 256MB memory mapping for faster access
- **Batch Operations**: Transaction-based bulk operations for sync

### Query Interface
- **High-Level Queries**: Convenient functions for common operations
- **Flexible Filtering**: Advanced filtering by multiple criteria
- **Statistics**: Built-in analytics and reporting functions
- **Memory Management**: Automatic cleanup of query results

## Database Schema

### Tables

#### `blockchain_info`
- Stores blockchain metadata (creator, length, last update)

#### `blocks`
- Block-level information (index, timestamp, hashes, proposer)
- Indexed by block_index (primary key)

#### `transactions`
- Complete transaction data with encrypted payloads
- Indexed by sender, type, timestamp, block_index, group_id
- Supports content caching for decrypted data

#### `transaction_recipients`
- Normalized recipient data for efficient recipient queries
- Indexed by recipient_pubkey

## Usage Examples

### Basic Setup

```c
#include "packages/sql/database.h"
#include "packages/sql/queries.h"

// Initialize database
if (db_init("blockchain.db") != 0) {
    printf("Failed to initialize database\n");
    return -1;
}

// Sync existing blockchain
TW_BlockChain* blockchain = /* your blockchain */;
if (db_sync_blockchain(blockchain) != 0) {
    printf("Failed to sync blockchain\n");
    return -1;
}
```

### Querying Transactions

```c
// Get recent activity
TransactionRecord* results;
size_t count;
if (query_recent_activity(50, &results, &count) == 0) {
    printf("Found %zu recent transactions\n", count);
    
    for (size_t i = 0; i < count; i++) {
        printf("Transaction %lu: Type %d from %s\n", 
               results[i].transaction_id, 
               results[i].type, 
               results[i].sender);
    }
    
    db_free_transaction_records(results, count);
}

// Get messages for a specific user
if (query_messages_for_user("user_pubkey_hex", &results, &count) == 0) {
    printf("Found %zu messages for user\n", count);
    db_free_transaction_records(results, count);
}

// Advanced filtering
TransactionFilter* filter = create_transaction_filter();
filter->type = TW_TXN_MESSAGE;
filter->start_timestamp = 1640995200; // Jan 1, 2022
filter->limit = 100;

if (query_transactions(filter, &results, &count) == 0) {
    printf("Found %zu filtered transactions\n", count);
    db_free_transaction_records(results, count);
}

free_transaction_filter(filter);
```

### Statistics and Analytics

```c
// Get transaction statistics
uint64_t total_count, message_count, system_count;
if (query_transaction_stats(&total_count, &message_count, &system_count) == 0) {
    printf("Total: %lu, Messages: %lu, System: %lu\n", 
           total_count, message_count, system_count);
}

// Get user activity stats
uint64_t sent_count, received_count;
if (query_user_stats("user_pubkey_hex", &sent_count, &received_count) == 0) {
    printf("User sent %lu, received %lu transactions\n", 
           sent_count, received_count);
}
```

### Content Caching

```c
// Cache decrypted content for faster future access
uint64_t transaction_id = 12345;
const char* decrypted_content = "Hello, family!";

if (db_cache_decrypted_content(transaction_id, decrypted_content) == 0) {
    printf("Content cached successfully\n");
}

// Retrieve cached content
char* cached_content;
if (db_get_cached_content(transaction_id, &cached_content) == 0) {
    printf("Cached content: %s\n", cached_content);
    free(cached_content);
}
```

### Database Maintenance

```c
// Checkpoint WAL file
if (db_checkpoint_wal() == 0) {
    printf("WAL checkpoint completed\n");
}

// Vacuum database to reclaim space
if (db_vacuum() == 0) {
    printf("Database vacuum completed\n");
}

// Get database size
uint64_t size_bytes;
if (db_get_database_size(&size_bytes) == 0) {
    printf("Database size: %lu bytes\n", size_bytes);
}
```

### Cleanup

```c
// Always close database when done
db_close();
```

## Integration with Blockchain Operations

The SQL package is designed to work seamlessly with the existing blockchain infrastructure:

### Automatic Sync
When new blocks are added to the blockchain, they can be automatically synced to the database:

```c
// After adding a block to blockchain
TW_Block* new_block = /* newly created block */;
uint32_t block_index = blockchain->length - 1;

if (db_add_block(new_block, block_index) == 0) {
    printf("Block synced to database\n");
}
```

### Real-time Updates
For real-time applications, individual transactions can be added as they're processed:

```c
// After processing a new transaction
TW_Transaction* new_tx = /* newly created transaction */;
uint32_t block_index = current_block_index;
uint32_t tx_index = current_tx_index;

if (db_add_transaction(new_tx, block_index, tx_index) == 0) {
    printf("Transaction synced to database\n");
}
```

## Performance Considerations

### WAL Mode Benefits
- **Concurrent Access**: Multiple readers can access data while writes occur
- **Better Performance**: Reduced I/O operations and faster commits
- **Crash Safety**: Better recovery characteristics than rollback journal

### Indexing Strategy
The package creates strategic indexes for common query patterns:
- Sender-based queries (user activity)
- Recipient-based queries (inbox functionality)
- Type-based queries (filtering by transaction type)
- Temporal queries (time-range filtering)
- Block-based queries (blockchain exploration)

### Memory Management
- All query results must be freed using provided cleanup functions
- The package handles internal memory management automatically
- WAL checkpointing helps manage disk space usage

## Error Handling

All functions return integer status codes:
- `0`: Success
- `-1`: Error (check logs for details)

The package provides detailed error logging to help with debugging and monitoring.

## Thread Safety

The SQL package is designed to be thread-safe when used with WAL mode:
- Multiple threads can read simultaneously
- Only one thread should write at a time
- Database connection is managed globally

## Future Enhancements

Planned improvements include:
- Connection pooling for multi-threaded applications
- Advanced caching strategies
- Full-text search capabilities
- Blockchain analytics and reporting
- Data export/import functionality

## Dependencies

- SQLite3 development libraries (`libsqlite3-dev`)
- Existing CTinyWeb blockchain structures
- Standard C libraries

## Files

- `database.h/c`: Core database operations and connection management
- `schema.h/c`: Database schema definition and migration
- `queries.h/c`: High-level query interface and convenience functions
- `README.md`: This documentation file 