#ifndef SCHEMA_H
#define SCHEMA_H

// Database schema version
#define CURRENT_SCHEMA_VERSION 1

// SQL statements for creating tables
extern const char* SQL_CREATE_BLOCKCHAIN_INFO;
extern const char* SQL_CREATE_BLOCKS;
extern const char* SQL_CREATE_TRANSACTIONS;
extern const char* SQL_CREATE_TRANSACTION_RECIPIENTS;

// SQL statements for creating indexes
extern const char* SQL_CREATE_INDEX_TRANSACTIONS_SENDER;
extern const char* SQL_CREATE_INDEX_TRANSACTIONS_TYPE;
extern const char* SQL_CREATE_INDEX_TRANSACTIONS_TIMESTAMP;
extern const char* SQL_CREATE_INDEX_TRANSACTIONS_BLOCK;
extern const char* SQL_CREATE_INDEX_RECIPIENTS_PUBKEY;
extern const char* SQL_CREATE_INDEX_TRANSACTIONS_GROUP_ID;

// SQL statements for common queries
extern const char* SQL_INSERT_BLOCKCHAIN_INFO;
extern const char* SQL_UPDATE_BLOCKCHAIN_INFO;
extern const char* SQL_INSERT_BLOCK;
extern const char* SQL_INSERT_TRANSACTION;
extern const char* SQL_INSERT_RECIPIENT;

extern const char* SQL_SELECT_TRANSACTION_COUNT;
extern const char* SQL_SELECT_BLOCK_COUNT;
extern const char* SQL_SELECT_BLOCK_COUNT_WITH_TRANSACTIONS;
extern const char* SQL_SELECT_TRANSACTIONS_BY_SENDER;
extern const char* SQL_SELECT_TRANSACTIONS_BY_RECIPIENT;
extern const char* SQL_SELECT_TRANSACTIONS_BY_TYPE;
extern const char* SQL_SELECT_TRANSACTIONS_BY_BLOCK;
extern const char* SQL_SELECT_RECENT_TRANSACTIONS;
extern const char* SQL_SELECT_BLOCK_INFO;

extern const char* SQL_UPDATE_CACHED_CONTENT;
extern const char* SQL_SELECT_CACHED_CONTENT;

// Schema management functions
int schema_create_all_tables(sqlite3* db);
int schema_create_all_indexes(sqlite3* db);
int schema_check_version(sqlite3* db, int* version);
int schema_set_version(sqlite3* db, int version);
int schema_migrate(sqlite3* db, int from_version, int to_version);

#endif // SCHEMA_H 