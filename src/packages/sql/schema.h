#ifndef SCHEMA_H
#define SCHEMA_H

// Database schema version
#define CURRENT_SCHEMA_VERSION 2

// SQL statements for creating tables
extern const char* SQL_CREATE_BLOCKCHAIN_INFO;
extern const char* SQL_CREATE_BLOCKS;
extern const char* SQL_CREATE_TRANSACTIONS;
extern const char* SQL_CREATE_TRANSACTION_RECIPIENTS;
extern const char* SQL_CREATE_NODE_STATUS;

// User, Role, and Permission tables
extern const char* SQL_CREATE_USERS;
extern const char* SQL_CREATE_ROLES;
extern const char* SQL_CREATE_PERMISSIONS;
extern const char* SQL_CREATE_USER_ROLES;
extern const char* SQL_CREATE_ROLE_PERMISSIONS;

// SQL statements for creating indexes
extern const char* SQL_CREATE_INDEX_TRANSACTIONS_SENDER;
extern const char* SQL_CREATE_INDEX_TRANSACTIONS_TYPE;
extern const char* SQL_CREATE_INDEX_TRANSACTIONS_TIMESTAMP;
extern const char* SQL_CREATE_INDEX_TRANSACTIONS_BLOCK;
extern const char* SQL_CREATE_INDEX_RECIPIENTS_PUBKEY;
extern const char* SQL_CREATE_INDEX_TRANSACTIONS_GROUP_ID;
extern const char* SQL_CREATE_INDEX_BLOCKS_HASH;

// User, Role, and Permission indexes
extern const char* SQL_CREATE_INDEX_USERS_PUBKEY;
extern const char* SQL_CREATE_INDEX_USERS_USERNAME;
extern const char* SQL_CREATE_INDEX_ROLES_NAME;
extern const char* SQL_CREATE_INDEX_USER_ROLES_USER;
extern const char* SQL_CREATE_INDEX_USER_ROLES_ROLE;
extern const char* SQL_CREATE_INDEX_ROLE_PERMISSIONS_ROLE;

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
extern const char* SQL_SELECT_BLOCK_BY_HASH;
extern const char* SQL_SELECT_RECIPIENTS_BY_TRANSACTION;

extern const char* SQL_UPDATE_CACHED_CONTENT;
extern const char* SQL_SELECT_CACHED_CONTENT;

// Node status management queries
extern const char* SQL_INSERT_NODE_STATUS;
extern const char* SQL_UPDATE_NODE_HEARTBEAT;
extern const char* SQL_SET_NODE_OFFLINE;
extern const char* SQL_SET_STALE_NODES_OFFLINE;
extern const char* SQL_SELECT_ALL_NODES;
extern const char* SQL_SELECT_ONLINE_NODES;
extern const char* SQL_COUNT_TOTAL_NODES;
extern const char* SQL_COUNT_ONLINE_NODES;

// User, Role, and Permission management queries
extern const char* SQL_INSERT_USER;
extern const char* SQL_UPDATE_USER;
extern const char* SQL_SELECT_USER_BY_PUBKEY;
extern const char* SQL_SELECT_USER_BY_USERNAME;
extern const char* SQL_SELECT_ALL_USERS;
extern const char* SQL_DELETE_USER;

extern const char* SQL_INSERT_ROLE;
extern const char* SQL_UPDATE_ROLE;
extern const char* SQL_SELECT_ROLE_BY_NAME;
extern const char* SQL_SELECT_ALL_ROLES;
extern const char* SQL_DELETE_ROLE;

extern const char* SQL_INSERT_PERMISSION;
extern const char* SQL_UPDATE_PERMISSION;
extern const char* SQL_SELECT_PERMISSION_BY_NAME;
extern const char* SQL_SELECT_ALL_PERMISSIONS;
extern const char* SQL_DELETE_PERMISSION;

extern const char* SQL_INSERT_USER_ROLE;
extern const char* SQL_DELETE_USER_ROLE;
extern const char* SQL_SELECT_USER_ROLES;
extern const char* SQL_SELECT_ROLE_USERS;

extern const char* SQL_INSERT_ROLE_PERMISSION;
extern const char* SQL_DELETE_ROLE_PERMISSION;
extern const char* SQL_SELECT_ROLE_PERMISSIONS;
extern const char* SQL_SELECT_PERMISSION_ROLES;

// Schema management functions
int schema_create_all_tables(sqlite3* db);
int schema_create_all_indexes(sqlite3* db);
int schema_check_version(sqlite3* db, int* version);
int schema_set_version(sqlite3* db, int version);
int schema_migrate(sqlite3* db, int from_version, int to_version);

#endif // SCHEMA_H 