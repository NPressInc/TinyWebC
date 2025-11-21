#ifndef SCHEMA_H
#define SCHEMA_H

#include <sqlite3.h>

// Database schema version
#define CURRENT_SCHEMA_VERSION 1

// SQL statements for creating tables
// User, Role, and Permission tables
extern const char* SQL_CREATE_USERS;
extern const char* SQL_CREATE_ROLES;
extern const char* SQL_CREATE_PERMISSIONS;
extern const char* SQL_CREATE_USER_ROLES;
extern const char* SQL_CREATE_ROLE_PERMISSIONS;

// SQL statements for creating indexes
// User, Role, and Permission indexes
extern const char* SQL_CREATE_INDEX_USERS_PUBKEY;
extern const char* SQL_CREATE_INDEX_USERS_USERNAME;
extern const char* SQL_CREATE_INDEX_ROLES_NAME;
extern const char* SQL_CREATE_INDEX_USER_ROLES_USER;
extern const char* SQL_CREATE_INDEX_USER_ROLES_ROLE;
extern const char* SQL_CREATE_INDEX_ROLE_PERMISSIONS_ROLE;

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