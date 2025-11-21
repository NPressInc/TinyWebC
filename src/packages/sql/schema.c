#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include "schema.h"

// SQL statements for creating tables
// User, Role, and Permission tables
const char* SQL_CREATE_USERS = 
    "CREATE TABLE IF NOT EXISTS users ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    pubkey TEXT NOT NULL UNIQUE,"
    "    username TEXT NOT NULL,"
    "    age INTEGER,"
    "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    is_active BOOLEAN DEFAULT TRUE"
    ");";

const char* SQL_CREATE_ROLES = 
    "CREATE TABLE IF NOT EXISTS roles ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    name TEXT NOT NULL UNIQUE,"
    "    description TEXT,"
    "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
    ");";

const char* SQL_CREATE_PERMISSIONS = 
    "CREATE TABLE IF NOT EXISTS permissions ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    name TEXT NOT NULL UNIQUE,"
    "    permission_flags INTEGER NOT NULL,"
    "    scope_flags INTEGER NOT NULL,"
    "    condition_flags INTEGER NOT NULL,"
    "    category INTEGER NOT NULL,"
    "    description TEXT,"
    "    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
    ");";

const char* SQL_CREATE_USER_ROLES = 
    "CREATE TABLE IF NOT EXISTS user_roles ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    user_id INTEGER NOT NULL,"
    "    role_id INTEGER NOT NULL,"
    "    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    assigned_by_user_id INTEGER,"
    "    is_active BOOLEAN DEFAULT TRUE,"
    "    FOREIGN KEY (user_id) REFERENCES users(id),"
    "    FOREIGN KEY (role_id) REFERENCES roles(id),"
    "    FOREIGN KEY (assigned_by_user_id) REFERENCES users(id),"
    "    UNIQUE(user_id, role_id)"
    ");";

const char* SQL_CREATE_ROLE_PERMISSIONS = 
    "CREATE TABLE IF NOT EXISTS role_permissions ("
    "    id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "    role_id INTEGER NOT NULL,"
    "    permission_id INTEGER NOT NULL,"
    "    granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
    "    granted_by_user_id INTEGER,"
    "    scope_flags INTEGER NOT NULL DEFAULT 0,"
    "    condition_flags INTEGER NOT NULL DEFAULT 0,"
    "    time_start INTEGER,"
    "    time_end INTEGER,"
    "    is_active BOOLEAN DEFAULT TRUE,"
    "    FOREIGN KEY (role_id) REFERENCES roles(id),"
    "    FOREIGN KEY (permission_id) REFERENCES permissions(id),"
    "    FOREIGN KEY (granted_by_user_id) REFERENCES users(id),"
    "    UNIQUE(role_id, permission_id)"
    ");";

// SQL statements for creating indexes
// User, Role, and Permission indexes
const char* SQL_CREATE_INDEX_USERS_PUBKEY = 
    "CREATE INDEX IF NOT EXISTS idx_users_pubkey ON users(pubkey);";

const char* SQL_CREATE_INDEX_USERS_USERNAME = 
    "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);";

const char* SQL_CREATE_INDEX_ROLES_NAME = 
    "CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);";

const char* SQL_CREATE_INDEX_USER_ROLES_USER = 
    "CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);";

const char* SQL_CREATE_INDEX_USER_ROLES_ROLE = 
    "CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);";

const char* SQL_CREATE_INDEX_ROLE_PERMISSIONS_ROLE = 
    "CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);";

// User, Role, and Permission management queries
const char* SQL_INSERT_USER = 
    "INSERT OR REPLACE INTO users (pubkey, username, age, updated_at) "
    "VALUES (?, ?, ?, CURRENT_TIMESTAMP);";

const char* SQL_UPDATE_USER = 
    "UPDATE users SET username = ?, age = ?, updated_at = CURRENT_TIMESTAMP WHERE pubkey = ?;";

const char* SQL_SELECT_USER_BY_PUBKEY = 
    "SELECT id, pubkey, username, age, created_at, updated_at, is_active "
    "FROM users WHERE pubkey = ?;";

const char* SQL_SELECT_USER_BY_USERNAME = 
    "SELECT id, pubkey, username, age, created_at, updated_at, is_active "
    "FROM users WHERE username = ?;";

const char* SQL_SELECT_ALL_USERS = 
    "SELECT id, pubkey, username, age, created_at, updated_at, is_active "
    "FROM users WHERE is_active = 1 ORDER BY username;";

const char* SQL_DELETE_USER = 
    "UPDATE users SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE pubkey = ?;";

const char* SQL_INSERT_ROLE = 
    "INSERT OR REPLACE INTO roles (name, description, updated_at) "
    "VALUES (?, ?, CURRENT_TIMESTAMP);";

const char* SQL_UPDATE_ROLE = 
    "UPDATE roles SET description = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?;";

const char* SQL_SELECT_ROLE_BY_NAME = 
    "SELECT id, name, description, created_at, updated_at "
    "FROM roles WHERE name = ?;";

const char* SQL_SELECT_ALL_ROLES = 
    "SELECT id, name, description, created_at, updated_at "
    "FROM roles ORDER BY name;";

const char* SQL_DELETE_ROLE = 
    "DELETE FROM roles WHERE name = ?;";

const char* SQL_INSERT_PERMISSION = 
    "INSERT OR REPLACE INTO permissions (name, permission_flags, scope_flags, condition_flags, category, description, updated_at) "
    "VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP);";

const char* SQL_UPDATE_PERMISSION = 
    "UPDATE permissions SET permission_flags = ?, scope_flags = ?, condition_flags = ?, category = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE name = ?;";

const char* SQL_SELECT_PERMISSION_BY_NAME = 
    "SELECT id, name, permission_flags, scope_flags, condition_flags, category, description, created_at, updated_at "
    "FROM permissions WHERE name = ?;";

const char* SQL_SELECT_ALL_PERMISSIONS = 
    "SELECT id, name, permission_flags, scope_flags, condition_flags, category, description, created_at, updated_at "
    "FROM permissions ORDER BY name;";

const char* SQL_DELETE_PERMISSION = 
    "DELETE FROM permissions WHERE name = ?;";

const char* SQL_INSERT_USER_ROLE = 
    "INSERT OR REPLACE INTO user_roles (user_id, role_id, assigned_by_user_id) "
    "VALUES (?, ?, ?);";

const char* SQL_DELETE_USER_ROLE = 
    "UPDATE user_roles SET is_active = 0 WHERE user_id = ? AND role_id = ?;";

const char* SQL_SELECT_USER_ROLES = 
    "SELECT ur.id, ur.user_id, ur.role_id, ur.assigned_at, ur.assigned_by_user_id, r.name as role_name "
    "FROM user_roles ur "
    "JOIN roles r ON ur.role_id = r.id "
    "WHERE ur.user_id = ? AND ur.is_active = 1;";

const char* SQL_SELECT_ROLE_USERS = 
    "SELECT ur.id, ur.user_id, ur.role_id, ur.assigned_at, ur.assigned_by_user_id, u.username, u.pubkey "
    "FROM user_roles ur "
    "JOIN users u ON ur.user_id = u.id "
    "WHERE ur.role_id = ? AND ur.is_active = 1 AND u.is_active = 1;";

const char* SQL_INSERT_ROLE_PERMISSION = 
    "INSERT OR REPLACE INTO role_permissions (role_id, permission_id, granted_by_user_id, scope_flags, condition_flags, time_start, time_end) "
    "VALUES (?, ?, ?, ?, ?, ?, ?);";

const char* SQL_DELETE_ROLE_PERMISSION = 
    "UPDATE role_permissions SET is_active = 0 WHERE role_id = ? AND permission_id = ?;";

const char* SQL_SELECT_ROLE_PERMISSIONS = 
    "SELECT rp.id, rp.role_id, rp.permission_id, rp.granted_at, rp.granted_by_user_id, "
    "rp.scope_flags, rp.condition_flags, rp.time_start, rp.time_end, "
    "p.name as permission_name, p.permission_flags, p.category "
    "FROM role_permissions rp "
    "JOIN permissions p ON rp.permission_id = p.id "
    "WHERE rp.role_id = ? AND rp.is_active = 1;";

const char* SQL_SELECT_PERMISSION_ROLES = 
    "SELECT rp.id, rp.role_id, rp.permission_id, rp.granted_at, rp.granted_by_user_id, "
    "rp.time_start, rp.time_end, r.name as role_name "
    "FROM role_permissions rp "
    "JOIN roles r ON rp.role_id = r.id "
    "WHERE rp.permission_id = ? AND rp.is_active = 1;";

// Schema management functions
int schema_create_all_tables(sqlite3* db) {
    char* error_msg = NULL;
    int rc;

    // Create tables in dependency order
    const char* table_statements[] = {
        SQL_CREATE_USERS,
        SQL_CREATE_ROLES,
        SQL_CREATE_PERMISSIONS,
        SQL_CREATE_USER_ROLES,
        SQL_CREATE_ROLE_PERMISSIONS,
        NULL
    };

    for (int i = 0; table_statements[i] != NULL; i++) {
        rc = sqlite3_exec(db, table_statements[i], NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            printf("Failed to create table: %s\n", error_msg);
            sqlite3_free(error_msg);
            return -1;
        }
    }

    printf("All database tables created successfully\n");
    return 0;
}

int schema_create_all_indexes(sqlite3* db) {
    char* error_msg = NULL;
    int rc;

    const char* index_statements[] = {
        SQL_CREATE_INDEX_USERS_PUBKEY,
        SQL_CREATE_INDEX_USERS_USERNAME,
        SQL_CREATE_INDEX_ROLES_NAME,
        SQL_CREATE_INDEX_USER_ROLES_USER,
        SQL_CREATE_INDEX_USER_ROLES_ROLE,
        SQL_CREATE_INDEX_ROLE_PERMISSIONS_ROLE,
        NULL
    };

    for (int i = 0; index_statements[i] != NULL; i++) {
        rc = sqlite3_exec(db, index_statements[i], NULL, NULL, &error_msg);
        if (rc != SQLITE_OK) {
            printf("Failed to create index: %s\n", error_msg);
            sqlite3_free(error_msg);
            return -1;
        }
    }

    printf("All database indexes created successfully\n");
    return 0;
}

int schema_check_version(sqlite3* db, int* version) {
    sqlite3_stmt* stmt;
    int rc;

    // Check if schema_version table exists
    const char* check_table_sql = 
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version';";
    
    rc = sqlite3_prepare_v2(db, check_table_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_ROW) {
        // Table doesn't exist, assume version 0
        *version = 0;
        return 0;
    }

    // Get version from table
    const char* get_version_sql = "SELECT version FROM schema_version WHERE id = 1;";
    rc = sqlite3_prepare_v2(db, get_version_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *version = sqlite3_column_int(stmt, 0);
    } else {
        *version = 0;
    }

    sqlite3_finalize(stmt);
    return 0;
}

int schema_set_version(sqlite3* db, int version) {
    char* error_msg = NULL;
    int rc;

    // Create schema_version table if it doesn't exist
    const char* create_version_table = 
        "CREATE TABLE IF NOT EXISTS schema_version ("
        "    id INTEGER PRIMARY KEY,"
        "    version INTEGER NOT NULL,"
        "    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
        ");";

    rc = sqlite3_exec(db, create_version_table, NULL, NULL, &error_msg);
    if (rc != SQLITE_OK) {
        printf("Failed to create schema_version table: %s\n", error_msg);
        sqlite3_free(error_msg);
        return -1;
    }

    // Insert or update version
    const char* set_version_sql = 
        "INSERT OR REPLACE INTO schema_version (id, version, updated_at) "
        "VALUES (1, ?, CURRENT_TIMESTAMP);";

    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db, set_version_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        return -1;
    }

    sqlite3_bind_int(stmt, 1, version);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        return -1;
    }

    printf("Database schema version set to %d\n", version);
    return 0;
}

int schema_migrate(sqlite3* db, int from_version, int to_version) {
    printf("Migrating database schema from version %d to %d\n", from_version, to_version);

    if (from_version == 0 && to_version >= 1) {
        // Initial schema creation with user/role/permission tables
        if (schema_create_all_tables(db) != 0) {
            return -1;
        }
        if (schema_create_all_indexes(db) != 0) {
            return -1;
        }
        if (schema_set_version(db, 1) != 0) {
            return -1;
        }
        return 0;
    }

    // No migration path found
    printf("No migration path from version %d to %d\n", from_version, to_version);
    return -1;
} 