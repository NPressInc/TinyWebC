#include "init.h"

#include <errno.h>
#include <limits.h>
#include <sodium.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "packages/sql/database_gossip.h"
#include "packages/sql/gossip_peers.h"
#include "packages/sql/schema.h"
#include "packages/sql/schema.h"
#include "packages/utils/logger.h"
#include "structs/permission/permission.h"

// ============================================================================
// Helper Functions
// ============================================================================

static int ensure_directory(const char* path) {
    if (!path) {
        return -1;
    }
    struct stat st = {0};
    if (stat(path, &st) == 0) {
        return 0;
    }
    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
        logger_error("init", "Failed to create directory %s: %s", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int ensure_sodium_ready(void) {
    static int initialized = 0;
    if (!initialized) {
        if (sodium_init() < 0) {
            logger_error("init", "Failed to initialize libsodium");
            return -1;
        }
        initialized = 1;
    }
    return 0;
}

static void hex_encode(const unsigned char* in, size_t len, char* out, size_t out_len) {
    static const char hex[] = "0123456789abcdef";
    if (!out || out_len < len * 2 + 1) {
        return;
    }
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = hex[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[in[i] & 0xF];
    }
    out[len * 2] = '\0';
}

// Build path: {base_path}/keys/users/
static int build_keys_dir(const char* base_path, char* out_path, size_t path_len) {
    if (!base_path || !out_path || path_len == 0) {
        return -1;
    }
    int ret = snprintf(out_path, path_len, "%s/keys/users", base_path);
    if (ret < 0 || (size_t)ret >= path_len) {
        return -1;
    }
    return 0;
}

// Build path: {base_path}/storage/tinyweb.db
static int build_db_path(const char* base_path, char* out_path, size_t path_len) {
    if (!base_path || !out_path || path_len == 0) {
        return -1;
    }
    int ret = snprintf(out_path, path_len, "%s/storage/tinyweb.db", base_path);
    if (ret < 0 || (size_t)ret >= path_len) {
        return -1;
    }
    return 0;
}

// Build path: {base_path}/keys/users/{user_id}.key
static int build_user_key_path(const char* base_path, const char* user_id, 
                                char* out_path, size_t path_len) {
    if (!base_path || !user_id || !out_path || path_len == 0) {
        return -1;
    }
    int ret = snprintf(out_path, path_len, "%s/keys/users/%s/key.bin", base_path, user_id);
    if (ret < 0 || (size_t)ret >= path_len) {
        return -1;
    }
    return 0;
}

// ============================================================================
// Key Generation
// ============================================================================

int generate_user_keypair(const char* user_id, const char* base_path, 
                          unsigned char* out_pubkey) {
    if (!user_id || !base_path || !out_pubkey) {
        return -1;
    }
    
    if (ensure_sodium_ready() != 0) {
        return -1;
    }

    // Ensure directories exist
    char base_dir[PATH_MAX];
    char keys_dir[PATH_MAX];
    char users_dir[PATH_MAX];
    char user_dir[PATH_MAX];
    
    snprintf(base_dir, sizeof(base_dir), "%s", base_path);
    snprintf(keys_dir, sizeof(keys_dir), "%s/keys", base_path);
    snprintf(users_dir, sizeof(users_dir), "%s/keys/users", base_path);
    snprintf(user_dir, sizeof(user_dir), "%s/keys/users/%s", base_path, user_id);
    
    if (ensure_directory(base_dir) != 0 ||
        ensure_directory(keys_dir) != 0 ||
        ensure_directory(users_dir) != 0 ||
        ensure_directory(user_dir) != 0) {
        return -1;
    }

    char key_path[PATH_MAX];
    if (build_user_key_path(base_path, user_id, key_path, sizeof(key_path)) != 0) {
        return -1;
    }

    unsigned char secret[crypto_sign_SECRETKEYBYTES];
    unsigned char pub[crypto_sign_PUBLICKEYBYTES];

    // Try to load existing key
    FILE* f = fopen(key_path, "rb");
    if (f) {
        size_t read = fread(secret, 1, sizeof(secret), f);
        fclose(f);
        if (read == sizeof(secret) && crypto_sign_ed25519_sk_to_pk(pub, secret) == 0) {
            memcpy(out_pubkey, pub, PUBKEY_SIZE);
            return 0;
        }
        logger_error("init", "Warning: key file %s corrupted, regenerating", key_path);
    }

    // Generate new keypair
    if (crypto_sign_keypair(pub, secret) != 0) {
        logger_error("init", "Failed to generate keypair for user %s", user_id);
        return -1;
    }

    // Save secret key
    f = fopen(key_path, "wb");
    if (!f) {
        logger_error("init", "Failed to write key file %s", key_path);
        return -1;
    }
    if (fwrite(secret, 1, sizeof(secret), f) != sizeof(secret)) {
        fclose(f);
        logger_error("init", "Failed to store key file %s", key_path);
        return -1;
    }
    fclose(f);

    memcpy(out_pubkey, pub, PUBKEY_SIZE);
    return 0;
}

int generate_node_keypair(const char* node_id, const char* base_path, 
                          unsigned char* out_pubkey) {
    if (!node_id || !base_path || !out_pubkey) {
        return -1;
    }
    
    if (ensure_sodium_ready() != 0) {
        return -1;
    }

    // Ensure directories exist
    char base_dir[PATH_MAX];
    char keys_dir[PATH_MAX];
    
    snprintf(base_dir, sizeof(base_dir), "%s", base_path);
    snprintf(keys_dir, sizeof(keys_dir), "%s/keys", base_path);
    
    if (ensure_directory(base_dir) != 0 ||
        ensure_directory(keys_dir) != 0) {
        return -1;
    }

    // Node key path: {base_path}/keys/node_private.key
    char key_path[PATH_MAX];
    snprintf(key_path, sizeof(key_path), "%s/keys/node_private.key", base_path);

    unsigned char secret[crypto_sign_SECRETKEYBYTES];
    unsigned char pub[crypto_sign_PUBLICKEYBYTES];

    // Try to load existing key
    FILE* f = fopen(key_path, "rb");
    if (f) {
        size_t read = fread(secret, 1, sizeof(secret), f);
        fclose(f);
        if (read == sizeof(secret) && crypto_sign_ed25519_sk_to_pk(pub, secret) == 0) {
            memcpy(out_pubkey, pub, PUBKEY_SIZE);
            return 0;
        }
        logger_error("init", "Warning: node key file %s corrupted, regenerating", key_path);
    }

    // Generate new keypair
    if (crypto_sign_keypair(pub, secret) != 0) {
        logger_error("init", "Failed to generate keypair for node %s", node_id);
        return -1;
    }

    // Save secret key
    f = fopen(key_path, "wb");
    if (!f) {
        logger_error("init", "Failed to write node key file %s", key_path);
        return -1;
    }
    if (fwrite(secret, 1, sizeof(secret), f) != sizeof(secret)) {
        fclose(f);
        logger_error("init", "Failed to store node key file %s", key_path);
        return -1;
    }
    fclose(f);

    memcpy(out_pubkey, pub, PUBKEY_SIZE);
    return 0;
}

// ============================================================================
// Database Seeding
// ============================================================================

int seed_basic_roles(sqlite3* db) {
    if (!db) {
        return -1;
    }

    const char* sql = "INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)";
    sqlite3_stmt* stmt = NULL;
    
    // Admin role
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        logger_error("init", "SQLite error: %s", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, "admin", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, "Administrative role with full privileges", -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // Member role
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        logger_error("init", "SQLite error: %s", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, "member", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, "Standard member", -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // Contact role
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        logger_error("init", "SQLite error: %s", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, "contact", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, "Contact/peer role with limited permissions", -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return 0;
}

// Helper function to insert a permission
static int insert_permission(sqlite3* db, const char* name, uint64_t permission_flags, 
                             int category, const char* description) {
    const char* sql = 
        "INSERT OR IGNORE INTO permissions (name, permission_flags, scope_flags, "
        "condition_flags, category, description) VALUES (?, ?, 0, 0, ?, ?)";
    
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        logger_error("init", "SQLite error: %s", sqlite3_errmsg(db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, (int64_t)permission_flags);
    sqlite3_bind_int(stmt, 3, category);
    sqlite3_bind_text(stmt, 4, description, -1, SQLITE_STATIC);
    
    int result = (sqlite3_step(stmt) == SQLITE_DONE) ? 0 : -1;
    sqlite3_finalize(stmt);
    return result;
}

int seed_basic_permissions(sqlite3* db) {
    if (!db) {
        return -1;
    }

    // Communication Permissions (category 1: messaging)
    if (insert_permission(db, "send_message", PERMISSION_SEND_MESSAGE, 1, "Send messages to other users") != 0) return -1;
    if (insert_permission(db, "read_message", PERMISSION_READ_MESSAGE, 1, "Read messages") != 0) return -1;
    if (insert_permission(db, "delete_message", PERMISSION_DELETE_MESSAGE, 1, "Delete messages") != 0) return -1;
    if (insert_permission(db, "edit_message", PERMISSION_EDIT_MESSAGE, 1, "Edit messages") != 0) return -1;
    if (insert_permission(db, "forward_message", PERMISSION_FORWARD_MESSAGE, 1, "Forward messages") != 0) return -1;
    if (insert_permission(db, "send_emergency", PERMISSION_SEND_EMERGENCY, 1, "Send emergency alerts") != 0) return -1;

    // Group Management Permissions (category 2: group management)
    if (insert_permission(db, "create_group", PERMISSION_CREATE_GROUP, 2, "Create groups") != 0) return -1;
    if (insert_permission(db, "delete_group", PERMISSION_DELETE_GROUP, 2, "Delete groups") != 0) return -1;
    if (insert_permission(db, "edit_group", PERMISSION_EDIT_GROUP, 2, "Edit group settings") != 0) return -1;
    if (insert_permission(db, "invite_users", PERMISSION_INVITE_USERS, 2, "Invite users to groups") != 0) return -1;
    if (insert_permission(db, "remove_users", PERMISSION_REMOVE_USERS, 2, "Remove users from groups") != 0) return -1;
    if (insert_permission(db, "approve_members", PERMISSION_APPROVE_MEMBERS, 2, "Approve group membership") != 0) return -1;
    if (insert_permission(db, "moderate_group", PERMISSION_MODERATE_GROUP, 2, "Moderate group content") != 0) return -1;

    // User Management Permissions (category 3: user management)
    if (insert_permission(db, "view_status", PERMISSION_VIEW_STATUS, 3, "View user status/activity") != 0) return -1;
    if (insert_permission(db, "view_location", PERMISSION_VIEW_LOCATION, 3, "View location data") != 0) return -1;
    if (insert_permission(db, "track_location", PERMISSION_TRACK_LOCATION, 3, "Actively track location") != 0) return -1;
    if (insert_permission(db, "manage_contacts", PERMISSION_MANAGE_CONTACTS, 3, "Manage user's contacts") != 0) return -1;
    if (insert_permission(db, "approve_contacts", PERMISSION_APPROVE_CONTACTS, 3, "Approve new contacts") != 0) return -1;
    if (insert_permission(db, "monitor_activity", PERMISSION_MONITOR_ACTIVITY, 3, "Monitor user activity") != 0) return -1;
    if (insert_permission(db, "set_boundaries", PERMISSION_SET_BOUNDARIES, 3, "Set communication boundaries") != 0) return -1;

    // Administrative Permissions (category 4: admin)
    if (insert_permission(db, "set_controls", PERMISSION_SET_CONTROLS, 4, "Set administrative controls") != 0) return -1;
    if (insert_permission(db, "view_controls", PERMISSION_VIEW_CONTROLS, 4, "View administrative controls") != 0) return -1;
    if (insert_permission(db, "set_content_filters", PERMISSION_SET_CONTENT_FILTERS, 4, "Set content filters") != 0) return -1;
    if (insert_permission(db, "view_content_filters", PERMISSION_VIEW_CONTENT_FILTERS, 4, "View content filters") != 0) return -1;
    if (insert_permission(db, "manage_roles", PERMISSION_MANAGE_ROLES, 4, "Manage user roles") != 0) return -1;
    if (insert_permission(db, "view_logs", PERMISSION_VIEW_LOGS, 4, "View system logs") != 0) return -1;
    if (insert_permission(db, "manage_settings", PERMISSION_MANAGE_SETTINGS, 4, "Manage system settings") != 0) return -1;
    if (insert_permission(db, "view_settings", PERMISSION_VIEW_SETTINGS, 4, "View system settings") != 0) return -1;

    return 0;
}

// Helper to get role ID by name
static int get_role_id(sqlite3* db, const char* role_name) {
    const char* sql = "SELECT id FROM roles WHERE name = ?";
    sqlite3_stmt* stmt = NULL;
    int role_id = -1;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, role_name, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            role_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    return role_id;
}

// Helper to get permission ID by permission flag
static int get_permission_id_by_flag(sqlite3* db, uint64_t permission_flag) {
    const char* sql = "SELECT id FROM permissions WHERE permission_flags = ?";
    sqlite3_stmt* stmt = NULL;
    int perm_id = -1;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_int64(stmt, 1, (int64_t)permission_flag);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            perm_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    } else {
        logger_error("init", "get_permission_id_by_flag: SQL error: %s", sqlite3_errmsg(db));
    }
    
    if (perm_id < 0) {
        logger_error("init", "get_permission_id_by_flag: No permission found for flag 0x%llx", 
                (unsigned long long)permission_flag);
    }
    
    return perm_id;
}

// Helper to map a PermissionSet to a role
static int map_permission_set_to_role(sqlite3* db, int role_id, const PermissionSet* perm_set) {
    if (!db || role_id < 0 || !perm_set) return -1;
    
    const char* sql = SQL_INSERT_ROLE_PERMISSION;
    sqlite3_stmt* stmt = NULL;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        logger_error("init", "SQLite error: %s", sqlite3_errmsg(db));
        return -1;
    }
    
    // Iterate through all permission flags in the PermissionSet
    uint64_t remaining_perms = perm_set->permissions;
    uint64_t flag = 1ULL;
    int inserted_count = 0;
    
    while (remaining_perms > 0 && flag <= PERMISSION_VIEW_SETTINGS) {
        if (remaining_perms & flag) {
            // Get permission ID for this flag
            int perm_id = get_permission_id_by_flag(db, flag);
            if (perm_id > 0) {
                // Reset statement for reuse
                sqlite3_reset(stmt);
                sqlite3_bind_int(stmt, 1, role_id);
                sqlite3_bind_int(stmt, 2, perm_id);
                sqlite3_bind_null(stmt, 3); // granted_by_user_id
                sqlite3_bind_int(stmt, 4, (int)perm_set->scopes); // scope_flags
                sqlite3_bind_int64(stmt, 5, (int64_t)perm_set->conditions); // condition_flags
                sqlite3_bind_int64(stmt, 6, (int64_t)perm_set->time_start);
                sqlite3_bind_int64(stmt, 7, (int64_t)perm_set->time_end);
                
                if (sqlite3_step(stmt) != SQLITE_DONE) {
                    logger_error("init", "Failed to insert role_permission: %s", sqlite3_errmsg(db));
                    sqlite3_finalize(stmt);
                    return -1;
                }
                inserted_count++;
            } else {
                logger_error("init", "Warning: Permission flag 0x%llx not found in database", 
                        (unsigned long long)flag);
            }
            remaining_perms &= ~flag;
        }
        flag <<= 1;
    }
    
    sqlite3_finalize(stmt);
    return 0;
}

int seed_role_permissions(sqlite3* db) {
    if (!db) {
        return -1;
    }

    // Get role IDs
    int admin_role_id = get_role_id(db, "admin");
    int member_role_id = get_role_id(db, "member");
    int contact_role_id = get_role_id(db, "contact");

    // Map admin role to all its PermissionSets
    if (admin_role_id > 0) {
        if (map_permission_set_to_role(db, admin_role_id, &ADMIN_MESSAGING) != 0) return -1;
        if (map_permission_set_to_role(db, admin_role_id, &ADMIN_GROUP_MANAGEMENT) != 0) return -1;
        if (map_permission_set_to_role(db, admin_role_id, &ADMIN_USER_MANAGEMENT) != 0) return -1;
        if (map_permission_set_to_role(db, admin_role_id, &ADMIN_SYSTEM) != 0) return -1;
        if (map_permission_set_to_role(db, admin_role_id, &ADMIN_BASIC) != 0) return -1;
    }

    // Map member role to its PermissionSets
    if (member_role_id > 0) {
        if (map_permission_set_to_role(db, member_role_id, &MEMBER_MESSAGING) != 0) return -1;
        if (map_permission_set_to_role(db, member_role_id, &MEMBER_BASIC) != 0) return -1;
    }

    // Map contact role to its PermissionSets
    if (contact_role_id > 0) {
        if (map_permission_set_to_role(db, contact_role_id, &CONTACT_MESSAGING) != 0) return -1;
        if (map_permission_set_to_role(db, contact_role_id, &CONTACT_BASIC) != 0) return -1;
    }

    return 0;
}

static int seed_users(sqlite3* db, const InitUserConfig* users, uint32_t user_count, 
                     const char* base_path) {
    if (!db || !users || !base_path) {
        return -1;
    }

    const char* insert_user_sql = 
        "INSERT OR REPLACE INTO users (pubkey, username, age, is_active) VALUES (?, ?, ?, 1)";
    const char* select_user_sql = "SELECT id FROM users WHERE pubkey = ?";
    const char* select_role_sql = "SELECT id FROM roles WHERE name = ?";
    const char* insert_user_role_sql = 
        "INSERT OR REPLACE INTO user_roles (user_id, role_id, assigned_by_user_id, "
        "assignment_transaction_id, is_active) VALUES (?, ?, NULL, NULL, 1)";
    
    sqlite3_stmt* stmt = NULL;

    for (uint32_t i = 0; i < user_count; ++i) {
        const InitUserConfig* user = &users[i];
        if (!user->id) {
            continue;
        }

        // Show progress before key generation
        printf("    Generating keypair for user %s (%u/%u)...", 
               user->id, i + 1, user_count);
        fflush(stdout);  // Force immediate output

        // Generate keypair
        unsigned char pubkey[PUBKEY_SIZE];
        if (generate_user_keypair(user->id, base_path, pubkey) != 0) {
            printf(" FAILED\n");
            logger_error("init", "Failed to generate key for user %s", user->id);
            return -1;
        }
        
        printf(" done\n");  // Key generation complete
        fflush(stdout);

        // Convert to hex
        char pubkey_hex[PUBKEY_SIZE * 2 + 1];
        hex_encode(pubkey, PUBKEY_SIZE, pubkey_hex, sizeof(pubkey_hex));

        // Insert user
        if (sqlite3_prepare_v2(db, insert_user_sql, -1, &stmt, NULL) != SQLITE_OK) {
            logger_error("init", "SQLite error: %s", sqlite3_errmsg(db));
            return -1;
        }
        sqlite3_bind_text(stmt, 1, pubkey_hex, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, user->name ? user->name : user->id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 3, (int)user->age);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        // Get user ID
        int user_id = -1;
        if (sqlite3_prepare_v2(db, select_user_sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, pubkey_hex, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                user_id = sqlite3_column_int(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }

        if (user_id < 0) {
            logger_error("init", "Failed to retrieve user_id for %s", user->id);
            return -1;
        }

        // Get role ID
        const char* role_name = user->role ? user->role : "member";
        int role_id = -1;
        if (sqlite3_prepare_v2(db, select_role_sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, role_name, -1, SQLITE_STATIC);
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                role_id = sqlite3_column_int(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }

        if (role_id < 0) {
            logger_error("init", "Failed to retrieve role_id for role %s", role_name);
            return -1;
        }

        // Assign role to user
        if (sqlite3_prepare_v2(db, insert_user_role_sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, user_id);
            sqlite3_bind_int(stmt, 2, role_id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    return 0;
}

static int seed_peers(sqlite3* db, const char** peers, uint32_t peer_count) {
    if (!db || !peers) {
        return 0;  // No peers is okay
    }

    for (uint32_t i = 0; i < peer_count; ++i) {
        const char* endpoint = peers[i];
        if (!endpoint || endpoint[0] == '\0') {
            continue;
        }

        // Parse host:port
        char host[256];
        uint16_t port = 9000;  // Default gossip port
        
        const char* colon = strrchr(endpoint, ':');
        if (colon && strchr(colon + 1, ':') == NULL) {
            size_t host_len = (size_t)(colon - endpoint);
            if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
            memcpy(host, endpoint, host_len);
            host[host_len] = '\0';
            port = (uint16_t)atoi(colon + 1);
        } else {
            strncpy(host, endpoint, sizeof(host) - 1);
            host[sizeof(host) - 1] = '\0';
        }

        if (host[0] != '\0') {
            if (gossip_peers_add_or_update(host, port, 0, NULL, NULL) != 0) {
                logger_error("init", "Warning: failed to add peer %s", endpoint);
            }
        }
    }

    return 0;
}

// ============================================================================
// Node and Network Initialization
// ============================================================================

int initialize_node(const InitNodeConfig* node, const InitUserConfig* users, 
                   uint32_t user_count, const char* base_path) {
    if (!node || !base_path) {
        logger_error("init", "Invalid arguments to initialize_node");
        return -1;
    }

    // Build paths
    char db_dir[PATH_MAX];
    char db_path[PATH_MAX];
    snprintf(db_dir, sizeof(db_dir), "%s/storage", base_path);
    if (build_db_path(base_path, db_path, sizeof(db_path)) != 0) {
        logger_error("init", "Failed to build database path");
        return -1;
    }

    // Create directories
    char base_dir[PATH_MAX];
    snprintf(base_dir, sizeof(base_dir), "%s", base_path);
    if (ensure_directory(base_dir) != 0 || ensure_directory(db_dir) != 0) {
        logger_error("init", "Failed to create directories for %s", base_path);
        return -1;
    }

    // Initialize database
    printf("  Initializing database...\n");
    fflush(stdout);
    if (db_init_gossip(db_path) != 0) {
        logger_error("init", "Failed to initialize gossip database at %s", db_path);
        return -1;
    }

    if (gossip_store_init() != 0) {
        logger_error("init", "Failed to initialize gossip store schema");
        db_close();
        return -1;
    }

    if (gossip_peers_init() != 0) {
        logger_error("init", "Failed to initialize gossip peers schema");
        db_close();
        return -1;
    }
    printf("  ✓ Database initialized\n");
    fflush(stdout);

    sqlite3* db = db_get_handle();
    if (!db) {
        logger_error("init", "Failed to get database handle");
        return -1;
    }

    // Note: gossip_store_init() already creates all user/role/permission tables and indexes
    // No need to call schema_create_all_tables() or schema_create_all_indexes() anymore
    // (Those functions were in the old schema.c which has been replaced)

    // Seed database
    printf("  Seeding roles and permissions...\n");
    fflush(stdout);
    if (seed_basic_roles(db) != 0) {
        fprintf(stderr, "Failed to seed roles\n");
        db_close();
        return -1;
    }

    if (seed_basic_permissions(db) != 0) {
        fprintf(stderr, "Failed to seed permissions\n");
        db_close();
        return -1;
    }

    if (seed_role_permissions(db) != 0) {
        fprintf(stderr, "Failed to seed role-permission mappings\n");
        db_close();
        return -1;
    }
    printf("  ✓ Roles and permissions seeded\n");
    fflush(stdout);

    if (users && user_count > 0) {
        printf("  Seeding %u user(s)...\n", user_count);
        fflush(stdout);
        if (seed_users(db, users, user_count, base_path) != 0) {
            fprintf(stderr, "Failed to seed users\n");
            db_close();
            return -1;
        }
        printf("  ✓ Users seeded successfully\n");
        fflush(stdout);
    }

    if (node->peers && node->peer_count > 0) {
        if (seed_peers(db, (const char**)node->peers, node->peer_count) != 0) {
            fprintf(stderr, "Failed to seed peers\n");
            db_close();
            return -1;
        }
    }

    // Generate node keypair and store public key in gossip_peers
    printf("  Generating node keypair...\n");
    fflush(stdout);
    unsigned char node_pubkey[PUBKEY_SIZE];
    if (generate_node_keypair(node->id, base_path, node_pubkey) != 0) {
        fprintf(stderr, "Failed to generate node keypair\n");
        db_close();
        return -1;
    }
    printf("  ✓ Node keypair generated\n");
    fflush(stdout);

    // Use node hostname if available, otherwise construct from node ID
    char node_hostname[256];
    if (node->hostname && node->hostname[0] != '\0') {
        snprintf(node_hostname, sizeof(node_hostname), "%s", node->hostname);
    } else {
        // Default hostname format: use node ID as hostname
        snprintf(node_hostname, sizeof(node_hostname), "%s", node->id ? node->id : "unknown");
    }
    
    // Use default ports if not specified
    uint16_t gossip_port = node->gossip_port > 0 ? node->gossip_port : 9000;
    uint16_t api_port = node->api_port > 0 ? node->api_port : 8000;

    // Store node's own public key in gossip_peers (authorized node whitelist)
    if (gossip_peers_add_or_update(node_hostname, gossip_port, api_port, node_pubkey, NULL) != 0) {
        logger_info("init", "Failed to store node public key in gossip_peers (non-fatal)");
    } else {
        logger_info("init", "Stored node public key in gossip_peers for %s", node_hostname);
    }

    // Store node configuration in database
    // Use defaults for discovery parameters (they'll be updated when main.c loads the config)
    const char* discovery_mode = "static";  // Default, will be updated from config at runtime
    const char* hostname_prefix = NULL;      // Will be updated from config at runtime
    const char* dns_domain = NULL;           // Will be updated from config at runtime
    
    if (nodes_insert_or_update(
            node->id ? node->id : "unknown",
            node->name ? node->name : node->id ? node->id : "Unknown Node",
            node_hostname,
            gossip_port,
            api_port,
            discovery_mode,
            hostname_prefix,
            dns_domain) != 0) {
        logger_info("init", "Failed to store node configuration in database (non-fatal)");
        // Non-fatal, continue
    }

    db_close();
    printf("Initialized node '%s' in %s\n", node->name ? node->name : node->id, base_path);
    return 0;
}

int initialize_network(const InitNetworkConfig* config, const char* base_path, const char* original_config_path) {
    if (!config || !base_path) {
        fprintf(stderr, "Invalid arguments to initialize_network\n");
        return -1;
    }

    if (!config->nodes || config->node_count == 0) {
        fprintf(stderr, "Network configuration requires at least one node\n");
        return -1;
    }

    printf("Initializing network '%s' in %s/\n", 
           config->network_name ? config->network_name : "TinyWeb", 
           base_path);

    // First pass: Initialize each node and collect public keys
    unsigned char** node_pubkeys = malloc(sizeof(unsigned char*) * config->node_count);
    char** node_hostnames = malloc(sizeof(char*) * config->node_count);
    uint16_t* node_gossip_ports = malloc(sizeof(uint16_t) * config->node_count);
    uint16_t* node_api_ports = malloc(sizeof(uint16_t) * config->node_count);
    
    if (!node_pubkeys || !node_hostnames || !node_gossip_ports || !node_api_ports) {
        fprintf(stderr, "Failed to allocate memory for node public keys\n");
        free(node_pubkeys);
        free(node_hostnames);
        free(node_gossip_ports);
        free(node_api_ports);
        return -1;
    }

    for (uint32_t i = 0; i < config->node_count; ++i) {
        node_pubkeys[i] = malloc(PUBKEY_SIZE);
        node_hostnames[i] = malloc(256);
        if (!node_pubkeys[i] || !node_hostnames[i]) {
            // Cleanup and return
            for (uint32_t j = 0; j < i; ++j) {
                free(node_pubkeys[j]);
                free(node_hostnames[j]);
            }
            free(node_pubkeys);
            free(node_hostnames);
            free(node_gossip_ports);
            free(node_api_ports);
            return -1;
        }
        
        // Initialize node
        char node_path[PATH_MAX];
        snprintf(node_path, sizeof(node_path), "%s/%s", base_path, config->nodes[i].id);
        if (initialize_node(&config->nodes[i], config->users, config->user_count, node_path) != 0) {
            logger_error("init", "Failed to initialize node %u", i);
            // Cleanup
            for (uint32_t j = 0; j <= i; ++j) {
                free(node_pubkeys[j]);
                free(node_hostnames[j]);
            }
            free(node_pubkeys);
            free(node_hostnames);
            free(node_gossip_ports);
            free(node_api_ports);
            return -1;
        }
        
        // Read the node's public key from its key file
        char key_path[PATH_MAX];
        snprintf(key_path, sizeof(key_path), "%s/keys/node_private.key", node_path);
        FILE* f = fopen(key_path, "rb");
        if (f) {
            unsigned char secret[crypto_sign_SECRETKEYBYTES];
            if (fread(secret, 1, sizeof(secret), f) == sizeof(secret)) {
                crypto_sign_ed25519_sk_to_pk(node_pubkeys[i], secret);
            }
            fclose(f);
        }
        
        // Store node info
        if (config->nodes[i].hostname && config->nodes[i].hostname[0] != '\0') {
            snprintf(node_hostnames[i], 256, "%s", config->nodes[i].hostname);
        } else {
            snprintf(node_hostnames[i], 256, "%s", config->nodes[i].id ? config->nodes[i].id : "unknown");
        }
        node_gossip_ports[i] = config->nodes[i].gossip_port > 0 ? config->nodes[i].gossip_port : 9000;
        node_api_ports[i] = config->nodes[i].api_port > 0 ? config->nodes[i].api_port : 8000;
        
        // Save network config to node's directory
        if (init_save_node_config(original_config_path, config, &config->nodes[i], node_path) != 0) {
            logger_error("init", "Failed to save config for node %s", config->nodes[i].id);
            // Non-fatal, continue
        }
    }

    // Second pass: Store all nodes' public keys in each node's database
    printf("  Storing all node public keys in each node's database...\n");
    fflush(stdout);
    for (uint32_t i = 0; i < config->node_count; ++i) {
        char node_path[PATH_MAX];
        char db_path[PATH_MAX];
        snprintf(node_path, sizeof(node_path), "%s/%s", base_path, config->nodes[i].id);
        snprintf(db_path, sizeof(db_path), "%s/storage/tinyweb.db", node_path);
        
        // Open this node's database
        if (db_init_gossip(db_path) == 0) {
            // Add all nodes' public keys to this node's gossip_peers table
            for (uint32_t j = 0; j < config->node_count; ++j) {
                if (gossip_peers_add_or_update(node_hostnames[j], node_gossip_ports[j], 
                                                node_api_ports[j], node_pubkeys[j], NULL) != 0) {
                    logger_info("init", "Failed to store public key for node %s in node %s's database", 
                               node_hostnames[j], node_hostnames[i]);
                }
            }
            db_close();
        }
    }
    printf("  ✓ All node public keys stored\n");
    fflush(stdout);

    // Cleanup
    for (uint32_t i = 0; i < config->node_count; ++i) {
        free(node_pubkeys[i]);
        free(node_hostnames[i]);
    }
    free(node_pubkeys);
    free(node_hostnames);
    free(node_gossip_ports);
    free(node_api_ports);

    printf("Network initialization complete. %u node(s), %u user(s) configured.\n",
           config->node_count, config->user_count);
    return 0;
}

// Save network config JSON to node's directory
// This saves the complete network_config.json (including all network-level settings)
// to each node's directory so the node can load its config at runtime
int init_save_node_config(const char* original_config_path, const InitNetworkConfig* network_config, const InitNodeConfig* node, const char* node_path) {
    if (!network_config || !node || !node_path) {
        logger_error("init", "Invalid arguments to init_save_node_config");
        return -1;
    }
    
    // Build path: node_path/network_config.json
    char config_path[PATH_MAX];
    snprintf(config_path, sizeof(config_path), "%s/network_config.json", node_path);
    
    // Ensure node directory exists
    if (ensure_directory(node_path) != 0) {
        logger_error("init", "Failed to create node directory: %s", node_path);
        return -1;
    }
    
    // If we have the original config file path, copy it directly (preserves all settings)
    if (original_config_path) {
        FILE* src = fopen(original_config_path, "r");
        if (src) {
            FILE* dst = fopen(config_path, "w");
            if (dst) {
                char buffer[4096];
                size_t bytes;
                while ((bytes = fread(buffer, 1, sizeof(buffer), src)) > 0) {
                    fwrite(buffer, 1, bytes, dst);
                }
                fclose(dst);
                fclose(src);
                logger_info("init", "Saved full network config to %s", config_path);
                return 0;
            }
            fclose(src);
            logger_error("init", "Failed to create config file: %s", config_path);
            return -1;
        }
        // If original file doesn't exist, fall through to reconstruction
        logger_error("init", "Original config file not found: %s, reconstructing", original_config_path);
    }
    
    // Fallback: Reconstruct the full JSON from the parsed structure
    // This ensures all network-level settings are included
    FILE* f = fopen(config_path, "w");
    if (!f) {
        logger_error("init", "Failed to create config file: %s", config_path);
        return -1;
    }
    
    // Write complete network config JSON
    fprintf(f, "{\n");
    
    // Network section
    fprintf(f, "  \"network\": {\n");
    if (network_config->network_name) {
        fprintf(f, "    \"name\": \"%s\",\n", network_config->network_name);
    }
    if (network_config->network_description) {
        fprintf(f, "    \"description\": \"%s\",\n", network_config->network_description);
    }
    
    // Network-level settings with defaults (these should come from the original JSON)
    fprintf(f, "    \"validation\": {\n");
    fprintf(f, "      \"max_clock_skew_seconds\": 300,\n");
    fprintf(f, "      \"message_ttl_seconds\": 2592000,\n");
    fprintf(f, "      \"max_payload_bytes\": 1048576\n");
    fprintf(f, "    },\n");
    
    fprintf(f, "    \"logging\": {\n");
    fprintf(f, "      \"level\": \"INFO\",\n");
    fprintf(f, "      \"to_file\": false,\n");
    fprintf(f, "      \"file_path\": \"logs/tinyweb.log\"\n");
    fprintf(f, "    },\n");
    
    fprintf(f, "    \"network_error_handling\": {\n");
    fprintf(f, "      \"max_retries\": 3,\n");
    fprintf(f, "      \"initial_delay_ms\": 100,\n");
    fprintf(f, "      \"backoff_multiplier\": 2.0,\n");
    fprintf(f, "      \"max_delay_ms\": 5000\n");
    fprintf(f, "    }\n");
    fprintf(f, "  },\n");
    
    // Nodes array (include all nodes so peers can be discovered)
    fprintf(f, "  \"nodes\": [\n");
    for (uint32_t i = 0; i < network_config->node_count; ++i) {
        const InitNodeConfig* n = &network_config->nodes[i];
        fprintf(f, "    {\n");
        if (n->id) fprintf(f, "      \"id\": \"%s\",\n", n->id);
        if (n->name) fprintf(f, "      \"name\": \"%s\",\n", n->name);
        // Note: type field removed from InitNodeConfig (all nodes are equal)
        if (n->hostname) fprintf(f, "      \"hostname\": \"%s\",\n", n->hostname);
        fprintf(f, "      \"gossip_port\": %u,\n", n->gossip_port);
        fprintf(f, "      \"api_port\": %u", n->api_port);
        if (n->peers && n->peer_count > 0) {
            fprintf(f, ",\n      \"peers\": [\n");
            for (uint32_t p = 0; p < n->peer_count; ++p) {
                fprintf(f, "        \"%s\"", n->peers[p]);
                if (p < n->peer_count - 1) fprintf(f, ",");
                fprintf(f, "\n");
            }
            fprintf(f, "      ]");
        }
        if (n->tags) {
            fprintf(f, ",\n      \"tags\": \"%s\"", n->tags);
        }
        fprintf(f, "\n    }");
        if (i < network_config->node_count - 1) fprintf(f, ",");
        fprintf(f, "\n");
    }
    fprintf(f, "  ]\n");
    
    // Users section (optional, but include if present)
    if (network_config->users && network_config->user_count > 0) {
        fprintf(f, ",\n  \"users\": {\n");
        fprintf(f, "    \"admins\": [],\n");
        fprintf(f, "    \"members\": []\n");
        fprintf(f, "  }\n");
    }
    
    fprintf(f, "}\n");
    fclose(f);
    
    logger_info("init", "Reconstructed and saved network config to %s", config_path);
    return 0;
}
