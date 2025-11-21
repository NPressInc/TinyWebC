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
#include "packages/sql/gossip_store.h"

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
        fprintf(stderr, "Failed to create directory %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int ensure_sodium_ready(void) {
    static int initialized = 0;
    if (!initialized) {
        if (sodium_init() < 0) {
            fprintf(stderr, "Failed to initialize libsodium\n");
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

// Build path: {base_path}/database/gossip.db
static int build_db_path(const char* base_path, char* out_path, size_t path_len) {
    if (!base_path || !out_path || path_len == 0) {
        return -1;
    }
    int ret = snprintf(out_path, path_len, "%s/database/gossip.db", base_path);
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
        fprintf(stderr, "Warning: key file %s corrupted, regenerating.\n", key_path);
    }

    // Generate new keypair
    if (crypto_sign_keypair(pub, secret) != 0) {
        fprintf(stderr, "Failed to generate keypair for user %s\n", user_id);
        return -1;
    }

    // Save secret key
    f = fopen(key_path, "wb");
    if (!f) {
        fprintf(stderr, "Failed to write key file %s\n", key_path);
        return -1;
    }
    if (fwrite(secret, 1, sizeof(secret), f) != sizeof(secret)) {
        fclose(f);
        fprintf(stderr, "Failed to store key file %s\n", key_path);
        return -1;
    }
    fclose(f);

    memcpy(out_pubkey, pub, PUBKEY_SIZE);
    return 0;
}

// ============================================================================
// Database Seeding
// ============================================================================

static int seed_basic_roles(sqlite3* db) {
    if (!db) {
        return -1;
    }

    const char* sql = "INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)";
    sqlite3_stmt* stmt = NULL;
    
    // Admin role
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQLite error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, "admin", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, "Administrative role with full privileges", -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // Member role
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQLite error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, "member", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, "Standard member", -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return 0;
}

static int seed_basic_permissions(sqlite3* db) {
    if (!db) {
        return -1;
    }

    const char* sql = 
        "INSERT OR IGNORE INTO permissions (name, permission_flags, scope_flags, "
        "condition_flags, category, description) VALUES (?, ?, ?, ?, ?, ?)";
    
    sqlite3_stmt* stmt = NULL;

    // send_message permission
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQLite error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, "send_message", -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, 1);  // Basic flag
    sqlite3_bind_int(stmt, 3, 1);    // Basic scope
    sqlite3_bind_int64(stmt, 4, 0);  // No conditions
    sqlite3_bind_int(stmt, 5, 1);    // Category: messaging
    sqlite3_bind_text(stmt, 6, "Send messages to other users", -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // manage_users permission
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQLite error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, "manage_users", -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, 2);  // Admin flag
    sqlite3_bind_int(stmt, 3, 2);    // Network scope
    sqlite3_bind_int64(stmt, 4, 0);
    sqlite3_bind_int(stmt, 5, 2);    // Category: admin
    sqlite3_bind_text(stmt, 6, "Manage user accounts", -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    // manage_network permission
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "SQLite error: %s\n", sqlite3_errmsg(db));
        return -1;
    }
    sqlite3_bind_text(stmt, 1, "manage_network", -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, 4);  // Admin flag
    sqlite3_bind_int(stmt, 3, 4);    // System scope
    sqlite3_bind_int64(stmt, 4, 0);
    sqlite3_bind_int(stmt, 5, 2);    // Category: admin
    sqlite3_bind_text(stmt, 6, "Manage network configuration", -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return 0;
}

static int seed_role_permissions(sqlite3* db) {
    if (!db) {
        return -1;
    }

    const char* get_role_sql = "SELECT id FROM roles WHERE name = ?";
    const char* get_perm_sql = "SELECT id FROM permissions WHERE name = ?";
    const char* map_sql = 
        "INSERT OR IGNORE INTO role_permissions (role_id, permission_id, "
        "granted_by_user_id, grant_transaction_id, time_start, time_end, is_active) "
        "VALUES (?, ?, NULL, NULL, 0, 0, 1)";
    
    sqlite3_stmt* stmt = NULL;
    int admin_role_id = -1;
    int member_role_id = -1;
    int send_msg_perm_id = -1;
    int manage_users_perm_id = -1;
    int manage_network_perm_id = -1;

    // Get role IDs
    if (sqlite3_prepare_v2(db, get_role_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, "admin", -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            admin_role_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    
    if (sqlite3_prepare_v2(db, get_role_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, "member", -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            member_role_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    // Get permission IDs
    if (sqlite3_prepare_v2(db, get_perm_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, "send_message", -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            send_msg_perm_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    
    if (sqlite3_prepare_v2(db, get_perm_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, "manage_users", -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            manage_users_perm_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    
    if (sqlite3_prepare_v2(db, get_perm_sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, "manage_network", -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            manage_network_perm_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }

    // Map admin role to all permissions
    if (admin_role_id > 0) {
        if (send_msg_perm_id > 0 && sqlite3_prepare_v2(db, map_sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, admin_role_id);
            sqlite3_bind_int(stmt, 2, send_msg_perm_id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        if (manage_users_perm_id > 0 && sqlite3_prepare_v2(db, map_sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, admin_role_id);
            sqlite3_bind_int(stmt, 2, manage_users_perm_id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
        if (manage_network_perm_id > 0 && sqlite3_prepare_v2(db, map_sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, admin_role_id);
            sqlite3_bind_int(stmt, 2, manage_network_perm_id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }

    // Map member role to send_message only
    if (member_role_id > 0 && send_msg_perm_id > 0) {
        if (sqlite3_prepare_v2(db, map_sql, -1, &stmt, NULL) == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, member_role_id);
            sqlite3_bind_int(stmt, 2, send_msg_perm_id);
            sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
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

        // Generate keypair
        unsigned char pubkey[PUBKEY_SIZE];
        if (generate_user_keypair(user->id, base_path, pubkey) != 0) {
            fprintf(stderr, "Failed to generate key for user %s\n", user->id);
            return -1;
        }

        // Convert to hex
        char pubkey_hex[PUBKEY_SIZE * 2 + 1];
        hex_encode(pubkey, PUBKEY_SIZE, pubkey_hex, sizeof(pubkey_hex));

        // Insert user
        if (sqlite3_prepare_v2(db, insert_user_sql, -1, &stmt, NULL) != SQLITE_OK) {
            fprintf(stderr, "SQLite error: %s\n", sqlite3_errmsg(db));
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
            fprintf(stderr, "Failed to retrieve user_id for %s\n", user->id);
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
            fprintf(stderr, "Failed to retrieve role_id for role %s\n", role_name);
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
            if (gossip_peers_add_or_update(host, port, 0, NULL) != 0) {
                fprintf(stderr, "Warning: failed to add peer %s\n", endpoint);
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
        fprintf(stderr, "Invalid arguments to initialize_node\n");
        return -1;
    }

    // Build paths
    char db_dir[PATH_MAX];
    char db_path[PATH_MAX];
    snprintf(db_dir, sizeof(db_dir), "%s/database", base_path);
    if (build_db_path(base_path, db_path, sizeof(db_path)) != 0) {
        fprintf(stderr, "Failed to build database path\n");
        return -1;
    }

    // Create directories
    char base_dir[PATH_MAX];
    snprintf(base_dir, sizeof(base_dir), "%s", base_path);
    if (ensure_directory(base_dir) != 0 || ensure_directory(db_dir) != 0) {
        fprintf(stderr, "Failed to create directories for %s\n", base_path);
        return -1;
    }

    // Initialize database
    if (db_init_gossip(db_path) != 0) {
        fprintf(stderr, "Failed to initialize gossip database at %s\n", db_path);
        return -1;
    }

    if (gossip_store_init() != 0) {
        fprintf(stderr, "Failed to initialize gossip store schema\n");
        db_close();
        return -1;
    }

    if (gossip_peers_init() != 0) {
        fprintf(stderr, "Failed to initialize gossip peers schema\n");
        db_close();
        return -1;
    }

    sqlite3* db = db_get_handle();
    if (!db) {
        fprintf(stderr, "Failed to get database handle\n");
        return -1;
    }

    // Seed database
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

    if (users && user_count > 0) {
        if (seed_users(db, users, user_count, base_path) != 0) {
            fprintf(stderr, "Failed to seed users\n");
            db_close();
            return -1;
        }
    }

    if (node->peers && node->peer_count > 0) {
        if (seed_peers(db, (const char**)node->peers, node->peer_count) != 0) {
            fprintf(stderr, "Failed to seed peers\n");
            db_close();
            return -1;
        }
    }

    db_close();
    printf("Initialized node '%s' in %s\n", node->name ? node->name : node->id, base_path);
    return 0;
}

int initialize_network(const InitNetworkConfig* config, const char* base_path) {
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

    // Initialize each node
    for (uint32_t i = 0; i < config->node_count; ++i) {
        if (initialize_node(&config->nodes[i], config->users, config->user_count, base_path) != 0) {
            fprintf(stderr, "Failed to initialize node %u\n", i);
            return -1;
        }
    }

    printf("Network initialization complete. %u node(s), %u user(s) configured.\n",
           config->node_count, config->user_count);
    return 0;
}
