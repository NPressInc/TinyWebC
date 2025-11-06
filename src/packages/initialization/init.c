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
#include "packages/utils/statePaths.h"
#include "structs/permission/permission.h"
#include "features/blockchain/core/transaction_types.h"

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

static int ensure_user_keys_dir(int debug_mode, char* out, size_t out_len) {
    const char* base = debug_mode ? "test_state/keys/users" : "state/keys/users";
    if (out_len < strlen(base) + 1) {
        return -1;
    }
    strcpy(out, base);
    char intermediate[PATH_MAX];
    snprintf(intermediate, sizeof(intermediate), "%s/..", base);
    ensure_directory(debug_mode ? "test_state" : "state");
    ensure_directory(debug_mode ? "test_state/keys" : "state/keys");
    if (ensure_directory(base) != 0) {
        return -1;
    }
    return 0;
}

static int generate_or_load_user_key(int debug_mode, InitUserRecord* user) {
    if (!user || !user->id) {
        return -1;
    }
    if (ensure_sodium_ready() != 0) {
        return -1;
    }

    char keys_dir[PATH_MAX];
    if (ensure_user_keys_dir(debug_mode, keys_dir, sizeof(keys_dir)) != 0) {
        return -1;
    }

    char key_path[PATH_MAX];
    snprintf(key_path, sizeof(key_path), "%s/%s.key", keys_dir, user->id);

    unsigned char secret[crypto_sign_SECRETKEYBYTES];
    unsigned char pub[crypto_sign_PUBLICKEYBYTES];

    FILE* f = fopen(key_path, "rb");
    if (f) {
        size_t read = fread(secret, 1, sizeof(secret), f);
        fclose(f);
        if (read != sizeof(secret)) {
            fprintf(stderr, "Warning: key file %s corrupted, regenerating.\n", key_path);
        } else if (crypto_sign_ed25519_sk_to_pk(pub, secret) == 0) {
            memcpy(user->public_key, pub, PUBKEY_SIZE);
            hex_encode(pub, PUBKEY_SIZE, user->public_key_hex, sizeof(user->public_key_hex));
            user->key_path = strdup(key_path);
            return 0;
        }
    }

    if (crypto_sign_keypair(pub, secret) != 0) {
        fprintf(stderr, "Failed to generate keypair for user %s\n", user->id);
        return -1;
    }

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

    memcpy(user->public_key, pub, PUBKEY_SIZE);
    hex_encode(pub, PUBKEY_SIZE, user->public_key_hex, sizeof(user->public_key_hex));
    user->key_path = strdup(key_path);
    return 0;
}

static int seed_roles_permissions(sqlite3* db) {
    if (!db) {
        return -1;
    }

    const char* insert_role_sql = "INSERT OR IGNORE INTO roles (name, description) VALUES (?, ?)";
    const char* select_role_sql = "SELECT id FROM roles WHERE name = ? LIMIT 1";
    const char* insert_perm_sql =
        "INSERT OR IGNORE INTO permissions (name, permission_flags, scope_flags, condition_flags, category, description) "
        "VALUES (?, ?, ?, ?, ?, ?)";
    const char* select_perm_sql = "SELECT id FROM permissions WHERE name = ? LIMIT 1";
    const char* map_sql =
        "INSERT OR IGNORE INTO role_permissions (role_id, permission_id, granted_by_user_id, grant_transaction_id, time_start, time_end, is_active) "
        "VALUES (?, ?, NULL, NULL, 0, 0, 1)";

    sqlite3_stmt *stmt = NULL;
    int rc;

    typedef struct {
        const char* role_name;
        const char* description;
        const PermissionSet* const* sets;
        size_t set_count;
        const char* permission_bundle_name;
        const char* permission_description;
        int category;
    } RoleSeed;

    const PermissionSet* admin_sets[] = {
        &ADMIN_MESSAGING,
        &ADMIN_GROUP_MANAGEMENT,
        &ADMIN_USER_MANAGEMENT,
        &ADMIN_SYSTEM,
        &ADMIN_BASIC
    };

    const PermissionSet* member_sets[] = {
        &MEMBER_MESSAGING,
        &MEMBER_BASIC
    };

    RoleSeed seeds[] = {
        {
            .role_name = "admin",
            .description = "Administrative role with full privileges",
            .sets = admin_sets,
            .set_count = sizeof(admin_sets) / sizeof(admin_sets[0]),
            .permission_bundle_name = "bundle_admin_all",
            .permission_description = "Aggregated administrative permissions",
            .category = PERM_CATEGORY_ADMIN
        },
        {
            .role_name = "member",
            .description = "Standard family member",
            .sets = member_sets,
            .set_count = sizeof(member_sets) / sizeof(member_sets[0]),
            .permission_bundle_name = "bundle_member_basic",
            .permission_description = "Messaging and basic visibility",
            .category = PERM_CATEGORY_MESSAGING
        }
    };

    for (size_t i = 0; i < sizeof(seeds) / sizeof(seeds[0]); ++i) {
        const RoleSeed* seed = &seeds[i];
        uint64_t perm_flags = 0;
        uint32_t scope_flags = 0;
        uint64_t conditions = 0;
        for (size_t s = 0; s < seed->set_count; ++s) {
            perm_flags |= seed->sets[s]->permissions;
            scope_flags |= seed->sets[s]->scopes;
            conditions |= seed->sets[s]->conditions;
        }

        rc = sqlite3_prepare_v2(db, insert_role_sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQLite error preparing insert_role_sql: %s\n", sqlite3_errmsg(db));
            return -1;
        }
        sqlite3_bind_text(stmt, 1, seed->role_name, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, seed->description, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        int role_id = -1;
        rc = sqlite3_prepare_v2(db, select_role_sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQLite error preparing select_role_sql: %s\n", sqlite3_errmsg(db));
            return -1;
        }
        sqlite3_bind_text(stmt, 1, seed->role_name, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            role_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
        if (role_id < 0) return -1;

        rc = sqlite3_prepare_v2(db, insert_perm_sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQLite error preparing insert_perm_sql: %s\n", sqlite3_errmsg(db));
            return -1;
        }
        sqlite3_bind_text(stmt, 1, seed->permission_bundle_name, -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)perm_flags);
        sqlite3_bind_int(stmt, 3, (int)scope_flags);
        sqlite3_bind_int64(stmt, 4, (sqlite3_int64)conditions);
        sqlite3_bind_int(stmt, 5, seed->category);
        sqlite3_bind_text(stmt, 6, seed->permission_description, -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        int permission_id = -1;
        rc = sqlite3_prepare_v2(db, select_perm_sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQLite error preparing select_perm_sql: %s\n", sqlite3_errmsg(db));
            return -1;
        }
        sqlite3_bind_text(stmt, 1, seed->permission_bundle_name, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            permission_id = sqlite3_column_int(stmt, 0);
        }
        sqlite3_finalize(stmt);
        if (permission_id < 0) return -1;

        rc = sqlite3_prepare_v2(db, map_sql, -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQLite error preparing map_sql: %s\n", sqlite3_errmsg(db));
            return -1;
        }
        sqlite3_bind_int(stmt, 1, role_id);
        sqlite3_bind_int(stmt, 2, permission_id);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }

    return 0;
}

static int seed_transaction_permissions(sqlite3* db) {
    if (!db) {
        return -1;
    }

    const char* sql =
        "INSERT OR REPLACE INTO transaction_permissions (txn_type, required_permission, required_scope) VALUES (?, ?, ?)";
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQLite error preparing transaction_permissions insert: %s\n", sqlite3_errmsg(db));
        return -1;
    }

    for (size_t i = 0; i < sizeof(TXN_PERMISSIONS) / sizeof(TXN_PERMISSIONS[0]); ++i) {
        sqlite3_bind_int(stmt, 1, (int)TXN_PERMISSIONS[i].type);
        sqlite3_bind_int64(stmt, 2, (sqlite3_int64)TXN_PERMISSIONS[i].required_permissions);
        sqlite3_bind_int(stmt, 3, (int)TXN_PERMISSIONS[i].required_scope);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }

    sqlite3_finalize(stmt);
    return 0;
}

static int get_role_id(sqlite3* db, const char* role_name, int* out_id) {
    const char* sql = "SELECT id FROM roles WHERE name = ? LIMIT 1";
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, role_name, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *out_id = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return 0;
    }
    sqlite3_finalize(stmt);
    return -1;
}

static int seed_single_user(sqlite3* db, const InitUserRecord* user) {
    const char* insert_user_sql =
        "INSERT OR REPLACE INTO users (pubkey, username, age, is_active) VALUES (?, ?, ?, 1)";
    const char* select_user_sql = "SELECT id FROM users WHERE pubkey = ? LIMIT 1";
    const char* insert_user_role_sql =
        "INSERT OR REPLACE INTO user_roles (user_id, role_id, assigned_by_user_id, assignment_transaction_id, is_active) "
        "VALUES (?, ?, NULL, NULL, 1)";

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(db, insert_user_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, user->public_key_hex, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, user->name ? user->name : user->id, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, (int)user->age);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    int user_id = -1;
    rc = sqlite3_prepare_v2(db, select_user_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, user->public_key_hex, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user_id = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    if (user_id < 0) return -1;

    int role_id = -1;
    if (get_role_id(db, user->role ? user->role : "member", &role_id) != 0) {
        return -1;
    }

    rc = sqlite3_prepare_v2(db, insert_user_role_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_int(stmt, 1, user_id);
    sqlite3_bind_int(stmt, 2, role_id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    return 0;
}

static int seed_users(sqlite3* db, const InitNetworkConfig* config) {
    if (!db || !config) {
        return -1;
    }
    for (uint32_t i = 0; i < config->users.admin_count; ++i) {
        if (seed_single_user(db, &config->users.admins[i]) != 0) {
            return -1;
        }
    }
    for (uint32_t i = 0; i < config->users.member_count; ++i) {
        if (seed_single_user(db, &config->users.members[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

static int seed_peers(sqlite3* db, const InitNetworkConfig* config, const InitNodeConfig* node, uint32_t node_index) {
    if (!db || !config || !node) {
        return -1;
    }

    for (uint32_t i = 0; i < config->node_count; ++i) {
        const InitNodeConfig* other = &config->nodes[i];
        if (!other->hostname || other->hostname[0] == '\0') {
            continue;
        }
        uint16_t gossip_port = other->gossip_port ? other->gossip_port : (uint16_t)(config->base_port + i);
        uint16_t api_port = other->api_port;
        if (gossip_peers_add_or_update(other->hostname, gossip_port, api_port, other->tags) != 0) {
            fprintf(stderr, "Warning: failed to add peer %s\n", other->hostname);
        }
    }

    uint16_t fallback_port = node->gossip_port ? node->gossip_port : (uint16_t)(config->base_port + node_index);
    for (uint32_t p = 0; p < node->peer_count; ++p) {
        const char* endpoint = node->peers ? node->peers[p] : NULL;
        if (!endpoint || endpoint[0] == '\0') {
            continue;
        }
        char host[256];
        uint16_t port = fallback_port;
        const char* last_colon = strrchr(endpoint, ':');
        if (last_colon && strchr(last_colon + 1, ':') == NULL) {
            size_t host_len = (size_t)(last_colon - endpoint);
            if (host_len >= sizeof(host)) host_len = sizeof(host) - 1;
            memcpy(host, endpoint, host_len);
            host[host_len] = '\0';
            port = (uint16_t)atoi(last_colon + 1);
        } else {
            strncpy(host, endpoint, sizeof(host) - 1);
            host[sizeof(host) - 1] = '\0';
        }
        if (host[0] == '\0') {
            continue;
        }
        if (gossip_peers_add_or_update(host, port, node->api_port, NULL) != 0) {
            fprintf(stderr, "Warning: failed to add peer endpoint %s\n", host);
        }
    }

    return 0;
}

static uint32_t derive_node_numeric_id(const InitNodeConfig* node, uint32_t fallback) {
    if (!node || !node->id) {
        return fallback;
    }
    const char* digits = node->id;
    while (*digits && (*digits < '0' || *digits > '9')) {
        ++digits;
    }
    if (*digits == '\0') {
        return fallback;
    }
    char* endptr = NULL;
    long value = strtol(digits, &endptr, 10);
    if (endptr == digits || value < 0) {
        return fallback;
    }
    return (uint32_t)value;
}

static int seed_database_for_node(InitNetworkConfig* config, const InitNodeConfig* node, uint32_t index) {
    uint32_t numeric_id = derive_node_numeric_id(node, index);
    NodeStatePaths paths;
    if (!state_paths_init(numeric_id, config->debug_mode != 0, &paths)) {
        fprintf(stderr, "Failed to prepare state directories for node %u\n", numeric_id);
        return -1;
    }

    char db_path[MAX_STATE_PATH_LEN];
    if (!state_paths_get_database_file(&paths, db_path, sizeof(db_path))) {
        fprintf(stderr, "Failed to resolve database path for node %u\n", numeric_id);
        return -1;
    }

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
    if (seed_roles_permissions(db) != 0) {
        fprintf(stderr, "Failed to seed roles and permissions\n");
        db_close();
        return -1;
    }
    if (seed_transaction_permissions(db) != 0) {
        fprintf(stderr, "Failed to seed transaction permissions\n");
        db_close();
        return -1;
    }
    if (seed_users(db, config) != 0) {
        fprintf(stderr, "Failed to seed users\n");
        db_close();
        return -1;
    }
    if (seed_peers(db, config, node, index) != 0) {
        fprintf(stderr, "Failed to seed peers\n");
        db_close();
        return -1;
    }

    db_close();
    return 0;
}

static int ensure_user_records(InitNetworkConfig* config) {
    if (!config) return -1;
    for (uint32_t i = 0; i < config->users.admin_count; ++i) {
        if (generate_or_load_user_key(config->debug_mode, &config->users.admins[i]) != 0) {
            return -1;
        }
    }
    for (uint32_t i = 0; i < config->users.member_count; ++i) {
        if (generate_or_load_user_key(config->debug_mode, &config->users.members[i]) != 0) {
            return -1;
        }
    }
    return 0;
}

int initialize_network(InitNetworkConfig* config) {
    if (!config || !config->nodes || config->node_count == 0) {
        fprintf(stderr, "Initialization requires at least one node configuration.\n");
        return -1;
    }

    if (ensure_user_records(config) != 0) {
        fprintf(stderr, "Failed to ensure user keys.\n");
        return -1;
    }

    for (uint32_t i = 0; i < config->node_count; ++i) {
        if (seed_database_for_node(config, &config->nodes[i], i) != 0) {
            return -1;
        }
    }

    printf("Initialization complete. Users, permissions, and peers are ready.\n");
    return 0;
} 