#include "permissions.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sodium.h>
#include "database_gossip.h"
#include "schema.h"
#include "packages/utils/logger.h"
#include "structs/permission/permission.h"

// Helper function to hex encode a public key
static int hex_encode_pubkey(const unsigned char* pubkey, char* hex_out, size_t hex_len) {
    if (hex_len < 65) return -1; // Need at least 64 chars + null terminator
    
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        hex_out[i * 2] = hex[(pubkey[i] >> 4) & 0xF];
        hex_out[i * 2 + 1] = hex[pubkey[i] & 0xF];
    }
    hex_out[64] = '\0';
    return 0;
}

// Check if a user exists in the database (is registered and active)
bool user_exists(const unsigned char* user_pubkey) {
    if (!user_pubkey) return false;
    
    sqlite3* db = db_get_handle();
    if (!db) {
        logger_error("permissions", "user_exists: database not initialized");
        return false;
    }
    
    // Convert pubkey to hex
    char pubkey_hex[65];
    if (hex_encode_pubkey(user_pubkey, pubkey_hex, sizeof(pubkey_hex)) != 0) {
        logger_error("permissions", "user_exists: failed to encode pubkey");
        return false;
    }
    
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL_SELECT_USER_BY_PUBKEY, -1, &stmt, NULL) != SQLITE_OK) {
        logger_error("permissions", "user_exists: SQL error: %s", sqlite3_errmsg(db));
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, pubkey_hex, -1, SQLITE_STATIC);
    
    bool exists = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        // Check if user is active (column 6: is_active)
        int is_active = sqlite3_column_int(stmt, 6);
        exists = (is_active == 1);
    }
    
    sqlite3_finalize(stmt);
    return exists;
}

// Helper structure to group permissions by scope/condition/time
typedef struct {
    uint32_t scope_flags;
    uint64_t condition_flags;
    uint64_t time_start;
    uint64_t time_end;
    uint64_t combined_permissions;
    size_t count;
} PermissionGroup;

// Find or create a permission group matching the given criteria
static PermissionGroup* find_or_create_group(PermissionGroup* groups, size_t* group_count, 
                                             uint32_t scope_flags, uint64_t condition_flags,
                                             uint64_t time_start, uint64_t time_end) {
    // Search for existing group
    for (size_t i = 0; i < *group_count; i++) {
        if (groups[i].scope_flags == scope_flags &&
            groups[i].condition_flags == condition_flags &&
            groups[i].time_start == time_start &&
            groups[i].time_end == time_end) {
            return &groups[i];
        }
    }
    
    // Create new group
    if (*group_count >= 32) return NULL; // Limit to prevent excessive groups
    
    PermissionGroup* new_group = &groups[*group_count];
    new_group->scope_flags = scope_flags;
    new_group->condition_flags = condition_flags;
    new_group->time_start = time_start;
    new_group->time_end = time_end;
    new_group->combined_permissions = 0;
    new_group->count = 0;
    (*group_count)++;
    
    return new_group;
}

int load_role_permission_sets(int role_id, PermissionSet** out_sets, size_t* out_count) {
    if (!out_sets || !out_count) return -1;
    
    sqlite3* db = db_get_handle();
    if (!db) {
        logger_error("permissions", "load_role_permission_sets: database not initialized");
        return -1;
    }
    
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL_SELECT_ROLE_PERMISSIONS, -1, &stmt, NULL) != SQLITE_OK) {
        logger_error("permissions", "load_role_permission_sets: SQL error: %s", sqlite3_errmsg(db));
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, role_id);
    
    // Temporary array to group permissions
    PermissionGroup groups[32];
    size_t group_count = 0;
    
    // Read all role_permissions and group them
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t permission_flags = sqlite3_column_int64(stmt, 10); // p.permission_flags
        uint32_t scope_flags = sqlite3_column_int(stmt, 5); // rp.scope_flags
        uint64_t condition_flags = sqlite3_column_int64(stmt, 6); // rp.condition_flags
        uint64_t time_start = sqlite3_column_int64(stmt, 7); // rp.time_start
        uint64_t time_end = sqlite3_column_int64(stmt, 8); // rp.time_end
        
        // Find or create group for this scope/condition/time combination
        PermissionGroup* group = find_or_create_group(groups, &group_count, 
                                                      scope_flags, condition_flags,
                                                      time_start, time_end);
        if (!group) {
            logger_error("permissions", "load_role_permission_sets: too many permission groups");
            sqlite3_finalize(stmt);
            return -1;
        }
        
        // Combine permissions in this group
        group->combined_permissions |= permission_flags;
        group->count++;
    }
    
    sqlite3_finalize(stmt);
    
    if (group_count == 0) {
        *out_sets = NULL;
        *out_count = 0;
        return 0;
    }
    
    // Allocate PermissionSet array
    PermissionSet* sets = malloc(group_count * sizeof(PermissionSet));
    if (!sets) {
        logger_error("permissions", "load_role_permission_sets: memory allocation failed");
        return -1;
    }
    
    // Convert groups to PermissionSets
    for (size_t i = 0; i < group_count; i++) {
        sets[i].permissions = groups[i].combined_permissions;
        sets[i].scopes = groups[i].scope_flags;
        sets[i].conditions = groups[i].condition_flags;
        sets[i].time_start = groups[i].time_start;
        sets[i].time_end = groups[i].time_end;
    }
    
    *out_sets = sets;
    *out_count = group_count;
    return 0;
}

int load_user_roles(const unsigned char* user_pubkey, Role** out_roles, size_t* out_count) {
    if (!user_pubkey || !out_roles || !out_count) return -1;
    
    sqlite3* db = db_get_handle();
    if (!db) {
        logger_error("permissions", "load_user_roles: database not initialized");
        return -1;
    }
    
    // Convert pubkey to hex
    char pubkey_hex[65];
    if (hex_encode_pubkey(user_pubkey, pubkey_hex, sizeof(pubkey_hex)) != 0) {
        logger_error("permissions", "load_user_roles: failed to encode pubkey");
        return -1;
    }
    
    // Get user ID
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, SQL_SELECT_USER_BY_PUBKEY, -1, &stmt, NULL) != SQLITE_OK) {
        logger_error("permissions", "load_user_roles: SQL error: %s", sqlite3_errmsg(db));
        return -1;
    }
    
    sqlite3_bind_text(stmt, 1, pubkey_hex, -1, SQLITE_STATIC);
    
    int user_id = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        user_id = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    
    if (user_id < 0) {
        logger_error("permissions", "load_user_roles: User not found with pubkey: %s", pubkey_hex);
        *out_roles = NULL;
        *out_count = 0;
        return 0; // User not found, no roles
    }
    
    // Get user's roles
    if (sqlite3_prepare_v2(db, SQL_SELECT_USER_ROLES, -1, &stmt, NULL) != SQLITE_OK) {
        logger_error("permissions", "load_user_roles: SQL error: %s", sqlite3_errmsg(db));
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, user_id);
    
    // First pass: count roles
    size_t role_count = 0;
    int role_ids[32];
    const char* role_names[32];
    
    while (sqlite3_step(stmt) == SQLITE_ROW && role_count < 32) {
        role_ids[role_count] = sqlite3_column_int(stmt, 2); // ur.role_id
        const unsigned char* name = sqlite3_column_text(stmt, 5); // r.name as role_name
        if (name) {
            role_names[role_count] = (const char*)name;
            role_count++;
        }
    }
    sqlite3_finalize(stmt);
    
    if (role_count == 0) {
        logger_error("permissions", "load_user_roles: User %d has no roles assigned", user_id);
        *out_roles = NULL;
        *out_count = 0;
        return 0;
    }
    
    // Allocate role array
    Role* roles = malloc(role_count * sizeof(Role));
    if (!roles) {
        logger_error("permissions", "load_user_roles: memory allocation failed");
        return -1;
    }
    
    // Load permission sets for each role
    for (size_t i = 0; i < role_count; i++) {
        // Initialize role
        memset(&roles[i], 0, sizeof(Role));
        strncpy(roles[i].role_name, role_names[i], MAX_ROLE_NAME_LENGTH - 1);
        roles[i].role_name[MAX_ROLE_NAME_LENGTH - 1] = '\0';
        
        // Load permission sets
        PermissionSet* sets = NULL;
        size_t set_count = 0;
        
        if (load_role_permission_sets(role_ids[i], &sets, &set_count) != 0) {
            // Clean up on error
            for (size_t j = 0; j < i; j++) {
                if (roles[j].permission_sets) {
                    free(roles[j].permission_sets);
                }
            }
            free(roles);
            return -1;
        }
        
        roles[i].permission_sets = sets;
        roles[i].permission_set_count = set_count;
        roles[i].created_timestamp = 0; // Not stored in DB
        roles[i].modified_timestamp = 0; // Not stored in DB
    }
    
    *out_roles = roles;
    *out_count = role_count;
    return 0;
}

void free_role_array(Role* roles, size_t count) {
    if (!roles) return;
    
    for (size_t i = 0; i < count; i++) {
        if (roles[i].permission_sets) {
            free(roles[i].permission_sets);
        }
    }
    free(roles);
}

bool check_user_permission(const unsigned char* user_pubkey, uint64_t permission, permission_scope_t scope) {
    if (!user_pubkey) return false;
    
    // Load user's roles
    Role* roles = NULL;
    size_t role_count = 0;
    
    if (load_user_roles(user_pubkey, &roles, &role_count) != 0) {
        return false;
    }
    
    if (role_count == 0) {
        return false;
    }
    
    // Aggregate all permission sets from all roles into a single role
    // Count total permission sets
    size_t total_sets = 0;
    for (size_t i = 0; i < role_count; i++) {
        total_sets += roles[i].permission_set_count;
    }
    
    if (total_sets == 0) {
        free_role_array(roles, role_count);
        return false;
    }
    
    // Allocate aggregated permission sets
    PermissionSet* aggregated_sets = malloc(total_sets * sizeof(PermissionSet));
    if (!aggregated_sets) {
        free_role_array(roles, role_count);
        return false;
    }
    
    // Copy all permission sets
    size_t offset = 0;
    for (size_t i = 0; i < role_count; i++) {
        memcpy(&aggregated_sets[offset], roles[i].permission_sets, 
               roles[i].permission_set_count * sizeof(PermissionSet));
        offset += roles[i].permission_set_count;
    }
    
    // Create aggregated role
    Role aggregated_role;
    memset(&aggregated_role, 0, sizeof(Role));
    strncpy(aggregated_role.role_name, "aggregated", MAX_ROLE_NAME_LENGTH - 1);
    aggregated_role.permission_sets = aggregated_sets;
    aggregated_role.permission_set_count = total_sets;
    
    // Check permission
    bool has_perm = has_permission_in_scope(&aggregated_role, permission, scope);
    
    // Clean up
    free(aggregated_sets);
    free_role_array(roles, role_count);
    
    return has_perm;
}

