#include "permission.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Predefined role permission sets for common use cases
// Admin/Manager Role
const PermissionSet ADMIN_MESSAGING = {
    .permissions = PERMISSION_SEND_MESSAGE | PERMISSION_READ_MESSAGE | 
                  PERMISSION_DELETE_MESSAGE | PERMISSION_EDIT_MESSAGE | 
                  PERMISSION_FORWARD_MESSAGE | PERMISSION_SEND_EMERGENCY,
    .scopes = (1 << SCOPE_DIRECT) | (1 << SCOPE_PRIMARY_GROUP) | 
              (1 << SCOPE_EXTENDED_GROUP) | (1 << SCOPE_CONTACT_GROUP) | 
              (1 << SCOPE_COMMUNITY) | (1 << SCOPE_ORGANIZATION),
    .conditions = CONDITION_ALWAYS,
    .time_start = 0,
    .time_end = 0
};

const PermissionSet ADMIN_GROUP_MANAGEMENT = {
    .permissions = PERMISSION_CREATE_GROUP | PERMISSION_DELETE_GROUP | 
                  PERMISSION_EDIT_GROUP | PERMISSION_INVITE_USERS | 
                  PERMISSION_REMOVE_USERS | PERMISSION_APPROVE_MEMBERS | 
                  PERMISSION_MODERATE_GROUP,
    .scopes = (1 << SCOPE_PRIMARY_GROUP) | (1 << SCOPE_EXTENDED_GROUP) | 
              (1 << SCOPE_CONTACT_GROUP) | (1 << SCOPE_COMMUNITY) | 
              (1 << SCOPE_ORGANIZATION),
    .conditions = CONDITION_ALWAYS,
    .time_start = 0,
    .time_end = 0
};

const PermissionSet ADMIN_USER_MANAGEMENT = {
    .permissions = PERMISSION_VIEW_STATUS | PERMISSION_VIEW_LOCATION | 
                  PERMISSION_TRACK_LOCATION | PERMISSION_MANAGE_CONTACTS | 
                  PERMISSION_APPROVE_CONTACTS | PERMISSION_MONITOR_ACTIVITY | 
                  PERMISSION_SET_BOUNDARIES,
    .scopes = (1 << SCOPE_SUPERVISED_USERS) | (1 << SCOPE_PRIMARY_GROUP) | 
              (1 << SCOPE_EXTENDED_GROUP),
    .conditions = CONDITION_ALWAYS,
    .time_start = 0,
    .time_end = 0
};

const PermissionSet ADMIN_SYSTEM = {
    .permissions = PERMISSION_SET_CONTROLS | PERMISSION_VIEW_CONTROLS | 
                  PERMISSION_SET_CONTENT_FILTERS | PERMISSION_VIEW_CONTENT_FILTERS | 
                  PERMISSION_MANAGE_ROLES | PERMISSION_VIEW_LOGS | 
                  PERMISSION_MANAGE_SETTINGS | PERMISSION_VIEW_SETTINGS,
    .scopes = (1 << SCOPE_ORGANIZATION) | (1 << SCOPE_GLOBAL),
    .conditions = CONDITION_ALWAYS,
    .time_start = 0,
    .time_end = 0
};

// Admin Basic - includes SCOPE_SELF for self-related actions like access requests
const PermissionSet ADMIN_BASIC = {
    .permissions = PERMISSION_VIEW_STATUS | PERMISSION_VIEW_LOCATION,
    .scopes = (1 << SCOPE_SELF) | (1 << SCOPE_DIRECT) | (1 << SCOPE_PRIMARY_GROUP) | 
              (1 << SCOPE_CONTACT_GROUP),
    .conditions = CONDITION_ALWAYS,
    .time_start = 0,
    .time_end = 0
};

// Member/User Role
const PermissionSet MEMBER_MESSAGING = {
    .permissions = PERMISSION_SEND_MESSAGE | PERMISSION_READ_MESSAGE | 
                  PERMISSION_FORWARD_MESSAGE | PERMISSION_SEND_EMERGENCY,
    .scopes = (1 << SCOPE_DIRECT) | (1 << SCOPE_PRIMARY_GROUP) | 
              (1 << SCOPE_CONTACT_GROUP),
    .conditions = CONDITION_ALWAYS,
    .time_start = 0,
    .time_end = 0
};

const PermissionSet MEMBER_BASIC = {
    .permissions = PERMISSION_VIEW_STATUS | PERMISSION_VIEW_LOCATION,
    .scopes = (1 << SCOPE_SELF) | (1 << SCOPE_PRIMARY_GROUP) | 
              (1 << SCOPE_CONTACT_GROUP),
    .conditions = CONDITION_ALWAYS,
    .time_start = 0,
    .time_end = 0
};

// Contact/Peer Role
const PermissionSet CONTACT_MESSAGING = {
    .permissions = PERMISSION_SEND_MESSAGE | PERMISSION_READ_MESSAGE | 
                  PERMISSION_SEND_EMERGENCY,
    .scopes = (1 << SCOPE_DIRECT) | (1 << SCOPE_CONTACT_GROUP),
    .conditions = CONDITION_ALWAYS,
    .time_start = 0,
    .time_end = 0
};

const PermissionSet CONTACT_BASIC = {
    .permissions = PERMISSION_VIEW_STATUS,
    .scopes = (1 << SCOPE_CONTACT_GROUP),
    .conditions = CONDITION_ALWAYS,
    .time_start = 0,
    .time_end = 0
};

// Check if a user has a specific permission in a specific scope
bool has_permission_in_scope(const Role* role, uint64_t permission, permission_scope_t scope) {
    if (!role || !role->permission_sets) return false;
    
    for (size_t i = 0; i < role->permission_set_count; i++) {
        const PermissionSet* perm_set = &role->permission_sets[i];
        
        // Check if this permission set has the required permission
        if (!has_permission(perm_set->permissions, permission)) continue;
        
        // Check if this permission set applies to the required scope
        if (!has_scope(perm_set->scopes, scope)) continue;
        
        // Check if the permission set is currently active (time-based restrictions)
        if (!is_permission_set_active(perm_set, time(NULL))) continue;
        
        return true;
    }
    
    return false;
}

// Get all scopes where a user has a specific permission
uint32_t get_scopes_for_permission(const Role* role, uint64_t permission) {
    if (!role || !role->permission_sets) return 0;
    
    uint32_t available_scopes = 0;
    uint64_t current_time = time(NULL);
    
    for (size_t i = 0; i < role->permission_set_count; i++) {
        const PermissionSet* perm_set = &role->permission_sets[i];
        
        // Check if this permission set has the required permission
        if (!has_permission(perm_set->permissions, permission)) continue;
        
        // Check if the permission set is currently active
        if (!is_permission_set_active(perm_set, current_time)) continue;
        
        // Add all scopes from this permission set
        available_scopes |= perm_set->scopes;
    }
    
    return available_scopes;
}

// Check if user can perform action on target in given context
bool can_perform_action(const Role* role, uint64_t permission, permission_scope_t scope, 
                       const void* target, const void* context) {
    if (!role) return false;
    
    // Basic permission and scope check
    if (!has_permission_in_scope(role, permission, scope)) return false;
    
    // Additional context-specific checks can be added here
    // For example, checking if the target user is actually supervised by this role
    // or if the action is allowed in the current group context
    
    // For now, we'll just return the basic permission check
    return true;
}

// Check if permission set is valid for current time
bool is_permission_set_active(const PermissionSet* perm_set, uint64_t current_time) {
    if (!perm_set) return false;
    
    // If no time restrictions, always active
    if (!has_condition(perm_set->conditions, CONDITION_TIME_RESTRICTED)) {
        return true;
    }
    
    // Check time bounds
    if (perm_set->time_start > 0 && current_time < perm_set->time_start) {
        return false;
    }
    
    if (perm_set->time_end > 0 && current_time > perm_set->time_end) {
        return false;
    }
    
    return true;
}

// Role management functions
Role* create_role(const char* role_name) {
    if (!role_name) return NULL;
    
    Role* role = malloc(sizeof(Role));
    if (!role) return NULL;
    
    // Initialize role
    memset(role, 0, sizeof(Role));
    strncpy(role->role_name, role_name, MAX_ROLE_NAME_LENGTH - 1);
    role->role_name[MAX_ROLE_NAME_LENGTH - 1] = '\0';
    
    role->permission_sets = NULL;
    role->permission_set_count = 0;
    role->created_timestamp = time(NULL);
    role->modified_timestamp = role->created_timestamp;
    
    return role;
}

void destroy_role(Role* role) {
    if (!role) return;
    
    if (role->permission_sets) {
        free(role->permission_sets);
    }
    
    free(role);
}

int add_permission_set(Role* role, const PermissionSet* perm_set) {
    if (!role || !perm_set) return -1;
    
    // Check if we've reached the maximum number of permission sets
    if (role->permission_set_count >= MAX_PERMISSION_SETS_PER_ROLE) return -1;
    
    // Reallocate memory for the new permission set
    PermissionSet* new_sets = realloc(role->permission_sets, 
                                     sizeof(PermissionSet) * (role->permission_set_count + 1));
    if (!new_sets) return -1;
    
    role->permission_sets = new_sets;
    
    // Copy the new permission set
    memcpy(&role->permission_sets[role->permission_set_count], perm_set, sizeof(PermissionSet));
    role->permission_set_count++;
    role->modified_timestamp = time(NULL);
    
    return 0;
}

int remove_permission_set(Role* role, size_t index) {
    if (!role || !role->permission_sets || index >= role->permission_set_count) return -1;
    
    // Shift remaining permission sets down
    for (size_t i = index; i < role->permission_set_count - 1; i++) {
        memcpy(&role->permission_sets[i], &role->permission_sets[i + 1], sizeof(PermissionSet));
    }
    
    role->permission_set_count--;
    role->modified_timestamp = time(NULL);
    
    // Reallocate to smaller size (optional optimization)
    if (role->permission_set_count > 0) {
        PermissionSet* new_sets = realloc(role->permission_sets, 
                                         sizeof(PermissionSet) * role->permission_set_count);
        if (new_sets) {
            role->permission_sets = new_sets;
        }
    } else {
        free(role->permission_sets);
        role->permission_sets = NULL;
    }
    
    return 0;
}

// Predefined role creation helpers
Role* create_admin_role(void) {
    Role* role = create_role("admin");
    if (!role) return NULL;
    
    // Add all admin permission sets
    if (add_permission_set(role, &ADMIN_MESSAGING) != 0 ||
        add_permission_set(role, &ADMIN_GROUP_MANAGEMENT) != 0 ||
        add_permission_set(role, &ADMIN_USER_MANAGEMENT) != 0 ||
        add_permission_set(role, &ADMIN_SYSTEM) != 0 ||
        add_permission_set(role, &ADMIN_BASIC) != 0) { // Added ADMIN_BASIC
        destroy_role(role);
        return NULL;
    }
    
    return role;
}

Role* create_member_role(void) {
    Role* role = create_role("member");
    if (!role) return NULL;
    
    // Add member permission sets
    if (add_permission_set(role, &MEMBER_MESSAGING) != 0 ||
        add_permission_set(role, &MEMBER_BASIC) != 0) {
        destroy_role(role);
        return NULL;
    }
    
    return role;
}

Role* create_contact_role(void) {
    Role* role = create_role("contact");
    if (!role) return NULL;
    
    // Add contact permission sets
    if (add_permission_set(role, &CONTACT_MESSAGING) != 0 ||
        add_permission_set(role, &CONTACT_BASIC) != 0) {
        destroy_role(role);
        return NULL;
    }
    
    return role;
}

Role* create_community_role(void) {
    Role* role = create_role("community");
    if (!role) return NULL;
    
    // Create community-specific permission set
    PermissionSet community_perms = {
        .permissions = PERMISSION_SEND_MESSAGE | PERMISSION_READ_MESSAGE | PERMISSION_SEND_EMERGENCY,
        .scopes = (1 << SCOPE_COMMUNITY),
        .conditions = CONDITION_ALWAYS,
        .time_start = 0,
        .time_end = 0
    };
    
    PermissionSet community_status = {
        .permissions = PERMISSION_VIEW_STATUS,
        .scopes = (1 << SCOPE_COMMUNITY),
        .conditions = CONDITION_ALWAYS,
        .time_start = 0,
        .time_end = 0
    };
    
    // Add community permission sets
    if (add_permission_set(role, &community_perms) != 0 ||
        add_permission_set(role, &community_status) != 0) {
        destroy_role(role);
        return NULL;
    }
    
    return role;
} 