#ifndef TW_PERMISSION_H
#define TW_PERMISSION_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// Maximum lengths for permission system
#define MAX_ROLE_NAME_LENGTH 32
#define MAX_PERMISSION_SETS_PER_ROLE 16

// Base Permission Flags (What actions can be performed)
// Communication Permissions (0-15)
#define PERMISSION_SEND_MESSAGE         (1ULL << 0)   // Can send messages
#define PERMISSION_READ_MESSAGE         (1ULL << 1)   // Can read messages
#define PERMISSION_DELETE_MESSAGE       (1ULL << 2)   // Can delete messages
#define PERMISSION_EDIT_MESSAGE         (1ULL << 3)   // Can edit messages
#define PERMISSION_FORWARD_MESSAGE      (1ULL << 4)   // Can forward messages
#define PERMISSION_SEND_EMERGENCY       (1ULL << 5)   // Can send emergency alerts
// Reserved for future communication (6-15)

// Group Management Permissions (16-31)
#define PERMISSION_CREATE_GROUP         (1ULL << 16)  // Can create groups
#define PERMISSION_DELETE_GROUP         (1ULL << 17)  // Can delete groups
#define PERMISSION_EDIT_GROUP           (1ULL << 18)  // Can edit group settings
#define PERMISSION_INVITE_USERS         (1ULL << 19)  // Can invite users to groups
#define PERMISSION_REMOVE_USERS         (1ULL << 20)  // Can remove users from groups
#define PERMISSION_APPROVE_MEMBERS      (1ULL << 21)  // Can approve group membership
#define PERMISSION_MODERATE_GROUP       (1ULL << 22)  // Can moderate group content
// Reserved for future group management (23-31)

// User Management Permissions (32-47)
#define PERMISSION_VIEW_STATUS          (1ULL << 32)  // Can view user status/activity
#define PERMISSION_VIEW_LOCATION        (1ULL << 33)  // Can view location data
#define PERMISSION_TRACK_LOCATION       (1ULL << 34)  // Can actively track location
#define PERMISSION_MANAGE_CONTACTS      (1ULL << 35)  // Can manage user's contacts
#define PERMISSION_APPROVE_CONTACTS     (1ULL << 36)  // Can approve new contacts
#define PERMISSION_MONITOR_ACTIVITY     (1ULL << 37)  // Can monitor user activity
#define PERMISSION_SET_BOUNDARIES       (1ULL << 38)  // Can set communication boundaries
// Reserved for future user management (39-47)

// Administrative Permissions (48-63)
#define PERMISSION_SET_CONTROLS         (1ULL << 48)  // Can set administrative controls
#define PERMISSION_VIEW_CONTROLS        (1ULL << 49)  // Can view administrative controls
#define PERMISSION_SET_CONTENT_FILTERS  (1ULL << 50)  // Can set content filters
#define PERMISSION_VIEW_CONTENT_FILTERS (1ULL << 51)  // Can view content filters
#define PERMISSION_MANAGE_ROLES         (1ULL << 52)  // Can manage user roles
#define PERMISSION_VIEW_LOGS            (1ULL << 53)  // Can view system logs
#define PERMISSION_MANAGE_SETTINGS      (1ULL << 54)  // Can manage system settings
#define PERMISSION_VIEW_SETTINGS        (1ULL << 55)  // Can view system settings
// Reserved for future administrative (56-63)

// Scope Definitions (Where permissions can be applied)
typedef enum {
    SCOPE_SELF = 0,              // Only applies to yourself
    SCOPE_DIRECT,                // Direct 1-on-1 interactions
    SCOPE_PRIMARY_GROUP,         // Your primary/core group
    SCOPE_EXTENDED_GROUP,        // Extended groups you're part of
    SCOPE_CONTACT_GROUP,         // Contact/peer groups
    SCOPE_COMMUNITY,             // Community-wide
    SCOPE_ORGANIZATION,          // Organization-wide
    SCOPE_GLOBAL,                // System-wide (admin only)
    SCOPE_SUPERVISED_USERS,      // Users under your supervision
    SCOPE_PEER_USERS,            // Users at your level
    SCOPE_MAX
} permission_scope_t;

// Condition Flags (When permissions apply)
#define CONDITION_ALWAYS            (1ULL << 0)   // Always active
#define CONDITION_TIME_RESTRICTED   (1ULL << 1)   // Time-based restrictions
#define CONDITION_APPROVAL_REQUIRED (1ULL << 2)   // Requires approval
#define CONDITION_EMERGENCY_ONLY    (1ULL << 3)   // Only during emergencies
// Reserved for future conditions (4-63)

// Permission Set Structure
typedef struct {
    uint64_t permissions;        // What actions are allowed (bit flags)
    uint32_t scopes;            // Which scopes this applies to (bit flags)
    uint64_t conditions;        // Additional conditions (bit flags)
    uint64_t time_start;        // Start time for time-based restrictions (Unix timestamp)
    uint64_t time_end;          // End time for time-based restrictions (Unix timestamp)
} PermissionSet;

// Role Structure
typedef struct {
    char role_name[MAX_ROLE_NAME_LENGTH];
    PermissionSet* permission_sets;
    size_t permission_set_count;
    uint64_t created_timestamp;
    uint64_t modified_timestamp;
} Role;

// Predefined role permission sets for common use cases
// External declarations - definitions are in permission.c
extern const PermissionSet ADMIN_MESSAGING;
extern const PermissionSet ADMIN_GROUP_MANAGEMENT;
extern const PermissionSet ADMIN_USER_MANAGEMENT;
extern const PermissionSet ADMIN_SYSTEM;
extern const PermissionSet MEMBER_MESSAGING;
extern const PermissionSet MEMBER_BASIC;
extern const PermissionSet CONTACT_MESSAGING;
extern const PermissionSet CONTACT_BASIC;

// Helper functions for permission management
static inline bool has_permission(uint64_t permissions, uint64_t permission) {
    return (permissions & permission) != 0;
}

static inline void add_permission(uint64_t* permissions, uint64_t permission) {
    *permissions |= permission;
}

static inline void remove_permission(uint64_t* permissions, uint64_t permission) {
    *permissions &= ~permission;
}

static inline bool has_scope(uint32_t scopes, permission_scope_t scope) {
    return (scopes & (1 << scope)) != 0;
}

static inline void add_scope(uint32_t* scopes, permission_scope_t scope) {
    *scopes |= (1 << scope);
}

static inline void remove_scope(uint32_t* scopes, permission_scope_t scope) {
    *scopes &= ~(1 << scope);
}

static inline bool has_condition(uint64_t conditions, uint64_t condition) {
    return (conditions & condition) != 0;
}

// Check if a user has a specific permission in a specific scope
bool has_permission_in_scope(const Role* role, uint64_t permission, permission_scope_t scope);

// Get all scopes where a user has a specific permission
uint32_t get_scopes_for_permission(const Role* role, uint64_t permission);

// Check if user can perform action on target in given context
bool can_perform_action(const Role* role, uint64_t permission, permission_scope_t scope, 
                       const void* target, const void* context);

// Check if permission set is valid for current time
bool is_permission_set_active(const PermissionSet* perm_set, uint64_t current_time);

// Role management functions
Role* create_role(const char* role_name);
void destroy_role(Role* role);
int add_permission_set(Role* role, const PermissionSet* perm_set);
int remove_permission_set(Role* role, size_t index);

// Predefined role creation helpers
Role* create_admin_role(void);
Role* create_member_role(void);
Role* create_contact_role(void);
Role* create_community_role(void);

#endif // TW_PERMISSION_H 