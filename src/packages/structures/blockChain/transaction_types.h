#ifndef TW_TRANSACTION_TYPES_H
#define TW_TRANSACTION_TYPES_H

#include <stdint.h>
#include "transaction.h"
#include "../../../structs/permission/permission.h"

// Maximum lengths for string fields
#define MAX_USERNAME_LENGTH 32
#define MAX_GROUP_NAME_LENGTH 32
#define MAX_PERMISSION_NAME_LENGTH 32
#define MAX_CONTENT_FILTER_RULE_LENGTH 64

// Permission Categories
typedef enum {
    PERM_CATEGORY_MESSAGING = 0,    // Direct and group messaging
    PERM_CATEGORY_GROUP_MGMT = 1,   // Group creation and management
    PERM_CATEGORY_USER_MGMT = 2,    // User management and monitoring
    PERM_CATEGORY_ADMIN = 3,        // Administrative functions
    PERM_CATEGORY_COUNT             // Number of categories
} TW_PermissionCategory;

// Transaction Type to Permission Mapping
typedef struct {
    TW_TransactionType type;
    TW_PermissionCategory category;
    uint64_t required_permissions;  // Bit flags of required permissions
    permission_scope_t required_scope; // Required scope for the transaction
} TW_TransactionPermission;

// User Management Structs
typedef struct {
    char username[MAX_USERNAME_LENGTH];
    uint8_t age;
    unsigned char user_signing_pubkey[32]; // User's Ed25519 signing public key
    // Role assignment information (included in user registration)
    char assigned_role[MAX_ROLE_NAME_LENGTH];
    PermissionSet permission_sets[MAX_PERMISSION_SETS_PER_ROLE];
    uint8_t permission_set_count;
} TW_TXN_UserRegistration;

typedef struct {
    char role_name[MAX_ROLE_NAME_LENGTH];
    PermissionSet permission_sets[MAX_PERMISSION_SETS_PER_ROLE];
    uint8_t permission_set_count;
} TW_TXN_RoleAssignment;

// Group Management Structs
typedef struct {
    char group_name[MAX_GROUP_NAME_LENGTH];
    uint8_t group_type;  // e.g., primary, extended, contact, community
    permission_scope_t group_scope; // What scope this group represents
    uint8_t default_permissions;
} TW_TXN_GroupCreate;

typedef struct {
    uint8_t setting_type;  // e.g., name, type, permissions
    uint8_t new_value;     // New value for the setting
    permission_scope_t target_scope; // Which scope this update applies to
} TW_TXN_GroupUpdate;

// Permission Management Structs
typedef struct {
    char permission_name[MAX_PERMISSION_NAME_LENGTH];
    uint64_t permission_flags;  // New permission flags
    uint32_t scope_flags;       // New scope flags
    uint64_t condition_flags;   // New condition flags
} TW_TXN_PermissionEdit;

typedef struct {
    uint8_t control_type;  // e.g., screen time, content type, app access
    uint8_t control_value; // New control value
    permission_scope_t target_scope; // Which scope this control applies to
} TW_TXN_AdminControl;

typedef struct {
    char rule[MAX_CONTENT_FILTER_RULE_LENGTH];
    uint8_t rule_type;    // e.g., block, allow, warn
    uint8_t rule_action;  // What to do when rule is triggered
    permission_scope_t target_scope; // Which scope this filter applies to
} TW_TXN_ContentFilter;

typedef struct {
    double latitude;
    double longitude;
    uint64_t timestamp;
    uint8_t accuracy;  // Location accuracy in meters
    permission_scope_t visibility_scope; // Who can see this location
} TW_TXN_LocationUpdate;

typedef struct {
    uint8_t alert_type;  // e.g., medical, safety, lost
    char message[128];   // Emergency message
    permission_scope_t broadcast_scope; // How widely to broadcast
} TW_TXN_EmergencyAlert;

// Network Management Structs
typedef struct {
    uint8_t config_type;  // e.g., network settings, security settings
    uint8_t config_value; // New configuration value
    permission_scope_t config_scope; // Which scope this config applies to
} TW_TXN_SystemConfig;

// Access Control Structs
typedef struct {
    char resource_id[64];  // ID of resource being requested (e.g., "admin_dashboard")
    uint64_t requested_at; // When the access was requested (timestamp)
} TW_TXN_AccessRequest;

// Transaction Permission Mappings
static const TW_TransactionPermission TXN_PERMISSIONS[] = {
    // User Management
    {TW_TXN_USER_REGISTRATION, PERM_CATEGORY_ADMIN, PERMISSION_MANAGE_ROLES, SCOPE_ORGANIZATION},
    {TW_TXN_ROLE_ASSIGNMENT, PERM_CATEGORY_ADMIN, PERMISSION_MANAGE_ROLES, SCOPE_ORGANIZATION},
    
    // Messaging
    {TW_TXN_MESSAGE, PERM_CATEGORY_MESSAGING, PERMISSION_SEND_MESSAGE, SCOPE_DIRECT},
    {TW_TXN_GROUP_MESSAGE, PERM_CATEGORY_MESSAGING, PERMISSION_SEND_MESSAGE, SCOPE_PRIMARY_GROUP},
    
    // Group Management
    {TW_TXN_GROUP_CREATE, PERM_CATEGORY_GROUP_MGMT, PERMISSION_CREATE_GROUP, SCOPE_ORGANIZATION},
    {TW_TXN_GROUP_UPDATE, PERM_CATEGORY_GROUP_MGMT, PERMISSION_EDIT_GROUP, SCOPE_PRIMARY_GROUP},
    {TW_TXN_GROUP_MEMBER_ADD, PERM_CATEGORY_GROUP_MGMT, PERMISSION_INVITE_USERS, SCOPE_PRIMARY_GROUP},
    {TW_TXN_GROUP_MEMBER_REMOVE, PERM_CATEGORY_GROUP_MGMT, PERMISSION_REMOVE_USERS, SCOPE_PRIMARY_GROUP},
    {TW_TXN_GROUP_MEMBER_LEAVE, PERM_CATEGORY_GROUP_MGMT, 0, SCOPE_SELF}, // No special permission needed
    
    // User Management
    {TW_TXN_PERMISSION_EDIT, PERM_CATEGORY_USER_MGMT, PERMISSION_SET_CONTROLS, SCOPE_SUPERVISED_USERS},
    {TW_TXN_PARENTAL_CONTROL, PERM_CATEGORY_USER_MGMT, PERMISSION_SET_CONTROLS, SCOPE_SUPERVISED_USERS},
    {TW_TXN_CONTENT_FILTER, PERM_CATEGORY_USER_MGMT, PERMISSION_SET_CONTENT_FILTERS, SCOPE_SUPERVISED_USERS},
    {TW_TXN_LOCATION_UPDATE, PERM_CATEGORY_USER_MGMT, PERMISSION_TRACK_LOCATION, SCOPE_PRIMARY_GROUP},
    {TW_TXN_EMERGENCY_ALERT, PERM_CATEGORY_MESSAGING, PERMISSION_SEND_EMERGENCY, SCOPE_COMMUNITY},
    
    // System Management
    {TW_TXN_SYSTEM_CONFIG, PERM_CATEGORY_ADMIN, PERMISSION_MANAGE_SETTINGS, SCOPE_GLOBAL},
    
    // Access Control
    {TW_TXN_ACCESS_REQUEST, PERM_CATEGORY_USER_MGMT, 0, SCOPE_SELF}, // No special permission needed to request access
};

// Helper function to check if a role has permission for a transaction type in a specific scope
static inline bool has_transaction_permission(const Role* role, TW_TransactionType type, permission_scope_t scope) {
    if (!role) return false;
    
    for (size_t i = 0; i < sizeof(TXN_PERMISSIONS) / sizeof(TXN_PERMISSIONS[0]); i++) {
        if (TXN_PERMISSIONS[i].type == type) {
            // If no special permission required, allow
            if (TXN_PERMISSIONS[i].required_permissions == 0) return true;
            
            // Check if the role has the required permission in the required scope
            return has_permission_in_scope(role, TXN_PERMISSIONS[i].required_permissions, scope);
        }
    }
    return false; // Unknown transaction type
}

// Helper function to get required permissions for a transaction type
static inline uint64_t get_transaction_permissions(TW_TransactionType type) {
    for (size_t i = 0; i < sizeof(TXN_PERMISSIONS) / sizeof(TXN_PERMISSIONS[0]); i++) {
        if (TXN_PERMISSIONS[i].type == type) {
            return TXN_PERMISSIONS[i].required_permissions;
        }
    }
    return 0; // Unknown transaction type
}

// Helper function to get required scope for a transaction type
static inline permission_scope_t get_transaction_scope(TW_TransactionType type) {
    for (size_t i = 0; i < sizeof(TXN_PERMISSIONS) / sizeof(TXN_PERMISSIONS[0]); i++) {
        if (TXN_PERMISSIONS[i].type == type) {
            return TXN_PERMISSIONS[i].required_scope;
        }
    }
    return SCOPE_MAX; // Unknown transaction type
}

// Helper function to get permission category for a transaction type
static inline TW_PermissionCategory get_transaction_category(TW_TransactionType type) {
    for (size_t i = 0; i < sizeof(TXN_PERMISSIONS) / sizeof(TXN_PERMISSIONS[0]); i++) {
        if (TXN_PERMISSIONS[i].type == type) {
            return TXN_PERMISSIONS[i].category;
        }
    }
    return PERM_CATEGORY_COUNT; // Unknown transaction type
}

// Function declarations for serialization/deserialization
int serialize_user_registration(const TW_TXN_UserRegistration* reg, unsigned char** buffer);
int deserialize_user_registration(const unsigned char* buffer, TW_TXN_UserRegistration* reg);

int serialize_role_assignment(const TW_TXN_RoleAssignment* role, unsigned char** buffer);
int deserialize_role_assignment(const unsigned char* buffer, TW_TXN_RoleAssignment* role);

int serialize_group_create(const TW_TXN_GroupCreate* group, unsigned char** buffer);
int deserialize_group_create(const unsigned char* buffer, TW_TXN_GroupCreate* group);

int serialize_group_update(const TW_TXN_GroupUpdate* update, unsigned char** buffer);
int deserialize_group_update(const unsigned char* buffer, TW_TXN_GroupUpdate* update);

int serialize_permission_edit(const TW_TXN_PermissionEdit* perm, unsigned char** buffer);
int deserialize_permission_edit(const unsigned char* buffer, TW_TXN_PermissionEdit* perm);

int serialize_admin_control(const TW_TXN_AdminControl* control, unsigned char** buffer);
int deserialize_admin_control(const unsigned char* buffer, TW_TXN_AdminControl* control);

int serialize_content_filter(const TW_TXN_ContentFilter* filter, unsigned char** buffer);
int deserialize_content_filter(const unsigned char* buffer, TW_TXN_ContentFilter* filter);

int serialize_location_update(const TW_TXN_LocationUpdate* location, unsigned char** buffer);
int deserialize_location_update(const unsigned char* buffer, TW_TXN_LocationUpdate* location);

int serialize_emergency_alert(const TW_TXN_EmergencyAlert* alert, unsigned char** buffer);
int deserialize_emergency_alert(const unsigned char* buffer, TW_TXN_EmergencyAlert* alert);

int serialize_system_config(const TW_TXN_SystemConfig* config, unsigned char** buffer);
int deserialize_system_config(const unsigned char* buffer, TW_TXN_SystemConfig* config);

// Access Control transaction serialization
int serialize_access_request(const TW_TXN_AccessRequest* request, unsigned char** buffer);
int deserialize_access_request(const unsigned char* buffer, TW_TXN_AccessRequest* request);

#endif // TW_TRANSACTION_TYPES_H 