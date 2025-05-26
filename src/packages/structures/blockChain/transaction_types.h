#ifndef TW_TRANSACTION_TYPES_H
#define TW_TRANSACTION_TYPES_H

#include <stdint.h>
#include "transaction.h"
#include "../../../structs/permission/permission.h"

// Maximum lengths for string fields
#define MAX_USERNAME_LENGTH 32
#define MAX_ROLE_NAME_LENGTH 16
#define MAX_GROUP_NAME_LENGTH 32
#define MAX_PERMISSION_NAME_LENGTH 32
#define MAX_CONTENT_FILTER_RULE_LENGTH 64

// Permission Categories
typedef enum {
    PERM_CATEGORY_MESSAGING = 0,    // Direct and group messaging
    PERM_CATEGORY_GROUP_MGMT = 1,   // Group creation and management
    PERM_CATEGORY_SAFETY = 2,       // Safety and control features
    PERM_CATEGORY_SYSTEM = 3,       // System management
    PERM_CATEGORY_COUNT             // Number of categories
} TW_PermissionCategory;

// Transaction Type to Permission Mapping
typedef struct {
    TW_TransactionType type;
    TW_PermissionCategory category;
    uint64_t required_permissions;  // Bit flags of required permissions
} TW_TransactionPermission;

// User Management Structs
typedef struct {
    char username[MAX_USERNAME_LENGTH];
    uint8_t age;
    // Additional user metadata can be added here
} TW_TXN_UserRegistration;

typedef struct {
    char role_name[MAX_ROLE_NAME_LENGTH];
    uint64_t permissions;  // Bit flags for role permissions (64 bits)
} TW_TXN_RoleAssignment;

// Group Management Structs
typedef struct {
    char group_name[MAX_GROUP_NAME_LENGTH];
    uint8_t group_type;  // e.g., family, friends, community
    uint8_t default_permissions;
} TW_TXN_GroupCreate;

typedef struct {
    uint8_t setting_type;  // e.g., name, type, permissions
    uint8_t new_value;     // New value for the setting
} TW_TXN_GroupUpdate;

// Safety & Control Structs
typedef struct {
    char permission_name[MAX_PERMISSION_NAME_LENGTH];
    uint8_t permission_value;  // New permission value
} TW_TXN_PermissionEdit;

typedef struct {
    uint8_t control_type;  // e.g., screen time, content type, app access
    uint8_t control_value; // New control value
} TW_TXN_ParentalControl;

typedef struct {
    char rule[MAX_CONTENT_FILTER_RULE_LENGTH];
    uint8_t rule_type;    // e.g., block, allow, warn
    uint8_t rule_action;  // What to do when rule is triggered
} TW_TXN_ContentFilter;

typedef struct {
    double latitude;
    double longitude;
    uint64_t timestamp;
    uint8_t accuracy;  // Location accuracy in meters
} TW_TXN_LocationUpdate;

typedef struct {
    uint8_t alert_type;  // e.g., medical, safety, lost
    char message[128];   // Emergency message
} TW_TXN_EmergencyAlert;

// Network Management Structs
typedef struct {
    uint8_t config_type;  // e.g., network settings, security settings
    uint8_t config_value; // New configuration value
} TW_TXN_SystemConfig;

// Transaction Permission Mappings
static const TW_TransactionPermission TXN_PERMISSIONS[] = {
    // User Management
    {TW_TXN_USER_REGISTRATION, PERM_CATEGORY_SYSTEM, PERMISSION_MANAGE_ROLES},
    {TW_TXN_ROLE_ASSIGNMENT, PERM_CATEGORY_SYSTEM, PERMISSION_MANAGE_ROLES},
    
    // Messaging
    {TW_TXN_MESSAGE, PERM_CATEGORY_MESSAGING, PERMISSION_DIRECT_MESSAGE},
    {TW_TXN_GROUP_MESSAGE, PERM_CATEGORY_MESSAGING, 
        PERMISSION_FAMILY_GROUP_MSG | PERMISSION_FRIEND_GROUP_MSG | PERMISSION_COMMUNITY_MSG},
    
    // Group Management
    {TW_TXN_GROUP_CREATE, PERM_CATEGORY_GROUP_MGMT, 
        PERMISSION_CREATE_FAMILY_GROUP | PERMISSION_CREATE_FRIEND_GROUP | PERMISSION_CREATE_COMMUNITY_GROUP},
    {TW_TXN_GROUP_UPDATE, PERM_CATEGORY_GROUP_MGMT, 
        PERMISSION_EDIT_FAMILY_GROUP | PERMISSION_EDIT_FRIEND_GROUP | PERMISSION_EDIT_COMMUNITY_GROUP},
    {TW_TXN_GROUP_MEMBER_ADD, PERM_CATEGORY_GROUP_MGMT, 
        PERMISSION_INVITE_FAMILY | PERMISSION_INVITE_FRIENDS | PERMISSION_INVITE_COMMUNITY},
    {TW_TXN_GROUP_MEMBER_REMOVE, PERM_CATEGORY_GROUP_MGMT, 
        PERMISSION_REMOVE_FAMILY | PERMISSION_REMOVE_FRIENDS | PERMISSION_REMOVE_COMMUNITY},
    {TW_TXN_GROUP_MEMBER_LEAVE, PERM_CATEGORY_GROUP_MGMT, 0}, // No special permission needed
    
    // Safety & Control
    {TW_TXN_PERMISSION_EDIT, PERM_CATEGORY_SAFETY, PERMISSION_SET_PARENTAL_CONTROLS},
    {TW_TXN_PARENTAL_CONTROL, PERM_CATEGORY_SAFETY, PERMISSION_SET_PARENTAL_CONTROLS},
    {TW_TXN_CONTENT_FILTER, PERM_CATEGORY_SAFETY, PERMISSION_SET_CONTENT_FILTERS},
    {TW_TXN_LOCATION_UPDATE, PERM_CATEGORY_SAFETY, PERMISSION_TRACK_LOCATION},
    {TW_TXN_EMERGENCY_ALERT, PERM_CATEGORY_SAFETY, PERMISSION_EMERGENCY_ALERT},
    
    // System Management
    {TW_TXN_SYSTEM_CONFIG, PERM_CATEGORY_SYSTEM, PERMISSION_MANAGE_SETTINGS}
};

// Helper function to check if a user has permission for a transaction type
static inline int has_transaction_permission(TW_TransactionType type, uint64_t user_permissions) {
    for (size_t i = 0; i < sizeof(TXN_PERMISSIONS) / sizeof(TXN_PERMISSIONS[0]); i++) {
        if (TXN_PERMISSIONS[i].type == type) {
            return (user_permissions & TXN_PERMISSIONS[i].required_permissions) == 
                   TXN_PERMISSIONS[i].required_permissions;
        }
    }
    return 0; // Unknown transaction type
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

int serialize_parental_control(const TW_TXN_ParentalControl* control, unsigned char** buffer);
int deserialize_parental_control(const unsigned char* buffer, TW_TXN_ParentalControl* control);

int serialize_content_filter(const TW_TXN_ContentFilter* filter, unsigned char** buffer);
int deserialize_content_filter(const unsigned char* buffer, TW_TXN_ContentFilter* filter);

int serialize_location_update(const TW_TXN_LocationUpdate* location, unsigned char** buffer);
int deserialize_location_update(const unsigned char* buffer, TW_TXN_LocationUpdate* location);

int serialize_emergency_alert(const TW_TXN_EmergencyAlert* alert, unsigned char** buffer);
int deserialize_emergency_alert(const unsigned char* buffer, TW_TXN_EmergencyAlert* alert);

int serialize_system_config(const TW_TXN_SystemConfig* config, unsigned char** buffer);
int deserialize_system_config(const unsigned char* buffer, TW_TXN_SystemConfig* config);

#endif // TW_TRANSACTION_TYPES_H 