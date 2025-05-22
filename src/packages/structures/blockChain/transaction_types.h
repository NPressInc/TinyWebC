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

// User Management Structs
typedef struct {
    char username[MAX_USERNAME_LENGTH];
    uint8_t age;
    // Additional user metadata can be added here
} TW_TXN_UserRegistration;

typedef struct {
    char role_name[MAX_ROLE_NAME_LENGTH];
    uint32_t permissions;  // Bit flags for role permissions (32 bits)
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