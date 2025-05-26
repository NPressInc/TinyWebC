#include <stdlib.h>
#include <string.h>
#include "transaction_types.h"

// Helper function to safely copy strings
static void safe_strncpy(char* dest, const char* src, size_t max_len) {
    strncpy(dest, src, max_len - 1);
    dest[max_len - 1] = '\0';
}

// User Registration
int serialize_user_registration(const TW_TXN_UserRegistration* reg, unsigned char** buffer) {
    if (!reg || !buffer) return -1;
    
    size_t size = MAX_USERNAME_LENGTH + sizeof(uint8_t);
    *buffer = (unsigned char*)malloc(size);
    if (!*buffer) return -1;
    
    unsigned char* ptr = *buffer;
    memcpy(ptr, reg->username, MAX_USERNAME_LENGTH);
    ptr += MAX_USERNAME_LENGTH;
    memcpy(ptr, &reg->age, sizeof(uint8_t));
    
    return size;
}

int deserialize_user_registration(const unsigned char* buffer, TW_TXN_UserRegistration* reg) {
    if (!buffer || !reg) return -1;
    
    const unsigned char* ptr = buffer;
    memcpy(reg->username, ptr, MAX_USERNAME_LENGTH);
    ptr += MAX_USERNAME_LENGTH;
    memcpy(&reg->age, ptr, sizeof(uint8_t));
    
    return MAX_USERNAME_LENGTH + sizeof(uint8_t);
}

// Role Assignment
int serialize_role_assignment(const TW_TXN_RoleAssignment* role, unsigned char** buffer) {
    if (!role || !buffer) return -1;
    
    size_t size = MAX_ROLE_NAME_LENGTH + sizeof(uint64_t);
    *buffer = (unsigned char*)malloc(size);
    if (!*buffer) return -1;
    
    unsigned char* ptr = *buffer;
    memcpy(ptr, role->role_name, MAX_ROLE_NAME_LENGTH);
    ptr += MAX_ROLE_NAME_LENGTH;
    memcpy(ptr, &role->permissions, sizeof(uint64_t));
    
    return size;
}

int deserialize_role_assignment(const unsigned char* buffer, TW_TXN_RoleAssignment* role) {
    if (!buffer || !role) return -1;
    
    const unsigned char* ptr = buffer;
    memcpy(role->role_name, ptr, MAX_ROLE_NAME_LENGTH);
    ptr += MAX_ROLE_NAME_LENGTH;
    memcpy(&role->permissions, ptr, sizeof(uint64_t));
    
    return MAX_ROLE_NAME_LENGTH + sizeof(uint64_t);
}

// Group Create
int serialize_group_create(const TW_TXN_GroupCreate* group, unsigned char** buffer) {
    if (!group || !buffer) return -1;
    
    size_t size = MAX_GROUP_NAME_LENGTH + 2 * sizeof(uint8_t);
    *buffer = (unsigned char*)malloc(size);
    if (!*buffer) return -1;
    
    unsigned char* ptr = *buffer;
    memcpy(ptr, group->group_name, MAX_GROUP_NAME_LENGTH);
    ptr += MAX_GROUP_NAME_LENGTH;
    memcpy(ptr, &group->group_type, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    memcpy(ptr, &group->default_permissions, sizeof(uint8_t));
    
    return size;
}

int deserialize_group_create(const unsigned char* buffer, TW_TXN_GroupCreate* group) {
    if (!buffer || !group) return -1;
    
    const unsigned char* ptr = buffer;
    memcpy(group->group_name, ptr, MAX_GROUP_NAME_LENGTH);
    ptr += MAX_GROUP_NAME_LENGTH;
    memcpy(&group->group_type, ptr, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    memcpy(&group->default_permissions, ptr, sizeof(uint8_t));
    
    return MAX_GROUP_NAME_LENGTH + 2 * sizeof(uint8_t);
}

// Group Update
int serialize_group_update(const TW_TXN_GroupUpdate* update, unsigned char** buffer) {
    if (!update || !buffer) return -1;
    
    size_t size = 2 * sizeof(uint8_t);
    *buffer = (unsigned char*)malloc(size);
    if (!*buffer) return -1;
    
    unsigned char* ptr = *buffer;
    memcpy(ptr, &update->setting_type, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    memcpy(ptr, &update->new_value, sizeof(uint8_t));
    
    return size;
}

int deserialize_group_update(const unsigned char* buffer, TW_TXN_GroupUpdate* update) {
    if (!buffer || !update) return -1;
    
    const unsigned char* ptr = buffer;
    memcpy(&update->setting_type, ptr, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    memcpy(&update->new_value, ptr, sizeof(uint8_t));
    
    return 2 * sizeof(uint8_t);
}

// Permission Edit
int serialize_permission_edit(const TW_TXN_PermissionEdit* perm, unsigned char** buffer) {
    if (!perm || !buffer) return -1;
    
    size_t size = MAX_PERMISSION_NAME_LENGTH + sizeof(uint8_t);
    *buffer = (unsigned char*)malloc(size);
    if (!*buffer) return -1;
    
    unsigned char* ptr = *buffer;
    memcpy(ptr, perm->permission_name, MAX_PERMISSION_NAME_LENGTH);
    ptr += MAX_PERMISSION_NAME_LENGTH;
    memcpy(ptr, &perm->permission_value, sizeof(uint8_t));
    
    return size;
}

int deserialize_permission_edit(const unsigned char* buffer, TW_TXN_PermissionEdit* perm) {
    if (!buffer || !perm) return -1;
    
    const unsigned char* ptr = buffer;
    memcpy(perm->permission_name, ptr, MAX_PERMISSION_NAME_LENGTH);
    ptr += MAX_PERMISSION_NAME_LENGTH;
    memcpy(&perm->permission_value, ptr, sizeof(uint8_t));
    
    return MAX_PERMISSION_NAME_LENGTH + sizeof(uint8_t);
}

// Parental Control
int serialize_parental_control(const TW_TXN_ParentalControl* control, unsigned char** buffer) {
    if (!control || !buffer) return -1;
    
    size_t size = 2 * sizeof(uint8_t);
    *buffer = (unsigned char*)malloc(size);
    if (!*buffer) return -1;
    
    unsigned char* ptr = *buffer;
    memcpy(ptr, &control->control_type, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    memcpy(ptr, &control->control_value, sizeof(uint8_t));
    
    return size;
}

int deserialize_parental_control(const unsigned char* buffer, TW_TXN_ParentalControl* control) {
    if (!buffer || !control) return -1;
    
    const unsigned char* ptr = buffer;
    memcpy(&control->control_type, ptr, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    memcpy(&control->control_value, ptr, sizeof(uint8_t));
    
    return 2 * sizeof(uint8_t);
}

// Content Filter
int serialize_content_filter(const TW_TXN_ContentFilter* filter, unsigned char** buffer) {
    if (!filter || !buffer) return -1;
    
    size_t size = MAX_CONTENT_FILTER_RULE_LENGTH + 2 * sizeof(uint8_t);
    *buffer = (unsigned char*)malloc(size);
    if (!*buffer) return -1;
    
    unsigned char* ptr = *buffer;
    memcpy(ptr, filter->rule, MAX_CONTENT_FILTER_RULE_LENGTH);
    ptr += MAX_CONTENT_FILTER_RULE_LENGTH;
    memcpy(ptr, &filter->rule_type, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    memcpy(ptr, &filter->rule_action, sizeof(uint8_t));
    
    return size;
}

int deserialize_content_filter(const unsigned char* buffer, TW_TXN_ContentFilter* filter) {
    if (!buffer || !filter) return -1;
    
    const unsigned char* ptr = buffer;
    memcpy(filter->rule, ptr, MAX_CONTENT_FILTER_RULE_LENGTH);
    ptr += MAX_CONTENT_FILTER_RULE_LENGTH;
    memcpy(&filter->rule_type, ptr, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    memcpy(&filter->rule_action, ptr, sizeof(uint8_t));
    
    return MAX_CONTENT_FILTER_RULE_LENGTH + 2 * sizeof(uint8_t);
}

// Location Update
int serialize_location_update(const TW_TXN_LocationUpdate* location, unsigned char** buffer) {
    if (!location || !buffer) return -1;
    
    size_t size = 2 * sizeof(double) + sizeof(uint64_t) + sizeof(uint8_t);
    *buffer = (unsigned char*)malloc(size);
    if (!*buffer) return -1;
    
    unsigned char* ptr = *buffer;
    memcpy(ptr, &location->latitude, sizeof(double));
    ptr += sizeof(double);
    memcpy(ptr, &location->longitude, sizeof(double));
    ptr += sizeof(double);
    memcpy(ptr, &location->timestamp, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    memcpy(ptr, &location->accuracy, sizeof(uint8_t));
    
    return size;
}

int deserialize_location_update(const unsigned char* buffer, TW_TXN_LocationUpdate* location) {
    if (!buffer || !location) return -1;
    
    const unsigned char* ptr = buffer;
    memcpy(&location->latitude, ptr, sizeof(double));
    ptr += sizeof(double);
    memcpy(&location->longitude, ptr, sizeof(double));
    ptr += sizeof(double);
    memcpy(&location->timestamp, ptr, sizeof(uint64_t));
    ptr += sizeof(uint64_t);
    memcpy(&location->accuracy, ptr, sizeof(uint8_t));
    
    return 2 * sizeof(double) + sizeof(uint64_t) + sizeof(uint8_t);
}

// Emergency Alert
int serialize_emergency_alert(const TW_TXN_EmergencyAlert* alert, unsigned char** buffer) {
    if (!alert || !buffer) return -1;
    
    size_t size = sizeof(uint8_t) + 128;  // alert_type + message
    *buffer = (unsigned char*)malloc(size);
    if (!*buffer) return -1;
    
    unsigned char* ptr = *buffer;
    memcpy(ptr, &alert->alert_type, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    memcpy(ptr, alert->message, 128);
    
    return size;
}

int deserialize_emergency_alert(const unsigned char* buffer, TW_TXN_EmergencyAlert* alert) {
    if (!buffer || !alert) return -1;
    
    const unsigned char* ptr = buffer;
    memcpy(&alert->alert_type, ptr, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    memcpy(alert->message, ptr, 128);
    
    return sizeof(uint8_t) + 128;
}

// System Config
int serialize_system_config(const TW_TXN_SystemConfig* config, unsigned char** buffer) {
    if (!config || !buffer) return -1;
    
    size_t size = 2 * sizeof(uint8_t);
    *buffer = (unsigned char*)malloc(size);
    if (!*buffer) return -1;
    
    unsigned char* ptr = *buffer;
    memcpy(ptr, &config->config_type, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    memcpy(ptr, &config->config_value, sizeof(uint8_t));
    
    return size;
}

int deserialize_system_config(const unsigned char* buffer, TW_TXN_SystemConfig* config) {
    if (!buffer || !config) return -1;
    
    const unsigned char* ptr = buffer;
    memcpy(&config->config_type, ptr, sizeof(uint8_t));
    ptr += sizeof(uint8_t);
    memcpy(&config->config_value, ptr, sizeof(uint8_t));
    
    return 2 * sizeof(uint8_t);
} 