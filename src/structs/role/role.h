#ifndef TW_ROLE_H
#define TW_ROLE_H

typedef struct TW_RoleDef TW_RoleDef;
typedef struct TW_RoleAssignment TW_RoleAssignment;

TW_RoleDef* TW_RoleDef_create(const char* messageType, const char* name, const char* sender,
                             const char** permissionNames, int permissionCount);
void TW_RoleDef_set_version(TW_RoleDef* role, int version);
int TW_RoleDef_get_version(TW_RoleDef* role);
void TW_RoleDef_destroy(TW_RoleDef* role);

TW_RoleAssignment* TW_RoleAssignment_create(const char* messageType, const char* user,
                                           const char* roleName, const char* groupId, const char* sender);
void TW_RoleAssignment_set_assignedTime(TW_RoleAssignment* assign, int assignedTime);
int TW_RoleAssignment_get_assignedTime(TW_RoleAssignment* assign);
void TW_RoleAssignment_destroy(TW_RoleAssignment* assign);

#endif