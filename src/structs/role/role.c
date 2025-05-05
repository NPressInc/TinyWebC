#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "role.h"

struct TW_RoleDef {
    char* messageType;
    char* name;
    char* sender;
    char** permissionNames;
    int permissionCount;
    int version;
};

TW_RoleDef* TW_RoleDef_create(const char* messageType, const char* name, const char* sender,
                             const char** permissionNames, int permissionCount) {
    TW_RoleDef* role = malloc(sizeof(TW_RoleDef));
    if (role) {
        role->messageType = strdup(messageType);
        role->name = strdup(name);
        role->sender = strdup(sender);
        role->permissionNames = malloc(permissionCount * sizeof(char*));
        for (int i = 0; i < permissionCount; i++) role->permissionNames[i] = strdup(permissionNames[i]);
        role->permissionCount = permissionCount;
        role->version = 0;
    }
    return role;
}

void TW_RoleDef_set_version(TW_RoleDef* role, int version) {
    if (role) role->version = version;
}

int TW_RoleDef_get_version(TW_RoleDef* role) {
    return role ? role->version : 0;
}

void TW_RoleDef_destroy(TW_RoleDef* role) {
    if (role) {
        free(role->messageType);
        free(role->name);
        free(role->sender);
        for (int i = 0; i < role->permissionCount; i++) free(role->permissionNames[i]);
        free(role->permissionNames);
        free(role);
    }
}

struct TW_RoleAssignment {
    char* messageType;
    char* user;
    char* roleName;
    char* groupId;
    char* sender;
    int assignedTime;
};

TW_RoleAssignment* TW_RoleAssignment_create(const char* messageType, const char* user,
                                           const char* roleName, const char* groupId, const char* sender) {
    TW_RoleAssignment* assign = malloc(sizeof(TW_RoleAssignment));
    if (assign) {
        assign->messageType = strdup(messageType);
        assign->user = strdup(user);
        assign->roleName = strdup(roleName);
        assign->groupId = strdup(groupId);
        assign->sender = strdup(sender);
        assign->assignedTime = 0;
    }
    return assign;
}

void TW_RoleAssignment_set_assignedTime(TW_RoleAssignment* assign, int assignedTime) {
    if (assign) assign->assignedTime = assignedTime;
}

int TW_RoleAssignment_get_assignedTime(TW_RoleAssignment* assign) {
    return assign ? assign->assignedTime : 0;
}

void TW_RoleAssignment_destroy(TW_RoleAssignment* assign) {
    if (assign) {
        free(assign->messageType);
        free(assign->user);
        free(assign->roleName);
        free(assign->groupId);
        free(assign->sender);
        free(assign);
    }
}