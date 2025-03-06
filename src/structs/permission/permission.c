#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "permission.h"

struct TW_Permission {
    char* messageType;
    char* name;
    char* type;
    char* scope;
    char* sender;
    int expirationTime;
};

TW_Permission* TW_Permission_create(const char* messageType, const char* name, const char* type,
                                   const char* scope, const char* sender) {
    TW_Permission* perm = malloc(sizeof(TW_Permission));
    if (perm) {
        perm->messageType = strdup(messageType);
        perm->name = strdup(name);
        perm->type = strdup(type);
        perm->scope = strdup(scope);
        perm->sender = strdup(sender);
        perm->expirationTime = 0;
    }
    return perm;
}

void TW_Permission_set_expirationTime(TW_Permission* perm, int expirationTime) {
    if (perm) perm->expirationTime = expirationTime;
}

int TW_Permission_get_expirationTime(TW_Permission* perm) {
    return perm ? perm->expirationTime : 0;
}

void TW_Permission_destroy(TW_Permission* perm) {
    if (perm) {
        free(perm->messageType);
        free(perm->name);
        free(perm->type);
        free(perm->scope);
        free(perm->sender);
        free(perm);
    }
}