#ifndef TW_PERMISSION_H
#define TW_PERMISSION_H

typedef struct TW_Permission TW_Permission;

TW_Permission* TW_Permission_create(const char* messageType, const char* name, const char* type,
                                   const char* scope, const char* sender);
void TW_Permission_set_expirationTime(TW_Permission* perm, int expirationTime);
int TW_Permission_get_expirationTime(TW_Permission* perm);
void TW_Permission_destroy(TW_Permission* perm);

#endif