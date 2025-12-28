#ifndef PERMISSIONS_H
#define PERMISSIONS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "structs/permission/permission.h"

// Load all active roles for a user from the database
// user_pubkey: 32-byte Ed25519 public key (hex encoded in DB)
// out_roles: Pointer to array of Role pointers (caller must free)
// out_count: Number of roles loaded
// Returns 0 on success, -1 on error
// Caller must call destroy_role() for each role and free the array
int load_user_roles(const unsigned char* user_pubkey, Role** out_roles, size_t* out_count);

// Load all permission sets for a role from the database
// role_id: Database ID of the role
// out_sets: Pointer to array of PermissionSets (caller must free)
// out_count: Number of permission sets loaded
// Returns 0 on success, -1 on error
// Caller must free the PermissionSet array
int load_role_permission_sets(int role_id, PermissionSet** out_sets, size_t* out_count);

// Check if a user has a specific permission in a specific scope
// user_pubkey: 32-byte Ed25519 public key
// permission: Permission flag (e.g., PERMISSION_SEND_MESSAGE)
// scope: Scope to check (e.g., SCOPE_DIRECT)
// Returns true if user has permission, false otherwise
bool check_user_permission(const unsigned char* user_pubkey, uint64_t permission, permission_scope_t scope);

// Free an array of roles
// roles: Array of Role pointers
// count: Number of roles in array
void free_role_array(Role* roles, size_t count);

// Check if a user exists in the database (is registered)
// user_pubkey: 32-byte Ed25519 public key
// Returns true if user exists and is active, false otherwise
bool user_exists(const unsigned char* user_pubkey);

#endif // PERMISSIONS_H

