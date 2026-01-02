#ifndef LOCATION_PERMISSIONS_H
#define LOCATION_PERMISSIONS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef PUBKEY_SIZE
#define PUBKEY_SIZE 32
#endif

// Check if a requester has permission to view a user's location
// Rules:
// 1. Requester is the user themselves (SCOPE_SELF)
// 2. Requester is admin/parent (has PERMISSION_VIEW_LOCATION with SCOPE_SUPERVISED_USERS or SCOPE_GLOBAL)
// 3. Requester has PERMISSION_VIEW_LOCATION with appropriate scope
// Returns true if requester has permission, false otherwise
bool location_permissions_check_view(const unsigned char requester_pubkey[PUBKEY_SIZE],
                                     const unsigned char user_pubkey[PUBKEY_SIZE]);

// Check if a sender has permission to submit location updates
// Rules:
// 1. Sender must be the user themselves (can only submit their own location)
// 2. Sender must be a registered user
// Returns true if sender has permission, false otherwise
bool location_permissions_check_submit(const unsigned char sender_pubkey[PUBKEY_SIZE]);

#endif // LOCATION_PERMISSIONS_H

