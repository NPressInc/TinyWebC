#include "location_permissions.h"
#include "packages/sql/permissions.h"
#include "packages/utils/logger.h"
#include "structs/permission/permission.h"
#include <string.h>

bool location_permissions_check_view(const unsigned char requester_pubkey[PUBKEY_SIZE],
                                     const unsigned char user_pubkey[PUBKEY_SIZE]) {
    if (!requester_pubkey || !user_pubkey) {
        return false;
    }
    
    // Rule 1: Requester is the user themselves (SCOPE_SELF)
    if (memcmp(requester_pubkey, user_pubkey, PUBKEY_SIZE) == 0) {
        // Check if requester has PERMISSION_VIEW_LOCATION with SCOPE_SELF
        // (Users should be able to view their own location)
        if (check_user_permission(requester_pubkey, PERMISSION_VIEW_LOCATION, SCOPE_SELF)) {
            return true;
        }
        // Even without explicit permission, users can view their own location
        return true;
    }
    
    // Rule 2: Check if requester has PERMISSION_VIEW_LOCATION with SCOPE_SUPERVISED_USERS
    // (Parents/admins can view location of users they supervise)
    if (check_user_permission(requester_pubkey, PERMISSION_VIEW_LOCATION, SCOPE_SUPERVISED_USERS)) {
        return true;
    }
    
    // Rule 3: Check if requester has PERMISSION_VIEW_LOCATION with SCOPE_GLOBAL
    // (System admins can view any user's location)
    if (check_user_permission(requester_pubkey, PERMISSION_VIEW_LOCATION, SCOPE_GLOBAL)) {
        return true;
    }
    
    // Rule 4: Check if requester has PERMISSION_VIEW_LOCATION with SCOPE_DIRECT
    // (For direct relationships, if both users have appropriate permissions)
    if (check_user_permission(requester_pubkey, PERMISSION_VIEW_LOCATION, SCOPE_DIRECT)) {
        // Additional check: verify the target user has granted permission
        // For now, we allow if requester has the permission (future: check mutual relationship)
        return true;
    }
    
    logger_info("location_permissions", "Requester does not have permission to view location for user");
    return false;
}

bool location_permissions_check_submit(const unsigned char sender_pubkey[PUBKEY_SIZE]) {
    if (!sender_pubkey) {
        return false;
    }
    
    // Rule 1: Sender must be a registered user
    if (!user_exists(sender_pubkey)) {
        logger_info("location_permissions", "Sender is not a registered user");
        return false;
    }
    
    // Rule 2: Users can submit their own location updates
    // (No additional permission check needed - all registered users can submit their location)
    // Future: Could add PERMISSION_TRACK_LOCATION check if we want to restrict who can submit
    
    return true;
}

