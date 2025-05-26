#ifndef TW_PERMISSION_H
#define TW_PERMISSION_H

#include <stdint.h>

// Role Permission Bit Flags (64-bit)
// Core Family Communication (0-15)
#define PERMISSION_DIRECT_MESSAGE     (1ULL << 0)  // Can send direct messages to family members
#define PERMISSION_FAMILY_GROUP_MSG   (1ULL << 1)  // Can send messages in family groups
#define PERMISSION_EXTENDED_FAMILY_MSG (1ULL << 2) // Can message extended family
#define PERMISSION_FRIEND_GROUP_MSG   (1ULL << 3)  // Can message in friend groups
#define PERMISSION_COMMUNITY_MSG      (1ULL << 4)  // Can message in community groups
#define PERMISSION_EMERGENCY_ALERT    (1ULL << 5)  // Can send emergency alerts
#define PERMISSION_VIEW_FAMILY_STATUS (1ULL << 6)  // Can view family member status/activity
#define PERMISSION_VIEW_EXTENDED_STATUS (1ULL << 7) // Can view extended family status
#define PERMISSION_VIEW_FRIEND_STATUS (1ULL << 8)  // Can view friend status
#define PERMISSION_VIEW_COMMUNITY_STATUS (1ULL << 9) // Can view community status
// Reserved for future family communication (10-15)

// Group Management (16-31)
#define PERMISSION_CREATE_FAMILY_GROUP (1ULL << 16) // Can create family groups
#define PERMISSION_CREATE_FRIEND_GROUP (1ULL << 17) // Can create friend groups
#define PERMISSION_CREATE_COMMUNITY_GROUP (1ULL << 18) // Can create community groups
#define PERMISSION_INVITE_FAMILY      (1ULL << 19) // Can invite to family groups
#define PERMISSION_INVITE_FRIENDS     (1ULL << 20) // Can invite friends to groups
#define PERMISSION_INVITE_COMMUNITY   (1ULL << 21) // Can invite community members
#define PERMISSION_REMOVE_FAMILY      (1ULL << 22) // Can remove from family groups
#define PERMISSION_REMOVE_FRIENDS     (1ULL << 23) // Can remove from friend groups
#define PERMISSION_REMOVE_COMMUNITY   (1ULL << 24) // Can remove from community groups
#define PERMISSION_EDIT_FAMILY_GROUP  (1ULL << 25) // Can edit family group settings
#define PERMISSION_EDIT_FRIEND_GROUP  (1ULL << 26) // Can edit friend group settings
#define PERMISSION_EDIT_COMMUNITY_GROUP (1ULL << 27) // Can edit community group settings
// Reserved for future group management (28-31)

// Safety & Control (32-47)
#define PERMISSION_SET_PARENTAL_CONTROLS (1ULL << 32) // Can set parental controls
#define PERMISSION_VIEW_PARENTAL_CONTROLS (1ULL << 33) // Can view parental controls
#define PERMISSION_SET_CONTENT_FILTERS (1ULL << 34) // Can set content filters
#define PERMISSION_VIEW_CONTENT_FILTERS (1ULL << 35) // Can view content filters
#define PERMISSION_TRACK_LOCATION    (1ULL << 36) // Can track family location
#define PERMISSION_VIEW_LOCATION     (1ULL << 37) // Can view location data
#define PERMISSION_MANAGE_FRIENDS    (1ULL << 38) // Can manage child's friends
#define PERMISSION_APPROVE_FRIENDS   (1ULL << 39) // Can approve new friends
#define PERMISSION_MONITOR_ACTIVITY  (1ULL << 40) // Can monitor activity
#define PERMISSION_SET_BOUNDARIES    (1ULL << 41) // Can set communication boundaries
// Reserved for future safety features (42-47)

// System Management (48-63)
#define PERMISSION_MANAGE_ROLES      (1ULL << 48) // Can manage user roles
#define PERMISSION_VIEW_LOGS         (1ULL << 49) // Can view system logs
#define PERMISSION_MANAGE_SETTINGS   (1ULL << 50) // Can manage system settings
#define PERMISSION_VIEW_SETTINGS     (1ULL << 51) // Can view system settings
// Reserved for future system management (52-63)

// Predefined role permission sets
#define ROLE_PERMISSIONS_PARENT     (PERMISSION_DIRECT_MESSAGE | PERMISSION_FAMILY_GROUP_MSG | \
                                    PERMISSION_EXTENDED_FAMILY_MSG | PERMISSION_FRIEND_GROUP_MSG | \
                                    PERMISSION_COMMUNITY_MSG | PERMISSION_EMERGENCY_ALERT | \
                                    PERMISSION_VIEW_FAMILY_STATUS | PERMISSION_VIEW_EXTENDED_STATUS | \
                                    PERMISSION_VIEW_FRIEND_STATUS | PERMISSION_VIEW_COMMUNITY_STATUS | \
                                    PERMISSION_CREATE_FAMILY_GROUP | PERMISSION_CREATE_FRIEND_GROUP | \
                                    PERMISSION_CREATE_COMMUNITY_GROUP | PERMISSION_INVITE_FAMILY | \
                                    PERMISSION_INVITE_FRIENDS | PERMISSION_INVITE_COMMUNITY | \
                                    PERMISSION_REMOVE_FAMILY | PERMISSION_REMOVE_FRIENDS | \
                                    PERMISSION_REMOVE_COMMUNITY | PERMISSION_EDIT_FAMILY_GROUP | \
                                    PERMISSION_EDIT_FRIEND_GROUP | PERMISSION_EDIT_COMMUNITY_GROUP | \
                                    PERMISSION_SET_PARENTAL_CONTROLS | PERMISSION_VIEW_PARENTAL_CONTROLS | \
                                    PERMISSION_SET_CONTENT_FILTERS | PERMISSION_VIEW_CONTENT_FILTERS | \
                                    PERMISSION_TRACK_LOCATION | PERMISSION_VIEW_LOCATION | \
                                    PERMISSION_MANAGE_FRIENDS | PERMISSION_APPROVE_FRIENDS | \
                                    PERMISSION_MONITOR_ACTIVITY | PERMISSION_SET_BOUNDARIES | \
                                    PERMISSION_MANAGE_ROLES | PERMISSION_VIEW_LOGS | \
                                    PERMISSION_MANAGE_SETTINGS | PERMISSION_VIEW_SETTINGS)

#define ROLE_PERMISSIONS_CHILD      (PERMISSION_DIRECT_MESSAGE | PERMISSION_FAMILY_GROUP_MSG | \
                                    PERMISSION_FRIEND_GROUP_MSG | PERMISSION_EMERGENCY_ALERT | \
                                    PERMISSION_VIEW_FAMILY_STATUS | PERMISSION_VIEW_FRIEND_STATUS | \
                                    PERMISSION_VIEW_LOCATION)

#define ROLE_PERMISSIONS_FRIEND     (PERMISSION_DIRECT_MESSAGE | PERMISSION_FRIEND_GROUP_MSG | \
                                    PERMISSION_EMERGENCY_ALERT | PERMISSION_VIEW_FRIEND_STATUS)

#define ROLE_PERMISSIONS_COMMUNITY  (PERMISSION_COMMUNITY_MSG | PERMISSION_EMERGENCY_ALERT | \
                                    PERMISSION_VIEW_COMMUNITY_STATUS)

// Helper functions for permission management
static inline int has_permission(uint64_t permissions, uint64_t permission) {
    return (permissions & permission) != 0;
}

static inline void add_permission(uint64_t* permissions, uint64_t permission) {
    *permissions |= permission;
}

static inline void remove_permission(uint64_t* permissions, uint64_t permission) {
    *permissions &= ~permission;
}

#endif // TW_PERMISSION_H 