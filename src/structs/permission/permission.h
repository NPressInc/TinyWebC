#ifndef TW_PERMISSION_H
#define TW_PERMISSION_H

#include <stdint.h>

// Role Permission Bit Flags (32-bit)
// Basic Communication & Group Permissions (0-7)
#define PERMISSION_SEND_MESSAGE     (1U << 0)  // Can send direct messages
#define PERMISSION_CREATE_GROUP     (1U << 1)  // Can create new groups
#define PERMISSION_INVITE_USERS     (1U << 2)  // Can invite users to groups
#define PERMISSION_REMOVE_USERS     (1U << 3)  // Can remove users from groups
#define PERMISSION_EDIT_GROUP       (1U << 4)  // Can edit group settings
#define PERMISSION_VIEW_LOCATION    (1U << 5)  // Can view other users' locations
#define PERMISSION_SET_CONTROLS     (1U << 6)  // Can set parental controls
#define PERMISSION_EMERGENCY_ALERT  (1U << 7)  // Can send emergency alerts

// Content & Media Permissions (8-15)
#define PERMISSION_CREATE_CONTENT   (1U << 8)  // Can create and share content
#define PERMISSION_SHARE_MEDIA      (1U << 9)  // Can share photos/videos
#define PERMISSION_ACCESS_MEDIA     (1U << 10) // Can access shared media
#define PERMISSION_CREATE_ALBUM     (1U << 11) // Can create shared albums
#define PERMISSION_EDIT_CONTENT     (1U << 12) // Can edit shared content
#define PERMISSION_DELETE_CONTENT   (1U << 13) // Can delete shared content
#define PERMISSION_MODERATE_CONTENT (1U << 14) // Can moderate content
#define PERMISSION_ACCESS_LIBRARY   (1U << 15) // Can access digital library

// Educational & Learning Permissions (16-23)
#define PERMISSION_ACCESS_EDUCATION (1U << 16) // Can access educational content
#define PERMISSION_CREATE_CHALLENGE (1U << 17) // Can create learning challenges
#define PERMISSION_COMPLETE_CHALLENGE (1U << 18) // Can complete challenges
#define PERMISSION_TRACK_PROGRESS   (1U << 19) // Can track learning progress
#define PERMISSION_ACCESS_GAMES     (1U << 20) // Can access educational games
#define PERMISSION_CREATE_GAME      (1U << 21) // Can create game sessions
#define PERMISSION_JOIN_GAME        (1U << 22) // Can join game sessions
#define PERMISSION_LEAD_ACTIVITY    (1U << 23) // Can lead group activities

// Family & Community Permissions (24-31)
#define PERMISSION_CREATE_EVENT     (1U << 24) // Can create family events
#define PERMISSION_INVITE_TO_EVENT  (1U << 25) // Can invite to events
#define PERMISSION_VIEW_CALENDAR    (1U << 26) // Can view family calendar
#define PERMISSION_EDIT_CALENDAR    (1U << 27) // Can edit family calendar
#define PERMISSION_CREATE_CHORE     (1U << 28) // Can create chores
#define PERMISSION_ASSIGN_CHORE     (1U << 29) // Can assign chores
#define PERMISSION_VIEW_REWARDS     (1U << 30) // Can view reward system
#define PERMISSION_MANAGE_REWARDS   (1U << 31) // Can manage rewards

// Predefined role permission sets
#define ROLE_PERMISSIONS_PARENT     (PERMISSION_SEND_MESSAGE | PERMISSION_CREATE_GROUP | \
                                    PERMISSION_INVITE_USERS | PERMISSION_REMOVE_USERS | \
                                    PERMISSION_EDIT_GROUP | PERMISSION_VIEW_LOCATION | \
                                    PERMISSION_SET_CONTROLS | PERMISSION_EMERGENCY_ALERT | \
                                    PERMISSION_CREATE_CONTENT | PERMISSION_SHARE_MEDIA | \
                                    PERMISSION_ACCESS_MEDIA | PERMISSION_CREATE_ALBUM | \
                                    PERMISSION_EDIT_CONTENT | PERMISSION_DELETE_CONTENT | \
                                    PERMISSION_MODERATE_CONTENT | PERMISSION_ACCESS_LIBRARY | \
                                    PERMISSION_ACCESS_EDUCATION | PERMISSION_CREATE_CHALLENGE | \
                                    PERMISSION_TRACK_PROGRESS | PERMISSION_ACCESS_GAMES | \
                                    PERMISSION_CREATE_GAME | PERMISSION_LEAD_ACTIVITY | \
                                    PERMISSION_CREATE_EVENT | PERMISSION_INVITE_TO_EVENT | \
                                    PERMISSION_VIEW_CALENDAR | PERMISSION_EDIT_CALENDAR | \
                                    PERMISSION_CREATE_CHORE | PERMISSION_ASSIGN_CHORE | \
                                    PERMISSION_VIEW_REWARDS | PERMISSION_MANAGE_REWARDS)

#define ROLE_PERMISSIONS_CHILD      (PERMISSION_SEND_MESSAGE | PERMISSION_EMERGENCY_ALERT | \
                                    PERMISSION_CREATE_CONTENT | PERMISSION_SHARE_MEDIA | \
                                    PERMISSION_ACCESS_MEDIA | PERMISSION_ACCESS_LIBRARY | \
                                    PERMISSION_ACCESS_EDUCATION | PERMISSION_COMPLETE_CHALLENGE | \
                                    PERMISSION_ACCESS_GAMES | PERMISSION_JOIN_GAME | \
                                    PERMISSION_VIEW_CALENDAR)

#define ROLE_PERMISSIONS_COMMUNITY  (PERMISSION_SEND_MESSAGE | PERMISSION_VIEW_LOCATION | \
                                    PERMISSION_EMERGENCY_ALERT | PERMISSION_CREATE_CONTENT | \
                                    PERMISSION_SHARE_MEDIA | PERMISSION_ACCESS_MEDIA | \
                                    PERMISSION_ACCESS_LIBRARY | PERMISSION_ACCESS_EDUCATION | \
                                    PERMISSION_CREATE_CHALLENGE | PERMISSION_ACCESS_GAMES | \
                                    PERMISSION_JOIN_GAME | PERMISSION_LEAD_ACTIVITY | \
                                    PERMISSION_VIEW_CALENDAR)

// Helper functions for permission management
static inline int has_permission(uint32_t permissions, uint32_t permission) {
    return (permissions & permission) != 0;
}

static inline void add_permission(uint32_t* permissions, uint32_t permission) {
    *permissions |= permission;
}

static inline void remove_permission(uint32_t* permissions, uint32_t permission) {
    *permissions &= ~permission;
}

#endif // TW_PERMISSION_H 