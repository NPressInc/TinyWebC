#ifndef TW_TRANSACTION_H
#define TW_TRANSACTION_H

#include <stddef.h>  // For size_t
#include <stdint.h>
#include "packages/keystore/keystore.h"
#include "packages/encryption/encryption.h"
#include "packages/signing/signing.h"

#define MAX_RECIPIENTS 50       // Max recipients for group messages
#define MAX_PAYLOAD_SIZE_EXTERNAL 4096   // Max payload size
#define GROUP_ID_SIZE 16       // Fixed-size group identifier

typedef enum {
    // ===== MVP (Phase 1) - Core Functionality =====
    // These features form the foundation of the network and are essential for basic operation
    
    // User Management (Core)
    TW_TXN_USER_REGISTRATION,      // Register new user
    TW_TXN_ROLE_ASSIGNMENT,        // Assign roles (parent, child, community member)
    
    // Basic Communication (Core)
    TW_TXN_MESSAGE,                // Direct message
    TW_TXN_GROUP_MESSAGE,          // Group chat message
    
    // Basic Group Management (Core)
    TW_TXN_GROUP_CREATE,           // Create new group
    TW_TXN_GROUP_UPDATE,           // Update group settings
    TW_TXN_GROUP_MEMBER_ADD,       // Add member to group
    TW_TXN_GROUP_MEMBER_REMOVE,    // Remove member from group
    TW_TXN_GROUP_MEMBER_LEAVE,     // Member leaves group
    
    // Basic Safety & Control (Core)
    TW_TXN_PERMISSION_EDIT,        // Modify permissions
    TW_TXN_PARENTAL_CONTROL,       // Update parental control settings
    TW_TXN_CONTENT_FILTER,         // Update content filtering rules
    TW_TXN_LOCATION_UPDATE,        // Location tracking update
    TW_TXN_EMERGENCY_ALERT,        // Emergency notification
    
    // Network Management (Core)
    TW_TXN_SYSTEM_CONFIG,          // Network-wide configuration changes
    
    // Access Control (Core)
    TW_TXN_ACCESS_REQUEST,         // Request access to content/resource
    
    // Invitation Management (Core - Post Genesis)
    TW_TXN_INVITATION_CREATE,      // Create family/node invitation
    TW_TXN_INVITATION_ACCEPT,      // Accept invitation
    TW_TXN_INVITATION_REVOKE,      // Revoke invitation (admin only)
    
    // Proximity-Based Invitations (Enhanced Security)
    TW_TXN_PROXIMITY_INVITATION,   // Create invitation with proximity validation
    TW_TXN_PROXIMITY_VALIDATION,   // Submit proximity proof validation

    // ===== Phase 2 - Enhanced Communication & Media =====
    // These features build on the core functionality and add richer media support
    
    // Voice & Video Calls (Requires real-time communication infrastructure)
    TW_TXN_VOICE_CALL_REQ,         // Voice call request
    TW_TXN_VIDEO_CALL_REQ,         // Video call request
    
    // Media & Content (Requires media storage and streaming infrastructure)
    TW_TXN_MEDIA_DOWNLOAD,         // Media download request
    TW_TXN_CONTENT_ACCESS_UPDATE,  // Update content access permissions
    TW_TXN_CREATION_UPLOAD,        // Upload user-created content
    TW_TXN_CREATION_SHARE_REQUEST, // Request to share created content

    // ===== Phase 3 - Educational & Family Features =====
    // These features add educational and family management capabilities
    
    // Educational Features (Requires content management system)
    TW_TXN_EDUCATIONAL_RESOURCE_ADD, // Add educational content
    TW_TXN_CHALLENGE_COMPLETE,     // Mark educational challenge as complete
    TW_TXN_BOOK_ADD_TO_LIBRARY,    // Add book to digital library
    
    // Family Management (Requires reward system)
    TW_TXN_CHORE_ASSIGN,           // Assign chore to child
    TW_TXN_CHORE_COMPLETE,         // Mark chore as complete
    TW_TXN_REWARD_DISTRIBUTE,      // Distribute rewards/points

    // ===== Phase 4 - Advanced Features =====
    // These features add sophisticated functionality and require more complex infrastructure
    
    // Location & Safety (Requires geofencing system)
    TW_TXN_GEOFENCE_CREATE,        // Create geofenced area
    TW_TXN_GEOFENCE_CONFIG_UPDATE, // Update geofence settings/alerts
    
    // Usage Control (Requires device management system)
    TW_TXN_USAGE_POLICY_UPDATE,    // Update device usage schedules/quiet times
    
    // Multiplayer Games (Requires game server infrastructure)
    TW_TXN_GAME_SESSION_START,     // Start a multiplayer game session
    TW_TXN_GAME_PERMISSION_UPDATE, // Update game permissions
    
    // Community & Events (Requires event management system)
    TW_TXN_EVENT_CREATE,           // Create family/community event
    TW_TXN_EVENT_INVITE,           // Invite to event
    TW_TXN_EVENT_RSVP,             // Respond to event invitation
    TW_TXN_COMMUNITY_POST_CREATE,  // Create community bulletin board post
    
    // Shared Content (Requires advanced media sharing system)
    TW_TXN_SHARED_ALBUM_CREATE,    // Create shared photo/video album
    TW_TXN_MEDIA_ADD_TO_ALBUM_REQUEST, // Request to add media to shared album
    TW_TXN_COLLABORATIVE_PROJECT_CREATE, // Create collaborative project
    
    // Count of transaction types (must be last)
    TW_TXN_TYPE_COUNT
} TW_TransactionType;

typedef struct {
    TW_TransactionType type;
    unsigned char sender[PUBKEY_SIZE];
    uint64_t timestamp;
    unsigned char* recipients; // pubkey size * max recipients is max size
    uint8_t recipient_count;
    unsigned char group_id[GROUP_ID_SIZE];
    EncryptedPayload* payload;
    size_t payload_size;
    unsigned char signature[SIGNATURE_SIZE];       // Set externally
} TW_Transaction;

// Basic functions
TW_Transaction* TW_Transaction_create(TW_TransactionType type, const unsigned char* sender, 
                                     const unsigned char* recipients, uint8_t recipient_count, 
                                     const unsigned char* group_id, const EncryptedPayload* payload, 
                                     const unsigned char* signature);
void TW_Transaction_destroy(TW_Transaction* tx);

size_t TW_Transaction_get_size(const TW_Transaction* tx);
void TW_Transaction_hash(TW_Transaction* tx, unsigned char* hash_out);

int TW_Transaction_serialize(TW_Transaction* tx, unsigned char** out_buffer);
TW_Transaction* TW_Transaction_deserialize(const unsigned char* buffer, size_t buffer_size);

void TW_Transaction_add_signature(TW_Transaction* txn);

#endif