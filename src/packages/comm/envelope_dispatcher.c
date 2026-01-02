#include "envelope_dispatcher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "packages/encryption/encryption.h"
#include "packages/keystore/keystore.h"
#include "packages/sql/permissions.h"
#include "packages/sql/location_store.h"
#include "packages/utils/logger.h"
#include "structs/permission/permission.h"

#define MAX_HANDLERS 256

typedef struct {
    EnvelopeContentHandler handler;
    uint32_t content_type;
} HandlerEntry;

static HandlerEntry g_handlers[MAX_HANDLERS];
static size_t g_handler_count = 0;
static pthread_mutex_t g_handler_lock = PTHREAD_MUTEX_INITIALIZER;

// Forward declarations for default handlers
static int handle_location_update(const Tinyweb__Envelope* envelope, const unsigned char* payload, size_t payload_len, void* context);
static int handle_emergency_alert(const Tinyweb__Envelope* envelope, const unsigned char* payload, size_t payload_len, void* context);

// Forward declaration for internal handler registration (doesn't lock)
static int envelope_register_handler_internal(uint32_t content_type, EnvelopeContentHandler handler);

int envelope_dispatcher_init(void) {
    pthread_mutex_lock(&g_handler_lock);
    
    // Register default handlers for MVP content types
    g_handler_count = 0;
    
    // Safety handlers
    envelope_register_handler_internal(TINYWEB__CONTENT_TYPE__CONTENT_LOCATION_UPDATE, handle_location_update);
    envelope_register_handler_internal(TINYWEB__CONTENT_TYPE__CONTENT_EMERGENCY_ALERT, handle_emergency_alert);
    
    pthread_mutex_unlock(&g_handler_lock);
    return 0;
}

void envelope_dispatcher_cleanup(void) {
    pthread_mutex_lock(&g_handler_lock);
    g_handler_count = 0;
    memset(g_handlers, 0, sizeof(g_handlers));
    pthread_mutex_unlock(&g_handler_lock);
}

// Internal version that doesn't lock (assumes lock is already held)
static int envelope_register_handler_internal(uint32_t content_type, EnvelopeContentHandler handler) {
    if (!handler) {
        return -1;
    }
    
    // Check if handler already exists for this content type
    for (size_t i = 0; i < g_handler_count; i++) {
        if (g_handlers[i].content_type == content_type) {
            g_handlers[i].handler = handler;
            return 0;
        }
    }
    
    // Add new handler
    if (g_handler_count >= MAX_HANDLERS) {
        return -1;
    }
    
    g_handlers[g_handler_count].content_type = content_type;
    g_handlers[g_handler_count].handler = handler;
    g_handler_count++;
    
    return 0;
}

int envelope_register_handler(uint32_t content_type, EnvelopeContentHandler handler) {
    pthread_mutex_lock(&g_handler_lock);
    int result = envelope_register_handler_internal(content_type, handler);
    pthread_mutex_unlock(&g_handler_lock);
    return result;
}

void envelope_unregister_handler(uint32_t content_type) {
    pthread_mutex_lock(&g_handler_lock);
    
    for (size_t i = 0; i < g_handler_count; i++) {
        if (g_handlers[i].content_type == content_type) {
            // Shift remaining handlers down
            memmove(&g_handlers[i], &g_handlers[i + 1], 
                    (g_handler_count - i - 1) * sizeof(HandlerEntry));
            g_handler_count--;
            break;
        }
    }
    
    pthread_mutex_unlock(&g_handler_lock);
}

const char* envelope_content_type_name(uint32_t content_type) {
    switch (content_type) {
        // Phase 1: MVP
        case TINYWEB__CONTENT_TYPE__CONTENT_USER_REGISTRATION: return "UserRegistration";
        case TINYWEB__CONTENT_TYPE__CONTENT_ROLE_ASSIGNMENT: return "RoleAssignment";
        case TINYWEB__CONTENT_TYPE__CONTENT_GROUP_CREATE: return "GroupCreate";
        case TINYWEB__CONTENT_TYPE__CONTENT_GROUP_UPDATE: return "GroupUpdate";
        case TINYWEB__CONTENT_TYPE__CONTENT_GROUP_MEMBER_ADD: return "GroupMemberAdd";
        case TINYWEB__CONTENT_TYPE__CONTENT_GROUP_MEMBER_REMOVE: return "GroupMemberRemove";
        case TINYWEB__CONTENT_TYPE__CONTENT_GROUP_MEMBER_LEAVE: return "GroupMemberLeave";
        case TINYWEB__CONTENT_TYPE__CONTENT_PERMISSION_EDIT: return "PermissionEdit";
        case TINYWEB__CONTENT_TYPE__CONTENT_PARENTAL_CONTROL: return "ParentalControl";
        case TINYWEB__CONTENT_TYPE__CONTENT_CONTENT_FILTER: return "ContentFilter";
        case TINYWEB__CONTENT_TYPE__CONTENT_LOCATION_UPDATE: return "LocationUpdate";
        case TINYWEB__CONTENT_TYPE__CONTENT_EMERGENCY_ALERT: return "EmergencyAlert";
        case TINYWEB__CONTENT_TYPE__CONTENT_NODE_REGISTRATION: return "NodeRegistration";
        case TINYWEB__CONTENT_TYPE__CONTENT_SYSTEM_CONFIG: return "SystemConfig";
        case TINYWEB__CONTENT_TYPE__CONTENT_ACCESS_REQUEST: return "AccessRequest";
        
        // Phase 2
        case TINYWEB__CONTENT_TYPE__CONTENT_VOICE_CALL_REQUEST: return "VoiceCallRequest";
        case TINYWEB__CONTENT_TYPE__CONTENT_MEDIA_DOWNLOAD: return "MediaDownload";
        case TINYWEB__CONTENT_TYPE__CONTENT_CONTENT_ACCESS_UPDATE: return "ContentAccessUpdate";
        case TINYWEB__CONTENT_TYPE__CONTENT_CREATION_UPLOAD: return "CreationUpload";
        case TINYWEB__CONTENT_TYPE__CONTENT_CREATION_SHARE_REQUEST: return "CreationShareRequest";
        
        // Phase 3
        case TINYWEB__CONTENT_TYPE__CONTENT_EDUCATIONAL_RESOURCE_ADD: return "EducationalResourceAdd";
        case TINYWEB__CONTENT_TYPE__CONTENT_CHALLENGE_COMPLETE: return "ChallengeComplete";
        case TINYWEB__CONTENT_TYPE__CONTENT_BOOK_ADD_TO_LIBRARY: return "BookAddToLibrary";
        case TINYWEB__CONTENT_TYPE__CONTENT_CHORE_ASSIGN: return "ChoreAssign";
        case TINYWEB__CONTENT_TYPE__CONTENT_CHORE_COMPLETE: return "ChoreComplete";
        case TINYWEB__CONTENT_TYPE__CONTENT_REWARD_DISTRIBUTE: return "RewardDistribute";
        
        // Phase 4
        case TINYWEB__CONTENT_TYPE__CONTENT_GEOFENCE_CREATE: return "GeofenceCreate";
        case TINYWEB__CONTENT_TYPE__CONTENT_GEOFENCE_CONFIG_UPDATE: return "GeofenceConfigUpdate";
        case TINYWEB__CONTENT_TYPE__CONTENT_USAGE_POLICY_UPDATE: return "UsagePolicyUpdate";
        case TINYWEB__CONTENT_TYPE__CONTENT_GAME_SESSION_START: return "GameSessionStart";
        case TINYWEB__CONTENT_TYPE__CONTENT_GAME_PERMISSION_UPDATE: return "GamePermissionUpdate";
        case TINYWEB__CONTENT_TYPE__CONTENT_EVENT_CREATE: return "EventCreate";
        case TINYWEB__CONTENT_TYPE__CONTENT_EVENT_INVITE: return "EventInvite";
        case TINYWEB__CONTENT_TYPE__CONTENT_EVENT_RSVP: return "EventRSVP";
        case TINYWEB__CONTENT_TYPE__CONTENT_COMMUNITY_POST_CREATE: return "CommunityPostCreate";
        case TINYWEB__CONTENT_TYPE__CONTENT_SHARED_ALBUM_CREATE: return "SharedAlbumCreate";
        case TINYWEB__CONTENT_TYPE__CONTENT_MEDIA_ADD_TO_ALBUM_REQUEST: return "MediaAddToAlbumRequest";
        case TINYWEB__CONTENT_TYPE__CONTENT_COLLABORATIVE_PROJECT_CREATE: return "CollaborativeProjectCreate";
        
        default: return "Unknown";
    }
}

int envelope_dispatch(const Tinyweb__Envelope* envelope, void* context) {
    if (!envelope || !envelope->header) {
        logger_error("envelope_dispatch", "invalid envelope");
        return -1;
    }
    
    uint32_t content_type = envelope->header->content_type;
    
    // Find handler
    pthread_mutex_lock(&g_handler_lock);
    EnvelopeContentHandler handler = NULL;
    for (size_t i = 0; i < g_handler_count; i++) {
        if (g_handlers[i].content_type == content_type) {
            handler = g_handlers[i].handler;
            break;
        }
    }
    pthread_mutex_unlock(&g_handler_lock);
    
    if (!handler) {
        logger_error("envelope_dispatch", "no handler for content type %u (%s)",
                content_type, envelope_content_type_name(content_type));
        return -1;
    }
    
    // Attempt decryption
    unsigned char* decrypted = NULL;
    size_t decrypted_len = 0;
    int decrypt_result = decrypt_envelope_payload(envelope, &decrypted, &decrypted_len);
    
    // Call handler with decrypted payload (or NULL if decryption failed)
    // Decryption failure is not an error - we may not be a recipient
    int result = handler(envelope, 
                         (decrypt_result == 0) ? decrypted : NULL,
                         (decrypt_result == 0) ? decrypted_len : 0,
                         context);
    
    // Free decrypted payload if it was allocated
    if (decrypted != NULL) {
        free(decrypted);
    }
    
    if (result != 0) {
        logger_error("envelope_dispatch", "handler for %s failed",
                envelope_content_type_name(content_type));
    }
    
    return result;
}

// ===== Default Handlers =====

static int handle_location_update(const Tinyweb__Envelope* envelope,
                                  const unsigned char* payload,
                                  size_t payload_len,
                                  void* context) {
    (void)context;
    (void)payload;
    (void)payload_len;
    
    if (!envelope || !envelope->header) {
        logger_error("envelope_dispatch", "handle_location_update: invalid envelope");
        return -1;
    }
    
    // Store the ENCRYPTED envelope (not decrypted payload)
    // Note: envelope_dispatch() decrypts payload IF we're a recipient (line 182-189),
    // but we should store the ENCRYPTED envelope regardless of whether we can decrypt it
    
    // 1. Compute digest for deduplication from envelope
    unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE];
    if (location_store_compute_digest_envelope(envelope, digest) != 0) {
        logger_error("envelope_dispatch", "handle_location_update: failed to compute digest");
        return -1;
    }
    
    // 2. Check if already seen (deduplication)
    int seen = 0;
    if (location_store_has_seen(digest, &seen) == 0 && seen) {
        logger_info("envelope_dispatch", "handle_location_update: duplicate location update (already seen)");
        return 0; // Not an error - just a duplicate
    }
    
    // 3. Calculate expires_at from envelope timestamp (use same TTL logic as messages: 7 days)
    const uint64_t LOCATION_TTL = (7 * 24 * 60 * 60); // 7 days default TTL (same as messages)
    uint64_t expires_at = envelope->header->timestamp + LOCATION_TTL;
    
    // 4. Store encrypted envelope via location_store_save_envelope()
    if (location_store_save_envelope(envelope, expires_at) != 0) {
        logger_error("envelope_dispatch", "handle_location_update: failed to save location update");
        return -1;
    }
    
    // 5. Mark seen with expires_at
    location_store_mark_seen(digest, expires_at);
    
    // 6. Log success
    logger_info("envelope_dispatch", "handle_location_update: stored location update from sender (timestamp=%llu)",
                (unsigned long long)envelope->header->timestamp);
    
    // Optional: If we can decrypt (we're a recipient), log the location details
    if (payload && payload_len > 0) {
        Tinyweb__LocationUpdate* loc = tinyweb__location_update__unpack(NULL, payload_len, payload);
        if (loc) {
            logger_info("envelope_dispatch", "handle_location_update: lat=%.6f, lon=%.6f, accuracy=%um",
           loc->lat, loc->lon, loc->accuracy_m);
            tinyweb__location_update__free_unpacked(loc, NULL);
        }
    }
    
    return 0;
}

static int handle_emergency_alert(const Tinyweb__Envelope* envelope,
                                  const unsigned char* payload,
                                  size_t payload_len,
                                  void* context) {
    (void)context;
    
    if (!payload) {
        logger_error("envelope_dispatch", "handle_emergency_alert: unable to decrypt payload (not a recipient?)");
        return 0; // Not an error - we may not be a recipient of this message
    }
    
    Tinyweb__EmergencyAlert* alert = tinyweb__emergency_alert__unpack(NULL, payload_len, payload);
    if (!alert) {
        logger_error("envelope_dispatch", "handle_emergency_alert: failed to parse EmergencyAlert");
        return -1;
    }
    
    printf("🚨 EMERGENCY ALERT from %p (type %u): %s\n",
           (void*)envelope->header->sender_pubkey.data,
           alert->alert_type,
           alert->message);
    
    tinyweb__emergency_alert__free_unpacked(alert, NULL);
    return 0;
}

