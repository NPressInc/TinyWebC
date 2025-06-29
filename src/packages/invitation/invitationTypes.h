#ifndef INVITATION_TYPES_H
#define INVITATION_TYPES_H

#include <stdint.h>
#include <time.h>
#include "../keystore/keystore.h"
#include "../structures/blockChain/transaction.h"
#include "../../structs/permission/permission.h"

// Additional constants needed
#ifndef MAX_USERNAME_LENGTH
#define MAX_USERNAME_LENGTH 64
#endif

#ifndef PUBKEY_SIZE
#define PUBKEY_SIZE 32
#endif

#ifndef SIGNATURE_SIZE
#define SIGNATURE_SIZE 64
#endif

// Constants
#define INVITATION_CODE_LENGTH 32
#define INVITATION_MESSAGE_LENGTH 128
#define MAX_PENDING_INVITATIONS 50
#define INVITATION_EXPIRY_HOURS 72
#define MAX_FAMILY_NAME_LENGTH 32

// Proximity validation constants
#define MAX_PROXIMITY_PROOFS 5
#define PROXIMITY_PROOF_DATA_SIZE 128

// Invitation Status
typedef enum {
    INVITATION_STATUS_PENDING = 0,
    INVITATION_STATUS_ACCEPTED = 1,
    INVITATION_STATUS_REJECTED = 2,
    INVITATION_STATUS_EXPIRED = 3,
    INVITATION_STATUS_REVOKED = 4
} InvitationStatus;

// Invitation Type - determines what the invitee can do
typedef enum {
    // === USER/ROLE INVITATIONS === (Network Communication & Participation)
    INVITATION_TYPE_FAMILY_MEMBER = 0,    // Child or supervised member (user role)
    INVITATION_TYPE_FAMILY_ADMIN = 1,     // Parent or guardian (user role)
    INVITATION_TYPE_EMERGENCY_CONTACT = 2, // Emergency contact (limited user role)
    INVITATION_TYPE_COMMUNITY_MEMBER = 3,  // Community/friend access (user role)
    
    // === INFRASTRUCTURE INVITATIONS === (Node Operation & Consensus)
    INVITATION_TYPE_FAMILY_NODE = 10,     // Additional family device/node (infrastructure)
    INVITATION_TYPE_BACKUP_NODE = 11,     // Backup/redundancy node (infrastructure)
    INVITATION_TYPE_RELAY_NODE = 12       // Network relay node (infrastructure)
} InvitationType;

// Proximity proof types for in-person validation
typedef enum {
    PROXIMITY_PROOF_NONE = 0,
    PROXIMITY_PROOF_NFC = 1,
    PROXIMITY_PROOF_BLE = 2,
    PROXIMITY_PROOF_ULTRASONIC = 3,
    PROXIMITY_PROOF_GPS = 4,
    PROXIMITY_PROOF_QR_CODE = 5,
    PROXIMITY_PROOF_ENV_CONTEXT = 6
} ProximityProofType;

// Proximity proof structure for physical presence verification
typedef struct {
    ProximityProofType type;
    uint64_t timestamp;
    unsigned char proof_data[PROXIMITY_PROOF_DATA_SIZE];
    unsigned char proof_signature[SIGNATURE_SIZE];
} ProximityProof;

// Core invitation structure
typedef struct {
    // Invitation metadata
    char invitation_code[INVITATION_CODE_LENGTH];
    char family_name[MAX_FAMILY_NAME_LENGTH];
    char invited_name[MAX_USERNAME_LENGTH];
    char invitation_message[INVITATION_MESSAGE_LENGTH];
    
    // Invitation specifics
    InvitationType type;
    InvitationStatus status;
    uint64_t created_at;
    uint64_t expires_at;
    uint64_t responded_at;
    
    // Cryptographic data
    unsigned char inviter_pubkey[PUBKEY_SIZE];
    unsigned char invited_pubkey[PUBKEY_SIZE];  // Set when accepted
    unsigned char invitation_signature[SIGNATURE_SIZE];
    
    // Permissions and constraints
    uint64_t granted_permissions;     // What permissions they'll get
    permission_scope_t permission_scope; // What scope they'll have access to
    uint8_t requires_supervision;     // If they need parental oversight
    
    // Network information (for node invitations)
    char proposed_ip[16];            // IP address for new node
    uint16_t proposed_port;          // Port for new node
    uint32_t proposed_node_id;       // Suggested node ID
    
    // Proximity validation fields
    uint8_t requires_proximity;           // Boolean: does this invitation require proximity?
    uint8_t proximity_proof_count;        // Number of proximity proofs provided
    ProximityProof proximity_proofs[MAX_PROXIMITY_PROOFS];  // Array of proximity proofs
    uint64_t proximity_validated_at;      // When proximity was validated
    
} FamilyInvitation;

// Invitation request (sent over network)
typedef struct {
    char invitation_code[INVITATION_CODE_LENGTH];
    unsigned char invitee_pubkey[PUBKEY_SIZE];
    char invitee_name[MAX_USERNAME_LENGTH];
    unsigned char acceptance_signature[SIGNATURE_SIZE];
    uint64_t timestamp;
} InvitationAcceptance;

// Invitation revocation
typedef struct {
    char invitation_code[INVITATION_CODE_LENGTH];
    unsigned char revoker_pubkey[PUBKEY_SIZE];
    char revocation_reason[INVITATION_MESSAGE_LENGTH];
    unsigned char revocation_signature[SIGNATURE_SIZE];
    uint64_t timestamp;
} InvitationRevocation;

// Transaction types are defined in ../structures/blockChain/transaction_types.h

// Invitation manager state
typedef struct {
    FamilyInvitation pending_invitations[MAX_PENDING_INVITATIONS];
    uint32_t pending_count;
    uint32_t total_created;
    uint32_t total_accepted;
    uint32_t total_rejected;
    uint32_t total_expired;
} InvitationManager;

// Helper functions to distinguish invitation types
static inline int is_node_invitation(InvitationType type) {
    return (type >= 10);  // All infrastructure invitations are >= 10
}

static inline int is_user_invitation(InvitationType type) {
    return (type < 10);   // All user/role invitations are < 10
}

// Helper function to get invitation type name
static inline const char* get_invitation_type_name(InvitationType type) {
    switch (type) {
        // User/Role invitations
        case INVITATION_TYPE_FAMILY_MEMBER: return "Family Member";
        case INVITATION_TYPE_FAMILY_ADMIN: return "Family Admin";
        case INVITATION_TYPE_EMERGENCY_CONTACT: return "Emergency Contact";
        case INVITATION_TYPE_COMMUNITY_MEMBER: return "Community Member";
        
        // Infrastructure invitations
        case INVITATION_TYPE_FAMILY_NODE: return "Family Node";
        case INVITATION_TYPE_BACKUP_NODE: return "Backup Node";
        case INVITATION_TYPE_RELAY_NODE: return "Relay Node";
        
        default: return "Unknown";
    }
}

#endif // INVITATION_TYPES_H 