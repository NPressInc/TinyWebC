#include "invitation.h"
#include "invitationTypes.h"
#include "../keystore/keystore.h"
#include "../signing/signing.h"
#include "../utils/jsonUtils.h"
#include "../structures/blockChain/blockchain.h"
#include "../structures/blockChain/transaction.h"
#include "../structures/blockChain/transaction_types.h"
#include "../validation/transaction_validation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// Global invitation manager
static InvitationManager g_invitation_manager = {0};
static int g_invitation_system_initialized = 0;

// =============================================================================
// SYSTEM INITIALIZATION
// =============================================================================

int invitation_system_init(void) {
    if (g_invitation_system_initialized) {
        return 1; // Already initialized
    }
    
    memset(&g_invitation_manager, 0, sizeof(InvitationManager));
    g_invitation_system_initialized = 1;
    
    printf("Invitation system initialized\n");
    return 1;
}

void invitation_system_cleanup(void) {
    memset(&g_invitation_manager, 0, sizeof(InvitationManager));
    g_invitation_system_initialized = 0;
}

int invitation_load_from_blockchain(TW_BlockChain* blockchain) {
    if (!blockchain || !g_invitation_system_initialized) {
        return 0;
    }
    
    // TODO: Iterate through blockchain and load existing invitations
    // This would be implemented when blockchain persistence is needed
    return 1;
}

// =============================================================================
// INVITATION CREATION
// =============================================================================

int invitation_create_family_member(
    const unsigned char* inviter_pubkey,
    const char* invited_name,
    const char* invitation_message,
    InvitationType type,
    uint64_t granted_permissions,
    uint8_t requires_supervision,
    FamilyInvitation* invitation_out
) {
    if (!inviter_pubkey || !invited_name || !invitation_out || !g_invitation_system_initialized) {
        return 0;
    }
    
    if (g_invitation_manager.pending_count >= MAX_PENDING_INVITATIONS) {
        printf("Too many pending invitations\n");
        return 0;
    }
    
    // Generate invitation code
    if (!invitation_generate_code(invitation_out->invitation_code)) {
        return 0;
    }
    
    // Fill invitation details
    strncpy(invitation_out->family_name, "TinyWeb Family Network", MAX_FAMILY_NAME_LENGTH - 1);
    invitation_out->family_name[MAX_FAMILY_NAME_LENGTH - 1] = '\0';
    
    strncpy(invitation_out->invited_name, invited_name, MAX_USERNAME_LENGTH - 1);
    invitation_out->invited_name[MAX_USERNAME_LENGTH - 1] = '\0';
    
    strncpy(invitation_out->invitation_message, invitation_message, INVITATION_MESSAGE_LENGTH - 1);
    invitation_out->invitation_message[INVITATION_MESSAGE_LENGTH - 1] = '\0';
    
    invitation_out->type = type;
    invitation_out->status = INVITATION_STATUS_PENDING;
    invitation_out->created_at = (uint64_t)time(NULL);
    invitation_out->expires_at = invitation_out->created_at + (INVITATION_EXPIRY_HOURS * 3600);
    invitation_out->responded_at = 0;
    
    memcpy(invitation_out->inviter_pubkey, inviter_pubkey, PUBKEY_SIZE);
    memset(invitation_out->invited_pubkey, 0, PUBKEY_SIZE); // Set when accepted
    
    invitation_out->granted_permissions = granted_permissions;
    invitation_out->permission_scope = SCOPE_PRIMARY_GROUP; // Default scope
    invitation_out->requires_supervision = requires_supervision;
    
    // Clear network info (not used for user invitations)
    memset(invitation_out->proposed_ip, 0, 16);
    invitation_out->proposed_port = 0;
    invitation_out->proposed_node_id = 0;
    
    // Sign the invitation
    char invitation_data[512];
    snprintf(invitation_data, sizeof(invitation_data), "%s|%s|%s|%d|%lu|%lu",
             invitation_out->invitation_code,
             invitation_out->invited_name,
             invitation_out->invitation_message,
             invitation_out->type,
             invitation_out->created_at,
             invitation_out->expires_at);
    
    if (!sign_message(invitation_data, invitation_out->invitation_signature)) {
        printf("Failed to sign invitation\n");
        return 0;
    }
    
    // Add to pending invitations
    memcpy(&g_invitation_manager.pending_invitations[g_invitation_manager.pending_count], 
           invitation_out, sizeof(FamilyInvitation));
    g_invitation_manager.pending_count++;
    g_invitation_manager.total_created++;
    
    printf("Created %s invitation for %s with code %s\n", 
           get_invitation_type_name(type), invited_name, invitation_out->invitation_code);
    
    return 1;
}

int invitation_create_node(
    const unsigned char* inviter_pubkey,
    const char* node_name,
    const char* proposed_ip,
    uint16_t proposed_port,
    FamilyInvitation* invitation_out
) {
    if (!inviter_pubkey || !node_name || !proposed_ip || !invitation_out || !g_invitation_system_initialized) {
        return 0;
    }
    
    if (g_invitation_manager.pending_count >= MAX_PENDING_INVITATIONS) {
        printf("Too many pending invitations\n");
        return 0;
    }
    
    // Generate invitation code
    if (!invitation_generate_code(invitation_out->invitation_code)) {
        return 0;
    }
    
    // Fill invitation details
    strncpy(invitation_out->family_name, "TinyWeb Family Network", MAX_FAMILY_NAME_LENGTH - 1);
    invitation_out->family_name[MAX_FAMILY_NAME_LENGTH - 1] = '\0';
    
    strncpy(invitation_out->invited_name, node_name, MAX_USERNAME_LENGTH - 1);
    invitation_out->invited_name[MAX_USERNAME_LENGTH - 1] = '\0';
    
    snprintf(invitation_out->invitation_message, INVITATION_MESSAGE_LENGTH - 1, 
             "Join as PBFT consensus node at %s:%d", proposed_ip, proposed_port);
    invitation_out->invitation_message[INVITATION_MESSAGE_LENGTH - 1] = '\0';
    
    invitation_out->type = INVITATION_TYPE_FAMILY_NODE;
    invitation_out->status = INVITATION_STATUS_PENDING;
    invitation_out->created_at = (uint64_t)time(NULL);
    invitation_out->expires_at = invitation_out->created_at + (INVITATION_EXPIRY_HOURS * 3600);
    invitation_out->responded_at = 0;
    
    memcpy(invitation_out->inviter_pubkey, inviter_pubkey, PUBKEY_SIZE);
    memset(invitation_out->invited_pubkey, 0, PUBKEY_SIZE); // Set when accepted
    
    // Node permissions
    invitation_out->granted_permissions = 0; // Nodes don't get user permissions
    invitation_out->permission_scope = SCOPE_GLOBAL;
    invitation_out->requires_supervision = 0;
    
    // Network configuration
    strncpy(invitation_out->proposed_ip, proposed_ip, 15);
    invitation_out->proposed_ip[15] = '\0';
    invitation_out->proposed_port = proposed_port;
    invitation_out->proposed_node_id = rand() % 1000 + 100; // Generate node ID
    
    // Sign the invitation
    char invitation_data[512];
    snprintf(invitation_data, sizeof(invitation_data), "%s|%s|%s|%d|%lu|%lu|%s|%d",
             invitation_out->invitation_code,
             invitation_out->invited_name,
             invitation_out->invitation_message,
             invitation_out->type,
             invitation_out->created_at,
             invitation_out->expires_at,
             proposed_ip,
             proposed_port);
    
    if (!sign_message(invitation_data, invitation_out->invitation_signature)) {
        printf("Failed to sign invitation\n");
        return 0;
    }
    
    // Add to pending invitations
    memcpy(&g_invitation_manager.pending_invitations[g_invitation_manager.pending_count], 
           invitation_out, sizeof(FamilyInvitation));
    g_invitation_manager.pending_count++;
    g_invitation_manager.total_created++;
    
    printf("Created node invitation for %s at %s:%d with code %s\n", 
           node_name, proposed_ip, proposed_port, invitation_out->invitation_code);
    
    return 1;
}

int invitation_generate_code(char* code_out) {
    if (!code_out) return 0;
    
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static int seed_initialized = 0;
    
    // Initialize random seed only once
    if (!seed_initialized) {
        srand(time(NULL) + getpid());
        seed_initialized = 1;
    }
    
    for (int i = 0; i < INVITATION_CODE_LENGTH - 1; i++) {
        code_out[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    code_out[INVITATION_CODE_LENGTH - 1] = '\0';
    
    return 1;
}

// =============================================================================
// INVITATION MANAGEMENT
// =============================================================================

FamilyInvitation* invitation_find_by_code(const char* invitation_code) {
    if (!invitation_code || !g_invitation_system_initialized) {
        return NULL;
    }
    
    for (uint32_t i = 0; i < g_invitation_manager.pending_count; i++) {
        if (strcmp(g_invitation_manager.pending_invitations[i].invitation_code, invitation_code) == 0) {
            return &g_invitation_manager.pending_invitations[i];
        }
    }
    
    return NULL;
}

int invitation_accept(
    const char* invitation_code,
    const unsigned char* acceptor_pubkey,
    const char* acceptor_name,
    InvitationAcceptance* acceptance_out
) {
    if (!invitation_code || !acceptor_pubkey || !acceptor_name || !acceptance_out || !g_invitation_system_initialized) {
        return 0;
    }
    
    FamilyInvitation* invitation = invitation_find_by_code(invitation_code);
    if (!invitation) {
        printf("Invitation not found: %s\n", invitation_code);
        return 0;
    }
    
    if (invitation->status != INVITATION_STATUS_PENDING) {
        printf("Invitation not pending: %s\n", invitation_code);
        return 0;
    }
    
    if (invitation_is_expired(invitation)) {
        printf("Invitation expired: %s\n", invitation_code);
        invitation->status = INVITATION_STATUS_EXPIRED;
        g_invitation_manager.total_expired++;
        return 0;
    }
    
    // Create acceptance record
    strncpy(acceptance_out->invitation_code, invitation_code, INVITATION_CODE_LENGTH - 1);
    acceptance_out->invitation_code[INVITATION_CODE_LENGTH - 1] = '\0';
    
    memcpy(acceptance_out->invitee_pubkey, acceptor_pubkey, PUBKEY_SIZE);
    
    strncpy(acceptance_out->invitee_name, acceptor_name, MAX_USERNAME_LENGTH - 1);
    acceptance_out->invitee_name[MAX_USERNAME_LENGTH - 1] = '\0';
    
    acceptance_out->timestamp = (uint64_t)time(NULL);
    
    // Sign the acceptance
    char acceptance_data[256];
    snprintf(acceptance_data, sizeof(acceptance_data), "%s|%s|%lu",
             invitation_code, acceptor_name, acceptance_out->timestamp);
    
    if (!sign_message(acceptance_data, acceptance_out->acceptance_signature)) {
        printf("Failed to sign acceptance\n");
        return 0;
    }
    
    // Update invitation
    invitation->status = INVITATION_STATUS_ACCEPTED;
    invitation->responded_at = acceptance_out->timestamp;
    memcpy(invitation->invited_pubkey, acceptor_pubkey, PUBKEY_SIZE);
    
    g_invitation_manager.total_accepted++;
    
    printf("Invitation %s accepted by %s\n", invitation_code, acceptor_name);
    
    return 1;
}

int invitation_reject(
    const char* invitation_code,
    const unsigned char* rejector_pubkey
) {
    if (!invitation_code || !rejector_pubkey || !g_invitation_system_initialized) {
        return 0;
    }
    
    FamilyInvitation* invitation = invitation_find_by_code(invitation_code);
    if (!invitation) {
        printf("Invitation not found: %s\n", invitation_code);
        return 0;
    }
    
    if (invitation->status != INVITATION_STATUS_PENDING) {
        printf("Invitation not pending: %s\n", invitation_code);
        return 0;
    }
    
    invitation->status = INVITATION_STATUS_REJECTED;
    invitation->responded_at = (uint64_t)time(NULL);
    
    g_invitation_manager.total_rejected++;
    
    printf("Invitation %s rejected\n", invitation_code);
    return 1;
}

int invitation_revoke(
    const char* invitation_code,
    const unsigned char* revoker_pubkey,
    const char* reason,
    InvitationRevocation* revocation_out
) {
    if (!invitation_code || !revoker_pubkey || !reason || !revocation_out || !g_invitation_system_initialized) {
        return 0;
    }
    
    FamilyInvitation* invitation = invitation_find_by_code(invitation_code);
    if (!invitation) {
        printf("Invitation not found: %s\n", invitation_code);
        return 0;
    }
    
    if (invitation->status != INVITATION_STATUS_PENDING) {
        printf("Invitation not pending: %s\n", invitation_code);
        return 0;
    }
    
    // TODO: Check if revoker has admin permissions
    
    // Create revocation record
    strncpy(revocation_out->invitation_code, invitation_code, INVITATION_CODE_LENGTH - 1);
    revocation_out->invitation_code[INVITATION_CODE_LENGTH - 1] = '\0';
    
    memcpy(revocation_out->revoker_pubkey, revoker_pubkey, PUBKEY_SIZE);
    
    strncpy(revocation_out->revocation_reason, reason, INVITATION_MESSAGE_LENGTH - 1);
    revocation_out->revocation_reason[INVITATION_MESSAGE_LENGTH - 1] = '\0';
    
    revocation_out->timestamp = (uint64_t)time(NULL);
    
    // Sign the revocation
    char revocation_data[256];
    snprintf(revocation_data, sizeof(revocation_data), "%s|%s|%lu",
             invitation_code, reason, revocation_out->timestamp);
    
    if (!sign_message(revocation_data, revocation_out->revocation_signature)) {
        printf("Failed to sign revocation\n");
        return 0;
    }
    
    invitation->status = INVITATION_STATUS_REVOKED;
    invitation->responded_at = revocation_out->timestamp;
    
    printf("Invitation %s revoked: %s\n", invitation_code, reason);
    return 1;
}

// =============================================================================
// INVITATION QUERIES
// =============================================================================

int invitation_get_pending(FamilyInvitation* invitations_out, uint32_t max_invitations) {
    if (!invitations_out || !g_invitation_system_initialized) {
        return -1;
    }
    
    uint32_t count = 0;
    for (uint32_t i = 0; i < g_invitation_manager.pending_count && count < max_invitations; i++) {
        if (g_invitation_manager.pending_invitations[i].status == INVITATION_STATUS_PENDING &&
            !invitation_is_expired(&g_invitation_manager.pending_invitations[i])) {
            memcpy(&invitations_out[count], &g_invitation_manager.pending_invitations[i], 
                   sizeof(FamilyInvitation));
            count++;
        }
    }
    
    return count;
}

int invitation_get_by_creator(
    const unsigned char* creator_pubkey,
    FamilyInvitation* invitations_out,
    uint32_t max_invitations
) {
    if (!creator_pubkey || !invitations_out || !g_invitation_system_initialized) {
        return -1;
    }
    
    uint32_t count = 0;
    for (uint32_t i = 0; i < g_invitation_manager.pending_count && count < max_invitations; i++) {
        if (memcmp(g_invitation_manager.pending_invitations[i].inviter_pubkey, 
                   creator_pubkey, PUBKEY_SIZE) == 0) {
            memcpy(&invitations_out[count], &g_invitation_manager.pending_invitations[i], 
                   sizeof(FamilyInvitation));
            count++;
        }
    }
    
    return count;
}

int invitation_can_create(const unsigned char* user_pubkey, InvitationType invitation_type) {
    if (!user_pubkey || !g_invitation_system_initialized) {
        return 0;
    }
    
    // TODO: Check user permissions from blockchain
    // For now, allow all users to create invitations
    return 1;
}

// =============================================================================
// INVITATION VALIDATION
// =============================================================================

int invitation_validate_signature(const FamilyInvitation* invitation) {
    if (!invitation) return 0;
    
    // TODO: Implement signature validation using stored public key
    // For now, assume valid
    return 1;
}

int invitation_is_expired(const FamilyInvitation* invitation) {
    if (!invitation) return 1;
    
    uint64_t current_time = (uint64_t)time(NULL);
    return current_time > invitation->expires_at;
}

int invitation_validate_acceptance(
    const InvitationAcceptance* acceptance,
    const FamilyInvitation* invitation
) {
    if (!acceptance || !invitation) return 0;
    
    // Validate invitation code matches
    if (strcmp(acceptance->invitation_code, invitation->invitation_code) != 0) {
        return 0;
    }
    
    // TODO: Validate acceptance signature
    return 1;
}

// =============================================================================
// BLOCKCHAIN INTEGRATION
// =============================================================================

TW_Transaction* invitation_create_blockchain_transaction(
    const FamilyInvitation* invitation,
    const unsigned char* creator_pubkey
) {
    if (!invitation || !creator_pubkey) return NULL;
    
    TW_Transaction* transaction = malloc(sizeof(TW_Transaction));
    if (!transaction) return NULL;
    
    // Set transaction basics
    transaction->type = TW_TXN_INVITATION_CREATE;
    transaction->timestamp = (uint64_t)time(NULL);
    memcpy(transaction->sender, creator_pubkey, PUBKEY_SIZE);
    
    // TODO: Set transaction data based on actual TW_Transaction structure
    
    // TODO: Sign transaction
    
    return transaction;
}

TW_Transaction* invitation_acceptance_create_blockchain_transaction(
    const InvitationAcceptance* acceptance,
    const unsigned char* acceptor_pubkey
) {
    if (!acceptance || !acceptor_pubkey) return NULL;
    
    TW_Transaction* transaction = malloc(sizeof(TW_Transaction));
    if (!transaction) return NULL;
    
    // Set transaction basics
    transaction->type = TW_TXN_INVITATION_ACCEPT;
    transaction->timestamp = (uint64_t)time(NULL);
    memcpy(transaction->sender, acceptor_pubkey, PUBKEY_SIZE);
    
    // TODO: Set transaction data based on actual TW_Transaction structure
    
    // TODO: Sign transaction
    
    return transaction;
}

int invitation_process_blockchain_transaction(const TW_Transaction* transaction) {
    if (!transaction || !g_invitation_system_initialized) return 0;
    
    switch (transaction->type) {
        case TW_TXN_INVITATION_CREATE:
            // Process invitation creation from blockchain
            printf("Processing invitation creation transaction\n");
            return 1;
            
        case TW_TXN_INVITATION_ACCEPT:
            // Process invitation acceptance from blockchain
            printf("Processing invitation acceptance transaction\n");
            return 1;
            
        case TW_TXN_INVITATION_REVOKE:
            // Process invitation revocation from blockchain
            printf("Processing invitation revocation transaction\n");
            return 1;
            
        default:
            return 0;
    }
}

int invitation_process_user_acceptance(
    const InvitationAcceptance* acceptance,
    const FamilyInvitation* original_invitation
) {
    if (!acceptance || !original_invitation) return 0;
    
    printf("Processing USER invitation acceptance for %s\n", acceptance->invitee_name);
    
    // TODO: Create user registration transaction
    // TODO: Create role assignment transaction
    // TODO: Broadcast via PBFT
    
    return 1;
}

int invitation_process_node_acceptance(
    const InvitationAcceptance* acceptance,
    const FamilyInvitation* original_invitation
) {
    if (!acceptance || !original_invitation) return 0;
    
    printf("Processing NODE invitation acceptance for %s\n", acceptance->invitee_name);
    
    // TODO: Create node registration transaction
    // TODO: Update PBFT configuration
    // TODO: Broadcast via PBFT
    
    return 1;
}

// =============================================================================
// UTILITIES
// =============================================================================

int invitation_cleanup_expired(void) {
    if (!g_invitation_system_initialized) return 0;
    
    int cleaned = 0;
    for (uint32_t i = 0; i < g_invitation_manager.pending_count; i++) {
        if (invitation_is_expired(&g_invitation_manager.pending_invitations[i]) &&
            g_invitation_manager.pending_invitations[i].status == INVITATION_STATUS_PENDING) {
            g_invitation_manager.pending_invitations[i].status = INVITATION_STATUS_EXPIRED;
            g_invitation_manager.total_expired++;
            cleaned++;
        }
    }
    
    if (cleaned > 0) {
        printf("Cleaned up %d expired invitations\n", cleaned);
    }
    
    return cleaned;
}

void invitation_get_stats(
    uint32_t* total_created_out,
    uint32_t* total_accepted_out,
    uint32_t* total_pending_out,
    uint32_t* total_expired_out
) {
    if (!g_invitation_system_initialized) return;
    
    if (total_created_out) *total_created_out = g_invitation_manager.total_created;
    if (total_accepted_out) *total_accepted_out = g_invitation_manager.total_accepted;
    if (total_pending_out) {
        *total_pending_out = 0;
        for (uint32_t i = 0; i < g_invitation_manager.pending_count; i++) {
            if (g_invitation_manager.pending_invitations[i].status == INVITATION_STATUS_PENDING) {
                (*total_pending_out)++;
            }
        }
    }
    if (total_expired_out) *total_expired_out = g_invitation_manager.total_expired;
}

char* invitation_to_json(const FamilyInvitation* invitation) {
    if (!invitation) return NULL;
    
    // TODO: Implement JSON serialization
    return NULL;
}

int invitation_from_json(const char* json_str, FamilyInvitation* invitation_out) {
    if (!json_str || !invitation_out) return 0;
    
    // TODO: Implement JSON deserialization
    return 0;
}

// =============================================================================
// PROXIMITY VALIDATION FUNCTIONS
// =============================================================================

int invitation_validate_proximity_proofs(const FamilyInvitation* invitation) {
    if (!invitation || !g_invitation_system_initialized) {
        return 0;
    }
    
    // If proximity not required, always pass
    if (!invitation->requires_proximity) {
        return 1;
    }
    
    // Must have at least one proximity proof
    if (invitation->proximity_proof_count == 0) {
        printf("Invitation requires proximity but no proofs provided\n");
        return 0;
    }
    
    // Validate each proximity proof
    for (uint8_t i = 0; i < invitation->proximity_proof_count; i++) {
        if (!invitation_verify_single_proximity_proof(&invitation->proximity_proofs[i])) {
            printf("Proximity proof %d failed validation\n", i);
            return 0;
        }
    }
    
    printf("All proximity proofs validated successfully\n");
    return 1;
}

int invitation_verify_single_proximity_proof(const ProximityProof* proof) {
    if (!proof) return 0;
    
    // Basic timestamp validation (not too old, not in future)
    uint64_t now = (uint64_t)time(NULL);
    uint64_t max_age = 300; // 5 minutes
    
    if (proof->timestamp > now + 60) { // 1 minute future tolerance
        printf("Proximity proof timestamp is too far in future\n");
        return 0;
    }
    
    if (now - proof->timestamp > max_age) {
        printf("Proximity proof is too old\n");
        return 0;
    }
    
    // TODO: Add specific validation for each proof type
    switch (proof->type) {
        case PROXIMITY_PROOF_NFC:
            // TODO: Validate NFC proof data
            break;
        case PROXIMITY_PROOF_BLE:
            // TODO: Validate BLE proof data
            break;
        case PROXIMITY_PROOF_ULTRASONIC:
            // TODO: Validate ultrasonic proof data
            break;
        case PROXIMITY_PROOF_GPS:
            // TODO: Validate GPS proof data
            break;
        case PROXIMITY_PROOF_QR_CODE:
            // TODO: Validate QR code proof data
            break;
        case PROXIMITY_PROOF_ENV_CONTEXT:
            // TODO: Validate environmental context proof data
            break;
        default:
            printf("Unknown proximity proof type: %d\n", proof->type);
            return 0;
    }
    
    // For now, just validate that we have some proof data
    int has_data = 0;
    for (int i = 0; i < PROXIMITY_PROOF_DATA_SIZE; i++) {
        if (proof->proof_data[i] != 0) {
            has_data = 1;
            break;
        }
    }
    
    return has_data;
}

int invitation_check_proximity_requirements(const FamilyInvitation* invitation) {
    if (!invitation) return 0;
    
    // Check if proximity requirements are met
    if (invitation->requires_proximity && invitation->proximity_proof_count == 0) {
        return 0; // Proximity required but not provided
    }
    
    return invitation_validate_proximity_proofs(invitation);
}

int invitation_create_with_proximity(
    const unsigned char* inviter_pubkey,
    const char* invited_name,
    const char* invitation_message,
    InvitationType type,
    uint64_t granted_permissions,
    uint8_t requires_supervision,
    uint8_t requires_proximity,
    ProximityProof* proximity_proofs,
    uint8_t proof_count,
    FamilyInvitation* invitation_out
) {
    if (!inviter_pubkey || !invited_name || !invitation_out || !g_invitation_system_initialized) {
        return 0;
    }
    
    if (g_invitation_manager.pending_count >= MAX_PENDING_INVITATIONS) {
        printf("Too many pending invitations\n");
        return 0;
    }
    
    // Start with basic invitation creation
    memset(invitation_out, 0, sizeof(FamilyInvitation));
    
    // Generate invitation code
    if (!invitation_generate_code(invitation_out->invitation_code)) {
        return 0;
    }
    
    // Fill basic invitation details
    strncpy(invitation_out->family_name, "TinyWeb Family Network", MAX_FAMILY_NAME_LENGTH - 1);
    invitation_out->family_name[MAX_FAMILY_NAME_LENGTH - 1] = '\0';
    
    strncpy(invitation_out->invited_name, invited_name, MAX_USERNAME_LENGTH - 1);
    invitation_out->invited_name[MAX_USERNAME_LENGTH - 1] = '\0';
    
    strncpy(invitation_out->invitation_message, invitation_message, INVITATION_MESSAGE_LENGTH - 1);
    invitation_out->invitation_message[INVITATION_MESSAGE_LENGTH - 1] = '\0';
    
    invitation_out->type = type;
    invitation_out->status = INVITATION_STATUS_PENDING;
    invitation_out->created_at = (uint64_t)time(NULL);
    invitation_out->expires_at = invitation_out->created_at + (INVITATION_EXPIRY_HOURS * 3600);
    invitation_out->responded_at = 0;
    
    memcpy(invitation_out->inviter_pubkey, inviter_pubkey, PUBKEY_SIZE);
    memset(invitation_out->invited_pubkey, 0, PUBKEY_SIZE);
    
    invitation_out->granted_permissions = granted_permissions;
    invitation_out->permission_scope = SCOPE_PRIMARY_GROUP;
    invitation_out->requires_supervision = requires_supervision;
    
    // Clear network info (set properly for node invitations elsewhere)
    memset(invitation_out->proposed_ip, 0, 16);
    invitation_out->proposed_port = 0;
    invitation_out->proposed_node_id = 0;
    
    // Set proximity requirements
    invitation_out->requires_proximity = requires_proximity;
    invitation_out->proximity_proof_count = 0;
    invitation_out->proximity_validated_at = 0;
    
    // Add proximity proofs if provided
    if (requires_proximity && proximity_proofs && proof_count > 0) {
        uint8_t max_proofs = (proof_count > MAX_PROXIMITY_PROOFS) ? MAX_PROXIMITY_PROOFS : proof_count;
        
        for (uint8_t i = 0; i < max_proofs; i++) {
            memcpy(&invitation_out->proximity_proofs[i], &proximity_proofs[i], sizeof(ProximityProof));
            invitation_out->proximity_proof_count++;
        }
        
        // Validate proximity proofs
        if (invitation_validate_proximity_proofs(invitation_out)) {
            invitation_out->proximity_validated_at = invitation_out->created_at;
        } else {
            printf("Failed to validate proximity proofs\n");
            return 0;
        }
    }
    
    // Sign the invitation (include proximity flag in signature)
    char invitation_data[512];
    snprintf(invitation_data, sizeof(invitation_data), "%s|%s|%s|%d|%lu|%lu|%d|%d",
             invitation_out->invitation_code,
             invitation_out->invited_name,
             invitation_out->invitation_message,
             invitation_out->type,
             invitation_out->created_at,
             invitation_out->expires_at,
             invitation_out->requires_proximity,
             invitation_out->proximity_proof_count);
    
    if (!sign_message(invitation_data, invitation_out->invitation_signature)) {
        printf("Failed to sign invitation\n");
        return 0;
    }
    
    // Add to pending invitations
    memcpy(&g_invitation_manager.pending_invitations[g_invitation_manager.pending_count], 
           invitation_out, sizeof(FamilyInvitation));
    g_invitation_manager.pending_count++;
    g_invitation_manager.total_created++;
    
    printf("Created %s invitation for %s with code %s (proximity: %s)\n", 
           get_invitation_type_name(type), invited_name, invitation_out->invitation_code,
           requires_proximity ? "required" : "not required");
    
    return 1;
} 