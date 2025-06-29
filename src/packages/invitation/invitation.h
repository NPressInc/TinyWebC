#ifndef INVITATION_H
#define INVITATION_H

#include "invitationTypes.h"
#include "../structures/blockChain/blockchain.h"
#include "../structures/blockChain/transaction.h"

// Global invitation manager is declared in invitation.c

// =============================================================================
// INITIALIZATION AND CLEANUP
// =============================================================================

/**
 * Initialize the invitation system
 * @return 1 on success, 0 on failure
 */
int invitation_system_init(void);

/**
 * Cleanup the invitation system
 */
void invitation_system_cleanup(void);

/**
 * Load pending invitations from blockchain
 * @param blockchain The blockchain to scan for invitation transactions
 * @return Number of invitations loaded, -1 on error
 */
int invitation_load_from_blockchain(TW_BlockChain* blockchain);

// =============================================================================
// INVITATION CREATION
// =============================================================================

/**
 * Create a new family member invitation
 * @param inviter_pubkey Public key of the person sending invitation
 * @param invited_name Name of the person being invited
 * @param invitation_message Personal message to include
 * @param type Type of invitation (family member, admin, etc.)
 * @param granted_permissions Permissions to grant upon acceptance
 * @param requires_supervision Whether this person needs supervision
 * @param invitation_out Output parameter for created invitation
 * @return 1 on success, 0 on failure
 */
int invitation_create_family_member(
    const unsigned char* inviter_pubkey,
    const char* invited_name,
    const char* invitation_message,
    InvitationType type,
    uint64_t granted_permissions,
    uint8_t requires_supervision,
    FamilyInvitation* invitation_out
);

/**
 * Create a new node invitation (for adding family devices)
 * @param inviter_pubkey Public key of the person sending invitation
 * @param node_name Name/description of the node
 * @param proposed_ip IP address for the new node
 * @param proposed_port Port for the new node
 * @param invitation_out Output parameter for created invitation
 * @return 1 on success, 0 on failure
 */
int invitation_create_node(
    const unsigned char* inviter_pubkey,
    const char* node_name,
    const char* proposed_ip,
    uint16_t proposed_port,
    FamilyInvitation* invitation_out
);

/**
 * Generate a secure invitation code
 * @param code_out Buffer to store the generated code (must be INVITATION_CODE_LENGTH)
 * @return 1 on success, 0 on failure
 */
int invitation_generate_code(char* code_out);

// =============================================================================
// INVITATION MANAGEMENT
// =============================================================================

/**
 * Find an invitation by code
 * @param invitation_code The invitation code to search for
 * @return Pointer to invitation if found, NULL otherwise
 */
FamilyInvitation* invitation_find_by_code(const char* invitation_code);

/**
 * Accept an invitation
 * @param invitation_code The invitation code
 * @param acceptor_pubkey Public key of the person accepting
 * @param acceptor_name Name of the person accepting
 * @param acceptance_out Output parameter for acceptance data
 * @return 1 on success, 0 on failure
 */
int invitation_accept(
    const char* invitation_code,
    const unsigned char* acceptor_pubkey,
    const char* acceptor_name,
    InvitationAcceptance* acceptance_out
);

/**
 * Reject an invitation
 * @param invitation_code The invitation code
 * @param rejector_pubkey Public key of the person rejecting
 * @return 1 on success, 0 on failure
 */
int invitation_reject(
    const char* invitation_code,
    const unsigned char* rejector_pubkey
);

/**
 * Revoke an invitation (admin only)
 * @param invitation_code The invitation code
 * @param revoker_pubkey Public key of the person revoking (must be admin)
 * @param reason Reason for revocation
 * @param revocation_out Output parameter for revocation data
 * @return 1 on success, 0 on failure
 */
int invitation_revoke(
    const char* invitation_code,
    const unsigned char* revoker_pubkey,
    const char* reason,
    InvitationRevocation* revocation_out
);

// =============================================================================
// INVITATION QUERIES
// =============================================================================

/**
 * Get all pending invitations
 * @param invitations_out Array to store invitations
 * @param max_invitations Maximum number of invitations to return
 * @return Number of invitations returned, -1 on error
 */
int invitation_get_pending(FamilyInvitation* invitations_out, uint32_t max_invitations);

/**
 * Get invitations created by a specific user
 * @param creator_pubkey Public key of the invitation creator
 * @param invitations_out Array to store invitations
 * @param max_invitations Maximum number of invitations to return
 * @return Number of invitations returned, -1 on error
 */
int invitation_get_by_creator(
    const unsigned char* creator_pubkey,
    FamilyInvitation* invitations_out,
    uint32_t max_invitations
);

/**
 * Check if a user has permission to create invitations
 * @param user_pubkey Public key of the user
 * @param invitation_type Type of invitation they want to create
 * @return 1 if allowed, 0 if not allowed
 */
int invitation_can_create(const unsigned char* user_pubkey, InvitationType invitation_type);

// =============================================================================
// INVITATION VALIDATION
// =============================================================================

/**
 * Validate an invitation signature
 * @param invitation The invitation to validate
 * @return 1 if valid, 0 if invalid
 */
int invitation_validate_signature(const FamilyInvitation* invitation);

/**
 * Check if an invitation has expired
 * @param invitation The invitation to check
 * @return 1 if expired, 0 if still valid
 */
int invitation_is_expired(const FamilyInvitation* invitation);

/**
 * Validate an acceptance signature
 * @param acceptance The acceptance to validate
 * @param invitation The original invitation
 * @return 1 if valid, 0 if invalid
 */
int invitation_validate_acceptance(
    const InvitationAcceptance* acceptance,
    const FamilyInvitation* invitation
);

// =============================================================================
// PROXIMITY VALIDATION
// =============================================================================

/**
 * Validate proximity proofs for an invitation
 * @param invitation The invitation with proximity proofs to validate
 * @return 1 if valid, 0 if invalid
 */
int invitation_validate_proximity_proofs(const FamilyInvitation* invitation);

/**
 * Verify a single proximity proof
 * @param proof The proximity proof to verify
 * @return 1 if valid, 0 if invalid
 */
int invitation_verify_single_proximity_proof(const ProximityProof* proof);

/**
 * Check if proximity requirements are met for an invitation
 * @param invitation The invitation to check
 * @return 1 if requirements met, 0 otherwise
 */
int invitation_check_proximity_requirements(const FamilyInvitation* invitation);

/**
 * Create invitation with proximity validation
 * @param inviter_pubkey Public key of the person sending invitation
 * @param invited_name Name of the person being invited
 * @param invitation_message Personal message to include
 * @param type Type of invitation (family member, admin, etc.)
 * @param granted_permissions Permissions to grant upon acceptance
 * @param requires_supervision Whether this person needs supervision
 * @param requires_proximity Whether proximity validation is required
 * @param proximity_proofs Array of proximity proofs
 * @param proof_count Number of proximity proofs provided
 * @param invitation_out Output parameter for created invitation
 * @return 1 on success, 0 on failure
 */
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
);

// =============================================================================
// BLOCKCHAIN INTEGRATION  
// =============================================================================

/**
 * Create invitation transaction for blockchain
 * @param invitation The invitation to create transaction for
 * @param creator_pubkey Public key of transaction creator
 * @return Transaction pointer on success, NULL on failure
 */
TW_Transaction* invitation_create_blockchain_transaction(
    const FamilyInvitation* invitation,
    const unsigned char* creator_pubkey
);

/**
 * Create acceptance transaction for blockchain
 * @param acceptance The acceptance to create transaction for
 * @param acceptor_pubkey Public key of transaction creator
 * @return Transaction pointer on success, NULL on failure
 */
TW_Transaction* invitation_acceptance_create_blockchain_transaction(
    const InvitationAcceptance* acceptance,
    const unsigned char* acceptor_pubkey
);

/**
 * Process invitation transaction from blockchain
 * @param transaction The transaction to process
 * @return 1 on success, 0 on failure
 */
int invitation_process_blockchain_transaction(const TW_Transaction* transaction);

/**
 * Process accepted USER invitation - creates user account & assigns role
 * This handles INVITATION_TYPE_FAMILY_MEMBER, FAMILY_ADMIN, etc.
 * @param acceptance The accepted invitation
 * @param original_invitation The original invitation that was accepted
 * @return 1 on success, 0 on failure
 */
int invitation_process_user_acceptance(
    const InvitationAcceptance* acceptance,
    const FamilyInvitation* original_invitation
);

/**
 * Process accepted NODE invitation - registers new PBFT node
 * This handles INVITATION_TYPE_FAMILY_NODE, BACKUP_NODE, etc.
 * @param acceptance The accepted invitation
 * @param original_invitation The original invitation that was accepted  
 * @return 1 on success, 0 on failure
 */
int invitation_process_node_acceptance(
    const InvitationAcceptance* acceptance,
    const FamilyInvitation* original_invitation
);

// =============================================================================
// UTILITIES
// =============================================================================

/**
 * Cleanup expired invitations
 * @return Number of invitations cleaned up
 */
int invitation_cleanup_expired(void);

/**
 * Get invitation statistics
 * @param total_created_out Total invitations created
 * @param total_accepted_out Total invitations accepted
 * @param total_pending_out Total invitations pending
 * @param total_expired_out Total invitations expired
 */
void invitation_get_stats(
    uint32_t* total_created_out,
    uint32_t* total_accepted_out,
    uint32_t* total_pending_out,
    uint32_t* total_expired_out
);

/**
 * Convert invitation to JSON string for API responses
 * @param invitation The invitation to convert
 * @return JSON string (caller must free), NULL on error
 */
char* invitation_to_json(const FamilyInvitation* invitation);

/**
 * Parse invitation from JSON string
 * @param json_str JSON string to parse
 * @param invitation_out Output parameter for parsed invitation
 * @return 1 on success, 0 on failure
 */
int invitation_from_json(const char* json_str, FamilyInvitation* invitation_out);

#endif // INVITATION_H 