#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <assert.h>
#include <time.h>
#include <unistd.h>
#include "packages/keystore/keystore.h"
#include "packages/invitation/invitation.h"
#include "packages/invitation/invitationTypes.h"
#include "packages/signing/signing.h"

// Test helper functions
static int run_test(const char* test_name, int (*test_func)(void));
static void setup_test_keys(unsigned char* pubkey1, unsigned char* pubkey2);
static void create_mock_proximity_proof(ProximityProof* proof, ProximityProofType type);

// Test statistics
static int g_tests_passed = 0;
static int g_tests_failed = 0;

// =============================================================================
// TEST HELPER FUNCTIONS
// =============================================================================

static int run_test(const char* test_name, int (*test_func)(void)) {
    printf("Test: %s... ", test_name);
    fflush(stdout);
    
    int result = test_func();
    if (result == 0) {
        printf("✓ Passed\n");
        g_tests_passed++;
        return 0;
    } else {
        printf("✗ Failed\n");
        g_tests_failed++;
        return 1;
    }
}

static void setup_test_keys(unsigned char* pubkey1, unsigned char* pubkey2) {
    // Create mock public keys for testing
    memset(pubkey1, 0xAA, PUBKEY_SIZE);
    memset(pubkey2, 0xBB, PUBKEY_SIZE);
    
    // Make them slightly different
    pubkey1[0] = 0x01;
    pubkey2[0] = 0x02;
}

static void create_mock_proximity_proof(ProximityProof* proof, ProximityProofType type) {
    if (!proof) return;
    
    memset(proof, 0, sizeof(ProximityProof));
    proof->type = type;
    proof->timestamp = (uint64_t)time(NULL);
    
    // Create some mock proof data
    for (int i = 0; i < PROXIMITY_PROOF_DATA_SIZE; i++) {
        proof->proof_data[i] = (unsigned char)(i % 256);
    }
    
    // Create mock signature
    memset(proof->proof_signature, 0xCC, SIGNATURE_SIZE);
}

// =============================================================================
// BASIC INVITATION TESTS
// =============================================================================

static int test_invitation_system_init(void) {
    // Test initialization
    if (!invitation_system_init()) {
        return 1;
    }
    
    // Test double initialization (should succeed)
    if (!invitation_system_init()) {
        return 1;
    }
    
    invitation_system_cleanup();
    return 0;
}

static int test_invitation_code_generation(void) {
    char code1[INVITATION_CODE_LENGTH];
    char code2[INVITATION_CODE_LENGTH];
    
    if (!invitation_generate_code(code1)) {
        return 1;
    }
    
    if (!invitation_generate_code(code2)) {
        return 1;
    }
    
    // Codes should be different
    if (strcmp(code1, code2) == 0) {
        return 1;
    }
    
    // Codes should be non-empty
    if (strlen(code1) == 0 || strlen(code2) == 0) {
        return 1;
    }
    
    return 0;
}

static int test_create_family_member_invitation(void) {
    if (!invitation_system_init()) {
        return 1;
    }
    
    unsigned char inviter_pubkey[PUBKEY_SIZE];
    unsigned char dummy_pubkey[PUBKEY_SIZE];
    setup_test_keys(inviter_pubkey, dummy_pubkey);
    
    FamilyInvitation invitation;
    
    // Test successful creation
    int result = invitation_create_family_member(
        inviter_pubkey,
        "Alice Smith",
        "Welcome to our family network!",
        INVITATION_TYPE_FAMILY_MEMBER,
        0x0001, // Some permissions
        0,      // No supervision required
        &invitation
    );
    
    if (!result) {
        invitation_system_cleanup();
        return 1;
    }
    
    // Verify invitation details
    if (invitation.type != INVITATION_TYPE_FAMILY_MEMBER) {
        invitation_system_cleanup();
        return 1;
    }
    
    if (strcmp(invitation.invited_name, "Alice Smith") != 0) {
        invitation_system_cleanup();
        return 1;
    }
    
    if (invitation.status != INVITATION_STATUS_PENDING) {
        invitation_system_cleanup();
        return 1;
    }
    
    if (memcmp(invitation.inviter_pubkey, inviter_pubkey, PUBKEY_SIZE) != 0) {
        invitation_system_cleanup();
        return 1;
    }
    
    invitation_system_cleanup();
    return 0;
}

static int test_create_node_invitation(void) {
    if (!invitation_system_init()) {
        return 1;
    }
    
    unsigned char inviter_pubkey[PUBKEY_SIZE];
    unsigned char dummy_pubkey[PUBKEY_SIZE];
    setup_test_keys(inviter_pubkey, dummy_pubkey);
    
    FamilyInvitation invitation;
    
    // Test successful creation
    int result = invitation_create_node(
        inviter_pubkey,
        "Family Laptop Node",
        "192.168.1.100",
        8080,
        &invitation
    );
    
    if (!result) {
        invitation_system_cleanup();
        return 1;
    }
    
    // Verify invitation details
    if (invitation.type != INVITATION_TYPE_FAMILY_NODE) {
        invitation_system_cleanup();
        return 1;
    }
    
    if (strcmp(invitation.invited_name, "Family Laptop Node") != 0) {
        invitation_system_cleanup();
        return 1;
    }
    
    if (strcmp(invitation.proposed_ip, "192.168.1.100") != 0) {
        invitation_system_cleanup();
        return 1;
    }
    
    if (invitation.proposed_port != 8080) {
        invitation_system_cleanup();
        return 1;
    }
    
    invitation_system_cleanup();
    return 0;
}

static int test_find_invitation_by_code(void) {
    if (!invitation_system_init()) {
        return 1;
    }
    
    unsigned char inviter_pubkey[PUBKEY_SIZE];
    unsigned char dummy_pubkey[PUBKEY_SIZE];
    setup_test_keys(inviter_pubkey, dummy_pubkey);
    
    FamilyInvitation invitation;
    
    // Create an invitation
    if (!invitation_create_family_member(
        inviter_pubkey, "Test User", "Test Message",
        INVITATION_TYPE_FAMILY_MEMBER, 0, 0, &invitation)) {
        invitation_system_cleanup();
        return 1;
    }
    
    // Find the invitation by code
    FamilyInvitation* found = invitation_find_by_code(invitation.invitation_code);
    if (!found) {
        invitation_system_cleanup();
        return 1;
    }
    
    // Verify it's the same invitation
    if (strcmp(found->invitation_code, invitation.invitation_code) != 0) {
        invitation_system_cleanup();
        return 1;
    }
    
    // Test with non-existent code
    FamilyInvitation* not_found = invitation_find_by_code("NONEXISTENT_CODE");
    if (not_found != NULL) {
        invitation_system_cleanup();
        return 1;
    }
    
    invitation_system_cleanup();
    return 0;
}

static int test_accept_invitation(void) {
    if (!invitation_system_init()) {
        return 1;
    }
    
    unsigned char inviter_pubkey[PUBKEY_SIZE];
    unsigned char acceptor_pubkey[PUBKEY_SIZE];
    setup_test_keys(inviter_pubkey, acceptor_pubkey);
    
    FamilyInvitation invitation;
    InvitationAcceptance acceptance;
    
    // Create an invitation
    if (!invitation_create_family_member(
        inviter_pubkey, "Test User", "Test Message",
        INVITATION_TYPE_FAMILY_MEMBER, 0, 0, &invitation)) {
        invitation_system_cleanup();
        return 1;
    }
    
    // Accept the invitation
    int result = invitation_accept(
        invitation.invitation_code,
        acceptor_pubkey,
        "Test Acceptor",
        &acceptance
    );
    
    if (!result) {
        invitation_system_cleanup();
        return 1;
    }
    
    // Verify acceptance details
    if (strcmp(acceptance.invitation_code, invitation.invitation_code) != 0) {
        invitation_system_cleanup();
        return 1;
    }
    
    if (memcmp(acceptance.invitee_pubkey, acceptor_pubkey, PUBKEY_SIZE) != 0) {
        invitation_system_cleanup();
        return 1;
    }
    
    invitation_system_cleanup();
    return 0;
}

static int test_proximity_invitation(void) {
    if (!invitation_system_init()) {
        return 1;
    }
    
    unsigned char inviter_pubkey[PUBKEY_SIZE];
    unsigned char dummy_pubkey[PUBKEY_SIZE];
    setup_test_keys(inviter_pubkey, dummy_pubkey);
    
    FamilyInvitation invitation;
    ProximityProof proofs[2];
    
    // Create proximity proofs
    create_mock_proximity_proof(&proofs[0], PROXIMITY_PROOF_NFC);
    create_mock_proximity_proof(&proofs[1], PROXIMITY_PROOF_BLE);
    
    // Create invitation with proximity requirements
    int result = invitation_create_with_proximity(
        inviter_pubkey,
        "Alice Smith",
        "Welcome! Please verify proximity.",
        INVITATION_TYPE_FAMILY_MEMBER,
        0x0001,
        0,      // No supervision
        1,      // Requires proximity
        proofs,
        2,      // 2 proofs
        &invitation
    );
    
    if (!result) {
        invitation_system_cleanup();
        return 1;
    }
    
    // Verify proximity settings
    if (!invitation.requires_proximity) {
        invitation_system_cleanup();
        return 1;
    }
    
    if (invitation.proximity_proof_count != 2) {
        invitation_system_cleanup();
        return 1;
    }
    
    if (invitation.proximity_proofs[0].type != PROXIMITY_PROOF_NFC) {
        invitation_system_cleanup();
        return 1;
    }
    
    if (invitation.proximity_proofs[1].type != PROXIMITY_PROOF_BLE) {
        invitation_system_cleanup();
        return 1;
    }
    
    invitation_system_cleanup();
    return 0;
}

static int test_proximity_validation(void) {
    ProximityProof proof;
    
    // Test valid proof
    create_mock_proximity_proof(&proof, PROXIMITY_PROOF_GPS);
    if (!invitation_verify_single_proximity_proof(&proof)) {
        return 1;
    }
    
    // Test proof with future timestamp (should fail)
    proof.timestamp = (uint64_t)time(NULL) + 3600; // 1 hour in future
    if (invitation_verify_single_proximity_proof(&proof)) {
        return 1;
    }
    
    // Test proof with old timestamp (should fail)
    proof.timestamp = (uint64_t)time(NULL) - 3600; // 1 hour ago
    if (invitation_verify_single_proximity_proof(&proof)) {
        return 1;
    }
    
    return 0;
}

static int test_invitation_type_helpers(void) {
    // Test user invitations
    if (!is_user_invitation(INVITATION_TYPE_FAMILY_MEMBER)) {
        return 1;
    }
    
    if (!is_user_invitation(INVITATION_TYPE_FAMILY_ADMIN)) {
        return 1;
    }
    
    // Test node invitations
    if (!is_node_invitation(INVITATION_TYPE_FAMILY_NODE)) {
        return 1;
    }
    
    // Test mixed cases
    if (is_node_invitation(INVITATION_TYPE_FAMILY_MEMBER)) {
        return 1;
    }
    
    if (is_user_invitation(INVITATION_TYPE_FAMILY_NODE)) {
        return 1;
    }
    
    // Test type name function
    const char* name = get_invitation_type_name(INVITATION_TYPE_FAMILY_MEMBER);
    if (strcmp(name, "Family Member") != 0) {
        return 1;
    }
    
    return 0;
}

// =============================================================================
// MAIN TEST RUNNER
// =============================================================================

int invitation_test_main(void) {
    printf("Starting invitation system tests...\n\n");
    
    // Initialize sodium for cryptographic functions
    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return 1;
    }
    
    // Basic invitation tests
    run_test("Invitation system initialization", test_invitation_system_init);
    run_test("Invitation code generation", test_invitation_code_generation);
    run_test("Create family member invitation", test_create_family_member_invitation);
    run_test("Create node invitation", test_create_node_invitation);
    run_test("Find invitation by code", test_find_invitation_by_code);
    run_test("Accept invitation", test_accept_invitation);
    
    // Proximity validation tests
    run_test("Create proximity invitation", test_proximity_invitation);
    run_test("Proximity proof validation", test_proximity_validation);
    
    // Invitation type tests
    run_test("Invitation type helpers", test_invitation_type_helpers);
    
    // Print summary
    printf("\nInvitation test summary:\n");
    printf("Total tests: %d\n", g_tests_passed + g_tests_failed);
    printf("Passed: %d\n", g_tests_passed);
    printf("Failed: %d\n", g_tests_failed);
    
    return g_tests_failed > 0 ? 1 : 0;
} 