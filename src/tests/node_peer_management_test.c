#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include "../packages/PBFT/node.h"
#include "../packages/keystore/keystore.h"

// Test helper functions
void print_test_result(const char* test_name, int passed) {
    printf("[%s] %s\n", passed ? "PASS" : "FAIL", test_name);
}

// Test node_add_peer function
void test_node_add_peer() {
    printf("\n=== Testing node_add_peer ===\n");
    
    // Initialize node state
    node_state_init();
    
    // Test data
    unsigned char pubkey1[PUBKEY_SIZE] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    unsigned char pubkey2[PUBKEY_SIZE] = {32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    const char* ip1 = "192.168.1.100:8080";
    const char* ip2 = "192.168.1.101:8080";
    uint32_t id1 = 1;
    uint32_t id2 = 2;
    
    // Test 1: Add first peer
    int result1 = node_add_peer(pubkey1, ip1, id1);
    print_test_result("Add first peer", result1 == 1);
    print_test_result("Peer count is 1", node_get_peer_count() == 1);
    
    // Test 2: Add second peer
    int result2 = node_add_peer(pubkey2, ip2, id2);
    print_test_result("Add second peer", result2 == 1);
    print_test_result("Peer count is 2", node_get_peer_count() == 2);
    
    // Test 3: Try to add duplicate peer (same ID)
    int result3 = node_add_peer(pubkey2, "192.168.1.102:8080", id1);
    print_test_result("Reject duplicate ID", result3 == 0);
    print_test_result("Peer count still 2", node_get_peer_count() == 2);
    
    // Test 4: Try to add duplicate peer (same public key)
    int result4 = node_add_peer(pubkey1, "192.168.1.103:8080", 3);
    print_test_result("Reject duplicate public key", result4 == 0);
    print_test_result("Peer count still 2", node_get_peer_count() == 2);
    
    // Test 5: Test with NULL parameters
    int result5 = node_add_peer(NULL, ip1, 4);
    print_test_result("Reject NULL public key", result5 == 0);
    
    int result6 = node_add_peer(pubkey1, NULL, 5);
    print_test_result("Reject NULL IP", result6 == 0);
    
    // Test 6: Verify peer info is stored correctly
    PeerInfo info;
    int result7 = node_get_peer_info(id1, &info);
    print_test_result("Get peer info success", result7 == 1);
    print_test_result("Peer ID matches", info.id == id1);
    print_test_result("Peer IP matches", strcmp(info.ip, ip1) == 0);
    print_test_result("Peer public key matches", memcmp(info.public_key, pubkey1, PUBKEY_SIZE) == 0);
    print_test_result("Peer not delinquent", info.is_delinquent == 0);
    print_test_result("Delinquent count is 0", info.delinquent_count == 0);
    
    node_state_cleanup();
}

// Test node_remove_peer function
void test_node_remove_peer() {
    printf("\n=== Testing node_remove_peer ===\n");
    
    // Initialize node state
    node_state_init();
    
    // Add test peers
    unsigned char pubkey1[PUBKEY_SIZE] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    unsigned char pubkey2[PUBKEY_SIZE] = {32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    unsigned char pubkey3[PUBKEY_SIZE] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200, 210, 220, 230, 240, 250, 255, 254, 253, 252, 251, 250, 249};
    
    node_add_peer(pubkey1, "192.168.1.100:8080", 1);
    node_add_peer(pubkey2, "192.168.1.101:8080", 2);
    node_add_peer(pubkey3, "192.168.1.102:8080", 3);
    
    print_test_result("Initial peer count is 3", node_get_peer_count() == 3);
    
    // Test 1: Remove middle peer
    int result1 = node_remove_peer(2);
    print_test_result("Remove peer 2 success", result1 == 1);
    print_test_result("Peer count is 2", node_get_peer_count() == 2);
    
    // Test 2: Verify peer 2 is gone
    PeerInfo info;
    int result2 = node_get_peer_info(2, &info);
    print_test_result("Peer 2 not found", result2 == 0);
    
    // Test 3: Verify other peers still exist
    int result3 = node_get_peer_info(1, &info);
    print_test_result("Peer 1 still exists", result3 == 1);
    
    int result4 = node_get_peer_info(3, &info);
    print_test_result("Peer 3 still exists", result4 == 1);
    
    // Test 4: Try to remove non-existent peer
    int result5 = node_remove_peer(99);
    print_test_result("Remove non-existent peer fails", result5 == 0);
    print_test_result("Peer count still 2", node_get_peer_count() == 2);
    
    // Test 5: Verify lookup tables are updated
    const char* ip = node_get_ip_by_id(2);
    print_test_result("ID lookup for removed peer returns NULL", ip == NULL);
    
    ip = node_get_ip_by_pubkey(pubkey2);
    print_test_result("Public key lookup for removed peer returns NULL", ip == NULL);
    
    uint32_t id = node_get_id_by_pubkey(pubkey2);
    print_test_result("Public key to ID lookup for removed peer returns 0", id == 0);
    
    node_state_cleanup();
}

// Test node_mark_peer_delinquent function
void test_node_mark_peer_delinquent() {
    printf("\n=== Testing node_mark_peer_delinquent ===\n");
    
    // Initialize node state
    node_state_init();
    
    // Add test peer
    unsigned char pubkey1[PUBKEY_SIZE] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    node_add_peer(pubkey1, "192.168.1.100:8080", 1);
    
    // Test 1: Mark peer delinquent (should increment counter but not mark as delinquent yet)
    int result1 = node_mark_peer_delinquent(1);
    print_test_result("Mark peer delinquent success", result1 == 1);
    
    PeerInfo info;
    node_get_peer_info(1, &info);
    print_test_result("Delinquent count is 1", info.delinquent_count == 1);
    print_test_result("Peer not yet marked delinquent", info.is_delinquent == 0);
    
    // Test 2: Mark peer delinquent 14 more times (total 15)
    for (int i = 0; i < 14; i++) {
        node_mark_peer_delinquent(1);
    }
    
    node_get_peer_info(1, &info);
    print_test_result("Delinquent count is 15", info.delinquent_count == 15);
    print_test_result("Peer marked as delinquent", info.is_delinquent == 1);
    
    // Test 3: Try to mark non-existent peer
    int result2 = node_mark_peer_delinquent(99);
    print_test_result("Mark non-existent peer fails", result2 == 0);
    
    // Test 4: Test active peer count
    print_test_result("Active peer count is 0", node_get_active_peer_count() == 0);
    
    node_state_cleanup();
}

// Test node_reset_peer_delinquent function
void test_node_reset_peer_delinquent() {
    printf("\n=== Testing node_reset_peer_delinquent ===\n");
    
    // Initialize node state
    node_state_init();
    
    // Add test peer and mark as delinquent
    unsigned char pubkey1[PUBKEY_SIZE] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    node_add_peer(pubkey1, "192.168.1.100:8080", 1);
    
    // Mark peer delinquent 15 times
    for (int i = 0; i < 15; i++) {
        node_mark_peer_delinquent(1);
    }
    
    PeerInfo info;
    node_get_peer_info(1, &info);
    print_test_result("Peer is delinquent", info.is_delinquent == 1);
    print_test_result("Delinquent count is 15", info.delinquent_count == 15);
    
    // Test 1: Reset peer delinquent status
    int result1 = node_reset_peer_delinquent(1);
    print_test_result("Reset peer delinquent success", result1 == 1);
    
    node_get_peer_info(1, &info);
    print_test_result("Peer no longer delinquent", info.is_delinquent == 0);
    print_test_result("Delinquent count reset to 0", info.delinquent_count == 0);
    
    // Test 2: Try to reset non-existent peer
    int result2 = node_reset_peer_delinquent(99);
    print_test_result("Reset non-existent peer fails", result2 == 0);
    
    // Test 3: Test active peer count
    print_test_result("Active peer count is 1", node_get_active_peer_count() == 1);
    
    node_state_cleanup();
}

// Test peer lookup functions
void test_peer_lookup_functions() {
    printf("\n=== Testing peer lookup functions ===\n");
    
    // Initialize node state
    node_state_init();
    
    // Add test peers
    unsigned char pubkey1[PUBKEY_SIZE] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    unsigned char pubkey2[PUBKEY_SIZE] = {32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    const char* ip1 = "192.168.1.100:8080";
    const char* ip2 = "192.168.1.101:8080";
    
    node_add_peer(pubkey1, ip1, 1);
    node_add_peer(pubkey2, ip2, 2);
    
    // Test 1: node_get_ip_by_id
    const char* result_ip1 = node_get_ip_by_id(1);
    print_test_result("Get IP by ID 1", result_ip1 != NULL && strcmp(result_ip1, ip1) == 0);
    
    const char* result_ip2 = node_get_ip_by_id(2);
    print_test_result("Get IP by ID 2", result_ip2 != NULL && strcmp(result_ip2, ip2) == 0);
    
    const char* result_ip3 = node_get_ip_by_id(99);
    print_test_result("Get IP by non-existent ID returns NULL", result_ip3 == NULL);
    
    // Test 2: node_get_ip_by_pubkey
    const char* result_ip4 = node_get_ip_by_pubkey(pubkey1);
    print_test_result("Get IP by pubkey 1", result_ip4 != NULL && strcmp(result_ip4, ip1) == 0);
    
    const char* result_ip5 = node_get_ip_by_pubkey(pubkey2);
    print_test_result("Get IP by pubkey 2", result_ip5 != NULL && strcmp(result_ip5, ip2) == 0);
    
    unsigned char fake_pubkey[PUBKEY_SIZE] = {99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99};
    const char* result_ip6 = node_get_ip_by_pubkey(fake_pubkey);
    print_test_result("Get IP by non-existent pubkey returns NULL", result_ip6 == NULL);
    
    // Test 3: node_get_id_by_pubkey
    uint32_t result_id1 = node_get_id_by_pubkey(pubkey1);
    print_test_result("Get ID by pubkey 1", result_id1 == 1);
    
    uint32_t result_id2 = node_get_id_by_pubkey(pubkey2);
    print_test_result("Get ID by pubkey 2", result_id2 == 2);
    
    uint32_t result_id3 = node_get_id_by_pubkey(fake_pubkey);
    print_test_result("Get ID by non-existent pubkey returns 0", result_id3 == 0);
    
    node_state_cleanup();
}

// Test peer count functions
void test_peer_count_functions() {
    printf("\n=== Testing peer count functions ===\n");
    
    // Initialize node state
    node_state_init();
    
    // Test 1: Empty state
    print_test_result("Initial peer count is 0", node_get_peer_count() == 0);
    print_test_result("Initial active peer count is 0", node_get_active_peer_count() == 0);
    
    // Add test peers
    unsigned char pubkey1[PUBKEY_SIZE] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    unsigned char pubkey2[PUBKEY_SIZE] = {32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
    unsigned char pubkey3[PUBKEY_SIZE] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190, 200, 210, 220, 230, 240, 250, 255, 254, 253, 252, 251, 250, 249};
    
    node_add_peer(pubkey1, "192.168.1.100:8080", 1);
    node_add_peer(pubkey2, "192.168.1.101:8080", 2);
    node_add_peer(pubkey3, "192.168.1.102:8080", 3);
    
    // Test 2: All peers active
    print_test_result("Total peer count is 3", node_get_peer_count() == 3);
    print_test_result("Active peer count is 3", node_get_active_peer_count() == 3);
    
    // Test 3: Mark one peer delinquent
    for (int i = 0; i < 15; i++) {
        node_mark_peer_delinquent(2);
    }
    
    print_test_result("Total peer count still 3", node_get_peer_count() == 3);
    print_test_result("Active peer count is 2", node_get_active_peer_count() == 2);
    
    // Test 4: Reset delinquent peer
    node_reset_peer_delinquent(2);
    print_test_result("Active peer count back to 3", node_get_active_peer_count() == 3);
    
    node_state_cleanup();
}

int node_peer_management_test_main() {
    printf("Starting Node Peer Management Tests\n");
    printf("====================================\n");
    
    // Run all tests
    test_node_add_peer();
    test_node_remove_peer();
    test_node_mark_peer_delinquent();
    test_node_reset_peer_delinquent();
    test_peer_lookup_functions();
    test_peer_count_functions();
    
    printf("\n====================================\n");
    printf("Node Peer Management Tests Complete\n");
    
    return 0;
}