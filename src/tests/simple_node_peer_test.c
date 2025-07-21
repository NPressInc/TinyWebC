#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

// Include only the necessary headers for testing peer management
#include "../packages/keystore/keystore.h"

// Simplified definitions for testing (avoiding full blockchain dependencies)
#define MAX_PEERS 100
#define MAX_IP_LEN 50
#define PUBKEY_SIZE 32

// Structure to hold peer information
typedef struct {
    unsigned char public_key[PUBKEY_SIZE];
    char ip[MAX_IP_LEN]; 
    uint32_t id;  // Node ID (proposer order)
    int is_delinquent;  // Flag for delinquent status
    uint32_t delinquent_count;  // Counter for delinquent failures
    time_t last_seen;
} PeerInfo;

// Structure to hold node state
typedef struct {
    // Peer management
    PeerInfo peers[MAX_PEERS];
    size_t peer_count;
    
    // Peer lookup tables
    struct {
        uint32_t id;
        char ip[MAX_IP_LEN];
    } id_ip_map[MAX_PEERS];
    size_t id_ip_count;
    
    struct {
        unsigned char public_key[PUBKEY_SIZE];
        char ip[MAX_IP_LEN];
    } pkey_ip_map[MAX_PEERS];
    size_t pkey_ip_count;
    
    struct {
        unsigned char public_key[PUBKEY_SIZE];
        uint32_t id;
    } pkey_id_map[MAX_PEERS];
    size_t pkey_id_count;
} NodeState;

// Global node state
static NodeState node_state;

// Simplified node state management functions
void node_state_init(void) {
    memset(&node_state, 0, sizeof(NodeState));
}

void node_state_cleanup(void) {
    // Nothing to cleanup in simplified version
}

// Peer management functions (copied from node.c)
int node_add_peer(const unsigned char* public_key, const char* ip, uint32_t id) {
    if (!public_key || !ip) {
        return 0; // Invalid parameters
    }
    
    if (node_state.peer_count >= MAX_PEERS) {
        return 0; // Peer list is full
    }
    
    // Check if peer already exists (by ID or public key)
    for (size_t i = 0; i < node_state.peer_count; i++) {
        if (node_state.peers[i].id == id || 
            memcmp(node_state.peers[i].public_key, public_key, PUBKEY_SIZE) == 0) {
            return 0; // Peer already exists
        }
    }
    
    // Add to peers array
    PeerInfo* peer = &node_state.peers[node_state.peer_count];
    memcpy(peer->public_key, public_key, PUBKEY_SIZE);
    strncpy(peer->ip, ip, sizeof(peer->ip) - 1);
    peer->ip[sizeof(peer->ip) - 1] = '\0'; // Ensure null termination
    peer->id = id;
    peer->is_delinquent = 0;
    peer->delinquent_count = 0;
    peer->last_seen = time(NULL);
    
    // Add to ID-IP map
    node_state.id_ip_map[node_state.id_ip_count].id = id;
    strncpy(node_state.id_ip_map[node_state.id_ip_count].ip, ip, sizeof(node_state.id_ip_map[0].ip) - 1);
    node_state.id_ip_map[node_state.id_ip_count].ip[sizeof(node_state.id_ip_map[0].ip) - 1] = '\0';
    node_state.id_ip_count++;

    // Add to public key-IP map
    memcpy(node_state.pkey_ip_map[node_state.pkey_ip_count].public_key, public_key, PUBKEY_SIZE);
    strncpy(node_state.pkey_ip_map[node_state.pkey_ip_count].ip, ip, sizeof(node_state.pkey_ip_map[0].ip) - 1);
    node_state.pkey_ip_map[node_state.pkey_ip_count].ip[sizeof(node_state.pkey_ip_map[0].ip) - 1] = '\0';
    node_state.pkey_ip_count++;
    
    // Add to public key-ID map
    memcpy(node_state.pkey_id_map[node_state.pkey_id_count].public_key, public_key, PUBKEY_SIZE);
    node_state.pkey_id_map[node_state.pkey_id_count].id = id;
    node_state.pkey_id_count++;
    
    // Update peer count
    node_state.peer_count++;
    
    return 1; // Success
}

int node_remove_peer(uint32_t id) {
    // Find the peer to remove
    size_t peer_index = SIZE_MAX;
    for (size_t i = 0; i < node_state.peer_count; i++) {
        if (node_state.peers[i].id == id) {
            peer_index = i;
            break;
        }
    }
    
    if (peer_index == SIZE_MAX) {
        return 0; // Peer not found
    }
    
    // Get the public key before removing the peer
    unsigned char public_key[PUBKEY_SIZE];
    memcpy(public_key, node_state.peers[peer_index].public_key, PUBKEY_SIZE);
    
    // Remove from peers array by shifting remaining elements
    for (size_t i = peer_index; i < node_state.peer_count - 1; i++) {
        node_state.peers[i] = node_state.peers[i + 1];
    }
    node_state.peer_count--;
    
    // Remove from ID-IP map
    for (size_t i = 0; i < node_state.id_ip_count; i++) {
        if (node_state.id_ip_map[i].id == id) {
            // Shift remaining elements
            for (size_t j = i; j < node_state.id_ip_count - 1; j++) {
                node_state.id_ip_map[j] = node_state.id_ip_map[j + 1];
            }
            node_state.id_ip_count--;
            break;
        }
    }
    
    // Remove from public key-IP map
    for (size_t i = 0; i < node_state.pkey_ip_count; i++) {
        if (memcmp(node_state.pkey_ip_map[i].public_key, public_key, PUBKEY_SIZE) == 0) {
            // Shift remaining elements
            for (size_t j = i; j < node_state.pkey_ip_count - 1; j++) {
                node_state.pkey_ip_map[j] = node_state.pkey_ip_map[j + 1];
            }
            node_state.pkey_ip_count--;
            break;
        }
    }
    
    // Remove from public key-ID map
    for (size_t i = 0; i < node_state.pkey_id_count; i++) {
        if (memcmp(node_state.pkey_id_map[i].public_key, public_key, PUBKEY_SIZE) == 0) {
            // Shift remaining elements
            for (size_t j = i; j < node_state.pkey_id_count - 1; j++) {
                node_state.pkey_id_map[j] = node_state.pkey_id_map[j + 1];
            }
            node_state.pkey_id_count--;
            break;
        }
    }
    
    return 1; // Success
}

int node_mark_peer_delinquent(uint32_t id) {
    for (size_t i = 0; i < node_state.peer_count; i++) {
        if (node_state.peers[i].id == id) {
            node_state.peers[i].delinquent_count++;
            
            // Mark as delinquent if threshold exceeded (15 failures as per requirements)
            if (node_state.peers[i].delinquent_count >= 15) {
                node_state.peers[i].is_delinquent = 1;
            }
            
            return 1; // Successfully marked peer as delinquent
        }
    }
    return 0; // Peer not found
}

int node_reset_peer_delinquent(uint32_t id) {
    for (size_t i = 0; i < node_state.peer_count; i++) {
        if (node_state.peers[i].id == id) {
            node_state.peers[i].delinquent_count = 0;
            node_state.peers[i].is_delinquent = 0;
            node_state.peers[i].last_seen = time(NULL);
            return 1; // Successfully reset peer delinquent status
        }
    }
    return 0; // Peer not found
}

int node_get_peer_info(uint32_t id, PeerInfo* info) {
    if (!info) {
        return 0; // Invalid parameter
    }
    
    for (size_t i = 0; i < node_state.peer_count; i++) {
        if (node_state.peers[i].id == id) {
            memcpy(info, &node_state.peers[i], sizeof(PeerInfo));
            return 1;
        }
    }
    return 0;
}

size_t node_get_peer_count(void) {
    return node_state.peer_count;
}

size_t node_get_active_peer_count(void) {
    size_t active_count = 0;
    for (size_t i = 0; i < node_state.peer_count; i++) {
        if (!node_state.peers[i].is_delinquent) {
            active_count++;
        }
    }
    return active_count;
}

// Peer lookup functions
const char* node_get_ip_by_id(uint32_t id) {
    for (size_t i = 0; i < node_state.id_ip_count; i++) {
        if (node_state.id_ip_map[i].id == id) {
            return node_state.id_ip_map[i].ip;
        }
    }
    return NULL;
}

const char* node_get_ip_by_pubkey(const unsigned char* public_key) {
    for (size_t i = 0; i < node_state.pkey_ip_count; i++) {
        if (memcmp(node_state.pkey_ip_map[i].public_key, public_key, PUBKEY_SIZE) == 0) {
            return node_state.pkey_ip_map[i].ip;
        }
    }
    return NULL;
}

uint32_t node_get_id_by_pubkey(const unsigned char* public_key) {
    for (size_t i = 0; i < node_state.pkey_id_count; i++) {
        if (memcmp(node_state.pkey_id_map[i].public_key, public_key, PUBKEY_SIZE) == 0) {
            return node_state.pkey_id_map[i].id;
        }
    }
    return 0;
}

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

int main() {
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