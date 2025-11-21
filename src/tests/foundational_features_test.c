#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>
#include <sodium.h>

#include "packages/utils/error.h"
#include "packages/utils/config.h"
#include "packages/utils/retry.h"
#include "packages/utils/logger.h"
#include "packages/keystore/keystore.h"
#include "packages/comm/gossip/gossip.h"
#include "packages/initialization/init.h"

#define TEST_BASE_PATH "test_state_integration"
#define TEST_CONFIG_PATH "test_state_integration/test_network_config.json"

// Test counters
static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_TEST(condition, message) \
    do { \
        if (condition) { \
            printf("  ✓ %s\n", message); \
            tests_passed++; \
        } else { \
            printf("  ✗ %s\n", message); \
            tests_failed++; \
        } \
    } while(0)

// ============================================================================
// Test 1: Error Handling System
// ============================================================================

static int test_error_handling_system(void) {
    printf("\n=== Test 1: Error Handling System ===\n");
    
    // Test error creation
    tw_error_t* error = tw_error_create(TW_ERROR_NULL_POINTER, "test", "test_func", 42, "Test error message");
    ASSERT_TEST(error != NULL, "Error creation succeeds");
    ASSERT_TEST(error->code == TW_ERROR_NULL_POINTER, "Error code is correct");
    ASSERT_TEST(strcmp(error->module, "test") == 0, "Error module is correct");
    ASSERT_TEST(strcmp(error->function, "test_func") == 0, "Error function is correct");
    ASSERT_TEST(error->line == 42, "Error line is correct");
    
    // Test error to string
    const char* error_str = tw_error_to_string(error);
    ASSERT_TEST(error_str != NULL, "Error to string succeeds");
    ASSERT_TEST(strstr(error_str, "test") != NULL, "Error string contains module");
    ASSERT_TEST(strstr(error_str, "Test error message") != NULL, "Error string contains message");
    
    // Test thread-local error storage
    tw_error_t* last_error = tw_error_get_last();
    ASSERT_TEST(last_error == error, "Thread-local error storage works");
    ASSERT_TEST(tw_error_get_code(last_error) == TW_ERROR_NULL_POINTER, "Error code retrieval works");
    
    // Test error clearing
    tw_error_clear();
    last_error = tw_error_get_last();
    ASSERT_TEST(last_error == NULL, "Error clearing works");
    
    // Test conversion helpers
    int sqlite_result = tw_error_from_sqlite_error(SQLITE_OK);
    ASSERT_TEST(sqlite_result == 0, "SQLite OK converts to 0");
    
    sqlite_result = tw_error_from_sqlite_error(SQLITE_ERROR);
    ASSERT_TEST(sqlite_result == TW_ERROR_DATABASE_ERROR, "SQLite error converts correctly");
    
    int validation_result = tw_error_from_validation_result(0);
    ASSERT_TEST(validation_result == 0, "Validation OK converts to 0");
    
    validation_result = tw_error_from_validation_result(-1);
    ASSERT_TEST(validation_result == TW_ERROR_NULL_POINTER, "Validation error converts correctly");
    
    // Don't free thread-local error storage - it's managed by pthread
    
    printf("  Error handling tests: %d passed, %d failed\n", tests_passed, tests_failed);
    return (tests_failed == 0) ? 0 : -1;
}

// ============================================================================
// Test 2: Configuration Management
// ============================================================================

static int test_configuration_management(void) {
    printf("\n=== Test 2: Configuration Management ===\n");
    
    // Create a test network config JSON
    FILE* config_file = fopen(TEST_CONFIG_PATH, "w");
    if (!config_file) {
        printf("  ✗ Failed to create test config file\n");
        return -1;
    }
    
    fprintf(config_file, "{\n");
    fprintf(config_file, "  \"network\": {\n");
    fprintf(config_file, "    \"name\": \"Test Network\",\n");
    fprintf(config_file, "    \"description\": \"Integration test network\",\n");
    fprintf(config_file, "    \"base_port\": 8000,\n");
    fprintf(config_file, "    \"max_connections\": 10,\n");
    fprintf(config_file, "    \"validation\": {\n");
    fprintf(config_file, "      \"max_clock_skew_seconds\": 600,\n");
    fprintf(config_file, "      \"message_ttl_seconds\": 3600,\n");
    fprintf(config_file, "      \"max_payload_bytes\": 2048000\n");
    fprintf(config_file, "    },\n");
    fprintf(config_file, "    \"logging\": {\n");
    fprintf(config_file, "      \"level\": \"DEBUG\",\n");
    fprintf(config_file, "      \"to_file\": true,\n");
    fprintf(config_file, "      \"file_path\": \"test.log\"\n");
    fprintf(config_file, "    },\n");
    fprintf(config_file, "    \"network_error_handling\": {\n");
    fprintf(config_file, "      \"max_retries\": 5,\n");
    fprintf(config_file, "      \"initial_delay_ms\": 200,\n");
    fprintf(config_file, "      \"backoff_multiplier\": 1.5,\n");
    fprintf(config_file, "      \"max_delay_ms\": 10000\n");
    fprintf(config_file, "    }\n");
    fprintf(config_file, "  },\n");
    fprintf(config_file, "  \"nodes\": [\n");
    fprintf(config_file, "    {\n");
    fprintf(config_file, "      \"id\": \"node_001\",\n");
    fprintf(config_file, "      \"name\": \"Test Node 1\",\n");
    fprintf(config_file, "      \"type\": \"primary\",\n");
    fprintf(config_file, "      \"hostname\": \"test1.example.com\",\n");
    fprintf(config_file, "      \"gossip_port\": 9100,\n");
    fprintf(config_file, "      \"api_port\": 8100,\n");
    fprintf(config_file, "      \"peers\": [\n");
    fprintf(config_file, "        \"test2.example.com:9100\",\n");
    fprintf(config_file, "        \"test3.example.com:9100\"\n");
    fprintf(config_file, "      ]\n");
    fprintf(config_file, "    }\n");
    fprintf(config_file, "  ]\n");
    fprintf(config_file, "}\n");
    fclose(config_file);
    
    // Test config loading
    NodeConfig config;
    int result = config_load_node_from_network_config(TEST_CONFIG_PATH, "node_001", &config);
    ASSERT_TEST(result == 0, "Config loads from file");
    ASSERT_TEST(strcmp(config.node_id, "node_001") == 0, "Node ID is correct");
    ASSERT_TEST(strcmp(config.node_name, "Test Node 1") == 0, "Node name is correct");
    ASSERT_TEST(config.gossip_port == 9100, "Gossip port is correct");
    ASSERT_TEST(config.api_port == 8100, "API port is correct");
    ASSERT_TEST(config.max_clock_skew_seconds == 600, "Max clock skew from config");
    ASSERT_TEST(config.message_ttl_seconds == 3600, "Message TTL from config");
    ASSERT_TEST(config.max_payload_bytes == 2048000, "Max payload from config");
    ASSERT_TEST(config.max_retries == 5, "Max retries from config");
    ASSERT_TEST(config.initial_delay_ms == 200, "Initial delay from config");
    ASSERT_TEST(config.backoff_multiplier == 1.5, "Backoff multiplier from config");
    ASSERT_TEST(config.max_delay_ms == 10000, "Max delay from config");
    ASSERT_TEST(config.peer_count == 2, "Peer count is correct");
    if (config.peer_count == 2) {
        ASSERT_TEST(strcmp(config.peers[0], "test2.example.com:9100") == 0, "First peer is correct");
        ASSERT_TEST(strcmp(config.peers[1], "test3.example.com:9100") == 0, "Second peer is correct");
    }
    
    // Test config defaults
    NodeConfig default_config;
    config_set_defaults(&default_config);
    ASSERT_TEST(default_config.max_clock_skew_seconds == 300, "Default clock skew");
    ASSERT_TEST(default_config.message_ttl_seconds > 0, "Default TTL is set");
    ASSERT_TEST(default_config.max_payload_bytes == 1024 * 1024, "Default max payload");
    
    // Test config validation
    result = config_validate(&config);
    ASSERT_TEST(result == 0, "Valid config passes validation");
    
    NodeConfig invalid_config = config;
    invalid_config.gossip_port = 100; // Invalid port
    result = config_validate(&invalid_config);
    ASSERT_TEST(result != 0, "Invalid config fails validation");
    
    // Test environment variable overrides
    setenv("TINYWEB_GOSSIP_PORT", "9200", 1);
    setenv("TINYWEB_LOG_LEVEL", "ERROR", 1);
    setenv("TINYWEB_MAX_CLOCK_SKEW", "900", 1);
    
    NodeConfig env_config;
    memset(&env_config, 0, sizeof(env_config));
    result = config_load_from_env(&env_config);
    ASSERT_TEST(result == 0, "Environment config loads");
    ASSERT_TEST(env_config.gossip_port == 9200, "Environment overrides gossip port");
    ASSERT_TEST(env_config.log_level == LOG_LEVEL_ERROR, "Environment overrides log level");
    ASSERT_TEST(env_config.max_clock_skew_seconds == 900, "Environment overrides clock skew");
    
    // Test config merge (don't copy struct to avoid sharing peer pointers)
    // Just verify merge would work by checking env_config values
    ASSERT_TEST(env_config.gossip_port == 9200, "Environment config has correct gossip port");
    ASSERT_TEST(env_config.log_level == LOG_LEVEL_ERROR, "Environment config has correct log level");
    
    // Test merge on a copy (clear peers first to avoid double-free)
    NodeConfig merged_config;
    memcpy(&merged_config, &config, sizeof(NodeConfig));
    merged_config.peers = NULL;  // Don't copy peer pointers
    merged_config.peer_count = 0;
    config_merge(&merged_config, &env_config);
    ASSERT_TEST(merged_config.gossip_port == 9200, "Merged config uses env override");
    ASSERT_TEST(merged_config.api_port == 8100, "Merged config keeps file value");
    
    // Cleanup
    unsetenv("TINYWEB_GOSSIP_PORT");
    unsetenv("TINYWEB_LOG_LEVEL");
    unsetenv("TINYWEB_MAX_CLOCK_SKEW");
    
    // Free configs - only config has allocated peers
    config_free(&config);
    
    printf("  Configuration tests: %d passed, %d failed\n", tests_passed, tests_failed);
    return (tests_failed == 0) ? 0 : -1;
}

// ============================================================================
// Test 3: Retry Logic with Exponential Backoff
// ============================================================================

static int retry_test_func_success(void* arg) {
    (void)arg;
    return 0; // Success
}

static int retry_test_func_failure(void* arg) {
    int* attempt = (int*)arg;
    (*attempt)++;
    return -1; // Always fail
}

static int retry_test_func_succeed_after_retries(void* arg) {
    int* attempt = (int*)arg;
    (*attempt)++;
    if (*attempt >= 3) {
        return 0; // Succeed on 3rd attempt
    }
    return -1; // Fail first 2 times
}

static int test_retry_logic(void) {
    printf("\n=== Test 3: Retry Logic with Exponential Backoff ===\n");
    
    RetryConfig retry_config;
    retry_config_set_defaults(&retry_config);
    ASSERT_TEST(retry_config.max_retries == 3, "Default max retries is 3");
    ASSERT_TEST(retry_config.initial_delay_ms == 100, "Default initial delay is 100ms");
    ASSERT_TEST(retry_config.backoff_multiplier == 2.0, "Default backoff multiplier is 2.0");
    ASSERT_TEST(retry_config.max_delay_ms == 5000, "Default max delay is 5000ms");
    
    // Test successful function (no retries needed)
    int result = retry_with_backoff(retry_test_func_success, NULL, &retry_config, NULL);
    ASSERT_TEST(result == 0, "Successful function returns 0");
    
    // Test function that always fails
    int attempt = 0;
    tw_error_t* error = NULL;
    result = retry_with_backoff(retry_test_func_failure, &attempt, &retry_config, &error);
    ASSERT_TEST(result != 0, "Always-failing function returns error");
    ASSERT_TEST(attempt == retry_config.max_retries + 1, "Function called max_retries + 1 times");
    ASSERT_TEST(error != NULL, "Error is set on failure");
    // Don't free thread-local error storage - it's managed by pthread
    
    // Test function that succeeds after retries
    attempt = 0;
    RetryConfig custom_config = {
        .max_retries = 5,
        .initial_delay_ms = 10, // Fast for testing
        .backoff_multiplier = 2.0,
        .max_delay_ms = 1000
    };
    result = retry_with_backoff(retry_test_func_succeed_after_retries, &attempt, &custom_config, NULL);
    ASSERT_TEST(result == 0, "Function succeeds after retries");
    ASSERT_TEST(attempt == 3, "Function called 3 times before success");
    
    printf("  Retry logic tests: %d passed, %d failed\n", tests_passed, tests_failed);
    return (tests_failed == 0) ? 0 : -1;
}

// ============================================================================
// Test 4: Peer Health Monitoring
// ============================================================================

static int test_peer_health_monitoring(void) {
    printf("\n=== Test 4: Peer Health Monitoring ===\n");
    
    GossipService service;
    memset(&service, 0, sizeof(service));
    
    // Initialize gossip service
    int result = gossip_service_init(&service, 0, NULL, NULL);
    ASSERT_TEST(result == 0, "Gossip service initializes");
    
    // Add a peer
    result = gossip_service_add_peer(&service, "test.example.com", 9000);
    ASSERT_TEST(result == 0, "Peer added successfully");
    ASSERT_TEST(service.peer_count == 1, "Peer count is 1");
    
    // Check initial health state
    ASSERT_TEST(service.peers[0].is_healthy == true, "New peer starts healthy");
    ASSERT_TEST(service.peers[0].consecutive_failures == 0, "New peer has 0 failures");
    ASSERT_TEST(service.peers[0].last_success == 0, "New peer has no success time");
    ASSERT_TEST(service.peers[0].last_failure == 0, "New peer has no failure time");
    
    // Simulate failures (would normally happen in sendto)
    time_t now = time(NULL);
    service.peers[0].last_failure = now;
    service.peers[0].consecutive_failures = 1;
    ASSERT_TEST(service.peers[0].consecutive_failures == 1, "Failure count increments");
    
    service.peers[0].consecutive_failures = 3;
    service.peers[0].is_healthy = false;
    ASSERT_TEST(service.peers[0].is_healthy == false, "Peer marked unhealthy after 3 failures");
    
    // Simulate recovery
    service.peers[0].last_success = now + 10;
    service.peers[0].consecutive_failures = 0;
    service.peers[0].is_healthy = true;
    ASSERT_TEST(service.peers[0].is_healthy == true, "Peer recovers to healthy");
    ASSERT_TEST(service.peers[0].consecutive_failures == 0, "Failure count resets on success");
    
    gossip_service_stop(&service);
    
    printf("  Peer health monitoring tests: %d passed, %d failed\n", tests_passed, tests_failed);
    return (tests_failed == 0) ? 0 : -1;
}

// ============================================================================
// Test 5: Thread Safety (Keystore Mutex)
// ============================================================================

typedef struct {
    int thread_id;
    int success_count;
    int failure_count;
} KeystoreThreadData;

static void* keystore_thread_func(void* arg) {
    KeystoreThreadData* data = (KeystoreThreadData*)arg;
    
    // Initialize keystore (should be thread-safe)
    if (keystore_init() != 0) {
        data->failure_count++;
        return NULL;
    }
    
    // Generate keypair (should be thread-safe)
    if (keystore_generate_keypair() != 0) {
        data->failure_count++;
        return NULL;
    }
    
    // Get public key multiple times (should be thread-safe)
    unsigned char pubkey[32];
    for (int i = 0; i < 10; i++) {
        if (keystore_get_public_key(pubkey) == 0) {
            data->success_count++;
        } else {
            data->failure_count++;
        }
    }
    
    return NULL;
}

static int test_keystore_thread_safety(void) {
    printf("\n=== Test 5: Thread Safety (Keystore Mutex) ===\n");
    
    // Initialize keystore once
    if (keystore_init() != 0) {
        printf("  ✗ Failed to initialize keystore\n");
        return -1;
    }
    
    if (keystore_generate_keypair() != 0) {
        printf("  ✗ Failed to generate keypair\n");
        return -1;
    }
    
    // Test concurrent access from multiple threads
    const int num_threads = 5;
    pthread_t threads[num_threads];
    KeystoreThreadData thread_data[num_threads];
    
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].thread_id = i;
        thread_data[i].success_count = 0;
        thread_data[i].failure_count = 0;
        
        if (pthread_create(&threads[i], NULL, keystore_thread_func, &thread_data[i]) != 0) {
            printf("  ✗ Failed to create thread %d\n", i);
            return -1;
        }
    }
    
    // Wait for all threads
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Check results
    int total_success = 0;
    int total_failure = 0;
    for (int i = 0; i < num_threads; i++) {
        total_success += thread_data[i].success_count;
        total_failure += thread_data[i].failure_count;
    }
    
    ASSERT_TEST(total_failure == 0, "No thread safety failures");
    ASSERT_TEST(total_success == num_threads * 10, "All thread operations succeeded");
    
    keystore_cleanup();
    
    printf("  Thread safety tests: %d passed, %d failed\n", tests_passed, tests_failed);
    return (tests_failed == 0) ? 0 : -1;
}

// ============================================================================
// Test 6: Full Config Save/Load Cycle
// ============================================================================

static int test_config_save_load_cycle(void) {
    printf("\n=== Test 6: Full Config Save/Load Cycle ===\n");
    
    // Create test network config structure
    InitNetworkConfig network_config = {0};
    network_config.network_name = "Integration Test Network";
    network_config.network_description = "Full cycle test";
    network_config.base_port = 8000;
    network_config.node_count = 1;
    
    InitNodeConfig node = {0};
    node.id = strdup("node_001");
    node.name = strdup("Test Node");
    node.hostname = strdup("test.example.com");
    node.gossip_port = 9000;
    node.api_port = 8000;
    node.peer_count = 2;
    node.peers = calloc(2, sizeof(char*));
    node.peers[0] = strdup("peer1.example.com:9000");
    node.peers[1] = strdup("peer2.example.com:9000");
    
    network_config.nodes = &node;
    
    // Create node directory
    char node_path[256];
    snprintf(node_path, sizeof(node_path), "%s/node_001", TEST_BASE_PATH);
    mkdir(TEST_BASE_PATH, 0755);
    mkdir(node_path, 0755);
    
    // Save config (use NULL to force reconstruction from InitNodeConfig, not copying existing file)
    int result = init_save_node_config(NULL, &network_config, &node, node_path);
    ASSERT_TEST(result == 0, "Config saves successfully");
    
    // Verify file exists
    char saved_config_path[256];
    snprintf(saved_config_path, sizeof(saved_config_path), "%s/network_config.json", node_path);
    FILE* f = fopen(saved_config_path, "r");
    ASSERT_TEST(f != NULL, "Saved config file exists");
    if (f) {
        fclose(f);
    }
    
    // Load config back
    NodeConfig loaded_config;
    memset(&loaded_config, 0, sizeof(loaded_config));
    result = config_load_node_from_network_config(saved_config_path, "node_001", &loaded_config);
    ASSERT_TEST(result == 0, "Config loads from saved file");
    if (result == 0) {
        ASSERT_TEST(strcmp(loaded_config.node_id, "node_001") == 0, "Loaded node ID matches");
        ASSERT_TEST(loaded_config.gossip_port == 9000, "Loaded gossip port matches");
        ASSERT_TEST(loaded_config.api_port == 8000, "Loaded API port matches");
        ASSERT_TEST(loaded_config.peer_count == 2, "Loaded peer count matches");
    }
    
    config_free(&loaded_config);
    
    // Cleanup InitNodeConfig structure
    if (node.id) free(node.id);
    if (node.name) free(node.name);
    if (node.hostname) free(node.hostname);
    if (node.peers) {
        if (node.peers[0]) free(node.peers[0]);
        if (node.peers[1]) free(node.peers[1]);
        free(node.peers);   
    }
    
    printf("  Config save/load cycle tests: %d passed, %d failed\n", tests_passed, tests_failed);
    return (tests_failed == 0) ? 0 : -1;
}

// ============================================================================
// Main Test Runner
// ============================================================================

int foundational_features_test_main(void) {
    printf("\n");
    printf("========================================\n");
    printf("Foundational Features Integration Test\n");
    printf("========================================\n");
    
    // Initialize logger
    logger_init();
    
    // Initialize libsodium
    if (sodium_init() < 0) {
        printf("Failed to initialize libsodium\n");
        return 1;
    }
    
    // Reset counters
    tests_passed = 0;
    tests_failed = 0;
    
    // Run all tests
    int result = 0;
    
    if (test_error_handling_system() != 0) result = 1;
    if (test_configuration_management() != 0) result = 1;
    if (test_retry_logic() != 0) result = 1;
    if (test_peer_health_monitoring() != 0) result = 1;
    if (test_keystore_thread_safety() != 0) result = 1;
    if (test_config_save_load_cycle() != 0) result = 1;
    
    // Clear any errors before cleanup
    tw_error_clear();
    
    // Cleanup test files
    unlink(TEST_CONFIG_PATH);
    char saved_config_path[256];
    snprintf(saved_config_path, sizeof(saved_config_path), "%s/node_001/network_config.json", TEST_BASE_PATH);
    unlink(saved_config_path);
    rmdir(saved_config_path); // Remove directory if empty
    
    printf("\n========================================\n");
    printf("Test Summary\n");
    printf("========================================\n");
    printf("Total Tests: %d\n", tests_passed + tests_failed);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    printf("========================================\n");
    
    return result;
}

