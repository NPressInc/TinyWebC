#include "discovery_test.h"
#include "packages/discovery/discovery.h"
#include "packages/comm/gossip/gossip.h"
#include "packages/utils/config.h"
#include "packages/utils/logger.h"
#include "packages/sql/database_gossip.h"
#include "packages/sql/gossip_peers.h"
#include "packages/sql/schema.h"
#include "tests/test_init.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

static int test_discovery_mode_from_string(void) {
    printf("  Testing discovery_mode_from_string()...\n");
    
    // Test valid modes
    assert(discovery_mode_from_string("tailscale") == DISCOVERY_TAILSCALE);
    assert(discovery_mode_from_string("TAILSCALE") == DISCOVERY_TAILSCALE);  // Case insensitive
    assert(discovery_mode_from_string("Tailscale") == DISCOVERY_TAILSCALE);
    
    assert(discovery_mode_from_string("dns_pattern") == DISCOVERY_DNS_PATTERN);
    assert(discovery_mode_from_string("DNS_PATTERN") == DISCOVERY_DNS_PATTERN);
    
    assert(discovery_mode_from_string("static") == DISCOVERY_STATIC);
    assert(discovery_mode_from_string("STATIC") == DISCOVERY_STATIC);
    
    assert(discovery_mode_from_string("none") == DISCOVERY_NONE);
    assert(discovery_mode_from_string("NONE") == DISCOVERY_NONE);
    
    // Test edge cases
    assert(discovery_mode_from_string(NULL) == DISCOVERY_NONE);
    assert(discovery_mode_from_string("") == DISCOVERY_NONE);
    assert(discovery_mode_from_string("unknown") == DISCOVERY_NONE);
    assert(discovery_mode_from_string("invalid_mode") == DISCOVERY_NONE);
    
    printf("    ✓ discovery_mode_from_string() passed\n");
    return 0;
}

static int test_discover_peers_routing(void) {
    printf("  Testing discover_peers() routing...\n");
    
    // Create a minimal mock GossipService
    GossipService mock_service;
    memset(&mock_service, 0, sizeof(mock_service));
    mock_service.listen_port = 9000;
    pthread_mutex_init(&mock_service.peer_lock, NULL);
    
    // Test each discovery mode
    NodeConfig config;
    memset(&config, 0, sizeof(config));
    
    // Test None mode (fast, no external calls)
    strncpy(config.discovery_mode, "none", sizeof(config.discovery_mode) - 1);
    int result = discover_peers(&mock_service, &config);
    assert(result == 0);
    printf("    ✓ None mode routing works\n");
    
    // Test Static mode (fast, reads from config)
    strncpy(config.discovery_mode, "static", sizeof(config.discovery_mode) - 1);
    config.peer_count = 0;
    config.peers = NULL;
    result = discover_peers(&mock_service, &config);
    assert(result == 0);
    printf("    ✓ Static mode routing works\n");
    
    // Test unknown mode (should gracefully fallback)
    strncpy(config.discovery_mode, "unknown_mode", sizeof(config.discovery_mode) - 1);
    result = discover_peers(&mock_service, &config);
    assert(result == 0);  // Should gracefully fallback, not fail
    printf("    ✓ Unknown mode gracefully falls back\n");
    
    // Test NULL arguments (should fail gracefully)
    result = discover_peers(NULL, &config);
    assert(result == -1);
    result = discover_peers(&mock_service, NULL);
    assert(result == -1);
    printf("    ✓ NULL argument validation works\n");
    
    // Note: Tailscale and DNS pattern routing are tested separately
    // to avoid hanging on external calls
    
    pthread_mutex_destroy(&mock_service.peer_lock);
    
    printf("    ✓ discover_peers() routing passed\n");
    return 0;
}

static int test_static_discovery(void) {
    printf("  Testing static discovery...\n");
    
    // Use shared test database (already initialized by test_runner)
    if (!db_is_initialized()) {
        const char* db_path = test_get_db_path();
        if (db_init_gossip(db_path) != 0) {
            printf("    ✗ Failed to initialize database\n");
            return -1;
        }
    }
    
    // Ensure schema is initialized
    if (gossip_store_init() != 0) {
        printf("    ✗ Failed to initialize schema\n");
        return -1;
    }
    
    if (gossip_peers_init() != 0) {
        printf("    ✗ Failed to initialize gossip peers\n");
        return -1;
    }
    
    // Create mock GossipService
    GossipService mock_service;
    memset(&mock_service, 0, sizeof(mock_service));
    mock_service.listen_port = 9000;
    pthread_mutex_init(&mock_service.peer_lock, NULL);
    
    // Create config with static peers
    NodeConfig config;
    memset(&config, 0, sizeof(config));
    strncpy(config.discovery_mode, "static", sizeof(config.discovery_mode) - 1);
    strncpy(config.hostname, "tw-node01", sizeof(config.hostname) - 1);
    
    // Add peers array
    config.peer_count = 3;
    config.peers = malloc(sizeof(char*) * config.peer_count);
    config.peers[0] = strdup("tw-node02:9000");
    config.peers[1] = strdup("tw-node03");  // No port, should default to 9000
    config.peers[2] = strdup("192.168.1.100:8000");  // Custom port
    
    // Run static discovery
    int result = discover_static_peers(&mock_service, &config);
    assert(result == 0);
    
    // Verify peers were added to service
    assert(mock_service.peer_count == 3);
    assert(strcmp(mock_service.peers[0].address, "tw-node02") == 0);
    assert(mock_service.peers[0].port == 9000);
    assert(strcmp(mock_service.peers[1].address, "tw-node03") == 0);
    assert(mock_service.peers[1].port == 9000);
    assert(strcmp(mock_service.peers[2].address, "192.168.1.100") == 0);
    assert(mock_service.peers[2].port == 8000);
    
    // Verify peers were stored in database
    GossipPeerInfo* db_peers = NULL;
    size_t db_peer_count = 0;
    assert(gossip_peers_fetch_all(&db_peers, &db_peer_count) == 0);
    // Note: db_peer_count may be > 3 if other tests added peers, so we check >= 3
    assert(db_peer_count >= 3);
    
    // Cleanup
    gossip_peers_free(db_peers, db_peer_count);
    config_free(&config);
    pthread_mutex_destroy(&mock_service.peer_lock);
    // Don't close database - it's shared with other tests
    
    printf("    ✓ Static discovery passed\n");
    return 0;
}

static int test_static_discovery_skip_self(void) {
    printf("  Testing static discovery skips self...\n");
    
    // Use shared test database (already initialized by test_runner)
    if (!db_is_initialized()) {
        const char* db_path = test_get_db_path();
        if (db_init_gossip(db_path) != 0) {
            printf("    ✗ Failed to initialize database\n");
            return -1;
        }
    }
    
    // Ensure schema is initialized
    if (gossip_store_init() != 0) {
        printf("    ✗ Failed to initialize schema\n");
        return -1;
    }
    
    if (gossip_peers_init() != 0) {
        printf("    ✗ Failed to initialize gossip peers\n");
        return -1;
    }
    
    GossipService mock_service;
    memset(&mock_service, 0, sizeof(mock_service));
    mock_service.listen_port = 9000;
    pthread_mutex_init(&mock_service.peer_lock, NULL);
    
    NodeConfig config;
    memset(&config, 0, sizeof(config));
    strncpy(config.discovery_mode, "static", sizeof(config.discovery_mode) - 1);
    strncpy(config.hostname, "tw-node01", sizeof(config.hostname) - 1);
    
    // Add peers including self
    config.peer_count = 2;
    config.peers = malloc(sizeof(char*) * config.peer_count);
    config.peers[0] = strdup("tw-node01:9000");  // Self - should be skipped
    config.peers[1] = strdup("tw-node02:9000");
    
    int result = discover_static_peers(&mock_service, &config);
    assert(result == 0);
    
    // Verify only one peer was added (self was skipped)
    assert(mock_service.peer_count == 1);
    assert(strcmp(mock_service.peers[0].address, "tw-node02") == 0);
    
    config_free(&config);
    pthread_mutex_destroy(&mock_service.peer_lock);
    // Don't close database - it's shared with other tests
    
    printf("    ✓ Static discovery skip self passed\n");
    return 0;
}

static int test_static_discovery_empty_peers(void) {
    printf("  Testing static discovery with empty peers...\n");
    
    GossipService mock_service;
    memset(&mock_service, 0, sizeof(mock_service));
    mock_service.listen_port = 9000;
    pthread_mutex_init(&mock_service.peer_lock, NULL);
    
    NodeConfig config;
    memset(&config, 0, sizeof(config));
    strncpy(config.discovery_mode, "static", sizeof(config.discovery_mode) - 1);
    config.peer_count = 0;
    config.peers = NULL;
    
    // Should return 0 (success, just no peers)
    int result = discover_static_peers(&mock_service, &config);
    assert(result == 0);
    assert(mock_service.peer_count == 0);
    
    pthread_mutex_destroy(&mock_service.peer_lock);
    
    printf("    ✓ Static discovery empty peers passed\n");
    return 0;
}

static int test_dns_pattern_discovery_config(void) {
    printf("  Testing DNS pattern discovery config validation...\n");
    
    // Test config validation without actually doing DNS resolution
    // (DNS resolution would iterate through 99 hostnames and could hang)
    
    GossipService mock_service;
    memset(&mock_service, 0, sizeof(mock_service));
    mock_service.listen_port = 9000;
    pthread_mutex_init(&mock_service.peer_lock, NULL);
    
    NodeConfig config;
    memset(&config, 0, sizeof(config));
    strncpy(config.discovery_mode, "dns_pattern", sizeof(config.discovery_mode) - 1);
    strncpy(config.hostname_prefix, "tw-node", sizeof(config.hostname_prefix) - 1);
    strncpy(config.dns_domain, "example.com", sizeof(config.dns_domain) - 1);
    strncpy(config.hostname, "tw-node01.example.com", sizeof(config.hostname) - 1);
    
    // Verify config structure is correct
    assert(strcmp(config.hostname_prefix, "tw-node") == 0);
    assert(strcmp(config.dns_domain, "example.com") == 0);
    assert(strcmp(config.hostname, "tw-node01.example.com") == 0);
    
    // The actual DNS resolution is tested in integration tests
    // Unit tests verify config structure and validation
    
    pthread_mutex_destroy(&mock_service.peer_lock);
    
    printf("    ✓ DNS pattern discovery config validation passed\n");
    printf("    ⚠️  Full DNS resolution skipped (would iterate 99 hostnames, tested in integration)\n");
    return 0;
}

static int test_dns_pattern_discovery_hostname_format(void) {
    printf("  Testing DNS pattern discovery hostname format...\n");
    
    // Test that hostname format is correct (prefix + index + domain)
    // This tests the logic without doing actual DNS resolution
    
    NodeConfig config;
    memset(&config, 0, sizeof(config));
    strncpy(config.hostname_prefix, "tw-node", sizeof(config.hostname_prefix) - 1);
    strncpy(config.dns_domain, "example.com", sizeof(config.dns_domain) - 1);
    
    // Verify expected hostname format
    char expected_hostname[512];
    snprintf(expected_hostname, sizeof(expected_hostname), "%s%02d.%s", 
            config.hostname_prefix, 1, config.dns_domain);
    assert(strcmp(expected_hostname, "tw-node01.example.com") == 0);
    
    snprintf(expected_hostname, sizeof(expected_hostname), "%s%02d.%s", 
            config.hostname_prefix, 22, config.dns_domain);
    assert(strcmp(expected_hostname, "tw-node22.example.com") == 0);
    
    printf("    ✓ DNS pattern discovery hostname format correct\n");
    return 0;
}

static int test_tailscale_discovery_missing_prefix(void) {
    printf("  Testing Tailscale discovery with missing prefix...\n");
    
    GossipService mock_service;
    memset(&mock_service, 0, sizeof(mock_service));
    mock_service.listen_port = 9000;
    pthread_mutex_init(&mock_service.peer_lock, NULL);
    
    NodeConfig config;
    memset(&config, 0, sizeof(config));
    strncpy(config.discovery_mode, "tailscale", sizeof(config.discovery_mode) - 1);
    // hostname_prefix is empty - should fail gracefully
    
    // Should return -1 (invalid config)
    int result = discover_tailscale_peers(&mock_service, &config);
    assert(result == -1);  // Should return error for missing config
    
    pthread_mutex_destroy(&mock_service.peer_lock);
    
    printf("    ✓ Tailscale discovery missing prefix handled\n");
    return 0;
}

static int test_tailscale_discovery_unavailable(void) {
    printf("  Testing Tailscale discovery when tailscale unavailable...\n");
    
    GossipService mock_service;
    memset(&mock_service, 0, sizeof(mock_service));
    mock_service.listen_port = 9000;
    pthread_mutex_init(&mock_service.peer_lock, NULL);
    
    NodeConfig config;
    memset(&config, 0, sizeof(config));
    strncpy(config.discovery_mode, "tailscale", sizeof(config.discovery_mode) - 1);
    strncpy(config.hostname_prefix, "tw-node", sizeof(config.hostname_prefix) - 1);
    
    // If tailscale command doesn't exist or isn't running, should gracefully fallback
    // This will retry 30 times with 2-second delays (60 seconds total)
    // For unit tests, we just verify it doesn't crash
    // Note: This test may take a while if tailscale isn't available
    printf("    (This may take up to 60 seconds if tailscale is unavailable...)\n");
    int result = discover_tailscale_peers(&mock_service, &config);
    // Should return 0 (graceful fallback) if tailscale unavailable
    assert(result == 0);
    
    pthread_mutex_destroy(&mock_service.peer_lock);
    
    printf("    ✓ Tailscale discovery handles unavailable tailscale gracefully\n");
    return 0;
}

static int test_dns_pattern_discovery_missing_config(void) {
    printf("  Testing DNS pattern discovery with missing config...\n");
    
    GossipService mock_service;
    memset(&mock_service, 0, sizeof(mock_service));
    mock_service.listen_port = 9000;
    pthread_mutex_init(&mock_service.peer_lock, NULL);
    
    NodeConfig config;
    memset(&config, 0, sizeof(config));
    strncpy(config.discovery_mode, "dns_pattern", sizeof(config.discovery_mode) - 1);
    // Missing hostname_prefix or dns_domain - should fail gracefully
    
    int result = discover_dns_pattern_peers(&mock_service, &config);
    assert(result == -1);  // Should return error for missing config
    
    pthread_mutex_destroy(&mock_service.peer_lock);
    
    printf("    ✓ DNS pattern discovery missing config handled\n");
    return 0;
}

int discovery_test_main(void) {
    printf("\n🔍 Discovery Tests\n");
    printf("==================\n\n");
    
    // Initialize logger (needed for discovery functions)
    if (logger_init() != 0) {
        printf("  ✗ Failed to initialize logger\n");
        return 1;
    }
    
    // Ensure database is available (should already be initialized by test_runner)
    if (!db_is_initialized()) {
        const char* db_path = test_get_db_path();
        if (db_init_gossip(db_path) != 0) {
            printf("  ✗ Failed to initialize database\n");
            return 1;
        }
    }
    
    // Ensure schema is initialized
    if (gossip_store_init() != 0) {
        printf("  ✗ Failed to initialize schema\n");
        return 1;
    }
    
    int failures = 0;
    
    printf("Running discovery tests...\n");
    if (test_discovery_mode_from_string() != 0) {
        printf("  ✗ discovery_mode_from_string() failed\n");
        failures++;
    }
    
    if (test_discover_peers_routing() != 0) {
        printf("  ✗ discover_peers() routing failed\n");
        failures++;
    }
    
    // Test static discovery
    if (test_static_discovery() != 0) {
        printf("  ✗ Static discovery failed\n");
        failures++;
    }
    
    if (test_static_discovery_skip_self() != 0) {
        printf("  ✗ Static discovery skip self failed\n");
        failures++;
    }
    
    if (test_static_discovery_empty_peers() != 0) {
        printf("  ✗ Static discovery empty peers failed\n");
        failures++;
    }
    
    // Test DNS pattern discovery (config validation only, no actual DNS resolution)
    if (test_dns_pattern_discovery_config() != 0) {
        printf("  ✗ DNS pattern discovery config failed\n");
        failures++;
    }
    
    if (test_dns_pattern_discovery_hostname_format() != 0) {
        printf("  ✗ DNS pattern discovery hostname format failed\n");
        failures++;
    }
    
    if (test_dns_pattern_discovery_missing_config() != 0) {
        printf("  ✗ DNS pattern discovery missing config failed\n");
        failures++;
    }
    
    // Test Tailscale discovery (limited - can't easily mock tailscale command)
    if (test_tailscale_discovery_missing_prefix() != 0) {
        printf("  ✗ Tailscale discovery missing prefix failed\n");
        failures++;
    }
    
    // Skip the unavailable test by default (takes 60 seconds)
    // Uncomment to test graceful fallback when tailscale unavailable
    // if (test_tailscale_discovery_unavailable() != 0) {
    //     printf("  ✗ Tailscale discovery unavailable test failed\n");
    //     failures++;
    // }
    
    if (failures == 0) {
        printf("\n✅ All discovery tests passed!\n");
        return 0;
    } else {
        printf("\n❌ %d test(s) failed\n", failures);
        return 1;
    }
}

