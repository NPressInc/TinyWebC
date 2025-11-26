#include "discovery_test.h"
#include "packages/discovery/discovery.h"
#include "packages/comm/gossip/gossip.h"
#include "packages/utils/config.h"
#include "packages/utils/logger.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

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
    
    // Test each discovery mode
    NodeConfig config;
    memset(&config, 0, sizeof(config));
    
    // Test Tailscale mode
    strncpy(config.discovery_mode, "tailscale", sizeof(config.discovery_mode) - 1);
    strncpy(config.hostname_prefix, "tw_node", sizeof(config.hostname_prefix) - 1);
    int result = discover_peers(&mock_service, &config);
    assert(result == 0);  // Should return 0 (graceful fallback for stub)
    printf("    ✓ Tailscale mode routing works\n");
    
    // Test DNS pattern mode
    strncpy(config.discovery_mode, "dns_pattern", sizeof(config.discovery_mode) - 1);
    strncpy(config.hostname_prefix, "tw_node", sizeof(config.hostname_prefix) - 1);
    strncpy(config.dns_domain, "duckdns.org", sizeof(config.dns_domain) - 1);
    result = discover_peers(&mock_service, &config);
    assert(result == 0);
    printf("    ✓ DNS pattern mode routing works\n");
    
    // Test Static mode
    strncpy(config.discovery_mode, "static", sizeof(config.discovery_mode) - 1);
    result = discover_peers(&mock_service, &config);
    assert(result == 0);
    printf("    ✓ Static mode routing works\n");
    
    // Test None mode
    strncpy(config.discovery_mode, "none", sizeof(config.discovery_mode) - 1);
    result = discover_peers(&mock_service, &config);
    assert(result == 0);
    printf("    ✓ None mode routing works\n");
    
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
    
    printf("    ✓ discover_peers() routing passed\n");
    return 0;
}

int discovery_test_main(void) {
    printf("\n🔍 Discovery Router Smoke Test\n");
    printf("==============================\n\n");
    
    // Initialize logger (needed for discovery functions)
    if (logger_init() != 0) {
        printf("  ✗ Failed to initialize logger\n");
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
    
    if (failures == 0) {
        printf("\n✅ All discovery router tests passed!\n");
        return 0;
    } else {
        printf("\n❌ %d test(s) failed\n", failures);
        return 1;
    }
}

