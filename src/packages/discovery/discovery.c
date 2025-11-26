#include "discovery.h"
#include "packages/utils/logger.h"
#include <string.h>
#include <strings.h>  // For strcasecmp

// Forward declarations for discovery implementations (will be implemented in tasks 1.2-1.4)
static int discover_tailscale_peers(GossipService* service, const NodeConfig* config);
static int discover_dns_pattern_peers(GossipService* service, const NodeConfig* config);
static int discover_static_peers(GossipService* service, const NodeConfig* config);

// Helper function to convert discovery mode string to enum
DiscoveryMode discovery_mode_from_string(const char* mode_str) {
    if (!mode_str || mode_str[0] == '\0') {
        return DISCOVERY_NONE;
    }
    
    if (strcasecmp(mode_str, "tailscale") == 0) {
        return DISCOVERY_TAILSCALE;
    } else if (strcasecmp(mode_str, "dns_pattern") == 0) {
        return DISCOVERY_DNS_PATTERN;
    } else if (strcasecmp(mode_str, "static") == 0) {
        return DISCOVERY_STATIC;
    } else if (strcasecmp(mode_str, "none") == 0) {
        return DISCOVERY_NONE;
    }
    
    // Default to NONE for unknown modes
    return DISCOVERY_NONE;
}

// Main discovery router function
int discover_peers(GossipService* service, const NodeConfig* config) {
    if (!service || !config) {
        logger_error("discovery", "Invalid arguments to discover_peers");
        return -1;
    }
    
    // Convert string mode to enum
    DiscoveryMode mode = discovery_mode_from_string(config->discovery_mode);
    
    // Route to appropriate discovery implementation
    switch (mode) {
        case DISCOVERY_TAILSCALE:
            logger_info("discovery", "Using Tailscale discovery mode");
            return discover_tailscale_peers(service, config);
            
        case DISCOVERY_DNS_PATTERN:
            logger_info("discovery", "Using DNS pattern discovery mode");
            return discover_dns_pattern_peers(service, config);
            
        case DISCOVERY_STATIC:
            logger_info("discovery", "Using static discovery mode");
            return discover_static_peers(service, config);
            
        case DISCOVERY_NONE:
            logger_info("discovery", "Discovery disabled (mode: none)");
            return 0;  // Not an error, just no discovery
            
        default:
            logger_error("discovery", "Unknown discovery mode: %s, falling back to none", config->discovery_mode);
            return 0;  // Graceful fallback
    }
}

// Stub implementations (will be fully implemented in tasks 1.2-1.4)
static int discover_tailscale_peers(GossipService* service, const NodeConfig* config) {
    // TODO: Implement in task 1.2
    logger_info("discovery", "Tailscale discovery not yet implemented");
    return 0;  // Graceful fallback - don't fail if discovery unavailable
}

static int discover_dns_pattern_peers(GossipService* service, const NodeConfig* config) {
    // TODO: Implement in task 1.3
    logger_info("discovery", "DNS pattern discovery not yet implemented");
    return 0;  // Graceful fallback
}

static int discover_static_peers(GossipService* service, const NodeConfig* config) {
    // TODO: Implement in task 1.4
    logger_info("discovery", "Static discovery not yet implemented");
    return 0;  // Graceful fallback
}

