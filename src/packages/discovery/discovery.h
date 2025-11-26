#ifndef TW_DISCOVERY_H
#define TW_DISCOVERY_H

#include "packages/comm/gossip/gossip.h"
#include "packages/utils/config.h"

// Discovery mode enumeration
typedef enum {
    DISCOVERY_TAILSCALE,
    DISCOVERY_DNS_PATTERN,
    DISCOVERY_STATIC,
    DISCOVERY_NONE
} DiscoveryMode;

// Function pointer type for discovery implementations
typedef int (*PeerDiscoveryFunc)(GossipService* service, const NodeConfig* config);

// Main discovery router function
// Reads config->discovery_mode and routes to appropriate discovery implementation
// Returns 0 on success, -1 on failure (graceful fallback)
int discover_peers(GossipService* service, const NodeConfig* config);

// Helper function to convert discovery mode string to enum
// Returns DISCOVERY_NONE if string doesn't match any known mode
DiscoveryMode discovery_mode_from_string(const char* mode_str);

// Discovery implementation functions (internal use)
int discover_tailscale_peers(GossipService* service, const NodeConfig* config);
int discover_dns_pattern_peers(GossipService* service, const NodeConfig* config);
int discover_static_peers(GossipService* service, const NodeConfig* config);

#endif // TW_DISCOVERY_H

