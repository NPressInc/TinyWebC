#include "discovery.h"
#include "packages/comm/gossip/gossip.h"
#include "packages/sql/gossip_peers.h"
#include "packages/utils/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define GOSSIP_PORT 9000
#define MAX_NODE_INDEX 99

// Check if hostname resolves via DNS
static int hostname_resolves(const char* hostname) {
    if (!hostname || hostname[0] == '\0') {
        return 0;
    }
    
    struct addrinfo hints;
    struct addrinfo* result = NULL;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  // Support both IPv4 and IPv6
    hints.ai_socktype = SOCK_STREAM;
    
    int status = getaddrinfo(hostname, NULL, &hints, &result);
    if (status == 0 && result != NULL) {
        freeaddrinfo(result);
        return 1;  // Hostname resolves
    }
    
    return 0;  // Hostname doesn't resolve
}

int discover_dns_pattern_peers(GossipService* service, const NodeConfig* config) {
    if (!service || !config) {
        logger_error("dns_pattern_discovery", "Invalid arguments");
        return -1;
    }
    
    // Check if hostname_prefix and dns_domain are configured
    if (!config->hostname_prefix || config->hostname_prefix[0] == '\0') {
        logger_error("dns_pattern_discovery", "hostname_prefix not configured");
        return -1;
    }
    
    if (!config->dns_domain || config->dns_domain[0] == '\0') {
        logger_error("dns_pattern_discovery", "dns_domain not configured");
        return -1;
    }
    
    logger_info("dns_pattern_discovery", "Discovering peers with pattern: %s*.%s", 
               config->hostname_prefix, config->dns_domain);
    
    int peers_found = 0;
    char hostname[512];
    
    // Iterate through possible hostnames (01-99)
    // Since DNS wildcard enumeration is rarely supported, we try each possible hostname
    for (int i = 1; i <= MAX_NODE_INDEX; i++) {
        // Format hostname: {hostname_prefix}{zero-padded index}.{domain}
        // e.g., tw_node01.duckdns.org, tw_node22.duckdns.org
        snprintf(hostname, sizeof(hostname), "%s%02d.%s", 
                config->hostname_prefix, i, config->dns_domain);
        
        // Skip self (compare to own hostname from config)
        if (config->hostname[0] != '\0' && strcmp(hostname, config->hostname) == 0) {
            logger_info("dns_pattern_discovery", "Skipping self: %s", hostname);
            continue;
        }
        
        // Check if hostname resolves via DNS
        if (!hostname_resolves(hostname)) {
            continue;  // Hostname doesn't exist, try next
        }
        
        logger_info("dns_pattern_discovery", "Found peer via DNS: %s", hostname);
        
        // Add peer to gossip service
        if (gossip_service_add_peer(service, hostname, GOSSIP_PORT) == 0) {
            logger_info("dns_pattern_discovery", "Added peer: %s:%d", hostname, GOSSIP_PORT);
            
            // Store in database
            if (gossip_peers_add_or_update(hostname, GOSSIP_PORT, 0, NULL, NULL) == 0) {
                peers_found++;
            } else {
                logger_error("dns_pattern_discovery", "Failed to store peer %s in database", hostname);
            }
        } else {
            logger_error("dns_pattern_discovery", "Failed to add peer %s to gossip service", hostname);
        }
    }
    
    if (peers_found > 0) {
        logger_info("dns_pattern_discovery", "Discovered %d peer(s) via DNS pattern", peers_found);
    } else {
        logger_info("dns_pattern_discovery", "No peers discovered via DNS pattern (prefix: %s, domain: %s)", 
                   config->hostname_prefix, config->dns_domain);
    }
    
    return 0;  // Success (even if no peers found)
}

