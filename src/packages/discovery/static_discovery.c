#include "discovery.h"
#include "packages/comm/gossip/gossip.h"
#include "packages/sql/gossip_peers.h"
#include "packages/utils/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GOSSIP_PORT 9000  // Default port if not specified

// Parse hostname:port format, extract hostname and port
// Returns 0 on success, -1 on failure
static int parse_peer_string(const char* peer_str, char* hostname, size_t hostname_len, uint16_t* port) {
    if (!peer_str || !hostname || !port) {
        return -1;
    }
    
    // Default port
    *port = GOSSIP_PORT;
    
    // Check if port is specified
    char* colon = strchr(peer_str, ':');
    if (colon) {
        // Port specified: hostname:port
        size_t hostname_part_len = colon - peer_str;
        if (hostname_part_len >= hostname_len) {
            return -1;  // Hostname too long
        }
        
        strncpy(hostname, peer_str, hostname_part_len);
        hostname[hostname_part_len] = '\0';
        
        // Parse port
        int port_num = atoi(colon + 1);
        if (port_num <= 0 || port_num > 65535) {
            logger_error("static_discovery", "Invalid port in peer string: %s", peer_str);
            return -1;
        }
        *port = (uint16_t)port_num;
    } else {
        // No port specified, use default
        if (strlen(peer_str) >= hostname_len) {
            return -1;  // Hostname too long
        }
        strncpy(hostname, peer_str, hostname_len - 1);
        hostname[hostname_len - 1] = '\0';
    }
    
    return 0;
}

int discover_static_peers(GossipService* service, const NodeConfig* config) {
    if (!service || !config) {
        logger_error("static_discovery", "Invalid arguments");
        return -1;
    }
    
    // Check if peers array exists
    if (!config->peers || config->peer_count == 0) {
        logger_info("static_discovery", "No static peers configured");
        return 0;  // Not an error, just no peers configured
    }
    
    logger_info("static_discovery", "Discovering %u static peer(s)", config->peer_count);
    
    int peers_found = 0;
    char hostname[256];
    uint16_t port;
    
    // Process each peer in the config
    for (uint32_t i = 0; i < config->peer_count; i++) {
        if (!config->peers[i]) {
            continue;  // Skip NULL entries
        }
        
        // Parse peer string (hostname:port format)
        if (parse_peer_string(config->peers[i], hostname, sizeof(hostname), &port) != 0) {
            logger_error("static_discovery", "Failed to parse peer string: %s", config->peers[i]);
            continue;
        }
        
        // Skip self (compare hostname to own hostname from config)
        if (config->hostname[0] != '\0' && strcmp(hostname, config->hostname) == 0) {
            logger_info("static_discovery", "Skipping self: %s", hostname);
            continue;
        }
        
        logger_info("static_discovery", "Adding static peer: %s:%d", hostname, port);
        
        // Add peer to gossip service
        if (gossip_service_add_peer(service, hostname, port) == 0) {
            logger_info("static_discovery", "Added peer: %s:%d", hostname, port);
            
            // Store in database (gossip_port from config, api_port = 0 for static peers)
            if (gossip_peers_add_or_update(hostname, port, 0, NULL, NULL) == 0) {
                peers_found++;
            } else {
                logger_error("static_discovery", "Failed to store peer %s in database", hostname);
            }
        } else {
            logger_error("static_discovery", "Failed to add peer %s to gossip service", hostname);
        }
    }
    
    if (peers_found > 0) {
        logger_info("static_discovery", "Discovered %d peer(s) from static config", peers_found);
    } else {
        logger_info("static_discovery", "No peers added from static config");
    }
    
    return 0;  // Success (even if no peers found)
}

