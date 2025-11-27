#include "discovery.h"
#include "packages/comm/gossip/gossip.h"
#include "packages/sql/gossip_peers.h"
#include "packages/utils/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cjson/cJSON.h>
#include <sys/wait.h>

#define TAILSCALE_RETRY_COUNT 30
#define TAILSCALE_RETRY_DELAY_SECONDS 2
#define GOSSIP_PORT 9000

// Execute tailscale status --json and return JSON string
static char* execute_tailscale_status(void) {
    FILE* fp = popen("tailscale status --json 2>/dev/null", "r");
    if (!fp) {
        return NULL;
    }
    
    // Read output into buffer
    char buffer[8192] = {0};
    size_t total_read = 0;
    size_t buffer_size = sizeof(buffer) - 1;
    
    while (total_read < buffer_size) {
        size_t to_read = buffer_size - total_read;
        size_t bytes_read = fread(buffer + total_read, 1, to_read, fp);
        if (bytes_read == 0) {
            break;  // EOF or error
        }
        total_read += bytes_read;
    }
    
    int status = pclose(fp);
    if (status != 0) {
        return NULL;  // Command failed
    }
    
    // Allocate and return JSON string
    char* json_str = malloc(total_read + 1);
    if (json_str) {
        memcpy(json_str, buffer, total_read);
        json_str[total_read] = '\0';
    }
    
    return json_str;
}

// Check if hostname matches the prefix pattern
static int matches_hostname_prefix(const char* hostname, const char* prefix) {
    if (!hostname || !prefix || prefix[0] == '\0') {
        return 0;
    }
    
    size_t prefix_len = strlen(prefix);
    return (strncmp(hostname, prefix, prefix_len) == 0);
}

// Extract numeric suffix from hostname (e.g., "tw_node01" -> "01")
static int extract_node_index(const char* hostname, const char* prefix) {
    if (!hostname || !prefix) {
        return -1;
    }
    
    size_t prefix_len = strlen(prefix);
    if (strlen(hostname) < prefix_len + 2) {
        return -1;  // Hostname too short
    }
    
    // Check if it starts with prefix
    if (strncmp(hostname, prefix, prefix_len) != 0) {
        return -1;
    }
    
    // Extract 2-digit suffix
    const char* suffix = hostname + prefix_len;
    if (strlen(suffix) != 2) {
        return -1;  // Not 2 digits
    }
    
    // Verify it's numeric
    if (suffix[0] < '0' || suffix[0] > '9' || suffix[1] < '0' || suffix[1] > '9') {
        return -1;
    }
    
    return (suffix[0] - '0') * 10 + (suffix[1] - '0');
}

int discover_tailscale_peers(GossipService* service, const NodeConfig* config) {
    if (!service || !config) {
        logger_error("tailscale_discovery", "Invalid arguments");
        return -1;
    }
    
    // Check if hostname_prefix is configured
    if (!config->hostname_prefix || config->hostname_prefix[0] == '\0') {
        logger_error("tailscale_discovery", "hostname_prefix not configured");
        return -1;
    }
    
    // Retry logic: Wait for Tailscale to be ready
    char* json_str = NULL;
    int retry_count = 0;
    
    while (retry_count < TAILSCALE_RETRY_COUNT) {
        json_str = execute_tailscale_status();
        if (json_str) {
            // Try to parse JSON to verify it's valid
            cJSON* root = cJSON_Parse(json_str);
            if (root) {
                cJSON_Delete(root);
                break;  // Valid JSON, proceed
            }
            free(json_str);
            json_str = NULL;
        }
        
        retry_count++;
        if (retry_count < TAILSCALE_RETRY_COUNT) {
            logger_info("tailscale_discovery", "Tailscale not ready, retrying (%d/%d)...", 
                       retry_count, TAILSCALE_RETRY_COUNT);
            sleep(TAILSCALE_RETRY_DELAY_SECONDS);
        }
    }
    
    if (!json_str) {
        logger_error("tailscale_discovery", "Failed to get Tailscale status after %d retries", 
                    TAILSCALE_RETRY_COUNT);
        return 0;  // Graceful fallback - don't fail if Tailscale unavailable
    }
    
    // Parse JSON response
    cJSON* root = cJSON_Parse(json_str);
    if (!root) {
        logger_error("tailscale_discovery", "Failed to parse Tailscale status JSON");
        free(json_str);
        return 0;  // Graceful fallback
    }
    
    // Tailscale status --json structure:
    // {
    //   "Self": { "DNSName": "...", "Online": true, ... },
    //   "Peer": {
    //     "100.x.x.x": { "DNSName": "tw_node01", "Online": true, ... },
    //     ...
    //   }
    // }
    
    int peers_found = 0;
    cJSON* peer_obj = cJSON_GetObjectItem(root, "Peer");
    if (cJSON_IsObject(peer_obj)) {
        cJSON* peer_item = NULL;
        cJSON_ArrayForEach(peer_item, peer_obj) {
            if (!cJSON_IsObject(peer_item)) {
                continue;
            }
            
            // Get DNSName (hostname)
            cJSON* dns_name = cJSON_GetObjectItem(peer_item, "DNSName");
            if (!cJSON_IsString(dns_name) || !dns_name->valuestring) {
                continue;
            }
            
            const char* hostname = dns_name->valuestring;
            
            // Check if hostname matches prefix pattern
            if (!matches_hostname_prefix(hostname, config->hostname_prefix)) {
                continue;
            }
            
            // Skip self (compare to own hostname from config)
            if (config->hostname[0] != '\0' && strcmp(hostname, config->hostname) == 0) {
                logger_info("tailscale_discovery", "Skipping self: %s", hostname);
                continue;
            }
            
            // Check if peer is online
            cJSON* online = cJSON_GetObjectItem(peer_item, "Online");
            if (!cJSON_IsTrue(online)) {
                logger_info("tailscale_discovery", "Skipping offline peer: %s", hostname);
                continue;
            }
            
            // Add peer to gossip service
            if (gossip_service_add_peer(service, hostname, GOSSIP_PORT) == 0) {
                logger_info("tailscale_discovery", "Added peer: %s:%d", hostname, GOSSIP_PORT);
                
                // Store in database
                if (gossip_peers_add_or_update(hostname, GOSSIP_PORT, 0, NULL, NULL) == 0) {
                    peers_found++;
                } else {
                    logger_error("tailscale_discovery", "Failed to store peer %s in database", hostname);
                }
            } else {
                logger_error("tailscale_discovery", "Failed to add peer %s to gossip service", hostname);
            }
        }
    }
    
    cJSON_Delete(root);
    free(json_str);
    
    if (peers_found > 0) {
        logger_info("tailscale_discovery", "Discovered %d peer(s) via Tailscale", peers_found);
    } else {
        logger_info("tailscale_discovery", "No peers discovered via Tailscale (prefix: %s)", 
                   config->hostname_prefix);
    }
    
    return 0;  // Success (even if no peers found)
}

