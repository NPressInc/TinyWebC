#ifndef TW_CONFIG_H
#define TW_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include "packages/utils/logger.h"

// Node configuration structure
typedef struct {
    // Node identity (from network_config.json)
    char node_id[64];
    char node_name[128];
    char hostname[256];
    uint16_t gossip_port;
    uint16_t api_port;
    char** peers;
    uint32_t peer_count;
    
    // Runtime settings (from network config or defaults)
    uint64_t max_clock_skew_seconds;
    uint64_t message_ttl_seconds;
    size_t max_payload_bytes;
    
    // Logging settings
    log_level_t log_level;
    bool log_to_file;
    char log_file_path[256];
    
    // Network error handling
    int max_retries;
    int initial_delay_ms;
    double backoff_multiplier;
    int max_delay_ms;
    
    // Database settings
    char db_path[512];
    char state_path[512];
    
    // Discovery settings (from docker.discovery.* in config)
    char discovery_mode[32];        // 'tailscale', 'dns_pattern', 'static', or 'none'
    char hostname_prefix[64];       // For discovery pattern matching (e.g., 'tw_node', 'smithfam_tw_node')
    char dns_domain[256];           // For DNS pattern mode (e.g., 'duckdns.org', 'tinyweb.win')
    
    // Debug mode
    bool debug_mode;
    
    // Config file info
    char config_file_path[512];
    time_t config_file_mtime;
} NodeConfig;

// Load node configuration from network_config.json
int config_load_node_from_network_config(const char* config_file_path, const char* node_id, NodeConfig* config);

// Load configuration overrides from environment variables
int config_load_from_env(NodeConfig* config);

// Merge configurations (env overrides file)
int config_merge(NodeConfig* dest, const NodeConfig* src);

// Validate configuration values
int config_validate(const NodeConfig* config);

// Reload configuration file if modified
int config_reload(NodeConfig* config);

// Set default configuration values
void config_set_defaults(NodeConfig* config);

// Free allocated strings in configuration
void config_free(NodeConfig* config);

#endif // TW_CONFIG_H

