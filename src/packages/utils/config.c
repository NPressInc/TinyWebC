#include "config.h"
#include "packages/utils/logger.h"
#include "packages/utils/error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <cjson/cJSON.h>

void config_set_defaults(NodeConfig* config) {
    if (!config) return;
    
    memset(config, 0, sizeof(*config));
    
    // Default validation settings
    config->max_clock_skew_seconds = 300;
    config->message_ttl_seconds = 60ULL * 60ULL * 24ULL * 30ULL; // 30 days
    config->max_payload_bytes = 1024 * 1024; // 1MB
    
    // Default logging settings
    config->log_level = LOG_LEVEL_INFO;
    config->log_to_file = false;
    strncpy(config->log_file_path, "logs/tinyweb.log", sizeof(config->log_file_path) - 1);
    
    // Default network error handling
    config->max_retries = 3;
    config->initial_delay_ms = 100;
    config->backoff_multiplier = 2.0;
    config->max_delay_ms = 5000;
    
    // Default debug mode
    config->debug_mode = false;
}

int config_load_node_from_network_config(const char* config_file_path, const char* node_id, NodeConfig* config) {
    if (!config_file_path || !node_id || !config) {
        tw_error_create(TW_ERROR_NULL_POINTER, "config", __func__, __LINE__, "Invalid arguments");
        logger_error("config", "Invalid arguments to config_load_node_from_network_config");
        return -1;
    }
    
    // Set defaults first
    config_set_defaults(config);
    
    // Read config file
    FILE* file = fopen(config_file_path, "r");
    if (!file) {
        tw_error_create(TW_ERROR_IO_ERROR, "config", __func__, __LINE__, "Failed to open config file: %s", config_file_path);
        logger_error("config", "Failed to open config file: %s", config_file_path);
        return -1;
    }
    
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char* buffer = malloc((size_t)size + 1);
    if (!buffer) {
        fclose(file);
        tw_error_create(TW_ERROR_ALLOCATION_FAILED, "config", __func__, __LINE__, "Failed to allocate buffer");
        logger_error("config", "Failed to allocate buffer for config file");
        return -1;
    }
    
    fread(buffer, 1, (size_t)size, file);
    buffer[size] = '\0';
    fclose(file);
    
    cJSON* root = cJSON_Parse(buffer);
    free(buffer);
    if (!root) {
        tw_error_create(TW_ERROR_INVALID_ARGUMENT, "config", __func__, __LINE__, "Failed to parse JSON config");
        logger_error("config", "Failed to parse JSON config");
        return -1;
    }
    
    // Find the node in the nodes array
    cJSON* nodes = cJSON_GetObjectItem(root, "nodes");
    if (!cJSON_IsArray(nodes)) {
        cJSON_Delete(root);
        tw_error_create(TW_ERROR_INVALID_ARGUMENT, "config", __func__, __LINE__, "Config missing nodes array");
        logger_error("config", "Config missing nodes array");
        return -1;
    }
    
    cJSON* node = NULL;
    int node_count = cJSON_GetArraySize(nodes);
    for (int i = 0; i < node_count; i++) {
        cJSON* n = cJSON_GetArrayItem(nodes, i);
        cJSON* id = cJSON_GetObjectItem(n, "id");
        if (cJSON_IsString(id) && strcmp(id->valuestring, node_id) == 0) {
            node = n;
            break;
        }
    }
    
    if (!node) {
        cJSON_Delete(root);
        tw_error_create(TW_ERROR_NOT_FOUND, "config", __func__, __LINE__, "Node %s not found in config", node_id);
        logger_error("config", "Node %s not found in config", node_id);
        return -1;
    }
    
    // Load node-specific settings
    cJSON* name = cJSON_GetObjectItem(node, "name");
    if (cJSON_IsString(name)) {
        strncpy(config->node_name, name->valuestring, sizeof(config->node_name) - 1);
    }
    strncpy(config->node_id, node_id, sizeof(config->node_id) - 1);
    
    cJSON* hostname = cJSON_GetObjectItem(node, "hostname");
    if (cJSON_IsString(hostname)) {
        strncpy(config->hostname, hostname->valuestring, sizeof(config->hostname) - 1);
    }
    
    cJSON* gossip_port = cJSON_GetObjectItem(node, "gossip_port");
    if (cJSON_IsNumber(gossip_port)) {
        config->gossip_port = (uint16_t)gossip_port->valueint;
    }
    
    cJSON* api_port = cJSON_GetObjectItem(node, "api_port");
    if (cJSON_IsNumber(api_port)) {
        config->api_port = (uint16_t)api_port->valueint;
    }
    
    // Load peers
    cJSON* peers = cJSON_GetObjectItem(node, "peers");
    if (cJSON_IsArray(peers)) {
        config->peer_count = (uint32_t)cJSON_GetArraySize(peers);
        if (config->peer_count > 0) {
            config->peers = calloc(config->peer_count, sizeof(char*));
            if (config->peers) {
                for (uint32_t i = 0; i < config->peer_count; i++) {
                    cJSON* peer = cJSON_GetArrayItem(peers, (int)i);
                    if (cJSON_IsString(peer)) {
                        config->peers[i] = strdup(peer->valuestring);
                    }
                }
            }
        }
    }
    
    // Load network-level settings (validation, logging, error handling)
    cJSON* network = cJSON_GetObjectItem(root, "network");
    if (network) {
        cJSON* validation = cJSON_GetObjectItem(network, "validation");
        if (validation) {
            cJSON* max_skew = cJSON_GetObjectItem(validation, "max_clock_skew_seconds");
            if (cJSON_IsNumber(max_skew)) {
                config->max_clock_skew_seconds = (uint64_t)max_skew->valueint;
            }
            
            cJSON* ttl = cJSON_GetObjectItem(validation, "message_ttl_seconds");
            if (cJSON_IsNumber(ttl)) {
                config->message_ttl_seconds = (uint64_t)ttl->valueint;
            }
            
            cJSON* max_payload = cJSON_GetObjectItem(validation, "max_payload_bytes");
            if (cJSON_IsNumber(max_payload)) {
                config->max_payload_bytes = (size_t)max_payload->valueint;
            }
        }
        
        cJSON* logging = cJSON_GetObjectItem(network, "logging");
        if (logging) {
            cJSON* level = cJSON_GetObjectItem(logging, "level");
            if (cJSON_IsString(level)) {
                const char* level_str = level->valuestring;
                if (strcasecmp(level_str, "ERROR") == 0) {
                    config->log_level = LOG_LEVEL_ERROR;
                } else if (strcasecmp(level_str, "INFO") == 0) {
                    config->log_level = LOG_LEVEL_INFO;
                }
            }
            
            cJSON* to_file = cJSON_GetObjectItem(logging, "to_file");
            if (cJSON_IsBool(to_file)) {
                config->log_to_file = cJSON_IsTrue(to_file);
            }
            
            cJSON* file_path = cJSON_GetObjectItem(logging, "file_path");
            if (cJSON_IsString(file_path)) {
                strncpy(config->log_file_path, file_path->valuestring, sizeof(config->log_file_path) - 1);
            }
        }
        
        cJSON* error_handling = cJSON_GetObjectItem(network, "network_error_handling");
        if (error_handling) {
            cJSON* max_retries = cJSON_GetObjectItem(error_handling, "max_retries");
            if (cJSON_IsNumber(max_retries)) {
                config->max_retries = max_retries->valueint;
            }
            
            cJSON* initial_delay = cJSON_GetObjectItem(error_handling, "initial_delay_ms");
            if (cJSON_IsNumber(initial_delay)) {
                config->initial_delay_ms = initial_delay->valueint;
            }
            
            cJSON* backoff = cJSON_GetObjectItem(error_handling, "backoff_multiplier");
            if (cJSON_IsNumber(backoff)) {
                config->backoff_multiplier = backoff->valuedouble;
            }
            
            cJSON* max_delay = cJSON_GetObjectItem(error_handling, "max_delay_ms");
            if (cJSON_IsNumber(max_delay)) {
                config->max_delay_ms = max_delay->valueint;
            }
        }
    }
    
    // Store config file path and mtime
    strncpy(config->config_file_path, config_file_path, sizeof(config->config_file_path) - 1);
    struct stat st;
    if (stat(config_file_path, &st) == 0) {
        config->config_file_mtime = st.st_mtime;
    }
    
    cJSON_Delete(root);
    return 0;
}

int config_load_from_env(NodeConfig* config) {
    if (!config) {
        return -1;
    }
    
    const char* node_id = getenv("TINYWEB_NODE_ID");
    if (node_id) {
        strncpy(config->node_id, node_id, sizeof(config->node_id) - 1);
    }
    
    const char* gossip_port = getenv("TINYWEB_GOSSIP_PORT");
    if (gossip_port) {
        config->gossip_port = (uint16_t)atoi(gossip_port);
    }
    
    const char* api_port = getenv("TINYWEB_API_PORT");
    if (api_port) {
        config->api_port = (uint16_t)atoi(api_port);
    }
    
    const char* debug = getenv("TINYWEB_DEBUG");
    if (debug) {
        config->debug_mode = (atoi(debug) != 0);
    }
    
    const char* log_level = getenv("TINYWEB_LOG_LEVEL");
    if (log_level) {
        if (strcasecmp(log_level, "ERROR") == 0) {
            config->log_level = LOG_LEVEL_ERROR;
        } else if (strcasecmp(log_level, "INFO") == 0) {
            config->log_level = LOG_LEVEL_INFO;
        }
    }
    
    const char* max_skew = getenv("TINYWEB_MAX_CLOCK_SKEW");
    if (max_skew) {
        config->max_clock_skew_seconds = (uint64_t)atoll(max_skew);
    }
    
    const char* message_ttl = getenv("TINYWEB_MESSAGE_TTL");
    if (message_ttl) {
        config->message_ttl_seconds = (uint64_t)atoll(message_ttl);
    }
    
    return 0;
}

int config_merge(NodeConfig* dest, const NodeConfig* src) {
    if (!dest || !src) {
        return -1;
    }
    
    // Environment variables override file config
    // Only override non-zero/non-empty values from src
    if (src->gossip_port != 0) {
        dest->gossip_port = src->gossip_port;
    }
    if (src->api_port != 0) {
        dest->api_port = src->api_port;
    }
    if (src->node_id[0] != '\0') {
        strncpy(dest->node_id, src->node_id, sizeof(dest->node_id) - 1);
    }
    if (src->max_clock_skew_seconds != 0) {
        dest->max_clock_skew_seconds = src->max_clock_skew_seconds;
    }
    if (src->message_ttl_seconds != 0) {
        dest->message_ttl_seconds = src->message_ttl_seconds;
    }
    if (src->max_payload_bytes != 0) {
        dest->max_payload_bytes = src->max_payload_bytes;
    }
    
    dest->debug_mode = src->debug_mode;
    dest->log_level = src->log_level;
    dest->log_to_file = src->log_to_file;
    if (src->log_file_path[0] != '\0') {
        strncpy(dest->log_file_path, src->log_file_path, sizeof(dest->log_file_path) - 1);
    }
    
    if (src->max_retries != 0) {
        dest->max_retries = src->max_retries;
    }
    if (src->initial_delay_ms != 0) {
        dest->initial_delay_ms = src->initial_delay_ms;
    }
    if (src->backoff_multiplier != 0.0) {
        dest->backoff_multiplier = src->backoff_multiplier;
    }
    if (src->max_delay_ms != 0) {
        dest->max_delay_ms = src->max_delay_ms;
    }
    
    return 0;
}

int config_validate(const NodeConfig* config) {
    if (!config) {
        return -1;
    }
    
    if (config->gossip_port < 1024 || config->gossip_port > 65535) {
        logger_error("config", "Invalid gossip_port: %u (must be 1024-65535)", config->gossip_port);
        return -1;
    }
    
    if (config->api_port < 1024 || config->api_port > 65535) {
        logger_error("config", "Invalid api_port: %u (must be 1024-65535)", config->api_port);
        return -1;
    }
    
    if (config->max_clock_skew_seconds == 0) {
        logger_error("config", "max_clock_skew_seconds must be > 0");
        return -1;
    }
    
    if (config->message_ttl_seconds == 0) {
        logger_error("config", "message_ttl_seconds must be > 0");
        return -1;
    }
    
    if (config->max_payload_bytes == 0) {
        logger_error("config", "max_payload_bytes must be > 0");
        return -1;
    }
    
    return 0;
}

int config_reload(NodeConfig* config) {
    if (!config || config->config_file_path[0] == '\0') {
        return -1;
    }
    
    struct stat st;
    if (stat(config->config_file_path, &st) != 0) {
        return -1;
    }
    
    if (st.st_mtime != config->config_file_mtime) {
        // File modified, reload
        NodeConfig new_config;
        if (config_load_node_from_network_config(config->config_file_path, config->node_id, &new_config) == 0) {
            // Merge with current config (preserve env overrides)
            config_merge(&new_config, config);
            *config = new_config;
            config->config_file_mtime = st.st_mtime;
            return 0;
        }
    }
    
    return -1;
}

void config_free(NodeConfig* config) {
    if (!config) return;
    
    if (config->peers) {
        for (uint32_t i = 0; i < config->peer_count; i++) {
            free(config->peers[i]);
        }
        free(config->peers);
        config->peers = NULL;
        config->peer_count = 0;
    }
}

