#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <regex.h>
#include <yaml.h>
#include <cjson/cJSON.h>
#include <linux/limits.h>  // For PATH_MAX

#include "init.h"
#include "packages/utils/logger.h"

#define MAX_PATH_LEN 1024
#define MAX_NODE_ID_LEN 64
#define MAX_HOSTNAME_LEN 256
#define MAX_DISCOVERY_MODE_LEN 32

// Structure to hold discovery configuration
typedef struct {
    char mode[MAX_DISCOVERY_MODE_LEN];
    char hostname_prefix[64];
    char dns_domain[256];
} DiscoveryConfig;

// Structure to hold docker configuration
typedef struct {
    char mode[32];  // "production" or "test"
    DiscoveryConfig discovery;
} DockerConfig;

// Structure to hold parsed master config
typedef struct {
    cJSON* root;
    cJSON* nodes;
    cJSON* docker;
    DockerConfig docker_config;
    uint32_t node_count;
} MasterConfig;

// ============================================================================
// Helper Functions
// ============================================================================

static int ensure_directory(const char* path) {
    if (!path) return -1;
    struct stat st = {0};
    if (stat(path, &st) == 0) return 0;
    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
        fprintf(stderr, "Error: Failed to create directory %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int extract_node_index(const char* node_id, int* out_index) {
    if (!node_id || !out_index) return -1;
    
    // Simple extraction: node_XX where XX is 01-99
    // Skip regex for simplicity - just parse after "node_"
    if (strncmp(node_id, "node_", 5) != 0) {
        return -1;
    }
    
    const char* num_str = node_id + 5;
    if (strlen(num_str) != 2) {
        return -1;
    }
    
    int index = atoi(num_str);
    if (index < 1 || index > 99) {
        return -1;
    }
    
    *out_index = index;
    return 0;
}

static int format_node_index(int index, char* out, size_t out_len) {
    if (index < 1 || index > 99 || !out || out_len < 3) return -1;
    snprintf(out, out_len, "%02d", index);
    return 0;
}

static int generate_hostname(const char* node_id, const DiscoveryConfig* discovery, 
                            cJSON* node_config, char* out_hostname, size_t hostname_len) {
    if (!node_id || !discovery || !out_hostname) return -1;
    
    int index;
    if (extract_node_index(node_id, &index) != 0) {
        return -1;
    }
    
    char index_str[4];
    if (format_node_index(index, index_str, sizeof(index_str)) != 0) {
        return -1;
    }
    
    if (strcmp(discovery->mode, "tailscale") == 0) {
        // Short hostname: {prefix}{index} (e.g., tw-node01)
        // Tailscale requires DNS-compliant hostnames (no underscores)
        char temp_hostname[256];
        snprintf(temp_hostname, sizeof(temp_hostname), "%s%s", discovery->hostname_prefix, index_str);
        // Replace underscores with hyphens for Tailscale compatibility
        size_t len = strlen(temp_hostname);
        for (size_t i = 0; i < len && i < hostname_len - 1; i++) {
            if (temp_hostname[i] == '_') {
                out_hostname[i] = '-';
            } else {
                out_hostname[i] = temp_hostname[i];
            }
        }
        out_hostname[len < hostname_len - 1 ? len : hostname_len - 1] = '\0';
        return 0;
    } else if (strcmp(discovery->mode, "dns_pattern") == 0) {
        // Full domain: {prefix}{index}.{domain}
        if (discovery->dns_domain[0] == '\0') {
            fprintf(stderr, "Error: dns_pattern mode requires 'docker.discovery.dns_pattern.domain'\n");
            return -1;
        }
        char temp_hostname[256];
        snprintf(temp_hostname, sizeof(temp_hostname), "%s%s.%s", 
                discovery->hostname_prefix, index_str, discovery->dns_domain);
        // Replace underscores with hyphens for DNS compatibility
        for (size_t i = 0; temp_hostname[i] != '\0' && i < hostname_len - 1; i++) {
            if (temp_hostname[i] == '_') {
                out_hostname[i] = '-';
            } else {
                out_hostname[i] = temp_hostname[i];
            }
        }
        out_hostname[strlen(temp_hostname)] = '\0';
        return 0;
    } else if (strcmp(discovery->mode, "static") == 0) {
        // Use hostname from node config
        if (!node_config) {
            fprintf(stderr, "Error: Static mode requires node config\n");
            return -1;
        }
        cJSON* hostname = cJSON_GetObjectItem(node_config, "hostname");
        if (!cJSON_IsString(hostname)) {
            fprintf(stderr, "Error: Static mode requires 'hostname' field in node config\n");
            return -1;
        }
        strncpy(out_hostname, hostname->valuestring, hostname_len - 1);
        out_hostname[hostname_len - 1] = '\0';
        return 0;
    }
    
    fprintf(stderr, "Error: Unknown discovery mode: %s\n", discovery->mode);
    return -1;
}

static int generate_node_config_json(cJSON* node, const DiscoveryConfig* discovery, 
                                    const char* docker_mode, const char* out_path) {
    if (!node || !discovery || !out_path) return -1;
    
    cJSON* node_id_json = cJSON_GetObjectItem(node, "id");
    if (!cJSON_IsString(node_id_json)) return -1;
    const char* node_id = node_id_json->valuestring;
    
    char hostname[MAX_HOSTNAME_LEN];
    if (generate_hostname(node_id, discovery, node, hostname, sizeof(hostname)) != 0) {
        fprintf(stderr, "Error: Failed to generate hostname for %s\n", node_id);
        return -1;
    }
    
    // Create node-specific config
    cJSON* config = cJSON_CreateObject();
    cJSON_AddStringToObject(config, "id", node_id);
    
    cJSON* name = cJSON_GetObjectItem(node, "name");
    if (cJSON_IsString(name)) {
        cJSON_AddStringToObject(config, "name", name->valuestring);
    }
    
    cJSON_AddStringToObject(config, "hostname", hostname);
    cJSON_AddNumberToObject(config, "gossip_port", 9000);
    cJSON_AddNumberToObject(config, "api_port", 8000);
    cJSON_AddStringToObject(config, "discovery_mode", discovery->mode);
    
    // Add peers based on discovery mode
    if (strcmp(discovery->mode, "static") == 0) {
        cJSON* peers = cJSON_GetObjectItem(node, "peers");
        if (cJSON_IsArray(peers)) {
            cJSON_AddItemToObject(config, "peers", cJSON_Duplicate(peers, 1));
        } else {
            cJSON_AddArrayToObject(config, "peers");
        }
    } else {
        cJSON_AddArrayToObject(config, "peers");
    }
    
    // Add DNS pattern info if in dns_pattern mode
    if (strcmp(discovery->mode, "dns_pattern") == 0) {
        if (discovery->dns_domain[0] != '\0') {
            cJSON_AddStringToObject(config, "dns_domain", discovery->dns_domain);
        }
        if (discovery->hostname_prefix[0] != '\0') {
            cJSON_AddStringToObject(config, "hostname_prefix", discovery->hostname_prefix);
        }
    }
    
    // Add hostname_prefix for tailscale mode
    if (strcmp(discovery->mode, "tailscale") == 0 && discovery->hostname_prefix[0] != '\0') {
        cJSON_AddStringToObject(config, "hostname_prefix", discovery->hostname_prefix);
    }
    
    // Write to file
    char* json_string = cJSON_Print(config);
    if (!json_string) {
        cJSON_Delete(config);
        return -1;
    }
    
    FILE* f = fopen(out_path, "w");
    if (!f) {
        free(json_string);
        cJSON_Delete(config);
        fprintf(stderr, "Error: Failed to open %s for writing: %s\n", out_path, strerror(errno));
        return -1;
    }
    
    fprintf(f, "%s\n", json_string);
    fclose(f);
    free(json_string);
    cJSON_Delete(config);
    
    return 0;
}

// ============================================================================
// Config Parsing
// ============================================================================

static int parse_docker_config(cJSON* docker_json, DockerConfig* out) {
    if (!docker_json || !out) return -1;
    
    memset(out, 0, sizeof(*out));
    
    cJSON* mode = cJSON_GetObjectItem(docker_json, "mode");
    if (cJSON_IsString(mode)) {
        strncpy(out->mode, mode->valuestring, sizeof(out->mode) - 1);
    }
    
    cJSON* discovery = cJSON_GetObjectItem(docker_json, "discovery");
    if (!discovery) {
        fprintf(stderr, "Error: docker.discovery is required\n");
        return -1;
    }
    
    cJSON* disc_mode = cJSON_GetObjectItem(discovery, "mode");
    if (!cJSON_IsString(disc_mode)) {
        fprintf(stderr, "Error: docker.discovery.mode is required\n");
        return -1;
    }
    strncpy(out->discovery.mode, disc_mode->valuestring, sizeof(out->discovery.mode) - 1);
    
    cJSON* hostname_prefix = cJSON_GetObjectItem(discovery, "hostname_prefix");
    if (cJSON_IsString(hostname_prefix)) {
        strncpy(out->discovery.hostname_prefix, hostname_prefix->valuestring, 
                sizeof(out->discovery.hostname_prefix) - 1);
    }
    
    cJSON* dns_pattern = cJSON_GetObjectItem(discovery, "dns_pattern");
    if (dns_pattern) {
        cJSON* domain = cJSON_GetObjectItem(dns_pattern, "domain");
        if (cJSON_IsString(domain)) {
            strncpy(out->discovery.dns_domain, domain->valuestring, 
                    sizeof(out->discovery.dns_domain) - 1);
        }
    }
    
    return 0;
}

static int load_master_config(const char* path, MasterConfig* out) {
    if (!path || !out) return -1;
    
    FILE* file = fopen(path, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open config file '%s': %s\n", path, strerror(errno));
        return -1;
    }
    
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char* buffer = malloc((size_t)size + 1);
    if (!buffer) {
        fclose(file);
        fprintf(stderr, "Error: Failed to allocate memory for config\n");
        return -1;
    }
    
    fread(buffer, 1, (size_t)size, file);
    buffer[size] = '\0';
    fclose(file);
    
    cJSON* root = cJSON_Parse(buffer);
    free(buffer);
    if (!root) {
        fprintf(stderr, "Error: Invalid JSON in config\n");
        return -1;
    }
    
    memset(out, 0, sizeof(*out));
    out->root = root;
    
    // Parse nodes
    out->nodes = cJSON_GetObjectItem(root, "nodes");
    if (!cJSON_IsArray(out->nodes)) {
        fprintf(stderr, "Error: config must contain a 'nodes' array\n");
        cJSON_Delete(root);
        return -1;
    }
    out->node_count = (uint32_t)cJSON_GetArraySize(out->nodes);
    
    // Parse docker config
    out->docker = cJSON_GetObjectItem(root, "docker");
    if (!out->docker) {
        fprintf(stderr, "Error: config must contain 'docker' section\n");
        cJSON_Delete(root);
        return -1;
    }
    
    if (parse_docker_config(out->docker, &out->docker_config) != 0) {
        cJSON_Delete(root);
        return -1;
    }
    
    return 0;
}

static void free_master_config(MasterConfig* config) {
    if (config && config->root) {
        cJSON_Delete(config->root);
        config->root = NULL;
    }
}

// ============================================================================
// Initialization (Direct Function Calls)
// ============================================================================

static int initialize_node_direct(cJSON* node, const MasterConfig* master_config, 
                                  const char* state_dir) {
    if (!node || !master_config || !state_dir) return -1;
    
    // Get node_id first (for error messages)
    cJSON* id_json = cJSON_GetObjectItem(node, "id");
    const char* node_id = cJSON_IsString(id_json) ? id_json->valuestring : "unknown";
    
    // Parse node config from JSON
    InitNodeConfig node_config = {0};
    
    if (cJSON_IsString(id_json)) {
        node_config.id = strdup(id_json->valuestring);
    }
    
    cJSON* name = cJSON_GetObjectItem(node, "name");
    if (cJSON_IsString(name)) {
        node_config.name = strdup(name->valuestring);
    }
    
    cJSON* hostname = cJSON_GetObjectItem(node, "hostname");
    if (cJSON_IsString(hostname)) {
        node_config.hostname = strdup(hostname->valuestring);
    } else {
        // Generate hostname if not present
        char gen_hostname[MAX_HOSTNAME_LEN];
        if (generate_hostname(node_config.id, &master_config->docker_config.discovery, 
                             node, gen_hostname, sizeof(gen_hostname)) == 0) {
            node_config.hostname = strdup(gen_hostname);
        }
    }
    
    node_config.gossip_port = 9000;
    node_config.api_port = 8000;
    
    // Parse peers if present
    cJSON* peers = cJSON_GetObjectItem(node, "peers");
    if (cJSON_IsArray(peers)) {
        int peer_count = cJSON_GetArraySize(peers);
        if (peer_count > 0) {
            node_config.peers = calloc(peer_count, sizeof(char*));
            if (node_config.peers) {
                for (int i = 0; i < peer_count; i++) {
                    cJSON* peer = cJSON_GetArrayItem(peers, i);
                    if (cJSON_IsString(peer)) {
                        node_config.peers[i] = strdup(peer->valuestring);
                    }
                }
                node_config.peer_count = peer_count;
            }
        }
    }
    
    // Parse users from master config (handles admins/members structure)
    InitUserConfig* users = NULL;
    uint32_t user_count = 0;
    
    cJSON* users_json = cJSON_GetObjectItem(master_config->root, "users");
    if (users_json) {
        cJSON* admins = cJSON_GetObjectItem(users_json, "admins");
        cJSON* members = cJSON_GetObjectItem(users_json, "members");
        
        uint32_t admin_count = cJSON_IsArray(admins) ? (uint32_t)cJSON_GetArraySize(admins) : 0;
        uint32_t member_count = cJSON_IsArray(members) ? (uint32_t)cJSON_GetArraySize(members) : 0;
        user_count = admin_count + member_count;
        
        if (user_count > 0 && user_count <= MAX_USERS) {
            users = calloc(user_count, sizeof(InitUserConfig));
            if (users) {
                uint32_t idx = 0;
                
                // Parse admins
                for (uint32_t i = 0; i < admin_count && idx < user_count; i++, idx++) {
                    cJSON* admin = cJSON_GetArrayItem(admins, (int)i);
                    if (cJSON_IsObject(admin)) {
                        cJSON* user_id = cJSON_GetObjectItem(admin, "id");
                        if (cJSON_IsString(user_id)) {
                            users[idx].id = strdup(user_id->valuestring);
                        }
                        cJSON* user_name = cJSON_GetObjectItem(admin, "name");
                        if (cJSON_IsString(user_name)) {
                            users[idx].name = strdup(user_name->valuestring);
                        }
                        cJSON* role = cJSON_GetObjectItem(admin, "role");
                        if (cJSON_IsString(role)) {
                            users[idx].role = strdup(role->valuestring);
                        } else {
                            users[idx].role = strdup("admin");
                        }
                    }
                }
                
                // Parse members
                for (uint32_t i = 0; i < member_count && idx < user_count; i++, idx++) {
                    cJSON* member = cJSON_GetArrayItem(members, (int)i);
                    if (cJSON_IsObject(member)) {
                        cJSON* user_id = cJSON_GetObjectItem(member, "id");
                        if (cJSON_IsString(user_id)) {
                            users[idx].id = strdup(user_id->valuestring);
                        }
                        cJSON* user_name = cJSON_GetObjectItem(member, "name");
                        if (cJSON_IsString(user_name)) {
                            users[idx].name = strdup(user_name->valuestring);
                        }
                        cJSON* role = cJSON_GetObjectItem(member, "role");
                        if (cJSON_IsString(role)) {
                            users[idx].role = strdup(role->valuestring);
                        } else {
                            users[idx].role = strdup("member");
                        }
                        cJSON* age = cJSON_GetObjectItem(member, "age");
                        if (cJSON_IsNumber(age)) {
                            users[idx].age = (uint32_t)age->valueint;
                        }
                        cJSON* supervised_by = cJSON_GetObjectItem(member, "supervised_by");
                        if (cJSON_IsArray(supervised_by)) {
                            uint32_t sup_count = (uint32_t)cJSON_GetArraySize(supervised_by);
                            if (sup_count > 0) {
                                users[idx].supervised_by = calloc(sup_count, sizeof(char*));
                                if (users[idx].supervised_by) {
                                    for (uint32_t j = 0; j < sup_count; j++) {
                                        cJSON* sup = cJSON_GetArrayItem(supervised_by, (int)j);
                                        if (cJSON_IsString(sup)) {
                                            users[idx].supervised_by[j] = strdup(sup->valuestring);
                                        }
                                    }
                                    users[idx].supervisor_count = sup_count;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Call initialize_node directly
    printf("    Initializing state for %s...\n", node_id);
    fflush(stdout);
    
    int result = initialize_node(&node_config, users, user_count, state_dir);
    
    // Free allocated memory
    if (node_config.id) free(node_config.id);
    if (node_config.name) free(node_config.name);
    if (node_config.hostname) free(node_config.hostname);
    if (node_config.peers) {
        for (uint32_t i = 0; i < node_config.peer_count; i++) {
            if (node_config.peers[i]) free(node_config.peers[i]);
        }
        free(node_config.peers);
    }
    
    if (users) {
        for (uint32_t i = 0; i < user_count; i++) {
            if (users[i].id) free(users[i].id);
            if (users[i].name) free(users[i].name);
            if (users[i].role) free(users[i].role);
            if (users[i].supervised_by) {
                for (uint32_t j = 0; j < users[i].supervisor_count; j++) {
                    if (users[i].supervised_by[j]) free(users[i].supervised_by[j]);
                }
                free(users[i].supervised_by);
            }
        }
        free(users);
    }
    
    if (result == 0) {
        printf("    ✓ Initialized state for %s\n", node_id);
        fflush(stdout);
    } else {
        fprintf(stderr, "    Error: Failed to initialize state for %s\n", node_id);
    }
    
    return result;
}

// ============================================================================
// Docker Compose YAML Generation
// ============================================================================

static int write_yaml_scalar(yaml_emitter_t* emitter, const char* value, int quoted) {
    yaml_event_t event;
    yaml_scalar_style_t style = quoted ? YAML_SINGLE_QUOTED_SCALAR_STYLE : YAML_PLAIN_SCALAR_STYLE;
    
    if (!yaml_scalar_event_initialize(&event, NULL, NULL, (yaml_char_t*)value, 
                                      (int)strlen(value), 1, 0, style)) {
        return -1;
    }
    if (!yaml_emitter_emit(emitter, &event)) {
        return -1;
    }
    return 0;
}

static int write_yaml_mapping_start(yaml_emitter_t* emitter) {
    yaml_event_t event;
    if (!yaml_mapping_start_event_initialize(&event, NULL, NULL, 0, YAML_BLOCK_MAPPING_STYLE)) {
        return -1;
    }
    if (!yaml_emitter_emit(emitter, &event)) {
        return -1;
    }
    return 0;
}

static int write_yaml_mapping_end(yaml_emitter_t* emitter) {
    yaml_event_t event;
    if (!yaml_mapping_end_event_initialize(&event)) {
        return -1;
    }
    if (!yaml_emitter_emit(emitter, &event)) {
        return -1;
    }
    return 0;
}

static int write_yaml_sequence_start(yaml_emitter_t* emitter) {
    yaml_event_t event;
    if (!yaml_sequence_start_event_initialize(&event, NULL, NULL, 0, YAML_BLOCK_SEQUENCE_STYLE)) {
        return -1;
    }
    if (!yaml_emitter_emit(emitter, &event)) {
        return -1;
    }
    return 0;
}

static int write_yaml_sequence_end(yaml_emitter_t* emitter) {
    yaml_event_t event;
    if (!yaml_sequence_end_event_initialize(&event)) {
        return -1;
    }
    if (!yaml_emitter_emit(emitter, &event)) {
        return -1;
    }
    return 0;
}

static int generate_docker_compose_yaml(const MasterConfig* master_config, 
                                       const char* output_dir, const char* compose_mode) {
    if (!master_config || !output_dir) return -1;
    
    const DiscoveryConfig* discovery = &master_config->docker_config.discovery;
    const char* discovery_mode = discovery->mode;
    int is_production = (strcmp(compose_mode, "production") == 0);
    
    char compose_path[MAX_PATH_LEN];
    snprintf(compose_path, sizeof(compose_path), "%s/docker-compose%s.yml", 
            output_dir, is_production ? "" : ".test");
    
    FILE* file = fopen(compose_path, "w");
    if (!file) {
        fprintf(stderr, "Error: Failed to open %s for writing: %s\n", compose_path, strerror(errno));
        return -1;
    }
    
    yaml_emitter_t emitter;
    yaml_emitter_initialize(&emitter);
    yaml_emitter_set_output_file(&emitter, file);
    
    yaml_event_t event;
    
    // Start document
    if (!yaml_stream_start_event_initialize(&event, YAML_UTF8_ENCODING)) goto error;
    if (!yaml_emitter_emit(&emitter, &event)) goto error;
    
    if (!yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 1)) goto error;
    if (!yaml_emitter_emit(&emitter, &event)) goto error;
    
    // Start root mapping (version field is obsolete in Docker Compose v2)
    write_yaml_mapping_start(&emitter);
    
    // services:
    write_yaml_scalar(&emitter, "services", 0);
    write_yaml_mapping_start(&emitter);
    
    // Generate Tailscale sidecar services if in tailscale mode
    if (strcmp(discovery_mode, "tailscale") == 0) {
        for (uint32_t i = 0; i < master_config->node_count; i++) {
            cJSON* node = cJSON_GetArrayItem(master_config->nodes, (int)i);
            if (!node) continue;
            
            cJSON* node_id_json = cJSON_GetObjectItem(node, "id");
            if (!cJSON_IsString(node_id_json)) continue;
            const char* node_id = node_id_json->valuestring;
            
            // Extract node index for per-container auth keys
            int index;
            if (extract_node_index(node_id, &index) != 0) {
                continue;  // Skip if we can't extract index
            }
            
            char hostname[MAX_HOSTNAME_LEN];
            if (generate_hostname(node_id, discovery, node, hostname, sizeof(hostname)) != 0) {
                continue;
            }
            
            char tailscale_service_name[128];
            snprintf(tailscale_service_name, sizeof(tailscale_service_name), "tailscale_%s", node_id);
            
            // tailscale_{node_id}:
            write_yaml_scalar(&emitter, tailscale_service_name, 0);
            write_yaml_mapping_start(&emitter);
            
            write_yaml_scalar(&emitter, "image", 0);
            write_yaml_scalar(&emitter, "tailscale/tailscale:latest", 1);
            
            write_yaml_scalar(&emitter, "environment", 0);
            write_yaml_mapping_start(&emitter);
            write_yaml_scalar(&emitter, "TS_AUTHKEY", 0);
            // Use per-container auth key (TS_AUTHKEY_01, TS_AUTHKEY_02, etc.)
            // Docker Compose doesn't support ${VAR:-default} syntax, so use direct variable
            char index_str[4];
            if (format_node_index(index, index_str, sizeof(index_str)) == 0) {
                char authkey_var[64];
                snprintf(authkey_var, sizeof(authkey_var), "${TS_AUTHKEY_%s}", index_str);
                write_yaml_scalar(&emitter, authkey_var, 1);
            } else {
                write_yaml_scalar(&emitter, "${TS_AUTHKEY}", 1);
            }
            write_yaml_scalar(&emitter, "TS_HOSTNAME", 0);
            write_yaml_scalar(&emitter, hostname, 1);
            write_yaml_scalar(&emitter, "TS_STATE_DIR", 0);
            write_yaml_scalar(&emitter, "/var/lib/tailscale", 1);
            write_yaml_mapping_end(&emitter);
            
            write_yaml_scalar(&emitter, "volumes", 0);
            write_yaml_sequence_start(&emitter);
            char volume_name[128];
            snprintf(volume_name, sizeof(volume_name), "%s_state:/var/lib/tailscale", tailscale_service_name);
            write_yaml_scalar(&emitter, volume_name, 0);
            write_yaml_sequence_end(&emitter);
            
            write_yaml_scalar(&emitter, "cap_add", 0);
            write_yaml_sequence_start(&emitter);
            write_yaml_scalar(&emitter, "NET_ADMIN", 0);
            write_yaml_sequence_end(&emitter);
            
            write_yaml_scalar(&emitter, "healthcheck", 0);
            write_yaml_mapping_start(&emitter);
            write_yaml_scalar(&emitter, "test", 0);
            write_yaml_sequence_start(&emitter);
            write_yaml_scalar(&emitter, "CMD", 0);
            write_yaml_scalar(&emitter, "tailscale", 0);
            write_yaml_scalar(&emitter, "status", 0);
            write_yaml_scalar(&emitter, "--json", 0);
            write_yaml_sequence_end(&emitter);
            write_yaml_scalar(&emitter, "interval", 0);
            write_yaml_scalar(&emitter, "10s", 1);
            write_yaml_scalar(&emitter, "timeout", 0);
            write_yaml_scalar(&emitter, "5s", 1);
            write_yaml_scalar(&emitter, "retries", 0);
            write_yaml_scalar(&emitter, "3", 1);
            write_yaml_scalar(&emitter, "start_period", 0);
            write_yaml_scalar(&emitter, "30s", 1);
            write_yaml_mapping_end(&emitter);
            
            write_yaml_scalar(&emitter, "restart", 0);
            write_yaml_scalar(&emitter, is_production ? "unless-stopped" : "no", 1);
            
            write_yaml_mapping_end(&emitter);
        }
    }
    
    // Generate node services
    for (uint32_t i = 0; i < master_config->node_count; i++) {
        cJSON* node = cJSON_GetArrayItem(master_config->nodes, (int)i);
        if (!node) continue;
        
        cJSON* node_id_json = cJSON_GetObjectItem(node, "id");
        if (!cJSON_IsString(node_id_json)) continue;
        const char* node_id = node_id_json->valuestring;
        
        int index;
        if (extract_node_index(node_id, &index) != 0) continue;
        
        char node_service_name[128];
        snprintf(node_service_name, sizeof(node_service_name), "node_%s", node_id);
        
        // node_{node_id}:
        write_yaml_scalar(&emitter, node_service_name, 0);
        write_yaml_mapping_start(&emitter);
        
        write_yaml_scalar(&emitter, "build", 0);
        write_yaml_mapping_start(&emitter);
        write_yaml_scalar(&emitter, "context", 0);
        // Build context: relative to compose file location
        // Since compose file is in docker_configs/, use .. to go up to project root
        write_yaml_scalar(&emitter, "..", 1);
        write_yaml_scalar(&emitter, "dockerfile", 0);
        // Dockerfile path: relative to the build context (project root)
        // Since context is .. (project root), dockerfile is scripts/Dockerfile.node
        write_yaml_scalar(&emitter, "scripts/Dockerfile.node", 1);
        write_yaml_mapping_end(&emitter);
        
        write_yaml_scalar(&emitter, "environment", 0);
        write_yaml_mapping_start(&emitter);
        write_yaml_scalar(&emitter, "TINYWEB_NODE_ID", 0);
        char node_id_str[16];
        snprintf(node_id_str, sizeof(node_id_str), "%d", index);
        write_yaml_scalar(&emitter, node_id_str, 1);
        if (discovery_mode[0] != '\0') {
            write_yaml_scalar(&emitter, "TINYWEB_DISCOVERY_MODE", 0);
            write_yaml_scalar(&emitter, discovery_mode, 1);
        }
        write_yaml_mapping_end(&emitter);
        
        write_yaml_scalar(&emitter, "volumes", 0);
        write_yaml_sequence_start(&emitter);
        // Mount keys as bind mount (for copying/sharing keys)
        char keys_volume_path[MAX_PATH_LEN];
        snprintf(keys_volume_path, sizeof(keys_volume_path), "./%s/state/keys:/app/state/keys", node_id);
        write_yaml_scalar(&emitter, keys_volume_path, 0);
        // Mount database storage as named volume (off host machine)
        char storage_volume_name[128];
        snprintf(storage_volume_name, sizeof(storage_volume_name), "%s_storage:/app/state/storage", node_id);
        write_yaml_scalar(&emitter, storage_volume_name, 0);
        write_yaml_sequence_end(&emitter);
        
        write_yaml_scalar(&emitter, "healthcheck", 0);
        write_yaml_mapping_start(&emitter);
        write_yaml_scalar(&emitter, "test", 0);
        write_yaml_sequence_start(&emitter);
        if (strcmp(discovery_mode, "tailscale") == 0) {
            write_yaml_scalar(&emitter, "CMD-SHELL", 0);
            write_yaml_scalar(&emitter, "curl -f http://localhost:8000/health || exit 1", 1);
        } else {
            write_yaml_scalar(&emitter, "CMD", 0);
            write_yaml_scalar(&emitter, "curl", 0);
            write_yaml_scalar(&emitter, "-f", 0);
            write_yaml_scalar(&emitter, "http://localhost:8000/health", 1);
        }
        write_yaml_sequence_end(&emitter);
        write_yaml_scalar(&emitter, "interval", 0);
        write_yaml_scalar(&emitter, "30s", 1);
        write_yaml_scalar(&emitter, "timeout", 0);
        write_yaml_scalar(&emitter, "10s", 1);
        write_yaml_scalar(&emitter, "retries", 0);
        write_yaml_scalar(&emitter, "3", 1);
        write_yaml_scalar(&emitter, "start_period", 0);
        write_yaml_scalar(&emitter, "40s", 1);
        write_yaml_mapping_end(&emitter);
        
        write_yaml_scalar(&emitter, "restart", 0);
        write_yaml_scalar(&emitter, is_production ? "unless-stopped" : "no", 1);
        
        // Configure based on discovery mode
        if (strcmp(discovery_mode, "tailscale") == 0) {
            char tailscale_service_name[128];
            snprintf(tailscale_service_name, sizeof(tailscale_service_name), "tailscale_%s", node_id);
            
            write_yaml_scalar(&emitter, "network_mode", 0);
            char network_mode_str[256];
            snprintf(network_mode_str, sizeof(network_mode_str), "service:%s", tailscale_service_name);
            write_yaml_scalar(&emitter, network_mode_str, 1);
            
            write_yaml_scalar(&emitter, "depends_on", 0);
            write_yaml_mapping_start(&emitter);
            write_yaml_scalar(&emitter, tailscale_service_name, 0);
            write_yaml_mapping_start(&emitter);
            write_yaml_scalar(&emitter, "condition", 0);
            write_yaml_scalar(&emitter, "service_healthy", 1);
            write_yaml_mapping_end(&emitter);
            write_yaml_mapping_end(&emitter);
            
            if (is_production) {
                write_yaml_scalar(&emitter, "ports", 0);
                write_yaml_sequence_start(&emitter);
                char port_str[32];
                snprintf(port_str, sizeof(port_str), "%d:8000", 8000 + index);
                write_yaml_scalar(&emitter, port_str, 1);
                write_yaml_sequence_end(&emitter);
            }
        } else if (strcmp(discovery_mode, "dns_pattern") == 0) {
            write_yaml_scalar(&emitter, "network_mode", 0);
            write_yaml_scalar(&emitter, "bridge", 1);
        } else if (strcmp(discovery_mode, "static") == 0) {
            write_yaml_scalar(&emitter, "network_mode", 0);
            write_yaml_scalar(&emitter, "bridge", 1);
            
            write_yaml_scalar(&emitter, "ports", 0);
            write_yaml_sequence_start(&emitter);
            write_yaml_scalar(&emitter, "9000:9000/udp", 1);
            char port_str[32];
            snprintf(port_str, sizeof(port_str), "%d:8000", 8000 + index);
            write_yaml_scalar(&emitter, port_str, 1);
            write_yaml_sequence_end(&emitter);
        }
        
        write_yaml_mapping_end(&emitter);
    }
    
    write_yaml_mapping_end(&emitter);  // End services
    
    // volumes:
    write_yaml_scalar(&emitter, "volumes", 0);
    write_yaml_mapping_start(&emitter);
    
    // Define named volumes for database storage (off host machine)
    for (uint32_t i = 0; i < master_config->node_count; i++) {
        cJSON* node = cJSON_GetArrayItem(master_config->nodes, (int)i);
        if (!node) continue;
        
        cJSON* node_id_json = cJSON_GetObjectItem(node, "id");
        if (!cJSON_IsString(node_id_json)) continue;
        const char* node_id = node_id_json->valuestring;
        
        char storage_volume_name[128];
        snprintf(storage_volume_name, sizeof(storage_volume_name), "%s_storage", node_id);
        write_yaml_scalar(&emitter, storage_volume_name, 0);
        write_yaml_mapping_start(&emitter);
        write_yaml_mapping_end(&emitter);
    }
    
    if (strcmp(discovery_mode, "tailscale") == 0) {
        // Define named volumes for Tailscale state
        for (uint32_t i = 0; i < master_config->node_count; i++) {
            cJSON* node = cJSON_GetArrayItem(master_config->nodes, (int)i);
            if (!node) continue;
            
            cJSON* node_id_json = cJSON_GetObjectItem(node, "id");
            if (!cJSON_IsString(node_id_json)) continue;
            const char* node_id = node_id_json->valuestring;
            
            char tailscale_service_name[128];
            snprintf(tailscale_service_name, sizeof(tailscale_service_name), "tailscale_%s", node_id);
            
            char volume_name[128];
            snprintf(volume_name, sizeof(volume_name), "%s_state", tailscale_service_name);
            write_yaml_scalar(&emitter, volume_name, 0);
            write_yaml_mapping_start(&emitter);
            write_yaml_mapping_end(&emitter);
        }
    }
    
    write_yaml_mapping_end(&emitter);  // End volumes
    
    write_yaml_mapping_end(&emitter);  // End root mapping
    
    // End document
    if (!yaml_document_end_event_initialize(&event, 1)) goto error;
    if (!yaml_emitter_emit(&emitter, &event)) goto error;
    
    if (!yaml_stream_end_event_initialize(&event)) goto error;
    if (!yaml_emitter_emit(&emitter, &event)) goto error;
    
    yaml_emitter_delete(&emitter);
    fclose(file);
    
    printf("  Generated: %s\n", compose_path);
    return 0;
    
error:
    yaml_emitter_delete(&emitter);
    fclose(file);
    fprintf(stderr, "Error: Failed to generate YAML\n");
    return -1;
}

// ============================================================================
// Main Function
// ============================================================================

static void print_usage(const char* program_name) {
    printf("Usage: %s --master-config <config_file> [options]\n", program_name);
    printf("Generate Docker configs for TinyWeb nodes\n\n");
    printf("Required:\n");
    printf("  --master-config <file>  Path to master network config JSON file\n\n");
    printf("Options:\n");
    printf("  -h, --help              Show this help message\n");
    printf("  --mode <mode>          Docker deployment mode: production or test (default: production)\n");
    printf("  --output-dir <dir>     Output directory for generated configs (default: docker_configs)\n");
    printf("  --skip-init            Skip running initialization (for testing config generation only)\n");
}

int main(int argc, char* argv[]) {
    const char* master_config_path = NULL;
    const char* docker_mode = "production";
    const char* output_dir = "docker_configs";
    int skip_init = 0;
    
    // Set stdout to line buffered for real-time output
    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    
    // Parse arguments
    static struct option long_opts[] = {
        {"master-config", required_argument, 0, 'c'},
        {"mode", required_argument, 0, 'm'},
        {"output-dir", required_argument, 0, 'o'},
        {"skip-init", no_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int opt_idx = 0;
    while ((opt = getopt_long(argc, argv, "hc:m:o:s", long_opts, &opt_idx)) != -1) {
        switch (opt) {
            case 'c':
                master_config_path = optarg;
                break;
            case 'm':
                docker_mode = optarg;
                if (strcmp(docker_mode, "production") != 0 && strcmp(docker_mode, "test") != 0) {
                    fprintf(stderr, "Error: mode must be 'production' or 'test'\n");
                    return 1;
                }
                break;
            case 'o':
                output_dir = optarg;
                break;
            case 's':
                skip_init = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (!master_config_path) {
        fprintf(stderr, "Error: --master-config is required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // Load master config
    MasterConfig master_config;
    if (load_master_config(master_config_path, &master_config) != 0) {
        return 1;
    }
    
    printf("Generating configs for %u nodes...\n", master_config.node_count);
    printf("Discovery mode: %s\n", master_config.docker_config.discovery.mode);
    printf("Output directory: %s\n", output_dir);
    
    // Create output directory
    if (ensure_directory(output_dir) != 0) {
        free_master_config(&master_config);
        return 1;
    }
    
    // Generate configs for each node
    for (uint32_t i = 0; i < master_config.node_count; i++) {
        cJSON* node = cJSON_GetArrayItem(master_config.nodes, (int)i);
        if (!node) continue;
        
        cJSON* node_id_json = cJSON_GetObjectItem(node, "id");
        if (!cJSON_IsString(node_id_json)) continue;
        const char* node_id = node_id_json->valuestring;
        
        // Create node directory
        char node_dir[MAX_PATH_LEN];
        snprintf(node_dir, sizeof(node_dir), "%s/%s", output_dir, node_id);
        if (ensure_directory(node_dir) != 0) {
            continue;
        }
        
        char state_dir[MAX_PATH_LEN];
        snprintf(state_dir, sizeof(state_dir), "%s/state", node_dir);
        if (ensure_directory(state_dir) != 0) {
            continue;
        }
        
        // Generate node-specific config
        char config_path[MAX_PATH_LEN];
        snprintf(config_path, sizeof(config_path), "%s/network_config.json", node_dir);
        
        if (generate_node_config_json(node, &master_config.docker_config.discovery, 
                                     docker_mode, config_path) != 0) {
            fprintf(stderr, "  Error: Failed to generate config for %s\n", node_id);
            continue;
        }
        
        printf("  Generated config for %s: %s\n", node_id, config_path);
        
        // Get hostname for display
        char hostname[MAX_HOSTNAME_LEN];
        if (generate_hostname(node_id, &master_config.docker_config.discovery, 
                             node, hostname, sizeof(hostname)) == 0) {
            printf("    Hostname: %s\n", hostname);
        }
        
        // Initialize node state (direct function call)
        if (!skip_init) {
            if (initialize_node_direct(node, &master_config, state_dir) != 0) {
                fprintf(stderr, "  Warning: Failed to initialize state for %s (continuing...)\n", node_id);
            }
        }
    }
    
    // Generate docker-compose files
    printf("\nGenerating docker-compose files...\n");
    if (generate_docker_compose_yaml(&master_config, output_dir, "production") != 0) {
        fprintf(stderr, "Error: Failed to generate docker-compose.yml\n");
    }
    if (generate_docker_compose_yaml(&master_config, output_dir, "test") != 0) {
        fprintf(stderr, "Error: Failed to generate docker-compose.test.yml\n");
    }
    
    printf("\nConfig generation complete!\n");
    printf("Next steps:\n");
    printf("  1. Build tinyweb binary: cmake -S . -B build && cmake --build build\n");
    printf("  2. Build Docker image: docker build -f scripts/Dockerfile.node -t tinyweb-node .\n");
    printf("  3. Set TS_AUTHKEY environment variable (for Tailscale mode)\n");
    printf("  4. Start services: docker-compose -f %s/docker-compose.yml up -d\n", output_dir);
    
    free_master_config(&master_config);
    return 0;
}

