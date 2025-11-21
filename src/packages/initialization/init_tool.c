#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <cjson/cJSON.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "init.h"

#define DEFAULT_STATE_PATH "state"
#define DEFAULT_TEST_STATE_PATH "test_state"

static void print_usage(const char* program_name) {
    printf("Usage: %s --config <config_file> [options]\n", program_name);
    printf("Initialize a TinyWeb gossip network from JSON configuration\n\n");
    printf("Required:\n");
    printf("  --config <file>     Path to JSON configuration file\n\n");
    printf("Options:\n");
    printf("  -h, --help          Show this help message\n");
    printf("  -t, --test          Use test_state/ directory instead of state/\n");
    printf("  -v, --verbose       Enable verbose output\n");
    printf("\nExample:\n");
    printf("  %s --config src/packages/initialization/configs/network_config.json\n", program_name);
    printf("  %s --config config.json --test\n", program_name);
}

static int parse_json_config(const char* path, InitNetworkConfig* out_config,
                            InitNodeConfig** out_nodes, InitUserConfig** out_users) {
    if (!path || !out_config || !out_nodes || !out_users) {
        return -1;
    }

    FILE* file = fopen(path, "r");
    if (!file) {
        fprintf(stderr, "Error: cannot open config file '%s'\n", path);
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = malloc((size_t)size + 1);
    if (!buffer) {
        fclose(file);
        fprintf(stderr, "Error: failed to allocate memory for config\n");
        return -1;
    }

    fread(buffer, 1, (size_t)size, file);
    buffer[size] = '\0';
    fclose(file);

    cJSON* root = cJSON_Parse(buffer);
    free(buffer);
    if (!root) {
        fprintf(stderr, "Error: invalid JSON in config\n");
        return -1;
    }

    memset(out_config, 0, sizeof(*out_config));

    // Parse network section
    cJSON* network = cJSON_GetObjectItem(root, "network");
    if (network) {
        cJSON* name = cJSON_GetObjectItem(network, "name");
        if (cJSON_IsString(name)) {
            out_config->network_name = strdup(name->valuestring);
        }
        cJSON* description = cJSON_GetObjectItem(network, "description");
        if (cJSON_IsString(description)) {
            out_config->network_description = strdup(description->valuestring);
        }
        cJSON* base_port = cJSON_GetObjectItem(network, "base_port");
        if (cJSON_IsNumber(base_port)) {
            out_config->base_port = (uint16_t)base_port->valueint;
        }
    }

    // Parse nodes array
    cJSON* nodes = cJSON_GetObjectItem(root, "nodes");
    if (!cJSON_IsArray(nodes)) {
        fprintf(stderr, "Error: config must contain a 'nodes' array\n");
        cJSON_Delete(root);
        return -1;
    }

    out_config->node_count = (uint32_t)cJSON_GetArraySize(nodes);
    if (out_config->node_count > MAX_NODES) {
        fprintf(stderr, "Warning: limiting nodes to %d\n", MAX_NODES);
        out_config->node_count = MAX_NODES;
    }

    *out_nodes = calloc(out_config->node_count, sizeof(InitNodeConfig));
    if (!*out_nodes) {
        fprintf(stderr, "Error: failed to allocate memory for nodes\n");
        cJSON_Delete(root);
        return -1;
    }
    out_config->nodes = *out_nodes;

    for (uint32_t i = 0; i < out_config->node_count; ++i) {
        cJSON* node = cJSON_GetArrayItem(nodes, (int)i);
        if (!cJSON_IsObject(node)) {
            continue;
        }

        InitNodeConfig* nc = &(*out_nodes)[i];
        
        cJSON* id = cJSON_GetObjectItem(node, "id");
        if (cJSON_IsString(id)) {
            nc->id = strdup(id->valuestring);
        }
        cJSON* name = cJSON_GetObjectItem(node, "name");
        if (cJSON_IsString(name)) {
            nc->name = strdup(name->valuestring);
        }
        cJSON* type = cJSON_GetObjectItem(node, "type");
        if (cJSON_IsString(type)) {
            nc->type = strdup(type->valuestring);
        }
        cJSON* hostname = cJSON_GetObjectItem(node, "hostname");
        if (cJSON_IsString(hostname)) {
            nc->hostname = strdup(hostname->valuestring);
        }
        cJSON* gossip_port = cJSON_GetObjectItem(node, "gossip_port");
        if (cJSON_IsNumber(gossip_port)) {
            nc->gossip_port = (uint16_t)gossip_port->valueint;
        }
        cJSON* api_port = cJSON_GetObjectItem(node, "api_port");
        if (cJSON_IsNumber(api_port)) {
            nc->api_port = (uint16_t)api_port->valueint;
        }
        cJSON* tags = cJSON_GetObjectItem(node, "tags");
        if (cJSON_IsString(tags)) {
            nc->tags = strdup(tags->valuestring);
        }

        // Parse peers array
        cJSON* peers = cJSON_GetObjectItem(node, "peers");
        if (cJSON_IsArray(peers)) {
            nc->peer_count = (uint32_t)cJSON_GetArraySize(peers);
            if (nc->peer_count > 0) {
                nc->peers = calloc(nc->peer_count, sizeof(char*));
                if (nc->peers) {
                    for (uint32_t p = 0; p < nc->peer_count; ++p) {
                        cJSON* peer = cJSON_GetArrayItem(peers, (int)p);
                        if (cJSON_IsString(peer)) {
                            nc->peers[p] = strdup(peer->valuestring);
                        }
                    }
                }
            }
        }
    }

    // Parse users section
    uint32_t total_user_count = 0;
    cJSON* users = cJSON_GetObjectItem(root, "users");
    if (users) {
        cJSON* admins = cJSON_GetObjectItem(users, "admins");
        cJSON* members = cJSON_GetObjectItem(users, "members");
        
        uint32_t admin_count = cJSON_IsArray(admins) ? (uint32_t)cJSON_GetArraySize(admins) : 0;
        uint32_t member_count = cJSON_IsArray(members) ? (uint32_t)cJSON_GetArraySize(members) : 0;
        total_user_count = admin_count + member_count;

        if (total_user_count > MAX_USERS) {
            fprintf(stderr, "Warning: limiting users to %d\n", MAX_USERS);
            total_user_count = MAX_USERS;
        }

        if (total_user_count > 0) {
            *out_users = calloc(total_user_count, sizeof(InitUserConfig));
            if (!*out_users) {
                fprintf(stderr, "Error: failed to allocate memory for users\n");
                cJSON_Delete(root);
                return -1;
            }
            out_config->users = *out_users;
            out_config->user_count = total_user_count;

            uint32_t idx = 0;

            // Parse admins
            for (uint32_t i = 0; i < admin_count && idx < total_user_count; ++i, ++idx) {
                cJSON* admin = cJSON_GetArrayItem(admins, (int)i);
                if (!cJSON_IsObject(admin)) {
                    continue;
                }
                
                InitUserConfig* uc = &(*out_users)[idx];
                
                cJSON* id = cJSON_GetObjectItem(admin, "id");
                if (cJSON_IsString(id)) {
                    uc->id = strdup(id->valuestring);
                }
                cJSON* name = cJSON_GetObjectItem(admin, "name");
                if (cJSON_IsString(name)) {
                    uc->name = strdup(name->valuestring);
                }
                cJSON* role = cJSON_GetObjectItem(admin, "role");
                if (cJSON_IsString(role)) {
                    uc->role = strdup(role->valuestring);
                } else {
                    uc->role = strdup("admin");
                }
            }

            // Parse members
            for (uint32_t i = 0; i < member_count && idx < total_user_count; ++i, ++idx) {
                cJSON* member = cJSON_GetArrayItem(members, (int)i);
                if (!cJSON_IsObject(member)) {
                    continue;
                }
                
                InitUserConfig* uc = &(*out_users)[idx];
                
                cJSON* id = cJSON_GetObjectItem(member, "id");
                if (cJSON_IsString(id)) {
                    uc->id = strdup(id->valuestring);
                }
                cJSON* name = cJSON_GetObjectItem(member, "name");
                if (cJSON_IsString(name)) {
                    uc->name = strdup(name->valuestring);
                }
                cJSON* role = cJSON_GetObjectItem(member, "role");
                if (cJSON_IsString(role)) {
                    uc->role = strdup(role->valuestring);
                } else {
                    uc->role = strdup("member");
                }
                cJSON* age = cJSON_GetObjectItem(member, "age");
                if (cJSON_IsNumber(age)) {
                    uc->age = (uint32_t)age->valueint;
                }
                
                // Parse supervised_by array
                cJSON* supervisors = cJSON_GetObjectItem(member, "supervised_by");
                if (cJSON_IsArray(supervisors)) {
                    uint32_t count = (uint32_t)cJSON_GetArraySize(supervisors);
                    uc->supervisor_count = count;
                    if (count > 0) {
                        uc->supervised_by = calloc(count, sizeof(char*));
                        if (uc->supervised_by) {
                            for (uint32_t s = 0; s < count; ++s) {
                                cJSON* supervisor = cJSON_GetArrayItem(supervisors, (int)s);
                                if (cJSON_IsString(supervisor)) {
                                    uc->supervised_by[s] = strdup(supervisor->valuestring);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    cJSON_Delete(root);
    return 0;
}

static void free_config(InitNetworkConfig* config, InitNodeConfig* nodes, InitUserConfig* users) {
    if (!config) {
        return;
    }

    free((void*)config->network_name);
    free((void*)config->network_description);

    if (nodes) {
        for (uint32_t i = 0; i < config->node_count; ++i) {
            free(nodes[i].id);
            free(nodes[i].name);
            free(nodes[i].type);
            free(nodes[i].hostname);
            free(nodes[i].tags);
            if (nodes[i].peers) {
                for (uint32_t p = 0; p < nodes[i].peer_count; ++p) {
                    free(nodes[i].peers[p]);
                }
                free(nodes[i].peers);
            }
        }
        free(nodes);
    }

    if (users) {
        for (uint32_t i = 0; i < config->user_count; ++i) {
            free(users[i].id);
            free(users[i].name);
            free(users[i].role);
            if (users[i].supervised_by) {
                for (uint32_t s = 0; s < users[i].supervisor_count; ++s) {
                    free(users[i].supervised_by[s]);
                }
                free(users[i].supervised_by);
            }
        }
        free(users);
    }
}

static int directory_has_files(const char* path) {
    DIR* dir = opendir(path);
    if (!dir) {
        return 0;
    }

    struct dirent* entry;
    int has_files = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            has_files = 1;
            break;
        }
    }

    closedir(dir);
    return has_files;
}

static int prompt_user_confirmation(const char* message) {
    char response[16];
    printf("%s (y/N): ", message);
    fflush(stdout);

    if (!fgets(response, sizeof(response), stdin)) {
        return 0;
    }
    return response[0] == 'y' || response[0] == 'Y';
}

static int clean_directory(const char* path) {
    DIR* dir = opendir(path);
    if (!dir) {
        return 1;
    }

    struct dirent* entry;
    char child[512];
    int success = 1;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        struct stat st;
        if (stat(child, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                if (!clean_directory(child) || rmdir(child) != 0) {
                    fprintf(stderr, "Warning: failed to remove directory %s\n", child);
                    success = 0;
                }
            } else if (unlink(child) != 0) {
                fprintf(stderr, "Warning: failed to remove file %s\n", child);
                success = 0;
            }
        }
    }

    closedir(dir);
    return success;
}

static int check_and_clean_existing_state(const char* state_path) {
    if (!state_path) {
        return 0;
    }

    if (!directory_has_files(state_path)) {
        return 0;
    }

    printf("\nExisting state detected in '%s'.\n", state_path);
    if (!prompt_user_confirmation("Remove existing state and continue?")) {
        printf("Initialization cancelled by user.\n");
        return -1;
    }

    printf("Cleaning '%s' ...\n", state_path);
    if (!clean_directory(state_path)) {
        fprintf(stderr, "Warning: some files inside '%s' could not be removed.\n", state_path);
        return 1;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    int verbose = 0;
    int use_test_state = 0;
    const char* config_path = NULL;

    static struct option long_opts[] = {
        {"help",    no_argument,       0, 'h'},
        {"config",  required_argument, 0, 'c'},
        {"test",    no_argument,       0, 't'},
        {"verbose", no_argument,       0, 'v'},
        {0, 0, 0, 0}
    };

    int opt;
    int opt_index = 0;
    while ((opt = getopt_long(argc, argv, "hc:tv", long_opts, &opt_index)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'c':
                config_path = optarg;
                break;
            case 't':
                use_test_state = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (!config_path) {
        fprintf(stderr, "Error: --config option is required\n\n");
        print_usage(argv[0]);
        return 1;
    }

    InitNetworkConfig config = {0};
    InitNodeConfig* nodes = NULL;
    InitUserConfig* users = NULL;

    if (parse_json_config(config_path, &config, &nodes, &users) != 0) {
        return 1;
    }

    if (config.node_count == 0) {
        fprintf(stderr, "Error: configuration must define at least one node\n");
        free_config(&config, nodes, users);
        return 1;
    }

    if (verbose) {
        printf("Loaded network config from: %s\n", config_path);
        printf("  Network: %s\n", config.network_name ? config.network_name : "(unnamed)");
        printf("  Nodes: %u\n", config.node_count);
        printf("  Users: %u\n", config.user_count);
    }

    const char* base_path = use_test_state ? DEFAULT_TEST_STATE_PATH : DEFAULT_STATE_PATH;
    if (use_test_state) {
        printf("Using test state directory: %s/\n", base_path);
    }

    int clean_result = check_and_clean_existing_state(base_path);
    if (clean_result < 0) {
        free_config(&config, nodes, users);
        return 0; // User cancelled intentionally
    }

    printf("\nInitializing gossip network...\n");
    if (initialize_network(&config, base_path, config_path) != 0) {
        fprintf(stderr, "Initialization failed.\n");
        free_config(&config, nodes, users);
        return 1;
    }

    printf("\n✓ Network '%s' is ready in %s/\n", 
           config.network_name ? config.network_name : "TinyWeb",
           base_path);
    
    free_config(&config, nodes, users);
    return 0;
}
