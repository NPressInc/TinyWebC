#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <cjson/cJSON.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include "init.h"

#define DEFAULT_STATE_ROOT "state"
#define DEFAULT_TEST_STATE_ROOT "test_state"

typedef struct {
    char* network_name;
    char* network_description;
    uint16_t base_port;

    uint32_t node_count;
    struct {
        char* id;
        char* name;
        char* type;
        char* hostname;
        uint16_t gossip_port;
        uint16_t api_port;
        char* tags;
        char** peers;
        uint32_t peer_count;
    } nodes[MAX_NODES];

    uint32_t admin_count;
    struct {
        char* id;
        char* name;
        char* role;
    } admins[MAX_USERS];

    uint32_t member_count;
    struct {
        char* id;
        char* name;
        char* role;
        uint32_t age;
        char** supervised_by;
        uint32_t supervisor_count;
    } members[MAX_USERS];
} JsonConfig;

static void print_usage(const char* program_name) {
    printf("Usage: %s [options] <config_file>\n", program_name);
    printf("Initialize a TinyWeb gossip network from JSON configuration\n\n");
    printf("Arguments:\n");
    printf("  config_file         Path to JSON configuration file\n\n");
    printf("Options:\n");
    printf("  -h, --help          Show this help message\n");
    printf("  -v, --verbose       Enable verbose output\n");
    printf("  -d, --debug         Use test_state/ directories per node\n");
    printf("\nExample:\n");
    printf("  %s src/packages/initialization/configs/network_config.json\n", program_name);
    printf("  %s --debug config.json\n", program_name);
}

static int parse_json_config(const char* path, JsonConfig* out) {
    if (!path || !out) {
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

    memset(out, 0, sizeof(*out));

    cJSON* network = cJSON_GetObjectItem(root, "network");
    if (network) {
        cJSON* name = cJSON_GetObjectItem(network, "name");
        if (cJSON_IsString(name)) {
            out->network_name = strdup(name->valuestring);
        }
        cJSON* description = cJSON_GetObjectItem(network, "description");
        if (cJSON_IsString(description)) {
            out->network_description = strdup(description->valuestring);
        }
        cJSON* base_port = cJSON_GetObjectItem(network, "base_port");
        if (cJSON_IsNumber(base_port)) {
            out->base_port = (uint16_t)base_port->valueint;
        }
    }

    cJSON* nodes = cJSON_GetObjectItem(root, "nodes");
    if (!cJSON_IsArray(nodes)) {
        fprintf(stderr, "Error: config must contain a 'nodes' array\n");
        cJSON_Delete(root);
        return -1;
    }

    out->node_count = (uint32_t)cJSON_GetArraySize(nodes);
    if (out->node_count > MAX_NODES) {
        fprintf(stderr, "Warning: limiting nodes to %d\n", MAX_NODES);
        out->node_count = MAX_NODES;
    }

    for (uint32_t i = 0; i < out->node_count; ++i) {
        cJSON* node = cJSON_GetArrayItem(nodes, (int)i);
        if (!cJSON_IsObject(node)) {
            continue;
        }

        cJSON* id = cJSON_GetObjectItem(node, "id");
        if (cJSON_IsString(id)) {
            out->nodes[i].id = strdup(id->valuestring);
        }
        cJSON* name = cJSON_GetObjectItem(node, "name");
        if (cJSON_IsString(name)) {
            out->nodes[i].name = strdup(name->valuestring);
        }
        cJSON* type = cJSON_GetObjectItem(node, "type");
        if (cJSON_IsString(type)) {
            out->nodes[i].type = strdup(type->valuestring);
        }
        cJSON* hostname = cJSON_GetObjectItem(node, "hostname");
        if (cJSON_IsString(hostname)) {
            out->nodes[i].hostname = strdup(hostname->valuestring);
        }
        cJSON* gossip_port = cJSON_GetObjectItem(node, "gossip_port");
        if (cJSON_IsNumber(gossip_port)) {
            out->nodes[i].gossip_port = (uint16_t)gossip_port->valueint;
        }
        cJSON* api_port = cJSON_GetObjectItem(node, "api_port");
        if (cJSON_IsNumber(api_port)) {
            out->nodes[i].api_port = (uint16_t)api_port->valueint;
        }
        cJSON* tags = cJSON_GetObjectItem(node, "tags");
        if (cJSON_IsString(tags)) {
            out->nodes[i].tags = strdup(tags->valuestring);
        }

        cJSON* peers = cJSON_GetObjectItem(node, "peers");
        if (cJSON_IsArray(peers)) {
            out->nodes[i].peer_count = (uint32_t)cJSON_GetArraySize(peers);
            if (out->nodes[i].peer_count > 0) {
                out->nodes[i].peers = calloc(out->nodes[i].peer_count, sizeof(char*));
                if (out->nodes[i].peers) {
                    for (uint32_t p = 0; p < out->nodes[i].peer_count; ++p) {
                        cJSON* peer = cJSON_GetArrayItem(peers, (int)p);
                        if (cJSON_IsString(peer)) {
                            out->nodes[i].peers[p] = strdup(peer->valuestring);
                        }
                    }
                }
            }
        }
    }

    cJSON* users = cJSON_GetObjectItem(root, "users");
    if (users) {
        cJSON* admins = cJSON_GetObjectItem(users, "admins");
        if (cJSON_IsArray(admins)) {
            out->admin_count = (uint32_t)cJSON_GetArraySize(admins);
            if (out->admin_count > MAX_USERS) {
                out->admin_count = MAX_USERS;
            }
            for (uint32_t i = 0; i < out->admin_count; ++i) {
                cJSON* admin = cJSON_GetArrayItem(admins, (int)i);
                if (!cJSON_IsObject(admin)) {
                    continue;
                }
                cJSON* id = cJSON_GetObjectItem(admin, "id");
                if (cJSON_IsString(id)) {
                    out->admins[i].id = strdup(id->valuestring);
                }
                cJSON* name = cJSON_GetObjectItem(admin, "name");
                if (cJSON_IsString(name)) {
                    out->admins[i].name = strdup(name->valuestring);
                }
                cJSON* role = cJSON_GetObjectItem(admin, "role");
                if (cJSON_IsString(role)) {
                    out->admins[i].role = strdup(role->valuestring);
                }
            }
        }

        cJSON* members = cJSON_GetObjectItem(users, "members");
        if (cJSON_IsArray(members)) {
            out->member_count = (uint32_t)cJSON_GetArraySize(members);
            if (out->member_count > MAX_USERS) {
                out->member_count = MAX_USERS;
            }
            for (uint32_t i = 0; i < out->member_count; ++i) {
                cJSON* member = cJSON_GetArrayItem(members, (int)i);
                if (!cJSON_IsObject(member)) {
                    continue;
                }
                cJSON* id = cJSON_GetObjectItem(member, "id");
                if (cJSON_IsString(id)) {
                    out->members[i].id = strdup(id->valuestring);
                }
                cJSON* name = cJSON_GetObjectItem(member, "name");
                if (cJSON_IsString(name)) {
                    out->members[i].name = strdup(name->valuestring);
                }
                cJSON* role = cJSON_GetObjectItem(member, "role");
                if (cJSON_IsString(role)) {
                    out->members[i].role = strdup(role->valuestring);
                }
                cJSON* age = cJSON_GetObjectItem(member, "age");
                if (cJSON_IsNumber(age)) {
                    out->members[i].age = (uint32_t)age->valueint;
                }
                cJSON* supervisors = cJSON_GetObjectItem(member, "supervised_by");
                if (cJSON_IsArray(supervisors)) {
                    uint32_t count = (uint32_t)cJSON_GetArraySize(supervisors);
                    out->members[i].supervisor_count = count;
                    if (count > 0) {
                        out->members[i].supervised_by = calloc(count, sizeof(char*));
                        if (out->members[i].supervised_by) {
                            for (uint32_t s = 0; s < count; ++s) {
                                cJSON* supervisor = cJSON_GetArrayItem(supervisors, (int)s);
                                if (cJSON_IsString(supervisor)) {
                                    out->members[i].supervised_by[s] = strdup(supervisor->valuestring);
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

static void free_json_config(JsonConfig* config) {
    if (!config) {
        return;
    }

    free(config->network_name);
    free(config->network_description);

    for (uint32_t i = 0; i < config->node_count; ++i) {
        free(config->nodes[i].id);
        free(config->nodes[i].name);
        free(config->nodes[i].type);
        free(config->nodes[i].hostname);
        free(config->nodes[i].tags);
        if (config->nodes[i].peers) {
            for (uint32_t p = 0; p < config->nodes[i].peer_count; ++p) {
                free(config->nodes[i].peers[p]);
            }
            free(config->nodes[i].peers);
        }
    }

    for (uint32_t i = 0; i < config->admin_count; ++i) {
        free(config->admins[i].id);
        free(config->admins[i].name);
        free(config->admins[i].role);
    }

    for (uint32_t i = 0; i < config->member_count; ++i) {
        free(config->members[i].id);
        free(config->members[i].name);
        free(config->members[i].role);
        if (config->members[i].supervised_by) {
            for (uint32_t s = 0; s < config->members[i].supervisor_count; ++s) {
                free(config->members[i].supervised_by[s]);
            }
            free(config->members[i].supervised_by);
        }
    }

    memset(config, 0, sizeof(*config));
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

static int check_and_clean_existing_state(const char* state_root) {
    if (!state_root) {
        return 0;
    }

    if (!directory_has_files(state_root)) {
        return 0;
    }

    printf("\nExisting state detected in '%s'.\n", state_root);
    if (!prompt_user_confirmation("Remove existing state and continue?")) {
        printf("Initialization cancelled by user.\n");
        return -1;
    }

    printf("Cleaning '%s' ...\n", state_root);
    if (!clean_directory(state_root)) {
        fprintf(stderr, "Warning: some files inside '%s' could not be removed.\n", state_root);
        return 1;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    int verbose = 0;
    int debug_mode = 0;
    const char* config_path = NULL;

    static struct option long_opts[] = {
        {"help",   no_argument,       0, 'h'},
        {"verbose",no_argument,       0, 'v'},
        {"debug",  no_argument,       0, 'd'},
        {0, 0, 0, 0}
    };

    int opt;
    int opt_index = 0;
    while ((opt = getopt_long(argc, argv, "hvd", long_opts, &opt_index)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                verbose = 1;
                break;
            case 'd':
                debug_mode = 1;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Error: missing configuration file argument\n\n");
        print_usage(argv[0]);
        return 1;
    }
    config_path = argv[optind];

    JsonConfig json = {0};
    if (parse_json_config(config_path, &json) != 0) {
        return 1;
    }

    if (json.node_count == 0) {
        fprintf(stderr, "Error: configuration must define at least one node\n");
        free_json_config(&json);
        return 1;
    }

    if (verbose) {
        printf("Loaded network config from: %s\n", config_path);
        printf("  Nodes: %u\n", json.node_count);
    }

    const char* state_root = debug_mode ? DEFAULT_TEST_STATE_ROOT : DEFAULT_STATE_ROOT;
    if (debug_mode) {
        printf("Debug mode: using isolated directories under '%s/'\n", state_root);
    }

    int clean_result = check_and_clean_existing_state(state_root);
    if (clean_result < 0) {
        free_json_config(&json);
        return 0; // User cancelled intentionally
    }

    InitNodeConfig node_configs[MAX_NODES];
    memset(node_configs, 0, sizeof(node_configs));

    for (uint32_t i = 0; i < json.node_count; ++i) {
        node_configs[i].id = json.nodes[i].id;
        node_configs[i].name = json.nodes[i].name;
        node_configs[i].type = json.nodes[i].type;
        node_configs[i].hostname = json.nodes[i].hostname;
        node_configs[i].gossip_port = json.nodes[i].gossip_port;
        node_configs[i].api_port = json.nodes[i].api_port;
        node_configs[i].tags = json.nodes[i].tags;
        node_configs[i].peer_count = json.nodes[i].peer_count;
        node_configs[i].peers = (const char* const*)json.nodes[i].peers;
    }

    InitUserRecord* admin_records = NULL;
    if (json.admin_count > 0) {
        admin_records = calloc(json.admin_count, sizeof(InitUserRecord));
        for (uint32_t i = 0; i < json.admin_count; ++i) {
            admin_records[i].id = json.admins[i].id;
            admin_records[i].name = json.admins[i].name;
            admin_records[i].role = json.admins[i].role ? json.admins[i].role : "admin";
        }
    }

    InitUserRecord* member_records = NULL;
    if (json.member_count > 0) {
        member_records = calloc(json.member_count, sizeof(InitUserRecord));
        for (uint32_t i = 0; i < json.member_count; ++i) {
            member_records[i].id = json.members[i].id;
            member_records[i].name = json.members[i].name;
            member_records[i].role = json.members[i].role ? json.members[i].role : "member";
            member_records[i].age = json.members[i].age;
            member_records[i].supervised_by = (const char* const*)json.members[i].supervised_by;
            member_records[i].supervisor_count = json.members[i].supervisor_count;
        }
    }

    InitUsersConfig users_cfg = {
        .admins = admin_records,
        .admin_count = json.admin_count,
        .members = member_records,
        .member_count = json.member_count
    };

    InitNetworkConfig init_cfg = {
        .network_name = json.network_name,
        .network_description = json.network_description,
        .base_port = json.base_port,
        .node_count = json.node_count,
        .debug_mode = debug_mode,
        .nodes = node_configs,
        .users = users_cfg,
    };

    printf("\nInitializing gossip network...\n");
    if (initialize_network(&init_cfg) != 0) {
        fprintf(stderr, "Initialization failed.\n");
        free(admin_records);
        free(member_records);
        free_json_config(&json);
        return 1;
    }

    printf("\nNetwork '%s' is ready.\n", init_cfg.network_name ? init_cfg.network_name : "TinyWeb");
    if (admin_records) {
        for (uint32_t i = 0; i < json.admin_count; ++i) {
            free(admin_records[i].key_path);
        }
    }
    if (member_records) {
        for (uint32_t i = 0; i < json.member_count; ++i) {
            free(member_records[i].key_path);
        }
    }
    free(admin_records);
    free(member_records);
    free_json_config(&json);
    return 0;
} 