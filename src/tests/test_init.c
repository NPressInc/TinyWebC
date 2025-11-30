#include "test_init.h"
#include "init.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <cjson/cJSON.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "packages/sql/database_gossip.h"
#include "packages/sql/schema.h"
#include "packages/sql/gossip_peers.h"

#define TEST_BASE_PATH "test_state"
#define CONFIG_PATH "scripts/configs/network_config.json"

static char test_db_path[512] = {0};
static char test_keys_dir[512] = {0};
static char test_user_key_path[512] = {0};

// Helper function to ensure directory exists
static int ensure_directory(const char* path) {
    if (!path) {
        return -1;
    }
    struct stat st = {0};
    if (stat(path, &st) == 0) {
        return 0;  // Directory already exists
    }
    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
        fprintf(stderr, "Failed to create directory %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

// Parse the full network config file
static int parse_test_config(InitNetworkConfig* out_config,
                            InitNodeConfig** out_nodes,
                            InitUserConfig** out_users) {
    FILE* file = fopen(CONFIG_PATH, "r");
    if (!file) {
        fprintf(stderr, "Error: cannot open config file '%s'\n", CONFIG_PATH);
        return -1;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = malloc((size_t)size + 1);
    if (!buffer) {
        fclose(file);
        return -1;
    }

    fread(buffer, 1, (size_t)size, file);
    buffer[size] = '\0';
    fclose(file);

    cJSON* root = cJSON_Parse(buffer);
    free(buffer);
    if (!root) {
        fprintf(stderr, "Error: invalid JSON in test config\n");
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
        cJSON* base_port = cJSON_GetObjectItem(network, "base_port");
        if (cJSON_IsNumber(base_port)) {
            out_config->base_port = (uint16_t)base_port->valueint;
        }
    }

    // Parse nodes
    cJSON* nodes = cJSON_GetObjectItem(root, "nodes");
    if (cJSON_IsArray(nodes)) {
        out_config->node_count = (uint32_t)cJSON_GetArraySize(nodes);
        if (out_config->node_count > 0) {
            *out_nodes = calloc(out_config->node_count, sizeof(InitNodeConfig));
            if (*out_nodes) {
                out_config->nodes = *out_nodes;
                
                for (uint32_t i = 0; i < out_config->node_count; ++i) {
                    cJSON* node = cJSON_GetArrayItem(nodes, (int)i);
                    if (!cJSON_IsObject(node)) continue;

                    InitNodeConfig* nc = &(*out_nodes)[i];
                    
                    cJSON* id = cJSON_GetObjectItem(node, "id");
                    if (cJSON_IsString(id)) nc->id = strdup(id->valuestring);
                    
                    cJSON* name = cJSON_GetObjectItem(node, "name");
                    if (cJSON_IsString(name)) nc->name = strdup(name->valuestring);
                    
                    cJSON* hostname = cJSON_GetObjectItem(node, "hostname");
                    if (cJSON_IsString(hostname)) nc->hostname = strdup(hostname->valuestring);
                    
                    cJSON* gossip_port = cJSON_GetObjectItem(node, "gossip_port");
                    if (cJSON_IsNumber(gossip_port)) nc->gossip_port = (uint16_t)gossip_port->valueint;
                    
                    cJSON* api_port = cJSON_GetObjectItem(node, "api_port");
                    if (cJSON_IsNumber(api_port)) nc->api_port = (uint16_t)api_port->valueint;
                    
                    cJSON* peers = cJSON_GetObjectItem(node, "peers");
                    if (cJSON_IsArray(peers)) {
                        nc->peer_count = (uint32_t)cJSON_GetArraySize(peers);
                        if (nc->peer_count > 0) {
                            nc->peers = calloc(nc->peer_count, sizeof(char*));
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
        }
    }

    // Parse users (admins + members)
    uint32_t total_users = 0;
    cJSON* users = cJSON_GetObjectItem(root, "users");
    if (users) {
        cJSON* admins = cJSON_GetObjectItem(users, "admins");
        cJSON* members = cJSON_GetObjectItem(users, "members");
        
        uint32_t admin_count = cJSON_IsArray(admins) ? (uint32_t)cJSON_GetArraySize(admins) : 0;
        uint32_t member_count = cJSON_IsArray(members) ? (uint32_t)cJSON_GetArraySize(members) : 0;
        total_users = admin_count + member_count;

        if (total_users > 0) {
            *out_users = calloc(total_users, sizeof(InitUserConfig));
            if (*out_users) {
                out_config->users = *out_users;
                out_config->user_count = total_users;
                uint32_t idx = 0;

                // Parse admins
                for (uint32_t i = 0; i < admin_count; ++i, ++idx) {
                    cJSON* admin = cJSON_GetArrayItem(admins, (int)i);
                    if (!cJSON_IsObject(admin)) continue;
                    
                    InitUserConfig* uc = &(*out_users)[idx];
                    
                    cJSON* id = cJSON_GetObjectItem(admin, "id");
                    if (cJSON_IsString(id)) uc->id = strdup(id->valuestring);
                    
                    cJSON* name = cJSON_GetObjectItem(admin, "name");
                    if (cJSON_IsString(name)) uc->name = strdup(name->valuestring);
                    
                    cJSON* role = cJSON_GetObjectItem(admin, "role");
                    if (cJSON_IsString(role)) {
                        uc->role = strdup(role->valuestring);
                    } else {
                        uc->role = strdup("admin");
                    }
                }

                // Parse members
                for (uint32_t i = 0; i < member_count; ++i, ++idx) {
                    cJSON* member = cJSON_GetArrayItem(members, (int)i);
                    if (!cJSON_IsObject(member)) continue;
                    
                    InitUserConfig* uc = &(*out_users)[idx];
                    
                    cJSON* id = cJSON_GetObjectItem(member, "id");
                    if (cJSON_IsString(id)) uc->id = strdup(id->valuestring);
                    
                    cJSON* name = cJSON_GetObjectItem(member, "name");
                    if (cJSON_IsString(name)) uc->name = strdup(name->valuestring);
                    
                    cJSON* role = cJSON_GetObjectItem(member, "role");
                    if (cJSON_IsString(role)) {
                        uc->role = strdup(role->valuestring);
                    } else {
                        uc->role = strdup("member");
                    }
                    
                    cJSON* age = cJSON_GetObjectItem(member, "age");
                    if (cJSON_IsNumber(age)) uc->age = (uint32_t)age->valueint;
                }
            }
        }
    }

    cJSON_Delete(root);
    return 0;
}

static void free_test_config(InitNetworkConfig* config, InitNodeConfig* nodes, InitUserConfig* users) {
    if (!config) return;

    free((void*)config->network_name);

    if (nodes) {
        for (uint32_t i = 0; i < config->node_count; ++i) {
            free(nodes[i].id);
            free(nodes[i].name);
            free(nodes[i].hostname);
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
        }
        free(users);
    }
}

static int clean_directory(const char* path) {
    DIR* dir = opendir(path);
    if (!dir) {
        return 1;
    }

    struct dirent* entry;
    char child[512];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        struct stat st;
        if (stat(child, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                clean_directory(child);
                rmdir(child);
            } else {
                unlink(child);
            }
        }
    }

    closedir(dir);
    return 1;
}

int test_init_environment(void) {
    printf("Initializing test environment...\n");

    // Clean existing test state
    clean_directory(TEST_BASE_PATH);

    // Parse full network config
    InitNetworkConfig config = {0};
    InitNodeConfig* nodes = NULL;
    InitUserConfig* users = NULL;

    if (parse_test_config(&config, &nodes, &users) != 0) {
        fprintf(stderr, "Failed to parse test config\n");
        return -1;
    }

    // Initialize network in test_state
    if (initialize_network(&config, TEST_BASE_PATH, NULL) != 0) {
        fprintf(stderr, "Failed to initialize test network\n");
        free_test_config(&config, nodes, users);
        return -1;
    }

    // After network initialization, also create user keys and database at network level
    // (these are created in node directories, but tests expect them at network level)
    
    // Create storage directory
    char storage_dir[512];
    snprintf(storage_dir, sizeof(storage_dir), "%s/storage", TEST_BASE_PATH);
    if (ensure_directory(storage_dir) != 0) {
        fprintf(stderr, "Warning: Failed to create storage directory\n");
    }
    
    // Create user keys at network level
    for (uint32_t i = 0; i < config.user_count; ++i) {
        const InitUserConfig* user = &users[i];
        if (user->id) {
            unsigned char pubkey[32];
            if (generate_user_keypair(user->id, TEST_BASE_PATH, pubkey) != 0) {
                fprintf(stderr, "Warning: Failed to create network-level key for user %s\n", user->id);
                // Non-fatal, continue
            }
        }
    }
    
    // Create database at network level (tests expect it here)
    char network_db_path[512];
    snprintf(network_db_path, sizeof(network_db_path), "%s/storage/tinyweb.db", TEST_BASE_PATH);
    if (db_init_gossip(network_db_path) == 0) {
        if (gossip_store_init() != 0) {
            fprintf(stderr, "Warning: Failed to initialize gossip store schema\n");
        }
        if (gossip_peers_init() != 0) {
            fprintf(stderr, "Warning: Failed to initialize gossip peers schema\n");
        }
        db_close();  // Close the network-level DB, tests will reopen it
    } else {
        fprintf(stderr, "Warning: Failed to create network-level database\n");
    }

    free_test_config(&config, nodes, users);

    // Set up static paths for tests
    snprintf(test_db_path, sizeof(test_db_path), "%s/storage/tinyweb.db", TEST_BASE_PATH);
    snprintf(test_keys_dir, sizeof(test_keys_dir), "%s/keys/users", TEST_BASE_PATH);

    printf("Test environment initialized in %s/\n", TEST_BASE_PATH);
    return 0;
}

void test_cleanup_environment(void) {
    clean_directory(TEST_BASE_PATH);
    printf("Test environment cleaned up\n");
}

const char* test_get_base_path(void) {
    return TEST_BASE_PATH;
}

const char* test_get_db_path(void) {
    return test_db_path;
}

const char* test_get_keys_dir(void) {
    return test_keys_dir;
}

const char* test_get_user_key_path(const char* user_id) {
    if (!user_id) {
        return NULL;
    }
    snprintf(test_user_key_path, sizeof(test_user_key_path), 
             "%s/%s.key", test_keys_dir, user_id);
    return test_user_key_path;
}

