#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <cjson/cJSON.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "init.h"

// Extended configuration structure for JSON-based initialization
typedef struct {
    // Network settings
    char* network_name;
    char* network_description;
    uint16_t base_port;
    uint32_t max_connections;
    
    // Storage settings
    char* keystore_path;
    char* blockchain_path;
    char* passphrase;
    
    // Node information
    uint32_t node_count;
    struct {
        char* id;
        char* name;
        char* type;
        char* ip;
        uint16_t port;
        int is_validator;
    } nodes[MAX_NODES];
    
    // User information
    uint32_t admin_count;
    uint32_t member_count;
    struct {
        char* id;
        char* name;
        char* role;
        char* email;  // optional
    } admins[MAX_USERS];
    struct {
        char* id;
        char* name;
        char* role;
        uint32_t age;
        char* email;  // optional
        char* supervised_by[MAX_USERS];
        uint32_t supervisor_count;
    } members[MAX_USERS];
} JsonConfig;

void print_usage(const char* program_name) {
    printf("Usage: %s [options] <config_file>\n", program_name);
    printf("Initialize a TinyWeb blockchain network from JSON configuration\n\n");
    printf("Arguments:\n");
    printf("  config_file         Path to JSON configuration file\n\n");
    printf("Options:\n");
    printf("  -h, --help          Show this help message\n");
    printf("  -v, --verbose       Enable verbose output\n");
    printf("\nExample:\n");
    printf("  %s src/packages/initialization/configs/network_config.json\n", program_name);
}

int parse_json_config(const char* config_file, JsonConfig* config) {
    FILE* file = fopen(config_file, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open config file '%s'\n", config_file);
        return -1;
    }

    // Read file content
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char* json_string = malloc(file_size + 1);
    if (!json_string) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        return -1;
    }
    
    fread(json_string, 1, file_size, file);
    json_string[file_size] = '\0';
    fclose(file);

    // Parse JSON
    cJSON* json = cJSON_Parse(json_string);
    free(json_string);
    
    if (!json) {
        fprintf(stderr, "Error: Invalid JSON in config file\n");
        return -1;
    }

    // Parse network section
    cJSON* network = cJSON_GetObjectItem(json, "network");
    if (network) {
        cJSON* name = cJSON_GetObjectItem(network, "name");
        if (name && cJSON_IsString(name)) {
            config->network_name = strdup(name->valuestring);
        }
        
        cJSON* description = cJSON_GetObjectItem(network, "description");
        if (description && cJSON_IsString(description)) {
            config->network_description = strdup(description->valuestring);
        }
        
        cJSON* base_port = cJSON_GetObjectItem(network, "base_port");
        if (base_port && cJSON_IsNumber(base_port)) {
            config->base_port = (uint16_t)base_port->valueint;
        }
        
        cJSON* max_connections = cJSON_GetObjectItem(network, "max_connections");
        if (max_connections && cJSON_IsNumber(max_connections)) {
            config->max_connections = (uint32_t)max_connections->valueint;
        }
    }

    // Parse storage section
    cJSON* storage = cJSON_GetObjectItem(json, "storage");
    if (storage) {
        cJSON* keystore_path = cJSON_GetObjectItem(storage, "keystore_path");
        if (keystore_path && cJSON_IsString(keystore_path)) {
            config->keystore_path = strdup(keystore_path->valuestring);
        }
        
        cJSON* blockchain_path = cJSON_GetObjectItem(storage, "blockchain_path");
        if (blockchain_path && cJSON_IsString(blockchain_path)) {
            config->blockchain_path = strdup(blockchain_path->valuestring);
        }
        
        cJSON* passphrase = cJSON_GetObjectItem(storage, "passphrase");
        if (passphrase && cJSON_IsString(passphrase)) {
            config->passphrase = strdup(passphrase->valuestring);
        }
    }

    // Parse nodes section
    cJSON* nodes = cJSON_GetObjectItem(json, "nodes");
    if (nodes && cJSON_IsArray(nodes)) {
        config->node_count = cJSON_GetArraySize(nodes);
        if (config->node_count > MAX_NODES) {
            config->node_count = MAX_NODES;
        }
        
        for (int i = 0; i < config->node_count; i++) {
            cJSON* node = cJSON_GetArrayItem(nodes, i);
            if (node) {
                cJSON* id = cJSON_GetObjectItem(node, "id");
                if (id && cJSON_IsString(id)) {
                    config->nodes[i].id = strdup(id->valuestring);
                }
                
                cJSON* name = cJSON_GetObjectItem(node, "name");
                if (name && cJSON_IsString(name)) {
                    config->nodes[i].name = strdup(name->valuestring);
                }
                
                cJSON* type = cJSON_GetObjectItem(node, "type");
                if (type && cJSON_IsString(type)) {
                    config->nodes[i].type = strdup(type->valuestring);
                }
                
                cJSON* ip = cJSON_GetObjectItem(node, "ip");
                if (ip && cJSON_IsString(ip)) {
                    config->nodes[i].ip = strdup(ip->valuestring);
                }
                
                cJSON* port = cJSON_GetObjectItem(node, "port");
                if (port && cJSON_IsNumber(port)) {
                    config->nodes[i].port = (uint16_t)port->valueint;
                }
                
                cJSON* is_validator = cJSON_GetObjectItem(node, "is_validator");
                if (is_validator && cJSON_IsBool(is_validator)) {
                    config->nodes[i].is_validator = cJSON_IsTrue(is_validator);
                }
            }
        }
    }

    // Parse users section
    cJSON* users = cJSON_GetObjectItem(json, "users");
    if (users) {
        // Parse admins
        cJSON* admins = cJSON_GetObjectItem(users, "admins");
        if (admins && cJSON_IsArray(admins)) {
            config->admin_count = cJSON_GetArraySize(admins);
            if (config->admin_count > MAX_USERS) {
                config->admin_count = MAX_USERS;
            }
            
            for (int i = 0; i < config->admin_count; i++) {
                cJSON* admin = cJSON_GetArrayItem(admins, i);
                if (admin) {
                    cJSON* id = cJSON_GetObjectItem(admin, "id");
                    if (id && cJSON_IsString(id)) {
                        config->admins[i].id = strdup(id->valuestring);
                    }
                    
                    cJSON* name = cJSON_GetObjectItem(admin, "name");
                    if (name && cJSON_IsString(name)) {
                        config->admins[i].name = strdup(name->valuestring);
                    }
                    
                    cJSON* role = cJSON_GetObjectItem(admin, "role");
                    if (role && cJSON_IsString(role)) {
                        config->admins[i].role = strdup(role->valuestring);
                    }
                    
                    cJSON* email = cJSON_GetObjectItem(admin, "email");
                    if (email && cJSON_IsString(email)) {
                        config->admins[i].email = strdup(email->valuestring);
                    }
                }
            }
        }
        
        // Parse members
        cJSON* members = cJSON_GetObjectItem(users, "members");
        if (members && cJSON_IsArray(members)) {
            config->member_count = cJSON_GetArraySize(members);
            if (config->member_count > MAX_USERS) {
                config->member_count = MAX_USERS;
            }
            
            for (int i = 0; i < config->member_count; i++) {
                cJSON* member = cJSON_GetArrayItem(members, i);
                if (member) {
                    cJSON* id = cJSON_GetObjectItem(member, "id");
                    if (id && cJSON_IsString(id)) {
                        config->members[i].id = strdup(id->valuestring);
                    }
                    
                    cJSON* name = cJSON_GetObjectItem(member, "name");
                    if (name && cJSON_IsString(name)) {
                        config->members[i].name = strdup(name->valuestring);
                    }
                    
                    cJSON* role = cJSON_GetObjectItem(member, "role");
                    if (role && cJSON_IsString(role)) {
                        config->members[i].role = strdup(role->valuestring);
                    }
                    
                    cJSON* age = cJSON_GetObjectItem(member, "age");
                    if (age && cJSON_IsNumber(age)) {
                        config->members[i].age = (uint32_t)age->valueint;
                    }
                    
                    cJSON* email = cJSON_GetObjectItem(member, "email");
                    if (email && cJSON_IsString(email)) {
                        config->members[i].email = strdup(email->valuestring);
                    }
                    
                    cJSON* supervised_by = cJSON_GetObjectItem(member, "supervised_by");
                    if (supervised_by && cJSON_IsArray(supervised_by)) {
                        config->members[i].supervisor_count = cJSON_GetArraySize(supervised_by);
                        if (config->members[i].supervisor_count > MAX_USERS) {
                            config->members[i].supervisor_count = MAX_USERS;
                        }
                        
                        for (int j = 0; j < config->members[i].supervisor_count; j++) {
                            cJSON* supervisor = cJSON_GetArrayItem(supervised_by, j);
                            if (supervisor && cJSON_IsString(supervisor)) {
                                config->members[i].supervised_by[j] = strdup(supervisor->valuestring);
                            }
                        }
                    }
                }
            }
        }
    }

    cJSON_Delete(json);
    return 0;
}

void free_json_config(JsonConfig* config) {
    if (!config) return;
    
    free(config->network_name);
    free(config->network_description);
    free(config->keystore_path);
    free(config->blockchain_path);
    free(config->passphrase);
    
    for (int i = 0; i < config->node_count; i++) {
        free(config->nodes[i].id);
        free(config->nodes[i].name);
        free(config->nodes[i].type);
        free(config->nodes[i].ip);
    }
    
    for (int i = 0; i < config->admin_count; i++) {
        free(config->admins[i].id);
        free(config->admins[i].name);
        free(config->admins[i].role);
        free(config->admins[i].email);
    }
    
    for (int i = 0; i < config->member_count; i++) {
        free(config->members[i].id);
        free(config->members[i].name);
        free(config->members[i].role);
        free(config->members[i].email);
        for (int j = 0; j < config->members[i].supervisor_count; j++) {
            free(config->members[i].supervised_by[j]);
        }
    }
}

/**
 * Check if a directory exists and contains files
 */
int directory_has_files(const char* path) {
    DIR* dir = opendir(path);
    if (dir == NULL) {
        return 0; // Directory doesn't exist
    }
    
    struct dirent* entry;
    int has_files = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and .. entries
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            has_files = 1;
            break;
        }
    }
    
    closedir(dir);
    return has_files;
}

/**
 * Prompt user for yes/no confirmation
 */
int prompt_user_confirmation(const char* message) {
    char response[16];
    
    printf("%s (y/N): ", message);
    fflush(stdout);
    
    if (fgets(response, sizeof(response), stdin) == NULL) {
        return 0; // Default to no on input error
    }
    
    // Check if user responded with 'y' or 'Y'
    if (response[0] == 'y' || response[0] == 'Y') {
        return 1;
    }
    
    return 0;
}

/**
 * Remove all files in a directory
 */
int clean_directory(const char* path) {
    DIR* dir = opendir(path);
    if (dir == NULL) {
        return 0; // Directory doesn't exist, nothing to clean
    }
    
    struct dirent* entry;
    char filepath[512];
    int success = 1;
    
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and .. entries
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);
            
            struct stat statbuf;
            if (stat(filepath, &statbuf) == 0) {
                if (S_ISREG(statbuf.st_mode)) {
                    // Regular file - delete it
                    if (unlink(filepath) != 0) {
                        fprintf(stderr, "Warning: Failed to delete file %s\n", filepath);
                        success = 0;
                    }
                } else if (S_ISDIR(statbuf.st_mode)) {
                    // Directory - recursively clean and remove it
                    if (clean_directory(filepath) && rmdir(filepath) != 0) {
                        fprintf(stderr, "Warning: Failed to remove directory %s\n", filepath);
                        success = 0;
                    }
                }
            }
        }
    }
    
    closedir(dir);
    return success;
}

/**
 * Check for existing state and prompt user for cleanup
 */
int check_and_clean_existing_state(const char* keystore_path, const char* blockchain_path) {
    int keystore_has_files = directory_has_files(keystore_path);
    int blockchain_has_files = directory_has_files(blockchain_path);
    
    if (!keystore_has_files && !blockchain_has_files) {
        return 0; // No existing state found
    }
    
    printf("\nExisting blockchain state detected:\n");
    if (keystore_has_files) {
        printf("  - Keystore directory (%s) contains files\n", keystore_path);
    }
    if (blockchain_has_files) {
        printf("  - Blockchain directory (%s) contains files\n", blockchain_path);
    }
    
    printf("\nProceeding with initialization will overwrite existing data.\n");
    
    if (!prompt_user_confirmation("Do you want to delete the existing blockchain state and continue?")) {
        printf("Initialization cancelled by user.\n");
        return -1;
    }
    
    printf("\nCleaning existing state...\n");
    
    int success = 1;
    if (keystore_has_files) {
        printf("  - Cleaning keystore directory...\n");
        if (!clean_directory(keystore_path)) {
            success = 0;
        }
    }
    
    if (blockchain_has_files) {
        printf("  - Cleaning blockchain directory...\n");
        if (!clean_directory(blockchain_path)) {
            success = 0;
        }
    }
    
    if (!success) {
        fprintf(stderr, "Warning: Some files could not be removed. Initialization may fail.\n");
    } else {
        printf("Existing state cleaned successfully.\n");
    }
    
    return 0;
}

int main(int argc, char* argv[]) {
    int verbose = 0;
    const char* config_file = NULL;

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"verbose", no_argument, 0, 'v'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "hv", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                verbose = 1;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Check for config file argument
    if (optind >= argc) {
        fprintf(stderr, "Error: Missing configuration file argument\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    config_file = argv[optind];

    // Parse JSON configuration
    JsonConfig json_config = {0};
    if (parse_json_config(config_file, &json_config) != 0) {
        fprintf(stderr, "Error: Failed to parse configuration file\n");
        return 1;
    }

    if (verbose) {
        printf("Parsed configuration from: %s\n", config_file);
        printf("Network: %s\n", json_config.network_name ? json_config.network_name : "Unknown");
        printf("Nodes: %u\n", json_config.node_count);
        printf("Admins: %u\n", json_config.admin_count);
        printf("Members: %u\n", json_config.member_count);
        printf("\n");
    }

    // Convert to InitConfig for compatibility with existing initialize_network function
    InitConfig config = {
        .keystore_path = json_config.keystore_path ? json_config.keystore_path : "state/keys/",
        .blockchain_path = json_config.blockchain_path ? json_config.blockchain_path : "state/blockchain/",
        .passphrase = json_config.passphrase ? json_config.passphrase : "testpass",
        .base_port = json_config.base_port ? json_config.base_port : BASE_PORT,
        .node_count = json_config.node_count,
        .user_count = json_config.admin_count + json_config.member_count
    };

    printf("Initializing '%s' network...\n", json_config.network_name ? json_config.network_name : "TinyWeb");
    if (json_config.network_description) {
        printf("Description: %s\n", json_config.network_description);
    }
    printf("Configuration:\n");
    printf("  Nodes: %u\n", config.node_count);
    printf("  Users: %u (%u admins, %u members)\n", config.user_count, json_config.admin_count, json_config.member_count);
    printf("  Keystore: %s\n", config.keystore_path);
    printf("  Blockchain: %s\n", config.blockchain_path);
    printf("  Base Port: %u\n", config.base_port);
    printf("\n");
    
    // Check for existing state and prompt user for cleanup
    int cleanup_result = check_and_clean_existing_state(config.keystore_path, config.blockchain_path);
    if (cleanup_result != 0) {
        free_json_config(&json_config);
        return cleanup_result == -1 ? 0 : 1; // Return 0 if user cancelled, 1 if cleanup failed
    }

    int result = initialize_network(&config);
    if (result != 0) {
        fprintf(stderr, "Error: Network initialization failed\n");
        free_json_config(&json_config);
        return 1;
    }

    printf("Network initialization completed successfully!\n");
    printf("Network '%s' is ready for use.\n", json_config.network_name ? json_config.network_name : "TinyWeb");
    
    free_json_config(&json_config);
    return 0;
} 