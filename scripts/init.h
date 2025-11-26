#ifndef INIT_H
#define INIT_H

#include <stdint.h>
#include <sqlite3.h>

#define MAX_NODES 100
#define MAX_USERS 100
#define MAX_PEERS 100
#define PUBKEY_SIZE 32  // Ed25519 public key size

// Node configuration from JSON
typedef struct {
    char* id;
    char* name;
    char* hostname;
    uint16_t gossip_port;
    uint16_t api_port;
    char* tags;
    char** peers;
    uint32_t peer_count;
} InitNodeConfig;

// User configuration from JSON
typedef struct {
    char* id;
    char* name;
    char* role;
    uint32_t age;
    char** supervised_by;
    uint32_t supervisor_count;
} InitUserConfig;

// Network configuration
typedef struct {
    const char* network_name;
    const char* network_description;
    uint16_t base_port;
    InitNodeConfig* nodes;
    uint32_t node_count;
    InitUserConfig* users;
    uint32_t user_count;
} InitNetworkConfig;

// Initialize network with all nodes and users
// base_path: "state" (each container/node has isolated state directory)
// original_config_path: Path to the original network_config.json file (can be NULL)
int initialize_network(const InitNetworkConfig* config, const char* base_path, const char* original_config_path);

// Initialize a single node
int initialize_node(const InitNodeConfig* node, 
                   const InitUserConfig* users, 
                   uint32_t user_count, 
                   const char* base_path);

// Generate or load keypair for a user
// Returns 0 on success, stores public key in out_pubkey (32 bytes)
int generate_user_keypair(const char* user_id, 
                         const char* base_path, 
                         unsigned char* out_pubkey);

// Seed database with initial data (for testing)
// Requires schema tables to already exist
int seed_basic_roles(sqlite3* db);
int seed_basic_permissions(sqlite3* db);
int seed_role_permissions(sqlite3* db);

// Save network config to node's directory
// original_config_path: Path to the original network_config.json file
int init_save_node_config(const char* original_config_path, const InitNetworkConfig* network_config, const InitNodeConfig* node, const char* node_path);

#endif // INIT_H
