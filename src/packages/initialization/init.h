#ifndef INIT_H
#define INIT_H

#include <stdint.h>
#include "packages/transactions/transaction.h"

#define MAX_NODES 100
#define MAX_USERS 100

typedef struct {
    char* id;
    char* name;
    char* type;
    char* hostname;
    uint16_t gossip_port;
    uint16_t api_port;
    char* tags;
    const char* const* peers;
    uint32_t peer_count;
    unsigned char public_key[PUBKEY_SIZE];
} InitNodeConfig;

typedef struct {
    char* id;
    char* name;
    char* role;
    uint32_t age;
    const char* const* supervised_by;
    uint32_t supervisor_count;
    unsigned char public_key[PUBKEY_SIZE];
    char public_key_hex[PUBKEY_SIZE * 2 + 1];
    char* key_path;
} InitUserRecord;

typedef struct {
    InitUserRecord* admins;
    uint32_t admin_count;
    InitUserRecord* members;
    uint32_t member_count;
} InitUsersConfig;

typedef struct {
    const char* network_name;
    const char* network_description;
    uint16_t base_port;
    uint32_t node_count;
    int debug_mode;
    InitNodeConfig* nodes;
    InitUsersConfig users;
} InitNetworkConfig;

int initialize_network(InitNetworkConfig* config);

#endif // INIT_H