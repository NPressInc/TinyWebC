#ifndef INIT_H
#define INIT_H

#include <stdint.h>
#include "packages/keystore/keystore.h"
#include "packages/structures/blockChain/blockchain.h"

// Constants
#define BASE_PORT 8000
#define MAX_NODES 100
#define MAX_USERS 100

// Structure to hold initialization configuration
typedef struct {
    char* keystore_path;
    char* blockchain_path;
    char* database_path;       // Optional: if NULL, defaults to blockchain_path/blockchain.db
    char* passphrase;
    uint16_t base_port;
    uint32_t node_count;
    uint32_t user_count;
} InitConfig;

// Structure to hold generated keys
typedef struct {
    unsigned char** node_private_keys;  // Dynamically allocated
    unsigned char** node_public_keys;   // Dynamically allocated
    unsigned char** user_private_keys;  // Dynamically allocated
    unsigned char** user_public_keys;   // Dynamically allocated
    uint32_t node_count;
    uint32_t user_count;
} GeneratedKeys;

// Structure to hold peer information
typedef struct {
    char ip_port[50];  // IP:port format
    unsigned char public_key[PUBKEY_SIZE];
    uint32_t id;
    int is_delinquent;
    time_t last_seen;
} PeerInfo;

// Main initialization function
int initialize_network(const InitConfig* config);

// Key generation functions
int generate_initial_keys(GeneratedKeys* keys, const InitConfig* config);
int save_keys_to_keystore(const GeneratedKeys* keys, const char* keystore_path, const char* passphrase);

// Peer configuration functions
int generate_peer_list(PeerInfo* peers, const GeneratedKeys* keys, uint16_t base_port);
// Initialization block creation
int create_initialization_block(const GeneratedKeys* keys, const PeerInfo* peers, TW_BlockChain* blockchain, const InitConfig* config);

// Transaction creation functions
TW_Transaction* create_user_registration_transaction(const GeneratedKeys* keys, uint32_t user_index, const unsigned char* creator_pubkey);
TW_Transaction* create_role_assignment_transaction(const GeneratedKeys* keys, uint32_t user_index, const unsigned char* creator_pubkey);
TW_Transaction* create_peer_registration_transaction(const PeerInfo* peers, uint32_t peer_index, const unsigned char* creator_pubkey, const GeneratedKeys* keys);
TW_Transaction* create_system_config_transaction(const unsigned char* creator_pubkey, const GeneratedKeys* keys);
TW_Transaction* create_content_filter_transaction(const unsigned char* creator_pubkey, const GeneratedKeys* keys);

// Helper functions
unsigned char* create_all_recipients_flat(const GeneratedKeys* keys, uint32_t* total_count);
unsigned char** create_all_recipients_list(const GeneratedKeys* keys, uint32_t* total_count);
int create_genesis_block(TW_BlockChain* blockchain);

// Memory management
void free_generated_keys(GeneratedKeys* keys);

#endif // INIT_H 