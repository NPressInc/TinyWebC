#include <string.h>
#include <time.h>
#include <stddef.h> // For size_t
#include <stdint.h>
#include <stdio.h>
#include <openssl/sha.h>
#include "packages/keystore/keystore.h"
#include "packages/utils/byteorder.h"
#include "internalTransaction.h"

TW_InternalTransaction* tw_create_internal_transaction(TW_InternalTransactionType type, 
                                                      const unsigned char* sender,
                                                      uint32_t proposer_id,
                                                      uint32_t round_number)
{
    TW_InternalTransaction *txn = calloc(1, sizeof(TW_InternalTransaction));
    if (!txn) return NULL;

    txn->type = type;
    memcpy(txn->sender, sender, PUBKEY_SIZE);
    txn->timestamp = (uint64_t)time(NULL);
    txn->proposer_id = proposer_id;
    txn->round_number = round_number;
    txn->block_data = NULL;  // Initialize as NULL
    txn->payload_size = 0;
    
    // Initialize hashes to zero
    memset(txn->block_hash, 0, HASH_SIZE);
    memset(txn->chain_hash, 0, HASH_SIZE);
    memset(txn->signature, 0, SIGNATURE_SIZE);

    return txn;
}

void TW_Internal_Transaction_add_signature(TW_InternalTransaction *txn)
{
    if (!txn) return;

    unsigned char hash[HASH_SIZE];
    TW_InternalTransaction_hash(txn, hash);
    sign_message(hash, txn->signature);
}

size_t TW_InternalTransaction_serialize(TW_InternalTransaction *txn, unsigned char **buffer)
{
    if (!txn || !buffer) {
        if (buffer) *buffer = NULL;
        return 0;
    }

    // Calculate total size needed - FIXED: Use proper size calculation
    size_t base_size = sizeof(TW_InternalTransaction) - sizeof(TW_Block*); // Exclude pointer
    size_t block_size = 0;
    if (txn->block_data) {
        block_size = TW_Block_get_size(txn->block_data); // ✅ Use actual serialized size
        if (block_size == 0) {
            // Invalid block data
            if (buffer) *buffer = NULL;
            return 0;
        }
    }
    size_t total_size = base_size + block_size;

    *buffer = malloc(total_size);
    if (!*buffer) return 0;

    unsigned char* ptr = *buffer;
    
    // Serialize basic fields (excluding block_data pointer)
    memcpy(ptr, &txn->type, sizeof(txn->type)); ptr += sizeof(txn->type);
    memcpy(ptr, txn->sender, PUBKEY_SIZE); ptr += PUBKEY_SIZE;
    memcpy(ptr, &txn->timestamp, sizeof(txn->timestamp)); ptr += sizeof(txn->timestamp);
    memcpy(ptr, &txn->proposer_id, sizeof(txn->proposer_id)); ptr += sizeof(txn->proposer_id);
    memcpy(ptr, &txn->round_number, sizeof(txn->round_number)); ptr += sizeof(txn->round_number);
    
    memcpy(ptr, txn->block_hash, HASH_SIZE); ptr += HASH_SIZE;
    memcpy(ptr, txn->chain_hash, HASH_SIZE); ptr += HASH_SIZE;
    
    // Serialize block data if present - FIXED: Use proper serialization
    uint8_t has_block = txn->block_data ? 1 : 0;
    memcpy(ptr, &has_block, sizeof(has_block)); ptr += sizeof(has_block);
    if (txn->block_data) {
        // ✅ Use proper TW_Block_serialize instead of memcpy
        size_t serialized_size = TW_Block_serialize(txn->block_data, &ptr);
        if (serialized_size == 0) {
            // Serialization failed
            free(*buffer);
            *buffer = NULL;
            return 0;
        }
        // ptr is already advanced by TW_Block_serialize
    }
    
    // Serialize payload
    memcpy(ptr, &txn->payload, sizeof(txn->payload)); ptr += sizeof(txn->payload);
    memcpy(ptr, &txn->payload_size, sizeof(txn->payload_size)); ptr += sizeof(txn->payload_size);
    memcpy(ptr, txn->signature, SIGNATURE_SIZE); ptr += SIGNATURE_SIZE;

    return total_size;
}

TW_InternalTransaction *TW_InternalTransaction_deserialize(const unsigned char *buffer, size_t buffer_size)
{
    if (!buffer || buffer_size < sizeof(TW_InternalTransactionType))
        return NULL;

    TW_InternalTransaction *txn = calloc(1, sizeof(TW_InternalTransaction));
    if (!txn) return NULL;

    const unsigned char* ptr = buffer;
    
    // Deserialize basic fields
    memcpy(&txn->type, ptr, sizeof(txn->type)); ptr += sizeof(txn->type);
    memcpy(txn->sender, ptr, PUBKEY_SIZE); ptr += PUBKEY_SIZE;
    memcpy(&txn->timestamp, ptr, sizeof(txn->timestamp)); ptr += sizeof(txn->timestamp);
    memcpy(&txn->proposer_id, ptr, sizeof(txn->proposer_id)); ptr += sizeof(txn->proposer_id);
    memcpy(&txn->round_number, ptr, sizeof(txn->round_number)); ptr += sizeof(txn->round_number);
    
    memcpy(txn->block_hash, ptr, HASH_SIZE); ptr += HASH_SIZE;
    memcpy(txn->chain_hash, ptr, HASH_SIZE); ptr += HASH_SIZE;
    
    // Check if we have enough buffer left
    if (ptr - buffer + sizeof(uint8_t) > buffer_size) {
        free(txn);
        return NULL;
    }
    
    // Deserialize block data if present - FIXED: Use proper deserialization
    uint8_t has_block;
    memcpy(&has_block, ptr, sizeof(has_block)); ptr += sizeof(has_block);
    
    if (has_block) {
        // ✅ Use proper TW_Block_deserialize instead of memcpy
        size_t remaining_buffer = buffer_size - (ptr - buffer);
        txn->block_data = TW_Block_deserialize(ptr, remaining_buffer);
        if (!txn->block_data) {
            free(txn);
            return NULL;
        }
        
        // Calculate how much buffer was consumed by block deserialization
        size_t block_serialized_size = TW_Block_get_size(txn->block_data);
        if (block_serialized_size == 0 || ptr + block_serialized_size > buffer + buffer_size) {
            TW_Block_destroy(txn->block_data);
            free(txn);
            return NULL;
        }
        ptr += block_serialized_size;
    } else {
        txn->block_data = NULL;
    }
    
    // Check remaining buffer size for payload and signature
    if (ptr - buffer + sizeof(txn->payload) + sizeof(txn->payload_size) + SIGNATURE_SIZE > buffer_size) {
        if (txn->block_data) TW_Block_destroy(txn->block_data);
        free(txn);
        return NULL;
    }
    
    // Deserialize payload
    memcpy(&txn->payload, ptr, sizeof(txn->payload)); ptr += sizeof(txn->payload);
    memcpy(&txn->payload_size, ptr, sizeof(txn->payload_size)); ptr += sizeof(txn->payload_size);
    memcpy(txn->signature, ptr, SIGNATURE_SIZE); ptr += SIGNATURE_SIZE;

    return txn;
}

void tw_destroy_internal_transaction(TW_InternalTransaction *txn)
{
    if (!txn) return;
    
    // Free block data if it was allocated - FIXED: Use proper destructor
    if (txn->block_data) {
        TW_Block_destroy(txn->block_data); // ✅ Use proper destructor
    }
    
    free(txn);
}

void TW_InternalTransaction_hash(TW_InternalTransaction *txn, unsigned char *hash_out)
{
    if (!txn || !hash_out)
        return;

    // Calculate required buffer size dynamically
    size_t base_size = sizeof(txn->type) + PUBKEY_SIZE + sizeof(txn->timestamp) + 
                      sizeof(txn->proposer_id) + sizeof(txn->round_number) + 
                      HASH_SIZE + HASH_SIZE + sizeof(uint8_t); // has_block flag
    
    size_t block_size = 0;
    if (txn->block_data) {
        block_size = TW_Block_get_size(txn->block_data);
        if (block_size == 0) {
            memset(hash_out, 0, HASH_SIZE);
            return;
        }
    }
    
    size_t payload_size = (txn->payload_size > 0) ? txn->payload_size : sizeof(txn->payload);
    size_t total_size = base_size + block_size + payload_size + sizeof(txn->payload_size);
    
    unsigned char* buffer = malloc(total_size);
    if (!buffer) {
        memset(hash_out, 0, HASH_SIZE);
        return;
    }
    
    size_t offset = 0;

    // Hash all fields except signature
    memcpy(buffer + offset, &txn->type, sizeof(txn->type));
    offset += sizeof(txn->type);
    memcpy(buffer + offset, txn->sender, PUBKEY_SIZE);
    offset += PUBKEY_SIZE;
    memcpy(buffer + offset, &txn->timestamp, sizeof(txn->timestamp));
    offset += sizeof(txn->timestamp);
    memcpy(buffer + offset, &txn->proposer_id, sizeof(txn->proposer_id));
    offset += sizeof(txn->proposer_id);
    memcpy(buffer + offset, &txn->round_number, sizeof(txn->round_number));
    offset += sizeof(txn->round_number);
    
    memcpy(buffer + offset, txn->block_hash, HASH_SIZE);
    offset += HASH_SIZE;
    memcpy(buffer + offset, txn->chain_hash, HASH_SIZE);
    offset += HASH_SIZE;
    
    // Include block data if present - FIXED: Use proper serialization
    uint8_t has_block = txn->block_data ? 1 : 0;
    memcpy(buffer + offset, &has_block, sizeof(has_block));
    offset += sizeof(has_block);
    if (txn->block_data) {
        // ✅ Use proper serialization for hashing
        unsigned char* block_ptr = buffer + offset;
        size_t serialized_size = TW_Block_serialize(txn->block_data, &block_ptr);
        if (serialized_size == 0) {
            free(buffer);
            memset(hash_out, 0, HASH_SIZE);
            return;
        }
        offset += serialized_size;
    }
    
    // Include payload data
    memcpy(buffer + offset, &txn->payload, payload_size);
    offset += payload_size;
    memcpy(buffer + offset, &txn->payload_size, sizeof(txn->payload_size));
    offset += sizeof(txn->payload_size);

    // Compute the hash
    SHA256(buffer, offset, hash_out);
    free(buffer);
}

// New signature verification function
int TW_InternalTransaction_verify_signature(TW_InternalTransaction* txn)
{
    if (!txn) return 0;
    
    unsigned char hash[HASH_SIZE];
    TW_InternalTransaction_hash(txn, hash);
    
    // Use existing verification function from signing module
    // verify_signature(signature, message, message_len, public_key)
    return verify_signature(txn->signature, hash, HASH_SIZE, txn->sender) == 0 ? 1 : 0;
}

// PBFT-specific helper functions
TW_InternalTransaction* tw_create_block_proposal(const unsigned char* sender, uint32_t proposer_id, 
                                                uint32_t round_number, TW_Block* block, 
                                                const unsigned char* block_hash)
{
    TW_InternalTransaction* txn = tw_create_internal_transaction(TW_INT_TXN_PROPOSE_BLOCK, sender, proposer_id, round_number);
    if (!txn) return NULL;
    
    if (block_hash) {
        memcpy(txn->block_hash, block_hash, HASH_SIZE);
    }
    
    if (block) {
        txn->block_data = malloc(sizeof(TW_Block));
        if (!txn->block_data) {
            tw_destroy_internal_transaction(txn);
            return NULL;
        }
        memcpy(txn->block_data, block, sizeof(TW_Block));
    }
    
    // Auto-sign the transaction
    TW_Internal_Transaction_add_signature(txn);
    return txn;
}

TW_InternalTransaction* tw_create_vote_message(const unsigned char* sender, uint32_t proposer_id,
                                              uint32_t round_number, const unsigned char* block_hash,
                                              uint8_t vote_phase)
{
    TW_InternalTransactionType type;
    switch (vote_phase) {
        case 1: type = TW_INT_TXN_VOTE_VERIFY; break;
        case 2: type = TW_INT_TXN_VOTE_COMMIT; break;
        case 3: type = TW_INT_TXN_VOTE_NEW_ROUND; break;
        default: return NULL;
    }
    
    TW_InternalTransaction* txn = tw_create_internal_transaction(type, sender, proposer_id, round_number);
    if (!txn) return NULL;
    
    if (block_hash) {
        memcpy(txn->block_hash, block_hash, HASH_SIZE);
    }
    
    // Set up vote payload
    txn->payload.vote.round_number = round_number;
    txn->payload.vote.vote_phase = vote_phase;
    if (block_hash) {
        memcpy(txn->payload.vote.block_hash, block_hash, HASH_SIZE);
    }
    txn->payload_size = sizeof(TW_VotePayload);
    
    TW_Internal_Transaction_add_signature(txn);
    return txn;
}

TW_InternalTransaction* tw_create_sync_request(const unsigned char* sender, 
                                              const unsigned char* last_known_hash,
                                              uint32_t last_known_height,
                                              uint32_t max_blocks_requested)
{
    TW_InternalTransaction* txn = tw_create_internal_transaction(TW_INT_TXN_RESYNC_CHAIN, sender, 0, 0);
    if (!txn) return NULL;
    
    // Set up sync request payload
    if (last_known_hash) {
        memcpy(txn->payload.sync_request.last_known_hash, last_known_hash, HASH_SIZE);
    }
    txn->payload.sync_request.last_known_height = last_known_height;
    txn->payload.sync_request.max_blocks_requested = max_blocks_requested;
    txn->payload_size = sizeof(TW_SyncRequestPayload);
    
    TW_Internal_Transaction_add_signature(txn);
    return txn;
}

TW_InternalTransaction* tw_create_node_status(const unsigned char* sender, uint32_t chain_length,
                                             const unsigned char* last_block_hash,
                                             uint64_t node_uptime, uint8_t peer_count)
{
    TW_InternalTransaction* txn = tw_create_internal_transaction(TW_INT_TXN_NODE_STATUS, sender, 0, 0);
    if (!txn) return NULL;
    
    // Set up node status payload
    txn->payload.node_status.chain_length = chain_length;
    if (last_block_hash) {
        memcpy(txn->payload.node_status.last_block_hash, last_block_hash, HASH_SIZE);
    }
    txn->payload.node_status.node_uptime = node_uptime;
    txn->payload.node_status.peer_count = peer_count;
    txn->payload_size = sizeof(TW_NodeStatusPayload);
    
    TW_Internal_Transaction_add_signature(txn);
    return txn;
}

TW_InternalTransaction* tw_create_peer_discovery(const unsigned char* sender, const char* peer_ip,
                                                uint16_t peer_port, const unsigned char* peer_pubkey,
                                                uint32_t peer_id)
{
    TW_InternalTransaction* txn = tw_create_internal_transaction(TW_INT_TXN_PEER_DISCOVERY, sender, 0, 0);
    if (!txn) return NULL;
    
    // Set up peer discovery payload
    if (peer_ip) {
        strncpy(txn->payload.peer_discovery.peer_ip, peer_ip, sizeof(txn->payload.peer_discovery.peer_ip) - 1);
        txn->payload.peer_discovery.peer_ip[sizeof(txn->payload.peer_discovery.peer_ip) - 1] = '\0';
    }
    txn->payload.peer_discovery.peer_port = peer_port;
    if (peer_pubkey) {
        memcpy(txn->payload.peer_discovery.peer_pubkey, peer_pubkey, PUBKEY_SIZE);
    }
    txn->payload.peer_discovery.peer_id = peer_id;
    txn->payload_size = sizeof(TW_PeerDiscoveryPayload);
    
    TW_Internal_Transaction_add_signature(txn);
    return txn;
}

// HTTP Integration Functions for PBFT API
int tw_internal_transaction_to_http_binary(TW_InternalTransaction* txn, unsigned char** http_data, size_t* data_size)
{
    if (!txn || !http_data || !data_size) return 0;
    
    // Use existing serialization function
    *data_size = TW_InternalTransaction_serialize(txn, http_data);
    return (*data_size > 0) ? 1 : 0;
}

TW_InternalTransaction* tw_internal_transaction_from_http_binary(const unsigned char* http_data, size_t data_size)
{
    if (!http_data || data_size == 0) return NULL;
    
    // Use existing deserialization function
    return TW_InternalTransaction_deserialize(http_data, data_size);
}

// Utility Functions
const char* tw_internal_transaction_type_to_string(TW_InternalTransactionType type)
{
    switch (type) {
        case TW_INT_TXN_PROPOSE_BLOCK: return "PROPOSE_BLOCK";
        case TW_INT_TXN_VOTE_VERIFY: return "VOTE_VERIFY";
        case TW_INT_TXN_VOTE_COMMIT: return "VOTE_COMMIT";
        case TW_INT_TXN_VOTE_NEW_ROUND: return "VOTE_NEW_ROUND";
        case TW_INT_TXN_GET_LAST_HASH: return "GET_LAST_HASH";
        case TW_INT_TXN_RESYNC_CHAIN: return "RESYNC_CHAIN";
        case TW_INT_TXN_GET_PENDING_TXNS: return "GET_PENDING_TXNS";
        case TW_INT_TXN_GET_CHAIN_LENGTH: return "GET_CHAIN_LENGTH";
        case TW_INT_TXN_REQ_MISSING_BLOCKS: return "REQ_MISSING_BLOCKS";
        case TW_INT_TXN_REQ_FULL_CHAIN: return "REQ_FULL_CHAIN";
        case TW_INT_TXN_BROADCAST_BLOCK: return "BROADCAST_BLOCK";
        case TW_INT_TXN_BROADCAST_CHAIN: return "BROADCAST_CHAIN";
        case TW_INT_TXN_REBROADCAST_MSG: return "REBROADCAST_MSG";
        case TW_INT_TXN_HEARTBEAT: return "HEARTBEAT";
        case TW_INT_TXN_PEER_DISCOVERY: return "PEER_DISCOVERY";
        case TW_INT_TXN_NODE_STATUS: return "NODE_STATUS";
        case TW_INT_TXN_CREATE_BLOCK_SINGULAR: return "CREATE_BLOCK_SINGULAR";
        case TW_INT_MISC: return "MISC";
        default: return "UNKNOWN";
    }
}

int tw_internal_transaction_validate(TW_InternalTransaction* txn)
{
    if (!txn) return 0;
    
    // Basic validation checks
    if (txn->type < TW_INT_TXN_PROPOSE_BLOCK || txn->type > TW_INT_MISC) return 0;
    if (txn->timestamp == 0) return 0;
    if (txn->payload_size > MAX_PAYLOAD_SIZE_INTERNAL) return 0;
    
    // Verify signature
    if (!TW_InternalTransaction_verify_signature(txn)) return 0;
    
    return 1;
}

void tw_internal_transaction_print_debug(TW_InternalTransaction* txn)
{
    if (!txn) {
        printf("TW_InternalTransaction: NULL\n");
        return;
    }
    
    printf("=== TW_InternalTransaction Debug ===\n");
    printf("Type: %s (%d)\n", tw_internal_transaction_type_to_string(txn->type), txn->type);
    printf("Proposer ID: %u\n", txn->proposer_id);
    printf("Round Number: %u\n", txn->round_number);
    printf("Timestamp: %lu\n", txn->timestamp);
    printf("Payload Size: %zu\n", txn->payload_size);
    printf("Has Block Data: %s\n", txn->block_data ? "Yes" : "No");
    
    // Print sender public key (first 8 bytes)
    printf("Sender (first 8 bytes): ");
    for (int i = 0; i < 8 && i < PUBKEY_SIZE; i++) {
        printf("%02x", txn->sender[i]);
    }
    printf("\n");
    
    // Print block hash (first 8 bytes)
    printf("Block Hash (first 8 bytes): ");
    for (int i = 0; i < 8 && i < HASH_SIZE; i++) {
        printf("%02x", txn->block_hash[i]);
    }
    printf("\n");
    
    printf("==================================\n");
}