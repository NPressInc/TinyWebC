#ifndef BLOCK_VALIDATION_H
#define BLOCK_VALIDATION_H

#include <stdint.h>
#include <stdbool.h>
#include "packages/structures/blockChain/block.h"
#include "packages/structures/blockChain/blockchain.h"
#include "packages/structures/blockChain/transaction.h"

// Validation error codes
typedef enum {
    VALIDATION_SUCCESS = 0,
    VALIDATION_ERROR_NULL_POINTER = -1,
    VALIDATION_ERROR_INVALID_INDEX = -2,
    VALIDATION_ERROR_INVALID_HASH = -3,
    VALIDATION_ERROR_INVALID_TIMESTAMP = -4,
    VALIDATION_ERROR_INVALID_MERKLE_ROOT = -5,
    VALIDATION_ERROR_INVALID_TRANSACTION = -6,
    VALIDATION_ERROR_INVALID_SIGNATURE = -7,
    VALIDATION_ERROR_INVALID_PROPOSER = -8,
    VALIDATION_ERROR_DUPLICATE_TRANSACTION = -9,
    VALIDATION_ERROR_INSUFFICIENT_TRANSACTIONS = -10,
    VALIDATION_ERROR_TOO_MANY_TRANSACTIONS = -11,
    VALIDATION_ERROR_INVALID_TRANSACTION_TYPE = -12,
    VALIDATION_ERROR_INVALID_RECIPIENT = -13,
    VALIDATION_ERROR_INVALID_PAYLOAD = -14,
    VALIDATION_ERROR_CHAIN_INTEGRITY = -15
} ValidationResult;

// Validation configuration
typedef struct {
    uint32_t max_transactions_per_block;
    uint32_t min_transactions_per_block;
    uint64_t max_timestamp_drift;  // Maximum allowed timestamp drift in seconds
    bool strict_ordering;          // Enforce strict timestamp ordering
    bool validate_signatures;      // Whether to validate transaction signatures
    bool validate_merkle_tree;     // Whether to validate merkle tree
} ValidationConfig;

// Block validation functions
ValidationResult validate_block(const TW_Block* block, const TW_BlockChain* blockchain, const ValidationConfig* config);
ValidationResult validate_block_header(const TW_Block* block, const TW_Block* previous_block, const ValidationConfig* config);
ValidationResult validate_block_transactions(const TW_Block* block, const ValidationConfig* config);
ValidationResult validate_block_merkle_root(const TW_Block* block);
ValidationResult validate_block_hash_chain(const TW_Block* block, const TW_Block* previous_block);

// Transaction validation functions
ValidationResult validate_transaction(const TW_Transaction* transaction, const ValidationConfig* config);
ValidationResult validate_transaction_for_block(const TW_Transaction* transaction, const ValidationConfig* config, uint32_t block_index);
ValidationResult validate_transaction_signature(const TW_Transaction* transaction);
ValidationResult validate_transaction_payload(const TW_Transaction* transaction);
ValidationResult validate_transaction_recipients(const TW_Transaction* transaction);
ValidationResult validate_transaction_type(const TW_Transaction* transaction);

// Blockchain validation functions
ValidationResult validate_blockchain(const TW_BlockChain* blockchain, const ValidationConfig* config);
ValidationResult validate_blockchain_integrity(const TW_BlockChain* blockchain);
ValidationResult validate_genesis_block(const TW_Block* genesis_block);

// Utility functions
const char* validation_error_string(ValidationResult result);
ValidationConfig* create_default_validation_config(void);
void free_validation_config(ValidationConfig* config);
bool is_valid_timestamp(uint64_t timestamp, uint64_t max_drift);
bool is_valid_hash(const unsigned char* hash);
bool is_duplicate_transaction(const TW_Transaction* transaction, const TW_Block* block);

// Advanced validation functions
ValidationResult validate_block_consensus_rules(const TW_Block* block, const TW_BlockChain* blockchain);
ValidationResult validate_transaction_permissions(const TW_Transaction* transaction, const TW_BlockChain* blockchain);
ValidationResult validate_initialization_block(const TW_Block* block, const TW_BlockChain* blockchain);

#endif // BLOCK_VALIDATION_H 