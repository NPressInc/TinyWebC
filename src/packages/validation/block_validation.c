#include "block_validation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "packages/signing/signing.h"
#include "packages/structures/blockChain/merkleTree.h"
#include "packages/encryption/encryption.h"

// Default validation configuration
static const ValidationConfig DEFAULT_CONFIG = {
    .max_transactions_per_block = 1000,
    .min_transactions_per_block = 0,
    .max_timestamp_drift = 300,  // 5 minutes
    .strict_ordering = true,
    .validate_signatures = true,
    .validate_merkle_tree = true
};

// Main block validation function
ValidationResult validate_block(const TW_Block* block, const TW_BlockChain* blockchain, const ValidationConfig* config) {
    if (!block) return VALIDATION_ERROR_NULL_POINTER;
    if (!blockchain) return VALIDATION_ERROR_NULL_POINTER;
    if (!config) config = &DEFAULT_CONFIG;

    ValidationResult result;

    // Get previous block for validation
    TW_Block* previous_block = NULL;
    if (block->index > 0) {
        // For blocks being validated before addition to blockchain:
        // The block index should equal the current blockchain length
        // For blocks already in blockchain: 
        // The block index should be less than blockchain length
        if (block->index > blockchain->length) {
            return VALIDATION_ERROR_INVALID_INDEX;
        }
        
        // Get the previous block (index - 1)
        if (block->index - 1 < blockchain->length) {
            previous_block = blockchain->blocks[block->index - 1];
        } else {
            // This means we're trying to validate a block that's too far ahead
            return VALIDATION_ERROR_INVALID_INDEX;
        }
    }

    // Validate block header
    result = validate_block_header(block, previous_block, config);
    if (result != VALIDATION_SUCCESS) return result;

    // Validate hash chain
    if (previous_block) {
        result = validate_block_hash_chain(block, previous_block);
        if (result != VALIDATION_SUCCESS) return result;
    }

    // Validate transactions
    result = validate_block_transactions(block, config);
    if (result != VALIDATION_SUCCESS) return result;

    // Validate merkle root if enabled
    if (config->validate_merkle_tree) {
        result = validate_block_merkle_root(block);
        if (result != VALIDATION_SUCCESS) return result;
    }

    // Special validation for initialization block
    if (block->index == 1) {  // Initialization block
        result = validate_initialization_block(block, blockchain);
        if (result != VALIDATION_SUCCESS) return result;
    }

    return VALIDATION_SUCCESS;
}

// Validate block header
ValidationResult validate_block_header(const TW_Block* block, const TW_Block* previous_block, const ValidationConfig* config) {
    if (!block) return VALIDATION_ERROR_NULL_POINTER;
    if (!config) config = &DEFAULT_CONFIG;

    // Validate timestamp
    if (!is_valid_timestamp(block->timestamp, config->max_timestamp_drift)) {
        return VALIDATION_ERROR_INVALID_TIMESTAMP;
    }

    // Validate index sequence
    if (previous_block) {
        if (block->index != previous_block->index + 1) {
            return VALIDATION_ERROR_INVALID_INDEX;
        }

        // Validate timestamp ordering if strict ordering is enabled
        if (config->strict_ordering && block->timestamp <= previous_block->timestamp) {
            return VALIDATION_ERROR_INVALID_TIMESTAMP;
        }
    } else if (block->index != 0) {
        // Genesis block must have index 0
        return VALIDATION_ERROR_INVALID_INDEX;
    }

    // Validate proposer ID (should not be all zeros for non-genesis blocks)
    if (block->index > 0) {
        bool all_zeros = true;
        for (int i = 0; i < PROP_ID_SIZE; i++) {
            if (block->proposer_id[i] != 0) {
                all_zeros = false;
                break;
            }
        }
        if (all_zeros) {
            return VALIDATION_ERROR_INVALID_PROPOSER;
        }
    }

    return VALIDATION_SUCCESS;
}

// Validate block transactions
ValidationResult validate_block_transactions(const TW_Block* block, const ValidationConfig* config) {
    if (!block) return VALIDATION_ERROR_NULL_POINTER;
    if (!config) config = &DEFAULT_CONFIG;

    // Genesis block has relaxed transaction requirements
    if (block->index == 0) {
        // Genesis block can have zero transactions
        if (block->txn_count > config->max_transactions_per_block) {
            return VALIDATION_ERROR_TOO_MANY_TRANSACTIONS;
        }
    } else {
        // Regular blocks follow normal transaction count rules
        if (block->txn_count < config->min_transactions_per_block) {
            return VALIDATION_ERROR_INSUFFICIENT_TRANSACTIONS;
        }
        if (block->txn_count > config->max_transactions_per_block) {
            return VALIDATION_ERROR_TOO_MANY_TRANSACTIONS;
        }
    }

    // Validate each transaction
    for (uint32_t i = 0; i < block->txn_count; i++) {
        if (!block->txns[i]) {
            return VALIDATION_ERROR_INVALID_TRANSACTION;
        }

        ValidationResult result = validate_transaction_for_block(block->txns[i], config, block->index);
        if (result != VALIDATION_SUCCESS) return result;

        // Check for duplicate transactions
        for (uint32_t j = i + 1; j < block->txn_count; j++) {
            if (is_duplicate_transaction(block->txns[i], block)) {
                return VALIDATION_ERROR_DUPLICATE_TRANSACTION;
            }
        }
    }

    return VALIDATION_SUCCESS;
}

// Validate block merkle root
ValidationResult validate_block_merkle_root(const TW_Block* block) {
    if (!block) return VALIDATION_ERROR_NULL_POINTER;

    // If no transactions, merkle root should be zero
    if (block->txn_count == 0) {
        unsigned char zero_hash[HASH_SIZE] = {0};
        if (memcmp(block->merkle_root_hash, zero_hash, HASH_SIZE) != 0) {
            return VALIDATION_ERROR_INVALID_MERKLE_ROOT;
        }
        return VALIDATION_SUCCESS;
    }

    // Create transaction hashes array
    unsigned char** tx_hashes = malloc(sizeof(unsigned char*) * block->txn_count);
    if (!tx_hashes) return VALIDATION_ERROR_NULL_POINTER;

    size_t* hash_sizes = malloc(sizeof(size_t) * block->txn_count);
    if (!hash_sizes) {
        free(tx_hashes);
        return VALIDATION_ERROR_NULL_POINTER;
    }

    for (uint32_t i = 0; i < block->txn_count; i++) {
        tx_hashes[i] = malloc(HASH_SIZE);
        if (!tx_hashes[i]) {
            // Cleanup on failure
            for (uint32_t j = 0; j < i; j++) {
                free(tx_hashes[j]);
            }
            free(tx_hashes);
            free(hash_sizes);
            return VALIDATION_ERROR_NULL_POINTER;
        }
        TW_Transaction_hash(block->txns[i], tx_hashes[i]);
        hash_sizes[i] = HASH_SIZE;
    }

    // Build merkle tree and get root
    TW_MerkleTreeNode* root = TW_MerkleTree_buildTree((const unsigned char**)tx_hashes, block->txn_count, hash_sizes);
    
    ValidationResult result = VALIDATION_SUCCESS;
    if (!root) {
        result = VALIDATION_ERROR_INVALID_MERKLE_ROOT;
    } else {
        // Compare calculated root with stored root
        if (memcmp(root->hash, block->merkle_root_hash, HASH_SIZE) != 0) {
            result = VALIDATION_ERROR_INVALID_MERKLE_ROOT;
        }
    }

    // Cleanup
    for (uint32_t i = 0; i < block->txn_count; i++) {
        free(tx_hashes[i]);
    }
    free(tx_hashes);
    free(hash_sizes);
    
    // Note: We don't free the root node here as TW_MerkleTree_buildTree 
    // may return a node that's part of a larger tree structure

    return result;
}

// Validate block hash chain
ValidationResult validate_block_hash_chain(const TW_Block* block, const TW_Block* previous_block) {
    if (!block) return VALIDATION_ERROR_NULL_POINTER;
    
    // Genesis block has no previous block
    if (block->index == 0) {
        if (previous_block != NULL) return VALIDATION_ERROR_INVALID_HASH;
        return VALIDATION_SUCCESS;
    }
    
    if (!previous_block) return VALIDATION_ERROR_NULL_POINTER;
    
    // Calculate expected previous hash
    unsigned char expected_prev_hash[HASH_SIZE];
    TW_Block_getHash((TW_Block*)previous_block, expected_prev_hash);  // Cast away const
    
    // Compare with stored previous hash
    if (memcmp(block->previous_hash, expected_prev_hash, HASH_SIZE) != 0) {
        return VALIDATION_ERROR_INVALID_HASH;
    }
    
    return VALIDATION_SUCCESS;
}

// Validate transaction with block context (allows special handling for genesis block)
ValidationResult validate_transaction_for_block(const TW_Transaction* transaction, const ValidationConfig* config, uint32_t block_index) {
    if (!transaction) return VALIDATION_ERROR_NULL_POINTER;
    if (!config) config = &DEFAULT_CONFIG;

    ValidationResult result;

    // Validate transaction type
    result = validate_transaction_type(transaction);
    if (result != VALIDATION_SUCCESS) return result;

    // Validate recipients
    result = validate_transaction_recipients(transaction);
    if (result != VALIDATION_SUCCESS) return result;

    // Validate payload
    result = validate_transaction_payload(transaction);
    if (result != VALIDATION_SUCCESS) return result;

    // Validate signature if enabled, but skip for genesis block transactions
    if (config->validate_signatures && block_index > 0) {
        result = validate_transaction_signature(transaction);
        if (result != VALIDATION_SUCCESS) return result;
    }

    return VALIDATION_SUCCESS;
}

// Validate individual transaction (backward compatibility - assumes non-genesis block)
ValidationResult validate_transaction(const TW_Transaction* transaction, const ValidationConfig* config) {
    return validate_transaction_for_block(transaction, config, 1); // Use block_index = 1 (non-genesis)
}

// Validate transaction signature
ValidationResult validate_transaction_signature(const TW_Transaction* transaction) {
    if (!transaction) return VALIDATION_ERROR_NULL_POINTER;

    // Check if signature is not all zeros (indicating it was signed)
    bool has_signature = false;
    for (int i = 0; i < SIGNATURE_SIZE; i++) {
        if (transaction->signature[i] != 0) {
            has_signature = true;
            break;
        }
    }

    if (!has_signature) {
        return VALIDATION_ERROR_INVALID_SIGNATURE;
    }

    // Calculate transaction hash (this excludes the signature field)
    unsigned char tx_hash[HASH_SIZE];
    TW_Transaction_hash((TW_Transaction*)transaction, tx_hash);

    // Verify signature using the sender's public key
    // The verify_signature function expects:
    // - signature: the signature to verify
    // - message: the message that was signed (transaction hash)
    // - message_len: length of the message (HASH_SIZE = 32 bytes)
    // - public_key: the public key to use for verification (sender's public key)
    int verification_result = verify_signature(
        transaction->signature,     // signature
        tx_hash,                   // message (transaction hash)
        HASH_SIZE,                 // message length (32 bytes)
        transaction->sender        // public key (sender's public key)
    );

    // verify_signature returns 0 for valid signature, -1 for invalid
    if (verification_result != 0) {
        return VALIDATION_ERROR_INVALID_SIGNATURE;
    }

    return VALIDATION_SUCCESS;
}

// Validate transaction payload
ValidationResult validate_transaction_payload(const TW_Transaction* transaction) {
    if (!transaction) return VALIDATION_ERROR_NULL_POINTER;

    // Check payload consistency
    if (transaction->payload_size > 0 && !transaction->payload) {
        return VALIDATION_ERROR_INVALID_PAYLOAD;
    }

    if (transaction->payload_size == 0 && transaction->payload) {
        return VALIDATION_ERROR_INVALID_PAYLOAD;
    }

    // Validate encrypted payload structure if present
    if (transaction->payload) {
        if (transaction->payload->num_recipients == 0) {
            return VALIDATION_ERROR_INVALID_PAYLOAD;
        }

        if (transaction->payload->ciphertext_len == 0 || !transaction->payload->ciphertext) {
            return VALIDATION_ERROR_INVALID_PAYLOAD;
        }

        // Check that encrypted keys and nonces are present for all recipients
        if (transaction->payload->num_recipients > 0) {
            if (!transaction->payload->encrypted_keys || !transaction->payload->key_nonces) {
                return VALIDATION_ERROR_INVALID_PAYLOAD;
            }
        }
    }

    return VALIDATION_SUCCESS;
}

// Validate transaction recipients
ValidationResult validate_transaction_recipients(const TW_Transaction* transaction) {
    if (!transaction) return VALIDATION_ERROR_NULL_POINTER;

    // Check recipient consistency
    if (transaction->recipient_count > 0 && !transaction->recipients) {
        return VALIDATION_ERROR_INVALID_RECIPIENT;
    }

    if (transaction->recipient_count == 0 && transaction->recipients) {
        return VALIDATION_ERROR_INVALID_RECIPIENT;
    }

    // Validate recipient count doesn't exceed maximum
    if (transaction->recipient_count > MAX_RECIPIENTS) {
        return VALIDATION_ERROR_INVALID_RECIPIENT;
    }

    return VALIDATION_SUCCESS;
}

// Validate transaction type
ValidationResult validate_transaction_type(const TW_Transaction* transaction) {
    if (!transaction) return VALIDATION_ERROR_NULL_POINTER;

    // Check if transaction type is within valid range
    if (transaction->type < 0 || transaction->type >= TW_TXN_TYPE_COUNT) {
        return VALIDATION_ERROR_INVALID_TRANSACTION_TYPE;
    }

    return VALIDATION_SUCCESS;
}

// Validate entire blockchain
ValidationResult validate_blockchain(const TW_BlockChain* blockchain, const ValidationConfig* config) {
    if (!blockchain) return VALIDATION_ERROR_NULL_POINTER;
    if (!config) config = &DEFAULT_CONFIG;

    // Validate genesis block
    if (blockchain->length > 0) {
        ValidationResult result = validate_genesis_block(blockchain->blocks[0]);
        if (result != VALIDATION_SUCCESS) return result;
    }

    // Validate each block in sequence
    for (uint32_t i = 0; i < blockchain->length; i++) {
        ValidationResult result = validate_block(blockchain->blocks[i], blockchain, config);
        if (result != VALIDATION_SUCCESS) return result;
    }

    return validate_blockchain_integrity(blockchain);
}

// Validate blockchain integrity
ValidationResult validate_blockchain_integrity(const TW_BlockChain* blockchain) {
    if (!blockchain) return VALIDATION_ERROR_NULL_POINTER;

    // Check that all blocks are properly linked
    for (uint32_t i = 1; i < blockchain->length; i++) {
        unsigned char prev_hash[HASH_SIZE];
        TW_Block_getHash(blockchain->blocks[i - 1], prev_hash);

        if (memcmp(blockchain->blocks[i]->previous_hash, prev_hash, HASH_SIZE) != 0) {
            return VALIDATION_ERROR_CHAIN_INTEGRITY;
        }
    }

    return VALIDATION_SUCCESS;
}

// Validate genesis block
ValidationResult validate_genesis_block(const TW_Block* genesis_block) {
    if (!genesis_block) return VALIDATION_ERROR_NULL_POINTER;

    // Genesis block must have index 0
    if (genesis_block->index != 0) {
        return VALIDATION_ERROR_INVALID_INDEX;
    }

    // Genesis block should have all-zero previous hash
    for (int i = 0; i < HASH_SIZE; i++) {
        if (genesis_block->previous_hash[i] != 0) {
            return VALIDATION_ERROR_INVALID_HASH;
        }
    }

    return VALIDATION_SUCCESS;
}

// Validate initialization block (special rules)
ValidationResult validate_initialization_block(const TW_Block* block, const TW_BlockChain* blockchain) {
    if (!block || !blockchain) return VALIDATION_ERROR_NULL_POINTER;

    // Initialization block should be block index 1
    if (block->index != 1) {
        return VALIDATION_ERROR_INVALID_INDEX;
    }

    // Should have initialization transactions
    if (block->txn_count == 0) {
        return VALIDATION_ERROR_INSUFFICIENT_TRANSACTIONS;
    }

    // All transactions should have the same sender (creator)
    unsigned char expected_sender[PUBKEY_SIZE];
    memcpy(expected_sender, block->txns[0]->sender, PUBKEY_SIZE);

    for (uint32_t i = 1; i < block->txn_count; i++) {
        if (memcmp(block->txns[i]->sender, expected_sender, PUBKEY_SIZE) != 0) {
            return VALIDATION_ERROR_INVALID_TRANSACTION;
        }
    }

    return VALIDATION_SUCCESS;
}

// Utility functions
const char* validation_error_string(ValidationResult result) {
    switch (result) {
        case VALIDATION_SUCCESS: return "Success";
        case VALIDATION_ERROR_NULL_POINTER: return "Null pointer error";
        case VALIDATION_ERROR_INVALID_INDEX: return "Invalid block index";
        case VALIDATION_ERROR_INVALID_HASH: return "Invalid hash";
        case VALIDATION_ERROR_INVALID_TIMESTAMP: return "Invalid timestamp";
        case VALIDATION_ERROR_INVALID_MERKLE_ROOT: return "Invalid merkle root";
        case VALIDATION_ERROR_INVALID_TRANSACTION: return "Invalid transaction";
        case VALIDATION_ERROR_INVALID_SIGNATURE: return "Invalid signature";
        case VALIDATION_ERROR_INVALID_PROPOSER: return "Invalid proposer";
        case VALIDATION_ERROR_DUPLICATE_TRANSACTION: return "Duplicate transaction";
        case VALIDATION_ERROR_INSUFFICIENT_TRANSACTIONS: return "Insufficient transactions";
        case VALIDATION_ERROR_TOO_MANY_TRANSACTIONS: return "Too many transactions";
        case VALIDATION_ERROR_INVALID_TRANSACTION_TYPE: return "Invalid transaction type";
        case VALIDATION_ERROR_INVALID_RECIPIENT: return "Invalid recipient";
        case VALIDATION_ERROR_INVALID_PAYLOAD: return "Invalid payload";
        case VALIDATION_ERROR_CHAIN_INTEGRITY: return "Chain integrity error";
        default: return "Unknown error";
    }
}

ValidationConfig* create_default_validation_config(void) {
    ValidationConfig* config = malloc(sizeof(ValidationConfig));
    if (!config) return NULL;

    *config = DEFAULT_CONFIG;
    return config;
}

void free_validation_config(ValidationConfig* config) {
    if (config) {
        free(config);
    }
}

bool is_valid_timestamp(uint64_t timestamp, uint64_t max_drift) {
    uint64_t current_time = (uint64_t)time(NULL);
    
    // Check if timestamp is too far in the future
    if (timestamp > current_time + max_drift) {
        return false;
    }
    
    // Check if timestamp is reasonable (not too far in the past)
    // Allow up to 24 hours in the past for flexibility
    if (current_time > timestamp && (current_time - timestamp) > 86400) {
        return false;
    }
    
    return true;
}

bool is_valid_hash(const unsigned char* hash) {
    if (!hash) return false;
    
    // A valid hash should not be all zeros (except for genesis block previous hash)
    // This is a basic check - you might want more sophisticated validation
    bool all_zeros = true;
    for (int i = 0; i < HASH_SIZE; i++) {
        if (hash[i] != 0) {
            all_zeros = false;
            break;
        }
    }
    
    return !all_zeros;
}

bool is_duplicate_transaction(const TW_Transaction* transaction, const TW_Block* block) {
    if (!transaction || !block) return false;
    
    unsigned char tx_hash[HASH_SIZE];
    TW_Transaction_hash((TW_Transaction*)transaction, tx_hash);
    
    // Check against all other transactions in the block
    for (uint32_t i = 0; i < block->txn_count; i++) {
        if (block->txns[i] == transaction) continue;
        
        unsigned char other_hash[HASH_SIZE];
        TW_Transaction_hash(block->txns[i], other_hash);
        
        if (memcmp(tx_hash, other_hash, HASH_SIZE) == 0) {
            return true;
        }
    }
    
    return false;
}

// Advanced validation functions (stubs for future implementation)
ValidationResult validate_block_consensus_rules(const TW_Block* block, const TW_BlockChain* blockchain) {
    // Placeholder for consensus-specific validation rules
    // This could include PBFT-specific validation, stake validation, etc.
    if (!block || !blockchain) return VALIDATION_ERROR_NULL_POINTER;
    
    return VALIDATION_SUCCESS;
}

ValidationResult validate_transaction_permissions(const TW_Transaction* transaction, const TW_BlockChain* blockchain) {
    // Placeholder for permission-based validation
    // This could check if the sender has permission to perform the transaction type
    if (!transaction || !blockchain) return VALIDATION_ERROR_NULL_POINTER;
    
    return VALIDATION_SUCCESS;
} 