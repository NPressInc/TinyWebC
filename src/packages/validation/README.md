# Block Validation Module

This module provides comprehensive validation functionality for the TinyWeb blockchain system. It ensures the integrity and correctness of blocks, transactions, and the entire blockchain.

## Features

### Block Validation
- **Block Header Validation**: Validates block index, timestamp, previous hash, and proposer ID
- **Transaction Validation**: Validates all transactions within a block
- **Merkle Tree Validation**: Verifies the merkle root hash matches the calculated hash
- **Hash Chain Validation**: Ensures blocks are properly linked via previous hash

### Transaction Validation
- **Signature Validation**: Verifies transaction signatures
- **Payload Validation**: Validates encrypted payload structure
- **Recipient Validation**: Ensures recipient list is valid
- **Type Validation**: Checks transaction type is within valid range

### Blockchain Validation
- **Integrity Validation**: Ensures all blocks are properly linked
- **Genesis Block Validation**: Special validation for the first block
- **Initialization Block Validation**: Validates the network setup block

## Usage

### Basic Block Validation

```c
#include "packages/validation/block_validation.h"

// Create validation configuration
ValidationConfig* config = create_default_validation_config();

// Load blockchain
TW_BlockChain* blockchain = readBlockChainFromFile();

// Validate a specific block
ValidationResult result = validate_block(blockchain->blocks[0], blockchain, config);
if (result == VALIDATION_SUCCESS) {
    printf("Block validation passed\\n");
} else {
    printf("Block validation failed with error: %d\\n", result);
}

// Cleanup
free(config);
TW_BlockChain_destroy(blockchain);
```

### Blockchain Integrity Validation

```c
// Validate entire blockchain integrity
ValidationResult result = validate_blockchain_integrity(blockchain);
if (result == VALIDATION_SUCCESS) {
    printf("Blockchain integrity is valid\\n");
} else {
    printf("Blockchain integrity check failed\\n");
}
```

### Custom Validation Configuration

```c
ValidationConfig* config = create_default_validation_config();

// Customize validation rules
config->max_transactions_per_block = 500;
config->min_transactions_per_block = 1;
config->max_timestamp_drift = 600;  // 10 minutes
config->strict_ordering = false;
config->validate_signatures = true;
config->validate_merkle_tree = true;

// Use custom config for validation
ValidationResult result = validate_block(block, blockchain, config);
```

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | VALIDATION_SUCCESS | Validation passed |
| -1 | VALIDATION_ERROR_NULL_POINTER | Null pointer provided |
| -2 | VALIDATION_ERROR_INVALID_INDEX | Invalid block index |
| -3 | VALIDATION_ERROR_INVALID_HASH | Invalid hash value |
| -4 | VALIDATION_ERROR_INVALID_TIMESTAMP | Invalid timestamp |
| -5 | VALIDATION_ERROR_INVALID_MERKLE_ROOT | Merkle root mismatch |
| -6 | VALIDATION_ERROR_INVALID_TRANSACTION | Invalid transaction |
| -7 | VALIDATION_ERROR_INVALID_SIGNATURE | Invalid signature |
| -8 | VALIDATION_ERROR_INVALID_PROPOSER | Invalid proposer |
| -9 | VALIDATION_ERROR_DUPLICATE_TRANSACTION | Duplicate transaction found |
| -10 | VALIDATION_ERROR_INSUFFICIENT_TRANSACTIONS | Too few transactions |
| -11 | VALIDATION_ERROR_TOO_MANY_TRANSACTIONS | Too many transactions |
| -12 | VALIDATION_ERROR_INVALID_TRANSACTION_TYPE | Invalid transaction type |
| -13 | VALIDATION_ERROR_INVALID_RECIPIENT | Invalid recipient |
| -14 | VALIDATION_ERROR_INVALID_PAYLOAD | Invalid payload |
| -15 | VALIDATION_ERROR_CHAIN_INTEGRITY | Chain integrity violation |

## Configuration Options

### ValidationConfig Structure

```c
typedef struct {
    uint32_t max_transactions_per_block;  // Maximum transactions per block (default: 1000)
    uint32_t min_transactions_per_block;  // Minimum transactions per block (default: 0)
    uint64_t max_timestamp_drift;         // Max timestamp drift in seconds (default: 300)
    bool strict_ordering;                 // Enforce strict timestamp ordering (default: true)
    bool validate_signatures;             // Whether to validate signatures (default: true)
    bool validate_merkle_tree;            // Whether to validate merkle tree (default: true)
} ValidationConfig;
```

### Default Configuration

The default configuration provides:
- Maximum 1000 transactions per block
- Minimum 0 transactions per block
- Maximum 5 minutes timestamp drift
- Strict timestamp ordering enabled
- Signature validation enabled
- Merkle tree validation enabled

## Integration

The validation module is automatically included in the build system. To use it in your code:

1. Include the header: `#include "packages/validation/block_validation.h"`
2. Link with the validation module (automatically handled by CMake)
3. Create a validation configuration
4. Call the appropriate validation functions

## Testing

A test suite is available in `tests/test_block_validation.c` that demonstrates:
- Configuration creation and management
- Block validation with existing blockchain
- Error handling and edge cases

To run the validation tests:

```bash
gcc -I src -o test_validation tests/test_block_validation.c src/packages/validation/block_validation.c src/packages/structures/blockChain/*.c src/packages/fileIO/*.c src/packages/encryption/encryption.c src/packages/signing/signing.c src/packages/keystore/keystore.c src/packages/utils/*.c src/structs/permission/permission.c -lsodium -lcrypto -llz4 -lcjson -lm
./test_validation
```

## Notes

- The validation module is designed to be thread-safe for read operations
- Validation functions do not modify the input data
- Memory management is the caller's responsibility for configuration objects
- The module integrates with the existing blockchain, transaction, and encryption systems 