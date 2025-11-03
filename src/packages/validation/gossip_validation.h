#ifndef TW_GOSSIP_VALIDATION_H
#define TW_GOSSIP_VALIDATION_H

#include <stdint.h>
#include "packages/transactions/transaction.h"

typedef enum {
    GOSSIP_VALIDATION_OK = 0,
    GOSSIP_VALIDATION_ERROR_NULL = -1,
    GOSSIP_VALIDATION_ERROR_TYPE = -2,
    GOSSIP_VALIDATION_ERROR_SIGNATURE = -3,
    GOSSIP_VALIDATION_ERROR_TIMESTAMP = -4,
    GOSSIP_VALIDATION_ERROR_PAYLOAD = -5
} GossipValidationResult;

typedef struct {
    uint64_t max_clock_skew_seconds;
    uint64_t message_ttl_seconds;
    size_t max_payload_bytes;
} GossipValidationConfig;

GossipValidationResult gossip_validate_transaction(
    const TW_Transaction* transaction,
    const GossipValidationConfig* config,
    uint64_t now_epoch
);

uint64_t gossip_validation_expiration(const TW_Transaction* transaction,
                                      const GossipValidationConfig* config);

const char* gossip_validation_error_string(GossipValidationResult result);

#endif // TW_GOSSIP_VALIDATION_H

