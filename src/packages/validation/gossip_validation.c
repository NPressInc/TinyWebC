#include "gossip_validation.h"

#include <openssl/sha.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "packages/signing/signing.h"

static bool gossip_is_supported_type(TW_TransactionType type) {
    switch (type) {
        case TW_TXN_MESSAGE:
        case TW_TXN_GROUP_MESSAGE:
        case TW_TXN_LOCATION_UPDATE:
        case TW_TXN_EMERGENCY_ALERT:
            return true;
        default:
            return false;
    }
}

GossipValidationResult gossip_validate_transaction(
    const TW_Transaction* transaction,
    const GossipValidationConfig* config,
    uint64_t now_epoch
) {
    if (!transaction || !config) {
        return GOSSIP_VALIDATION_ERROR_NULL;
    }

    if (!gossip_is_supported_type(transaction->type)) {
        return GOSSIP_VALIDATION_ERROR_TYPE;
    }

    if (transaction->payload && transaction->payload_size > config->max_payload_bytes) {
        return GOSSIP_VALIDATION_ERROR_PAYLOAD;
    }

    if (now_epoch < transaction->timestamp) {
        uint64_t skew = transaction->timestamp - now_epoch;
        if (skew > config->max_clock_skew_seconds) {
            return GOSSIP_VALIDATION_ERROR_TIMESTAMP;
        }
    } else {
        uint64_t age = now_epoch - transaction->timestamp;
        if (age > (config->message_ttl_seconds + config->max_clock_skew_seconds)) {
            return GOSSIP_VALIDATION_ERROR_TIMESTAMP;
        }
    }

    unsigned char txn_hash[SHA256_DIGEST_LENGTH];
    memset(txn_hash, 0, sizeof(txn_hash));
    TW_Transaction_hash((TW_Transaction*)transaction, txn_hash);

    if (verify_signature(transaction->signature,
                         txn_hash,
                         sizeof(txn_hash),
                         transaction->sender) != 0) {
        return GOSSIP_VALIDATION_ERROR_SIGNATURE;
    }

    return GOSSIP_VALIDATION_OK;
}

uint64_t gossip_validation_expiration(const TW_Transaction* transaction,
                                      const GossipValidationConfig* config) {
    if (!transaction || !config) {
        return 0;
    }

    return transaction->timestamp + config->message_ttl_seconds;
}

const char* gossip_validation_error_string(GossipValidationResult result) {
    switch (result) {
        case GOSSIP_VALIDATION_OK:
            return "ok";
        case GOSSIP_VALIDATION_ERROR_NULL:
            return "null transaction or config";
        case GOSSIP_VALIDATION_ERROR_TYPE:
            return "unsupported transaction type";
        case GOSSIP_VALIDATION_ERROR_SIGNATURE:
            return "invalid signature";
        case GOSSIP_VALIDATION_ERROR_TIMESTAMP:
            return "timestamp outside allowed range";
        case GOSSIP_VALIDATION_ERROR_PAYLOAD:
            return "payload exceeds limit";
        default:
            return "unknown error";
    }
}

