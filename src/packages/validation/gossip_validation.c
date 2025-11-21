#include "gossip_validation.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "packages/transactions/envelope.h"

GossipValidationResult gossip_validate_envelope(
    const Tinyweb__Envelope* envelope,
    const GossipValidationConfig* config,
    uint64_t now_epoch
) {
    if (!envelope || !config) {
        return GOSSIP_VALIDATION_ERROR_NULL;
    }

    if (!envelope->header) {
        return GOSSIP_VALIDATION_ERROR_NULL;
    }

    // Check payload size
    if (envelope->payload_ciphertext.len > config->max_payload_bytes) {
        return GOSSIP_VALIDATION_ERROR_PAYLOAD;
    }

    // Check timestamp
    uint64_t timestamp = envelope->header->timestamp;
    if (now_epoch < timestamp) {
        uint64_t skew = timestamp - now_epoch;
        if (skew > config->max_clock_skew_seconds) {
            return GOSSIP_VALIDATION_ERROR_TIMESTAMP;
        }
    } else {
        uint64_t age = now_epoch - timestamp;
        if (age > (config->message_ttl_seconds + config->max_clock_skew_seconds)) {
            return GOSSIP_VALIDATION_ERROR_TIMESTAMP;
        }
    }

    // Verify signature
    if (tw_envelope_verify(envelope) != 0) {
        return GOSSIP_VALIDATION_ERROR_SIGNATURE;
    }

    return GOSSIP_VALIDATION_OK;
}

uint64_t gossip_validation_expiration(const Tinyweb__Envelope* envelope,
                                      const GossipValidationConfig* config) {
    if (!envelope || !config || !envelope->header) {
        return 0;
    }

    return envelope->header->timestamp + config->message_ttl_seconds;
}

const char* gossip_validation_error_string(GossipValidationResult result) {
    switch (result) {
        case GOSSIP_VALIDATION_OK:
            return "ok";
        case GOSSIP_VALIDATION_ERROR_NULL:
            return "null envelope or config";
        case GOSSIP_VALIDATION_ERROR_TYPE:
            return "unsupported content type";
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
