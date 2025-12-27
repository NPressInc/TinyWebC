#ifndef MESSAGE_VALIDATION_H
#define MESSAGE_VALIDATION_H

#include <stdint.h>
#include <stdbool.h>

// Forward declaration
struct Tinyweb__Message;
typedef struct Tinyweb__Message Tinyweb__Message;

typedef enum {
    MESSAGE_VALIDATION_OK = 0,
    MESSAGE_VALIDATION_INVALID_SIGNATURE,
    MESSAGE_VALIDATION_EXPIRED,
    MESSAGE_VALIDATION_FUTURE_TIMESTAMP,
    MESSAGE_VALIDATION_TOO_LARGE,
    MESSAGE_VALIDATION_INVALID_FORMAT,
    MESSAGE_VALIDATION_ERROR
} MessageValidationResult;

// Validate a message (signature, timestamp, size)
MessageValidationResult message_validate(const Tinyweb__Message* message);

// Calculate expiration for storage/deduplication
uint64_t message_validation_get_expiration(const Tinyweb__Message* message);

// Get human-readable error string
const char* message_validation_result_to_string(MessageValidationResult result);

#endif // MESSAGE_VALIDATION_H

