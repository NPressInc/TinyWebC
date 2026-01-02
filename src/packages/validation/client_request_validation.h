#ifndef CLIENT_REQUEST_VALIDATION_H
#define CLIENT_REQUEST_VALIDATION_H

#include <stdint.h>
#include <stdbool.h>

// Forward declaration
struct Tinyweb__ClientRequest;
typedef struct Tinyweb__ClientRequest Tinyweb__ClientRequest;

typedef enum {
    CLIENT_REQUEST_VALIDATION_OK = 0,
    CLIENT_REQUEST_VALIDATION_INVALID_SIGNATURE,
    CLIENT_REQUEST_VALIDATION_EXPIRED,
    CLIENT_REQUEST_VALIDATION_FUTURE_TIMESTAMP,
    CLIENT_REQUEST_VALIDATION_TOO_LARGE,
    CLIENT_REQUEST_VALIDATION_INVALID_FORMAT,
    CLIENT_REQUEST_VALIDATION_INVALID_RECIPIENTS,
    CLIENT_REQUEST_VALIDATION_ERROR
} ClientRequestValidationResult;

// Validate a client request (signature, timestamp, size)
ClientRequestValidationResult client_request_validate(const Tinyweb__ClientRequest* request);

// Validate that all required recipients are present in keywraps
ClientRequestValidationResult client_request_validate_recipients(const Tinyweb__ClientRequest* request);

// Calculate expiration for storage/deduplication
uint64_t client_request_get_expiration(const Tinyweb__ClientRequest* request);

// Get human-readable error string
const char* client_request_validation_result_to_string(ClientRequestValidationResult result);

#endif // CLIENT_REQUEST_VALIDATION_H

