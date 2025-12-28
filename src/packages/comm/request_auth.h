#ifndef REQUEST_AUTH_H
#define REQUEST_AUTH_H

#include <mongoose.h>
#include <stdbool.h>

// Request authentication result
typedef enum {
    REQUEST_AUTH_OK = 0,
    REQUEST_AUTH_MISSING_PUBKEY,
    REQUEST_AUTH_MISSING_SIGNATURE,
    REQUEST_AUTH_MISSING_TIMESTAMP,
    REQUEST_AUTH_INVALID_PUBKEY,
    REQUEST_AUTH_INVALID_SIGNATURE,
    REQUEST_AUTH_USER_NOT_REGISTERED,
    REQUEST_AUTH_EXPIRED_TIMESTAMP,
    REQUEST_AUTH_FUTURE_TIMESTAMP,
    REQUEST_AUTH_ERROR
} RequestAuthResult;

// Validate an HTTP request signature
// Checks that:
// 1. X-User-Pubkey header exists and is valid
// 2. X-Signature header exists and is valid Ed25519 signature
// 3. X-Timestamp header exists and is within valid window
// 4. Signature signs: method + uri + query + timestamp + pubkey
// 5. User is registered
// Returns REQUEST_AUTH_OK on success, error code otherwise
RequestAuthResult validate_request_auth(struct mg_http_message* hm, unsigned char* out_pubkey);

// Get error message for auth result
const char* request_auth_error_string(RequestAuthResult result);

#endif // REQUEST_AUTH_H

