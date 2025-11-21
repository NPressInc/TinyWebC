#ifndef TW_ERROR_H
#define TW_ERROR_H

#include <stdint.h>

// Error code enumeration
typedef enum {
    TW_ERROR_NONE = 0,
    TW_ERROR_NULL_POINTER = -1,
    TW_ERROR_INVALID_ARGUMENT = -2,
    TW_ERROR_ALLOCATION_FAILED = -3,
    TW_ERROR_IO_ERROR = -4,
    TW_ERROR_NETWORK_ERROR = -5,
    TW_ERROR_DATABASE_ERROR = -6,
    TW_ERROR_CRYPTO_ERROR = -7,
    TW_ERROR_VALIDATION_ERROR = -8,
    TW_ERROR_NOT_FOUND = -9,
    TW_ERROR_ALREADY_EXISTS = -10,
    TW_ERROR_PERMISSION_DENIED = -11,
    TW_ERROR_TIMEOUT = -12,
    TW_ERROR_NOT_INITIALIZED = -13,
    TW_ERROR_INVALID_STATE = -14
} tw_error_code_t;

// Error context structure
typedef struct {
    tw_error_code_t code;
    const char* module;        // e.g., "gossip", "database"
    const char* function;      // Function name
    int line;                  // Line number
    char message[256];         // Human-readable message
    int errno_value;           // System errno if applicable
} tw_error_t;

// Error creation and management
tw_error_t* tw_error_create(tw_error_code_t code, const char* module, const char* function, int line, const char* format, ...);
void tw_error_free(tw_error_t* error);
const char* tw_error_to_string(const tw_error_t* error);
tw_error_code_t tw_error_get_code(const tw_error_t* error);

// Thread-local error storage
tw_error_t* tw_error_get_last(void);
void tw_error_clear(void);

// Conversion helpers
int tw_error_from_validation_result(int validation_result);
int tw_error_from_sqlite_error(int sqlite_code);

#endif // TW_ERROR_H

