#include "error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <pthread.h>
#include <sqlite3.h>

// Thread-local error storage
static __thread tw_error_t* g_last_error = NULL;

tw_error_t* tw_error_create(tw_error_code_t code, const char* module, const char* function, int line, const char* format, ...) {
    tw_error_t* error = (tw_error_t*)calloc(1, sizeof(tw_error_t));
    if (!error) {
        return NULL;
    }
    
    error->code = code;
    error->module = module ? module : "unknown";
    error->function = function ? function : "unknown";
    error->line = line;
    error->errno_value = errno;
    
    if (format) {
        va_list args;
        va_start(args, format);
        vsnprintf(error->message, sizeof(error->message), format, args);
        va_end(args);
    } else {
        error->message[0] = '\0';
    }
    
    // Store in thread-local storage
    if (g_last_error) {
        tw_error_free(g_last_error);
    }
    g_last_error = error;
    
    return error;
}

void tw_error_free(tw_error_t* error) {
    if (error) {
        free(error);
    }
}

const char* tw_error_to_string(const tw_error_t* error) {
    if (!error) {
        return "No error";
    }
    
    static char buffer[512];
    snprintf(buffer, sizeof(buffer), "[%s:%s:%d] %s (code: %d%s)",
             error->module,
             error->function,
             error->line,
             error->message[0] ? error->message : "Unknown error",
             error->code,
             error->errno_value ? ", errno: " : "");
    
    if (error->errno_value) {
        char errno_str[64];
        snprintf(errno_str, sizeof(errno_str), "%d", error->errno_value);
        strncat(buffer, errno_str, sizeof(buffer) - strlen(buffer) - 1);
    }
    
    return buffer;
}

tw_error_code_t tw_error_get_code(const tw_error_t* error) {
    return error ? error->code : TW_ERROR_NONE;
}

tw_error_t* tw_error_get_last(void) {
    return g_last_error;
}

void tw_error_clear(void) {
    if (g_last_error) {
        tw_error_free(g_last_error);
        g_last_error = NULL;
    }
}

int tw_error_from_validation_result(int validation_result) {
    // Convert validation result (0 = success, negative = error) to error code
    // Note: This assumes validation results follow the pattern:
    // 0 = success, -1 = null pointer, -2 = invalid argument, -3 to -5 = validation errors
    if (validation_result == 0) {
        return 0;
    }
    
    // Map validation errors to appropriate error codes
    // These values match GossipValidationResult enum from gossip_validation.h
    switch (validation_result) {
        case -1: // GOSSIP_VALIDATION_ERROR_NULL
            return TW_ERROR_NULL_POINTER;
        case -2: // GOSSIP_VALIDATION_ERROR_TYPE
            return TW_ERROR_INVALID_ARGUMENT;
        case -3: // GOSSIP_VALIDATION_ERROR_SIGNATURE
        case -4: // GOSSIP_VALIDATION_ERROR_TIMESTAMP
        case -5: // GOSSIP_VALIDATION_ERROR_PAYLOAD
            return TW_ERROR_VALIDATION_ERROR;
        default:
            return TW_ERROR_VALIDATION_ERROR;
    }
}

int tw_error_from_sqlite_error(int sqlite_code) {
    // Convert SQLite error codes to our error codes
    switch (sqlite_code) {
        case SQLITE_OK:
        case SQLITE_DONE:
        case SQLITE_ROW:
            return 0; // Success
            
        case SQLITE_ERROR:
        case SQLITE_INTERNAL:
        case SQLITE_PERM:
        case SQLITE_ABORT:
        case SQLITE_BUSY:
        case SQLITE_LOCKED:
        case SQLITE_NOMEM:
        case SQLITE_READONLY:
        case SQLITE_INTERRUPT:
        case SQLITE_IOERR:
        case SQLITE_CORRUPT:
        case SQLITE_NOTFOUND:
        case SQLITE_FULL:
        case SQLITE_CANTOPEN:
        case SQLITE_PROTOCOL:
        case SQLITE_EMPTY:
        case SQLITE_SCHEMA:
        case SQLITE_TOOBIG:
        case SQLITE_CONSTRAINT:
        case SQLITE_MISMATCH:
        case SQLITE_MISUSE:
        case SQLITE_NOLFS:
        case SQLITE_AUTH:
        case SQLITE_FORMAT:
        case SQLITE_RANGE:
        case SQLITE_NOTADB:
        case SQLITE_NOTICE:
        case SQLITE_WARNING:
        default:
            return TW_ERROR_DATABASE_ERROR;
    }
}

