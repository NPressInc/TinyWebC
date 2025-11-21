#ifndef LOGGER_H
#define LOGGER_H

#include <stddef.h>

// Log levels
typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_INFO = 1
} log_level_t;

// Initialize logger, read log level from TINYWEB_LOG_LEVEL env var (default: INFO)
int logger_init(void);

// Set log level at runtime
void logger_set_level(log_level_t level);

// Get current log level
log_level_t logger_get_level(void);

// ERROR level logging
void logger_error(const char* module, const char* format, ...);

// INFO level logging
void logger_info(const char* module, const char* format, ...);

// Cleanup logger (if needed)
void logger_cleanup(void);

#endif // LOGGER_H

