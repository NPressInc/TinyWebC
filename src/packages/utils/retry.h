#ifndef TW_RETRY_H
#define TW_RETRY_H

#include <stdint.h>
#include "packages/utils/error.h"

// Retry configuration
typedef struct {
    int max_retries;           // Maximum retry attempts (default: 3)
    int initial_delay_ms;      // Initial delay in milliseconds (default: 100)
    double backoff_multiplier; // Backoff multiplier (default: 2.0)
    int max_delay_ms;          // Maximum delay cap (default: 5000)
} RetryConfig;

// Retry helper function
// func: Function to call (returns 0 on success, non-zero on error)
// arg: Argument to pass to func
// config: Retry configuration (NULL uses defaults)
// error: Optional error output
// Returns: 0 on success, -1 on failure after all retries
int retry_with_backoff(int (*func)(void*), void* arg, const RetryConfig* config, tw_error_t** error);

// Set default retry config
void retry_config_set_defaults(RetryConfig* config);

#endif // TW_RETRY_H

