#include "retry.h"
#include "packages/utils/logger.h"
#include <unistd.h>
#include <time.h>

void retry_config_set_defaults(RetryConfig* config) {
    if (!config) return;
    
    config->max_retries = 3;
    config->initial_delay_ms = 100;
    config->backoff_multiplier = 2.0;
    config->max_delay_ms = 5000;
}

int retry_with_backoff(int (*func)(void*), void* arg, const RetryConfig* config, tw_error_t** error) {
    if (!func) {
        if (error) {
            *error = tw_error_create(TW_ERROR_NULL_POINTER, "retry", __func__, __LINE__, "func is NULL");
        }
        return -1;
    }
    
    RetryConfig retry_config;
    if (config) {
        retry_config = *config;
    } else {
        retry_config_set_defaults(&retry_config);
    }
    
    int attempt = 0;
    int delay_ms = retry_config.initial_delay_ms;
    
    while (attempt <= retry_config.max_retries) {
        int result = func(arg);
        if (result == 0) {
            // Success
            return 0;
        }
        
        // Failure - check if we should retry
        if (attempt >= retry_config.max_retries) {
            // Out of retries
            if (error) {
                *error = tw_error_create(TW_ERROR_NETWORK_ERROR, "retry", __func__, __LINE__, 
                                        "Function failed after %d retries", retry_config.max_retries);
            }
            logger_error("retry", "Function failed after %d retries", retry_config.max_retries);
            return -1;
        }
        
        // Wait before retrying
        if (delay_ms > 0) {
            struct timespec ts;
            ts.tv_sec = delay_ms / 1000;
            ts.tv_nsec = (delay_ms % 1000) * 1000000;
            nanosleep(&ts, NULL);
        }
        
        // Calculate next delay with exponential backoff
        delay_ms = (int)(delay_ms * retry_config.backoff_multiplier);
        if (delay_ms > retry_config.max_delay_ms) {
            delay_ms = retry_config.max_delay_ms;
        }
        
        attempt++;
    }
    
    return -1;
}

