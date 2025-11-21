#include "logger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

// ANSI color codes
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[31m"
#define COLOR_DEFAULT "\033[0m"

// Logger state
static log_level_t g_log_level = LOG_LEVEL_INFO;
static int g_use_colors = 0;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_initialized = 0;

// Helper to get log level name
static const char* log_level_name(log_level_t level) {
    switch (level) {
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_INFO:  return "INFO";
        default: return "UNKNOWN";
    }
}

// Helper to get color code for log level
static const char* log_level_color(log_level_t level) {
    if (!g_use_colors) {
        return "";
    }
    switch (level) {
        case LOG_LEVEL_ERROR: return COLOR_RED;
        case LOG_LEVEL_INFO:  return COLOR_DEFAULT;
        default: return COLOR_DEFAULT;
    }
}

// Parse log level from string (case-insensitive)
static log_level_t parse_log_level(const char* str) {
    if (!str) {
        return LOG_LEVEL_INFO;
    }
    
    // Convert to uppercase for comparison
    char upper[16] = {0};
    size_t len = strlen(str);
    if (len >= sizeof(upper)) {
        len = sizeof(upper) - 1;
    }
    
    for (size_t i = 0; i < len; i++) {
        char c = str[i];
        if (c >= 'a' && c <= 'z') {
            upper[i] = c - 'a' + 'A';
        } else {
            upper[i] = c;
        }
    }
    upper[len] = '\0';
    
    if (strcmp(upper, "ERROR") == 0) {
        return LOG_LEVEL_ERROR;
    } else if (strcmp(upper, "INFO") == 0) {
        return LOG_LEVEL_INFO;
    }
    
    return LOG_LEVEL_INFO; // Default
}

int logger_init(void) {
    if (g_initialized) {
        return 0;
    }
    
    // Check if stderr is a TTY for color support
    g_use_colors = isatty(STDERR_FILENO);
    
    // Read log level from environment variable
    const char* env_level = getenv("TINYWEB_LOG_LEVEL");
    if (env_level) {
        g_log_level = parse_log_level(env_level);
    } else {
        g_log_level = LOG_LEVEL_INFO; // Default
    }
    
    g_initialized = 1;
    return 0;
}

void logger_set_level(log_level_t level) {
    pthread_mutex_lock(&g_log_mutex);
    g_log_level = level;
    pthread_mutex_unlock(&g_log_mutex);
}

log_level_t logger_get_level(void) {
    return g_log_level;
}

void logger_error(const char* module, const char* format, ...) {
    if (!g_initialized) {
        logger_init();
    }
    
    if (g_log_level < LOG_LEVEL_ERROR) {
        return; // Filtered out
    }
    
    pthread_mutex_lock(&g_log_mutex);
    
    // Get current time
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Format message
    va_list args;
    va_start(args, format);
    char message[1024];
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    // Print formatted log
    const char* color = log_level_color(LOG_LEVEL_ERROR);
    const char* reset = g_use_colors ? COLOR_RESET : "";
    
    fprintf(stderr, "[%s] [%s%s%s] [%s] %s\n",
            timestamp,
            color, log_level_name(LOG_LEVEL_ERROR), reset,
            module ? module : "unknown",
            message);
    
    pthread_mutex_unlock(&g_log_mutex);
}

void logger_info(const char* module, const char* format, ...) {
    if (!g_initialized) {
        logger_init();
    }
    
    if (g_log_level < LOG_LEVEL_INFO) {
        return; // Filtered out
    }
    
    pthread_mutex_lock(&g_log_mutex);
    
    // Get current time
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // Format message
    va_list args;
    va_start(args, format);
    char message[1024];
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    // Print formatted log
    const char* color = log_level_color(LOG_LEVEL_INFO);
    const char* reset = g_use_colors ? COLOR_RESET : "";
    
    fprintf(stderr, "[%s] [%s%s%s] [%s] %s\n",
            timestamp,
            color, log_level_name(LOG_LEVEL_INFO), reset,
            module ? module : "unknown",
            message);
    
    pthread_mutex_unlock(&g_log_mutex);
}

void logger_cleanup(void) {
    // Nothing to cleanup for now, but keep function for future use
    g_initialized = 0;
}

