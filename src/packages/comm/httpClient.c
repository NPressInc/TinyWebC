#include "httpClient.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// HTTP client functions (stubs)
HttpResponse* http_client_request(const char* url, HttpMethod method, 
                                 const char* data, size_t data_len,
                                 const char* headers[], 
                                 const HttpClientConfig* config) {
    printf("HTTP request to %s (stub)\n", url);
    return NULL;
}

HttpResponse* http_client_get(const char* url, const char* headers[], 
                             const HttpClientConfig* config) {
    return http_client_request(url, HTTP_GET, NULL, 0, headers, config);
}

HttpResponse* http_client_post(const char* url, const char* data, size_t data_len,
                              const char* headers[], const HttpClientConfig* config) {
    return http_client_request(url, HTTP_POST, data, data_len, headers, config);
}

HttpResponse* http_client_post_json(const char* url, const char* json_data,
                                   const HttpClientConfig* config) {
    const char* headers[] = {"Content-Type: application/json", NULL};
    return http_client_post(url, json_data, strlen(json_data), headers, config);
}

// Response management
void http_response_free(HttpResponse* response) {
    if (response) {
        free(response->data);
        free(response->headers);
        free(response);
    }
}

int http_response_get_status(const HttpResponse* response) {
    return response ? response->status_code : 0;
}

const char* http_response_get_data(const HttpResponse* response) {
    return response ? response->data : NULL;
}

size_t http_response_get_size(const HttpResponse* response) {
    return response ? response->size : 0;
}

// Default configuration
HttpClientConfig* http_client_config_default(void) {
    HttpClientConfig* config = malloc(sizeof(HttpClientConfig));
    if (config) {
        config->timeout_seconds = 30;
        config->max_redirects = 5;
        config->user_agent = strdup("TinyWeb-PBFT/1.0");
        config->verify_ssl = 1;
    }
    return config;
}

void http_client_config_free(HttpClientConfig* config) {
    if (config) {
        free(config->user_agent);
        free(config);
    }
}

// Utility functions for PBFT
int http_client_is_success_status(int status_code) {
    return status_code >= 200 && status_code < 300;
}

char* http_client_extract_json_field(const char* json_response, const char* field_name) {
    // TODO: Implement JSON field extraction
    return NULL;
}

// Async HTTP client (stubs)
HttpAsyncRequest* http_client_async_post(const char* url, const char* json_data,
                                        void (*callback)(HttpResponse*, void*),
                                        void* callback_data) {
    printf("Async HTTP POST to %s (stub)\n", url);
    return NULL;
}

void http_async_request_wait(HttpAsyncRequest* request) {
    // Stub
}

void http_async_request_cancel(HttpAsyncRequest* request) {
    // Stub
}

void http_async_request_free(HttpAsyncRequest* request) {
    free(request);
} 