#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <stddef.h>
#include <stdint.h>

// HTTP response structure
typedef struct {
    char* data;
    size_t size;
    int status_code;
    char* headers;
    size_t headers_size;
} HttpResponse;

// HTTP request methods
typedef enum {
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE
} HttpMethod;

// HTTP client configuration
typedef struct {
    int timeout_seconds;
    int max_redirects;
    char* user_agent;
    int verify_ssl;
} HttpClientConfig;

// HTTP client functions
HttpResponse* http_client_request(const char* url, HttpMethod method, 
                                 const char* data, size_t data_len,
                                 const char* headers[], 
                                 const HttpClientConfig* config);

HttpResponse* http_client_get(const char* url, const char* headers[], 
                             const HttpClientConfig* config);

HttpResponse* http_client_post(const char* url, const char* data, size_t data_len,
                              const char* headers[], const HttpClientConfig* config);

HttpResponse* http_client_post_json(const char* url, const char* json_data,
                                   const HttpClientConfig* config);

// Response management
void http_response_free(HttpResponse* response);
int http_response_get_status(const HttpResponse* response);
const char* http_response_get_data(const HttpResponse* response);
size_t http_response_get_size(const HttpResponse* response);

// Default configuration
HttpClientConfig* http_client_config_default(void);
void http_client_config_free(HttpClientConfig* config);

// Utility functions for PBFT
int http_client_is_success_status(int status_code);
char* http_client_extract_json_field(const char* json_response, const char* field_name);

// Async HTTP client (for threading)
typedef struct HttpAsyncRequest HttpAsyncRequest;

HttpAsyncRequest* http_client_async_post(const char* url, const char* json_data,
                                        void (*callback)(HttpResponse*, void*),
                                        void* callback_data);
void http_async_request_wait(HttpAsyncRequest* request);
void http_async_request_cancel(HttpAsyncRequest* request);
void http_async_request_free(HttpAsyncRequest* request);

#endif // HTTP_CLIENT_H 