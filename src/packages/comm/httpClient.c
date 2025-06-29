#include "httpClient.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "external/mongoose/mongoose.h"
#include "packages/structures/blockChain/internalTransaction.h"

// Global HTTP client manager
static struct mg_mgr http_client_mgr;
static int client_initialized = 0;

// Request context for tracking async requests
typedef struct {
    HttpResponse* response;
    int completed;
    void (*callback)(HttpResponse*, void*);
    void* callback_data;
} RequestContext;

// Async request structure
struct HttpAsyncRequest {
    RequestContext ctx;
    struct mg_connection* conn;
    int completed;
};

// Initialize HTTP client
int http_client_init(void) {
    if (client_initialized) return 1;
    
    mg_mgr_init(&http_client_mgr);
    client_initialized = 1;
    printf("Mongoose HTTP client initialized\n");
    return 1;
}

// Cleanup HTTP client
void http_client_cleanup(void) {
    if (client_initialized) {
        mg_mgr_free(&http_client_mgr);
        client_initialized = 0;
        printf("Mongoose HTTP client cleaned up\n");
    }
}

// Event handler for HTTP client responses
static void http_client_event_handler(struct mg_connection *c, int ev, void *ev_data) {
    RequestContext *ctx = (RequestContext*)c->fn_data;
    
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message*)ev_data;
        
        if (ctx && ctx->response) {
            // Parse status code from response (it's in the proto field for HTTP responses)
            ctx->response->status_code = mg_http_status(hm);
            ctx->response->size = hm->body.len;
            
            if (hm->body.len > 0) {
                ctx->response->data = malloc(hm->body.len + 1);
                if (ctx->response->data) {
                    memcpy(ctx->response->data, hm->body.buf, hm->body.len);
                    ctx->response->data[hm->body.len] = '\0';
                }
            }
            
            // Copy first few headers (simplified)
            ctx->response->headers = malloc(512);
            if (ctx->response->headers) {
                ctx->response->headers[0] = '\0';
                for (int i = 0; i < 5 && hm->headers[i].name.buf; i++) {
                    if (strlen(ctx->response->headers) < 400) {
                        strncat(ctx->response->headers, hm->headers[i].name.buf, hm->headers[i].name.len);
                        strcat(ctx->response->headers, ": ");
                        strncat(ctx->response->headers, hm->headers[i].value.buf, hm->headers[i].value.len);
                        strcat(ctx->response->headers, "\r\n");
                    }
                }
            }
        }
        
        ctx->completed = 1;
        c->is_closing = 1;
        
    } else if (ev == MG_EV_ERROR) {
        printf("HTTP client connection error: %s\n", (char*)ev_data);
        // Mark as completed but indicate failure by setting status to 0
        if (ctx && ctx->response) {
            ctx->response->status_code = 0;
        }
        ctx->completed = 1;
        c->is_closing = 1;
    }
}

// Synchronous HTTP request
HttpResponse* http_client_request(const char* url, HttpMethod method, 
                                 const char* data, size_t data_len,
                                 const char* headers[], 
                                 const HttpClientConfig* config) {
    if (!client_initialized) {
        if (!http_client_init()) return NULL;
    }
    
    HttpResponse* response = malloc(sizeof(HttpResponse));
    if (!response) return NULL;
    
    memset(response, 0, sizeof(HttpResponse));
    
    // Allocate context on heap instead of stack to avoid corruption
    RequestContext* ctx = malloc(sizeof(RequestContext));
    if (!ctx) {
        free(response);
        return NULL;
    }
    memset(ctx, 0, sizeof(RequestContext));
    ctx->response = response;
    ctx->completed = 0;
    
    // Create connection
    struct mg_connection *c = mg_http_connect(&http_client_mgr, url, http_client_event_handler, ctx);
    if (!c) {
        printf("Failed to create HTTP connection to %s\n", url);
        free(response);
        free(ctx);
        return NULL;
    }
    
    // Set the context data on the connection
    c->fn_data = ctx;
    
    // Send HTTP request with proper formatting
    if (method == HTTP_POST && data) {
        // Determine content type
        const char* content_type = "application/json";  // Default
        int custom_content_type = 0;
        
        if (headers) {
            for (int i = 0; headers[i] != NULL; i++) {
                if (strstr(headers[i], "Content-Type:") != NULL) {
                    custom_content_type = 1;
                    break;
                }
            }
        }
        
        // Simple heuristic for binary data
        if (!custom_content_type && data_len > 0) {
            int binary_count = 0;
            for (size_t i = 0; i < data_len && i < 100; i++) {
                if (data[i] < 32 && data[i] != '\n' && data[i] != '\r' && data[i] != '\t') {
                    binary_count++;
                }
            }
            if (binary_count > data_len / 10) {
                content_type = "application/octet-stream";
            }
        }
        
        // Send POST request headers
        mg_printf(c, "POST %s HTTP/1.1\r\n", mg_url_uri(url));
        mg_printf(c, "Host: %s\r\n", mg_url_host(url));
        
        // Add custom headers
        if (headers) {
            for (int i = 0; headers[i] != NULL; i++) {
                mg_printf(c, "%s\r\n", headers[i]);
            }
        }
        
        // Add default content-type if not in custom headers
        if (!custom_content_type) {
            mg_printf(c, "Content-Type: %s\r\n", content_type);
        }
        
        mg_printf(c, "Content-Length: %zu\r\n", data_len);
        mg_printf(c, "Connection: close\r\n");
        mg_printf(c, "\r\n");
        
        // Send body
        mg_send(c, data, data_len);
    } else {
        // GET request
        mg_printf(c, "GET %s HTTP/1.1\r\n", mg_url_uri(url));
        mg_printf(c, "Host: %s\r\n", mg_url_host(url));
        mg_printf(c, "Connection: close\r\n");
        mg_printf(c, "\r\n");
    }
    
    // Poll until request completes (with timeout)
    int timeout_ms = config ? config->timeout_seconds * 1000 : 30000;
    int elapsed = 0;
    
    while (!ctx->completed && elapsed < timeout_ms) {
        mg_mgr_poll(&http_client_mgr, 100);
        elapsed += 100;
    }
    
    if (!ctx->completed) {
        printf("HTTP request to %s timed out\n", url);
        http_response_free(response);
        free(ctx);
        return NULL;
    }
    
    // Check if there was a connection error (status code 0)
    if (response->status_code == 0) {
        http_response_free(response);
        free(ctx);
        return NULL;
    }
    
    // Free the context before returning
    free(ctx);
    return response;
}

// Convenience methods
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
    if (!json_response || !field_name) return NULL;
    
    // Simple JSON field extraction (for production, use a proper JSON parser)
    char search_pattern[256];
    snprintf(search_pattern, sizeof(search_pattern), "\"%s\":", field_name);
    
    char* field_start = strstr(json_response, search_pattern);
    if (!field_start) return NULL;
    
    field_start += strlen(search_pattern);
    
    // Skip whitespace and quotes
    while (*field_start == ' ' || *field_start == '\t' || *field_start == '"') {
        field_start++;
    }
    
    // Find end of value
    char* field_end = field_start;
    while (*field_end && *field_end != '"' && *field_end != ',' && *field_end != '}') {
        field_end++;
    }
    
    // Extract value
    size_t value_len = field_end - field_start;
    char* value = malloc(value_len + 1);
    if (value) {
        memcpy(value, field_start, value_len);
        value[value_len] = '\0';
    }
    
    return value;
}

// Async HTTP client (simplified implementation)
HttpAsyncRequest* http_client_async_post(const char* url, const char* json_data,
                                        void (*callback)(HttpResponse*, void*),
                                        void* callback_data) {
    if (!client_initialized) {
        if (!http_client_init()) return NULL;
    }
    
    HttpAsyncRequest* async_req = malloc(sizeof(HttpAsyncRequest));
    if (!async_req) return NULL;
    
    // For this simplified implementation, we'll just do a synchronous call
    // In a full implementation, you'd use a separate thread or event loop
    HttpResponse* response = http_client_post_json(url, json_data, NULL);
    
    if (callback) {
        callback(response, callback_data);
    }
    
    http_response_free(response);
    
    return async_req;
}

void http_async_request_wait(HttpAsyncRequest* request) {
    // In this simplified implementation, requests complete immediately
    return;
}

void http_async_request_cancel(HttpAsyncRequest* request) {
    // Implementation would cancel ongoing request
    return;
}

void http_async_request_free(HttpAsyncRequest* request) {
    free(request);
}

// PBFT-specific binary protocol functions
int pbft_send_internal_transaction(const char* peer_url, const char* endpoint, 
                                   const unsigned char* binary_data, size_t data_size) {
    if (!peer_url || !endpoint || !binary_data || data_size == 0) {
        return 0;
    }
    
    // Construct full URL
    char full_url[512];
    snprintf(full_url, sizeof(full_url), "%s%s", peer_url, endpoint);
    
    // Use explicit binary headers for internal transactions
    const char* headers[] = {"Content-Type: application/octet-stream", NULL};
    
    // Send binary data via POST with proper headers
    HttpResponse* response = http_client_post(full_url, (const char*)binary_data, data_size, headers, NULL);
    
    int success = 0;
    if (response && http_client_is_success_status(response->status_code)) {
        success = 1;
        printf("Binary HTTP request to %s successful (status: %d)\n", full_url, response->status_code);
    } else {
        printf("Binary HTTP request to %s failed (status: %d)\n", full_url, 
               response ? response->status_code : 0);
    }
    
    if (response) {
        http_response_free(response);
    }
    
    return success;
}

int pbft_send_block_proposal_binary(const char* peer_url, TW_InternalTransaction* proposal) {
    if (!peer_url || !proposal) {
        return 0;
    }
    
    // Serialize the internal transaction to binary
    unsigned char* binary_data = NULL;
    size_t data_size = TW_InternalTransaction_serialize(proposal, &binary_data);
    
    if (!binary_data || data_size == 0) {
        return 0;
    }
    
    // Send to ProposeBlock endpoint
    int result = pbft_send_internal_transaction(peer_url, "/ProposeBlock", binary_data, data_size);
    
    free(binary_data);
    return result;
}

int pbft_send_vote_binary(const char* peer_url, TW_InternalTransaction* vote) {
    if (!peer_url || !vote) {
        return 0;
    }
    
    // Serialize the internal transaction to binary
    unsigned char* binary_data = NULL;
    size_t data_size = TW_InternalTransaction_serialize(vote, &binary_data);
    
    if (!binary_data || data_size == 0) {
        return 0;
    }
    
    // Determine endpoint based on vote type
    const char* endpoint;
    switch (vote->type) {
        case TW_INT_TXN_VOTE_VERIFY:
            endpoint = "/VerificationVote";
            break;
        case TW_INT_TXN_VOTE_COMMIT:
            endpoint = "/CommitVote";
            break;
        case TW_INT_TXN_VOTE_NEW_ROUND:
            endpoint = "/NewRound";
            break;
        default:
            free(binary_data);
            return 0;
    }
    
    int result = pbft_send_internal_transaction(peer_url, endpoint, binary_data, data_size);
    
    free(binary_data);
    return result;
}

// Legacy JSON functions (for client transactions only)
int pbft_send_block_proposal(const char* peer_url, const char* block_hash, 
                            const char* block_data, const char* sender_pubkey, 
                            const char* signature) {
    char url[512];
    snprintf(url, sizeof(url), "%s/ProposeBlock", peer_url);
    
    char json_payload[2048];
    snprintf(json_payload, sizeof(json_payload),
        "{"
        "\"blockHash\":\"%s\","
        "\"blockData\":\"%s\","
        "\"sender\":\"%s\","
        "\"signature\":\"%s\""
        "}",
        block_hash, block_data, sender_pubkey, signature);
    
    HttpResponse* response = http_client_post_json(url, json_payload, NULL);
    
    int success = 0;
    if (response) {
        success = http_client_is_success_status(response->status_code);
        printf("Block proposal to %s: status %d\n", peer_url, response->status_code);
        http_response_free(response);
    }
    
    return success;
}

int pbft_send_verification_vote(const char* peer_url, const char* block_hash, 
                               const char* sender_pubkey, const char* signature) {
    char url[512];
    snprintf(url, sizeof(url), "%s/VerificationVote", peer_url);
    
    char json_payload[1024];
    snprintf(json_payload, sizeof(json_payload),
        "{"
        "\"blockHash\":\"%s\","
        "\"sender\":\"%s\","
        "\"signature\":\"%s\""
        "}",
        block_hash, sender_pubkey, signature);
    
    HttpResponse* response = http_client_post_json(url, json_payload, NULL);
    
    int success = 0;
    if (response) {
        success = http_client_is_success_status(response->status_code);
        printf("Verification vote to %s: status %d\n", peer_url, response->status_code);
        http_response_free(response);
    }
    
    return success;
}

int pbft_get_blockchain_length(const char* peer_url) {
    char url[512];
    snprintf(url, sizeof(url), "%s/GetBlockChainLength", peer_url);
    
    HttpResponse* response = http_client_get(url, NULL, NULL);
    
    int chain_length = -1;
    if (response && http_client_is_success_status(response->status_code)) {
        char* length_str = http_client_extract_json_field(response->data, "chainLength");
        if (length_str) {
            chain_length = atoi(length_str);
            free(length_str);
        }
        http_response_free(response);
    }
    
    return chain_length;
} 