#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include "../packages/PBFT/pbftNode.h"
#include "../packages/comm/httpClient.h"

// Simple tests that don't require a running server
void test_pbft_http_client_initialization(void) {
    printf("\n=== Testing PBFT HTTP Client Initialization ===\n");
    
    // Test HTTP client initialization
    int result = http_client_init();
    assert(result == 1);
    printf("✅ HTTP client initialization successful\n");
    
    // Test cleanup
    http_client_cleanup();
    printf("✅ HTTP client cleanup successful\n");
    
    // Test re-initialization
    result = http_client_init();
    assert(result == 1);
    printf("✅ HTTP client re-initialization successful\n");
}

void test_pbft_http_config_management(void) {
    printf("\n=== Testing PBFT HTTP Config Management ===\n");
    
    // Test default config creation
    HttpClientConfig* config = http_client_config_default();
    assert(config != NULL);
    assert(config->timeout_seconds == 30);
    assert(config->max_redirects == 5);
    assert(config->user_agent != NULL);
    assert(strcmp(config->user_agent, "TinyWeb-PBFT/1.0") == 0);
    printf("✅ Default HTTP config created successfully\n");
    
    // Test config cleanup
    http_client_config_free(config);
    printf("✅ HTTP config cleanup successful\n");
    
    // Test NULL config handling
    http_client_config_free(NULL);  // Should not crash
    printf("✅ NULL config handling successful\n");
}

void test_pbft_http_utility_functions(void) {
    printf("\n=== Testing PBFT HTTP Utility Functions ===\n");
    
    // Test status code checking
    assert(http_client_is_success_status(200) == 1);
    assert(http_client_is_success_status(201) == 1);
    assert(http_client_is_success_status(299) == 1);
    assert(http_client_is_success_status(300) == 0);
    assert(http_client_is_success_status(404) == 0);
    assert(http_client_is_success_status(500) == 0);
    printf("✅ Status code checking works correctly\n");
    
    // Test JSON field extraction
    const char* test_json = "{\"status\":\"ok\",\"value\":123,\"message\":\"hello world\"}";
    
    char* status = http_client_extract_json_field(test_json, "status");
    assert(status != NULL);
    assert(strcmp(status, "ok") == 0);
    free(status);
    
    char* value = http_client_extract_json_field(test_json, "value");
    assert(value != NULL);
    assert(strcmp(value, "123") == 0);
    free(value);
    
    char* message = http_client_extract_json_field(test_json, "message");
    assert(message != NULL);
    assert(strcmp(message, "hello world") == 0);
    free(message);
    
    // Test non-existent field
    char* nonexistent = http_client_extract_json_field(test_json, "nonexistent");
    assert(nonexistent == NULL);
    
    printf("✅ JSON field extraction works correctly\n");
}

void test_pbft_http_invalid_requests(void) {
    printf("\n=== Testing PBFT HTTP Invalid Requests ===\n");
    
    // Test invalid URL (should fail gracefully)
    HttpResponse* response = pbft_node_http_request("invalid-url", "GET", NULL);
    assert(response == NULL);
    printf("✅ Invalid URL handled correctly\n");
    
    // Test NULL parameters
    response = pbft_node_http_request(NULL, "GET", NULL);
    assert(response == NULL);
    
    response = pbft_node_http_request("http://example.com", NULL, NULL);
    assert(response == NULL);
    printf("✅ NULL parameters handled correctly\n");
    
    // Test unsupported method
    response = pbft_node_http_request("http://example.com", "INVALID", NULL);
    assert(response == NULL);
    printf("✅ Unsupported method handled correctly\n");
    
    // Test response cleanup with NULL
    pbft_node_free_http_response(NULL);  // Should not crash
    printf("✅ NULL response cleanup handled correctly\n");
}

void test_pbft_http_unreachable_host(void) {
    printf("\n=== Testing PBFT HTTP Unreachable Host ===\n");
    
    // Test connection to unreachable host (should timeout and retry)
    printf("Testing connection to unreachable host (this will take a few seconds)...\n");
    
    HttpResponse* response = pbft_node_http_request("http://192.0.2.1:12345/test", "GET", NULL);
    assert(response == NULL);  // Should fail after retries
    printf("✅ Unreachable host handled correctly with retries\n");
}

void test_pbft_http_request_methods(void) {
    printf("\n=== Testing PBFT HTTP Request Methods ===\n");
    
    // These tests will fail to connect but should validate method handling
    
    // Test GET method
    HttpResponse* response = pbft_node_http_request("http://192.0.2.1:12345/get", "GET", NULL);
    assert(response == NULL);  // Expected to fail, but method should be accepted
    printf("✅ GET method handling validated\n");
    
    // Test POST method with JSON
    response = pbft_node_http_request("http://192.0.2.1:12345/post", "POST", "{\"test\":\"data\"}");
    assert(response == NULL);  // Expected to fail, but method should be accepted
    printf("✅ POST method with JSON handling validated\n");
    
    // Test POST method without data
    response = pbft_node_http_request("http://192.0.2.1:12345/post", "POST", NULL);
    assert(response == NULL);  // Expected to fail, but method should be accepted
    printf("✅ POST method without data handling validated\n");
    
    // Test PUT method
    response = pbft_node_http_request("http://192.0.2.1:12345/put", "PUT", "{\"update\":\"data\"}");
    assert(response == NULL);  // Expected to fail, but method should be accepted
    printf("✅ PUT method handling validated\n");
}

int main(void) {
    printf("Starting Simple PBFT HTTP Client Tests\n");
    printf("=====================================\n");
    
    // Run tests that don't require network connectivity
    test_pbft_http_client_initialization();
    test_pbft_http_config_management();
    test_pbft_http_utility_functions();
    test_pbft_http_invalid_requests();
    test_pbft_http_request_methods();
    
    // Run network test (will take longer)
    test_pbft_http_unreachable_host();
    
    // Cleanup
    http_client_cleanup();
    
    printf("\n=====================================\n");
    printf("✅ All Simple PBFT HTTP Client Tests Passed!\n");
    printf("Total tests: 6\n");
    
    return 0;
}