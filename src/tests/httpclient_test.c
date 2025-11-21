#include "httpclient_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "packages/comm/httpClient.h"

#define ASSERT_TEST(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[FAIL] %s\n", msg); \
            return -1; \
        } \
    } while (0)

// Test httpClient initialization
static int test_httpclient_init(void) {
    printf("  - test_httpclient_init...\n");
    
    int result = http_client_init();
    ASSERT_TEST(result != 0, "http_client_init failed");
    
    http_client_cleanup();
    
    printf("    ✓ httpClient initialization passed\n");
    return 0;
}

// Test httpClient config
static int test_httpclient_config(void) {
    printf("  - test_httpclient_config...\n");
    
    HttpClientConfig* config = http_client_config_default();
    ASSERT_TEST(config != NULL, "http_client_config_default returned NULL");
    ASSERT_TEST(config->timeout_seconds > 0, "Invalid timeout_seconds");
    ASSERT_TEST(config->user_agent != NULL, "user_agent is NULL");
    ASSERT_TEST(strstr(config->user_agent, "TinyWeb") != NULL, "user_agent doesn't contain TinyWeb");
    ASSERT_TEST(strstr(config->user_agent, "PBFT") == NULL, "user_agent should not contain PBFT");
    
    http_client_config_free(config);
    
    printf("    ✓ httpClient config passed\n");
    return 0;
}

// Test utility functions
static int test_httpclient_utilities(void) {
    printf("  - test_httpclient_utilities...\n");
    
    // Test http_client_is_success_status
    ASSERT_TEST(http_client_is_success_status(200) == 1, "200 should be success");
    ASSERT_TEST(http_client_is_success_status(201) == 1, "201 should be success");
    ASSERT_TEST(http_client_is_success_status(299) == 1, "299 should be success");
    ASSERT_TEST(http_client_is_success_status(199) == 0, "199 should not be success");
    ASSERT_TEST(http_client_is_success_status(300) == 0, "300 should not be success");
    ASSERT_TEST(http_client_is_success_status(404) == 0, "404 should not be success");
    ASSERT_TEST(http_client_is_success_status(500) == 0, "500 should not be success");
    
    // Test http_client_extract_json_field
    const char* json = "{\"name\":\"test\",\"value\":123,\"active\":true}";
    
    char* name = http_client_extract_json_field(json, "name");
    ASSERT_TEST(name != NULL, "Failed to extract name field");
    ASSERT_TEST(strcmp(name, "test") == 0, "Extracted name value incorrect");
    free(name);
    
    char* value = http_client_extract_json_field(json, "value");
    ASSERT_TEST(value != NULL, "Failed to extract value field");
    ASSERT_TEST(strcmp(value, "123") == 0, "Extracted value incorrect");
    free(value);
    
    char* missing = http_client_extract_json_field(json, "missing");
    ASSERT_TEST(missing == NULL, "Missing field should return NULL");
    
    printf("    ✓ httpClient utilities passed\n");
    return 0;
}

// Test that response management functions exist
static int test_response_management(void) {
    printf("  - test_response_management...\n");
    
    // Create a mock response
    HttpResponse* response = malloc(sizeof(HttpResponse));
    ASSERT_TEST(response != NULL, "Failed to allocate response");
    
    response->data = strdup("test data");
    response->size = strlen("test data");
    response->status_code = 200;
    response->headers = strdup("Content-Type: text/plain");
    response->headers_size = strlen("Content-Type: text/plain");
    
    // Test getter functions
    ASSERT_TEST(http_response_get_status(response) == 200, "get_status failed");
    ASSERT_TEST(http_response_get_size(response) == strlen("test data"), "get_size failed");
    
    const char* data = http_response_get_data(response);
    ASSERT_TEST(data != NULL, "get_data returned NULL");
    ASSERT_TEST(strcmp(data, "test data") == 0, "get_data returned wrong data");
    
    // Test free
    http_response_free(response);
    
    printf("    ✓ response management passed\n");
    return 0;
}

int httpclient_test_main(void) {
    printf("Running httpClient tests...\n\n");
    
    int passed = 0;
    int failed = 0;
    
    if (test_httpclient_init() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    if (test_httpclient_config() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    if (test_httpclient_utilities() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    if (test_response_management() == 0) {
        passed++;
    } else {
        failed++;
    }
    
    printf("\nHttpClient Tests: %d passed, %d failed\n", passed, failed);
    
    return (failed > 0) ? -1 : 0;
}

