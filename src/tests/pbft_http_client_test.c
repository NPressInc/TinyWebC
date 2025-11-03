#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include "../features/blockchain/pbft/pbft_node.h"
#include "../packages/comm/httpClient.h"
#include "../external/mongoose/mongoose.h"

// Test server configuration
#define TEST_SERVER_PORT 8899
#define TEST_SERVER_URL "http://127.0.0.1:8899"
#define TEST_TIMEOUT_MS 5000

// Test server state
static struct mg_mgr test_mgr;
static int test_server_running = 0;
static pthread_t test_server_thread;
static int test_response_status = 200;
static char test_response_body[1024] = "{\"status\":\"ok\"}";
static int test_request_count = 0;
static int test_simulate_failure = 0;
static int test_failure_count = 0;

// Test server event handler
static void test_server_handler(struct mg_connection *c, int ev, void *ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        test_request_count++;
        
        printf("Test server received request %d: %.*s %.*s\n", 
               test_request_count, (int)hm->method.len, hm->method.buf,
               (int)hm->uri.len, hm->uri.buf);
        
        // Simulate failure if requested
        if (test_simulate_failure && test_failure_count > 0) {
            test_failure_count--;
            printf("Test server simulating failure (remaining: %d)\n", test_failure_count);
            c->is_closing = 1;  // Close connection to simulate network error
            return;
        }
        
        // Send configured response
        mg_http_reply(c, test_response_status, "Content-Type: application/json\r\n", 
                     "%s", test_response_body);
    }
}

// Test server thread function
static void* test_server_thread_func(void* arg) {
    char addr[64];
    snprintf(addr, sizeof(addr), "http://0.0.0.0:%d", TEST_SERVER_PORT);
    
    mg_mgr_init(&test_mgr);
    
    struct mg_connection *c = mg_http_listen(&test_mgr, addr, test_server_handler, NULL);
    if (!c) {
        printf("Failed to start test server on port %d\n", TEST_SERVER_PORT);
        return NULL;
    }
    
    printf("Test server started on %s\n", addr);
    test_server_running = 1;
    
    while (test_server_running) {
        mg_mgr_poll(&test_mgr, 100);
    }
    
    mg_mgr_free(&test_mgr);
    printf("Test server stopped\n");
    return NULL;
}

// Start test server
static int start_test_server(void) {
    test_server_running = 0;
    test_request_count = 0;
    test_simulate_failure = 0;
    test_failure_count = 0;
    
    if (pthread_create(&test_server_thread, NULL, test_server_thread_func, NULL) != 0) {
        printf("Failed to start test server thread\n");
        return 0;
    }
    
    // Wait for server to start
    int timeout = 50;  // 5 seconds
    while (!test_server_running && timeout > 0) {
        usleep(100000);  // 100ms
        timeout--;
    }
    
    return test_server_running;
}

// Stop test server
static void stop_test_server(void) {
    if (test_server_running) {
        test_server_running = 0;
        pthread_join(test_server_thread, NULL);
    }
}

// Reset test server state
static void reset_test_server(void) {
    test_request_count = 0;
    test_response_status = 200;
    strcpy(test_response_body, "{\"status\":\"ok\"}");
    test_simulate_failure = 0;
    test_failure_count = 0;
}

// Test basic HTTP GET request
static void test_pbft_http_get_request(void) {
    printf("\n=== Testing PBFT HTTP GET Request ===\n");
    
    reset_test_server();
    strcpy(test_response_body, "{\"message\":\"GET success\"}");
    
    HttpResponse* response = pbft_node_http_request(TEST_SERVER_URL "/test", "GET", NULL);
    
    assert(response != NULL);
    assert(response->status_code == 200);
    assert(response->data != NULL);
    assert(strstr(response->data, "GET success") != NULL);
    assert(test_request_count == 1);
    
    pbft_node_free_http_response(response);
    printf("✅ PBFT HTTP GET request test passed\n");
}

// Test basic HTTP POST request with JSON
static void test_pbft_http_post_request(void) {
    printf("\n=== Testing PBFT HTTP POST Request ===\n");
    
    reset_test_server();
    strcpy(test_response_body, "{\"message\":\"POST success\"}");
    
    const char* json_data = "{\"test\":\"data\"}";
    HttpResponse* response = pbft_node_http_request(TEST_SERVER_URL "/test", "POST", json_data);
    
    assert(response != NULL);
    assert(response->status_code == 200);
    assert(response->data != NULL);
    assert(strstr(response->data, "POST success") != NULL);
    assert(test_request_count == 1);
    
    pbft_node_free_http_response(response);
    printf("✅ PBFT HTTP POST request test passed\n");
}

// Test HTTP request with retry logic
static void test_pbft_http_retry_logic(void) {
    printf("\n=== Testing PBFT HTTP Retry Logic ===\n");
    
    reset_test_server();
    test_simulate_failure = 1;
    test_failure_count = 2;  // Fail first 2 attempts, succeed on 3rd
    strcpy(test_response_body, "{\"message\":\"retry success\"}");
    
    HttpResponse* response = pbft_node_http_request(TEST_SERVER_URL "/retry", "GET", NULL);
    
    assert(response != NULL);
    assert(response->status_code == 200);
    assert(response->data != NULL);
    assert(strstr(response->data, "retry success") != NULL);
    assert(test_request_count == 3);  // Should have made 3 attempts
    
    pbft_node_free_http_response(response);
    printf("✅ PBFT HTTP retry logic test passed\n");
}

// Test HTTP request timeout and failure handling
static void test_pbft_http_failure_handling(void) {
    printf("\n=== Testing PBFT HTTP Failure Handling ===\n");
    
    reset_test_server();
    test_simulate_failure = 1;
    test_failure_count = 5;  // Fail all attempts (more than max retries)
    
    HttpResponse* response = pbft_node_http_request(TEST_SERVER_URL "/fail", "GET", NULL);
    
    assert(response == NULL);  // Should return NULL after all retries fail
    assert(test_request_count == 3);  // Should have made max retry attempts
    
    printf("✅ PBFT HTTP failure handling test passed\n");
}

// Test HTTP request with different status codes
static void test_pbft_http_status_codes(void) {
    printf("\n=== Testing PBFT HTTP Status Codes ===\n");
    
    // Test 404 error (client error - should not retry)
    reset_test_server();
    test_response_status = 404;
    strcpy(test_response_body, "{\"error\":\"not found\"}");
    
    HttpResponse* response = pbft_node_http_request(TEST_SERVER_URL "/notfound", "GET", NULL);
    
    assert(response != NULL);
    assert(response->status_code == 404);
    assert(test_request_count == 1);  // Should not retry client errors
    
    pbft_node_free_http_response(response);
    
    // Test 500 error (server error - should retry)
    reset_test_server();
    test_response_status = 500;
    strcpy(test_response_body, "{\"error\":\"server error\"}");
    
    response = pbft_node_http_request(TEST_SERVER_URL "/servererror", "GET", NULL);
    
    assert(response != NULL);
    assert(response->status_code == 500);
    assert(test_request_count == 3);  // Should retry server errors
    
    pbft_node_free_http_response(response);
    printf("✅ PBFT HTTP status codes test passed\n");
}

// Test invalid parameters
static void test_pbft_http_invalid_params(void) {
    printf("\n=== Testing PBFT HTTP Invalid Parameters ===\n");
    
    // Test NULL URL
    HttpResponse* response = pbft_node_http_request(NULL, "GET", NULL);
    assert(response == NULL);
    
    // Test NULL method
    response = pbft_node_http_request(TEST_SERVER_URL, NULL, NULL);
    assert(response == NULL);
    
    // Test invalid URL format
    response = pbft_node_http_request("invalid-url", "GET", NULL);
    assert(response == NULL);
    
    // Test unsupported method
    response = pbft_node_http_request(TEST_SERVER_URL, "INVALID", NULL);
    assert(response == NULL);
    
    // Test free with NULL response
    pbft_node_free_http_response(NULL);  // Should not crash
    
    printf("✅ PBFT HTTP invalid parameters test passed\n");
}

// Test PUT request support
static void test_pbft_http_put_request(void) {
    printf("\n=== Testing PBFT HTTP PUT Request ===\n");
    
    reset_test_server();
    strcpy(test_response_body, "{\"message\":\"PUT success\"}");
    
    const char* json_data = "{\"update\":\"data\"}";
    HttpResponse* response = pbft_node_http_request(TEST_SERVER_URL "/update", "PUT", json_data);
    
    assert(response != NULL);
    assert(response->status_code == 200);
    assert(response->data != NULL);
    assert(strstr(response->data, "PUT success") != NULL);
    assert(test_request_count == 1);
    
    pbft_node_free_http_response(response);
    printf("✅ PBFT HTTP PUT request test passed\n");
}

// Test concurrent HTTP requests
static void test_pbft_http_concurrent_requests(void) {
    printf("\n=== Testing PBFT HTTP Concurrent Requests ===\n");
    
    reset_test_server();
    strcpy(test_response_body, "{\"message\":\"concurrent success\"}");
    
    // Make multiple concurrent requests
    const int num_threads = 5;
    pthread_t threads[num_threads];
    HttpResponse* responses[num_threads];
    
    // Thread function for concurrent requests
    void* make_request(void* arg) {
        int thread_id = *(int*)arg;
        char url[256];
        snprintf(url, sizeof(url), "%s/concurrent/%d", TEST_SERVER_URL, thread_id);
        
        HttpResponse* response = pbft_node_http_request(url, "GET", NULL);
        responses[thread_id] = response;
        return NULL;
    }
    
    // Start threads
    int thread_ids[num_threads];
    for (int i = 0; i < num_threads; i++) {
        thread_ids[i] = i;
        pthread_create(&threads[i], NULL, make_request, &thread_ids[i]);
    }
    
    // Wait for all threads to complete
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Verify all requests succeeded
    for (int i = 0; i < num_threads; i++) {
        assert(responses[i] != NULL);
        assert(responses[i]->status_code == 200);
        pbft_node_free_http_response(responses[i]);
    }
    
    assert(test_request_count == num_threads);
    printf("✅ PBFT HTTP concurrent requests test passed\n");
}

// Test response data handling
static void test_pbft_http_response_data(void) {
    printf("\n=== Testing PBFT HTTP Response Data Handling ===\n");
    
    reset_test_server();
    
    // Test large response
    char large_response[2048];
    strcpy(large_response, "{\"data\":\"");
    for (int i = 0; i < 1000; i++) {
        strcat(large_response, "x");
    }
    strcat(large_response, "\"}");
    strcpy(test_response_body, large_response);
    
    HttpResponse* response = pbft_node_http_request(TEST_SERVER_URL "/large", "GET", NULL);
    
    assert(response != NULL);
    assert(response->status_code == 200);
    assert(response->data != NULL);
    assert(response->size > 1000);
    assert(strlen(response->data) == response->size);
    
    pbft_node_free_http_response(response);
    
    // Test empty response
    reset_test_server();
    strcpy(test_response_body, "");
    
    response = pbft_node_http_request(TEST_SERVER_URL "/empty", "GET", NULL);
    
    assert(response != NULL);
    assert(response->status_code == 200);
    // Empty response should still have valid structure
    
    pbft_node_free_http_response(response);
    printf("✅ PBFT HTTP response data handling test passed\n");
}

// Main test runner
int main(void) {
    printf("Starting PBFT HTTP Client Integration Tests\n");
    printf("==========================================\n");
    
    // Initialize HTTP client
    if (!http_client_init()) {
        printf("Failed to initialize HTTP client\n");
        return 1;
    }
    
    // Start test server
    if (!start_test_server()) {
        printf("Failed to start test server\n");
        http_client_cleanup();
        return 1;
    }
    
    // Run tests
    test_pbft_http_get_request();
    test_pbft_http_post_request();
    test_pbft_http_put_request();
    test_pbft_http_retry_logic();
    test_pbft_http_failure_handling();
    test_pbft_http_status_codes();
    test_pbft_http_invalid_params();
    test_pbft_http_concurrent_requests();
    test_pbft_http_response_data();
    
    // Cleanup
    stop_test_server();
    http_client_cleanup();
    
    printf("\n==========================================\n");
    printf("✅ All PBFT HTTP Client Integration Tests Passed!\n");
    printf("Total tests: 9\n");
    
    return 0;
}