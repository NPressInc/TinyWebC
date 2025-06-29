#ifndef HTTP_CLIENT_TEST_H
#define HTTP_CLIENT_TEST_H

// HTTP Client test functions
int test_http_client_init(void);
int test_http_get_request(void);
int test_http_post_json(void);
int test_http_post_binary(void);
int test_pbft_binary_transmission(void);
int test_http_error_handling(void);

// Main test function
int http_client_test_main(void);

#endif // HTTP_CLIENT_TEST_H 