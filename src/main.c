#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <pthread.h>
#include "packages/encryption/encryption.h"
#include "packages/keystore/keystore.h"
#include "packages/comm/nodeApi.h"

void* http_server_thread(void* arg) {
    start_node_api("http://localhost:8000");
    return NULL;
}

int main() {
    printf("Welcome to TinyWeb!\n");
    
    // Initialize sodium
    if (sodium_init() < 0) {
        printf("Failed to initialize sodium\n");
        return 1;
    }

    // Create HTTP server thread
    pthread_t http_thread;
    if (pthread_create(&http_thread, NULL, http_server_thread, NULL) != 0) {
        printf("Failed to create HTTP server thread\n");
        return 1;
    }

    // Wait for user input to exit
    printf("HTTP server running on http://localhost:8000\n");
    printf("Press Enter to exit...\n");
    getchar();

    return 0;
}