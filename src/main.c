// main.c
#include <stdio.h>
#include "packages/comm/blockChainQueryApi.h" // Include the header file for server.c

int main() {
    printf("Starting Tiny Web BlockchainQueryApi...\n");
    start_blockChainQueryApi(); // Call the server function
    return 0;
}