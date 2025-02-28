#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cjson/cJSON.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    // Setup address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind and listen
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("TCP Server listening on port %d...\n", PORT);

    while (1) {
        if ((client_fd = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept failed");
            continue;
        }

        read(client_fd, buffer, BUFFER_SIZE - 1);
        printf("Received: %s\n", buffer);

        cJSON *json = cJSON_Parse(buffer);
        if (json == NULL) {
            fprintf(stderr, "JSON parsing failed: %s\n", cJSON_GetErrorPtr());
            const char *response = "Error: Invalid JSON\n";
            write(client_fd, response, strlen(response));
        } else {
            cJSON *value = cJSON_GetObjectItem(json, "value");
            char *response = value ? cJSON_Print(value) : strdup("No 'value' field\n");
            write(client_fd, response, strlen(response));
            free(response);
            cJSON_Delete(json);
        }

        close(client_fd);
    }

    close(server_fd);
    return EXIT_SUCCESS;
}