// src/packages/comm/blockChainQueryApi.c
#include <microhttpd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include <stddef.h>  // For size_t
#include <stdint.h>

#define PORT 8080

// Structure to hold request context for POST data accumulation
struct RequestContext {
    char *post_data;
    size_t post_data_size;
};

// Utility function to parse JSON from received data
cJSON *parse_json_from_data(const char *data) {
    cJSON *json = cJSON_Parse(data);
    if (json == NULL) {
        fprintf(stderr, "Error parsing JSON: %s\n", cJSON_GetErrorPtr());
    }
    return json;
}

// Route handlers

/** Handler for GET / */
struct MHD_Response *handle_hello_world() {
    const char *response = "Hello, World!\n";
    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    if (mhd_response) {
        MHD_add_response_header(mhd_response, "Content-Type", "text/plain");
    }
    return mhd_response;
}

/** Handler for GET /CheckBlockChain */
struct MHD_Response *handle_CheckBlockChain() {
    const char *response = "Hello, World!\n";
    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    if (mhd_response) {
        MHD_add_response_header(mhd_response, "Content-Type", "text/plain");
    }
    return mhd_response;
}

/** Handler for POST /GetAllGroups */
struct MHD_Response *handle_GetAllGroups(cJSON *json) {
    if (json == NULL) {
        const char *response = "Error: Invalid JSON\n";
        return MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    }

    printf("Entering handle_GetAllGroups\nReceived: %s\n", cJSON_Print(json));
    cJSON *publicKeyItem = cJSON_GetObjectItem(json, "publicKey");
    if (!cJSON_IsString(publicKeyItem)) {
        printf("Invalid publicKey\n");
        cJSON_Delete(json);
        const char *response = "Error: No valid publicKey\n";
        return MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    }
    const char *publicKey = publicKeyItem->valuestring;
    printf("%s\n", publicKey);

    /*
    extern void *PBFTNode_node;
    printf("%p\n", PBFTNode_node);

    if (PBFTNode_node == NULL) {
        const char *response = json_dumps("{\"message\": \"Node not initialized\"}");
        write(client_fd, response, strlen(response));
        cJSON_Delete(json);
        return;
    }

    void *groups = BlockchainParser_getGroupsByPublicKey(PBFTNode_node->blockChain, publicKey);
    const char *response = json_dumps(groups);
    */
    const char *response = "{\"message\": \"Stub: Node or parser not implemented\"}\n";
    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    if (mhd_response) {
        MHD_add_response_header(mhd_response, "Content-Type", "application/json");
    }
    return mhd_response;
}

/** Handler for POST /GetSentMessages */
struct MHD_Response *handle_GetSentMessages(cJSON *json) {
    if (json == NULL) {
        const char *response = "Error: Invalid JSON\n";
        return MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    }

    printf("Received: %s\n", cJSON_Print(json));
    cJSON *publicKeyItem = cJSON_GetObjectItem(json, "publicKey");
    if (!cJSON_IsString(publicKeyItem)) {
        printf("Invalid publicKey\n");
        cJSON_Delete(json);
        const char *response = "Error: No valid publicKey\n";
        return MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    }
    const char *publicKey = publicKeyItem->valuestring;
    printf("%s\n", publicKey);

    /*
    extern void *PBFTNode_node;
    printf("%p\n", PBFTNode_node);

    if (PBFTNode_node == NULL) {
        const char *response = json_dumps("{\"message\": \"Node not initialized\"}");
        write(client_fd, response, strlen(response));
        cJSON_Delete(json);
        return;
    }

    void *messages = BlockchainParser_getSentMessagesFromPublicKey(PBFTNode_node->blockChain, publicKey);
    const char *response = json_dumps(messages);
    */
    const char *response = "{\"message\": \"Stub: Messages not implemented\"}\n";
    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    if (mhd_response) {
        MHD_add_response_header(mhd_response, "Content-Type", "application/json");
    }
    return mhd_response;
}

/** Handler for POST /GetReceivedMessages */
struct MHD_Response *handle_GetReceivedMessages(cJSON *json) {
    if (json == NULL) {
        const char *response = "Error: Invalid JSON\n";
        return MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    }

    printf("Received: %s\n", cJSON_Print(json));
    cJSON *publicKeyItem = cJSON_GetObjectItem(json, "publicKey");
    if (!cJSON_IsString(publicKeyItem)) {
        printf("Invalid publicKey\n");
        cJSON_Delete(json);
        const char *response = "Error: No valid publicKey\n";
        return MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    }
    const char *publicKey = publicKeyItem->valuestring;
    printf("%s\n", publicKey);

    /*
    extern void *PBFTNode_node;
    printf("%p\n", PBFTNode_node);

    if (PBFTNode_node == NULL) {
        const char *response = json_dumps("{\"message\": \"Node not initialized\"}");
        write(client_fd, response, strlen(response));
        cJSON_Delete(json);
        return;
    }

    void *messages = BlockchainParser_getRecievedMessagesFromPublicKey(PBFTNode_node->blockChain, publicKey);
    const char *response = json_dumps(messages);
    */
    const char *response = "{\"message\": \"Stub: Messages not implemented\"}\n";
    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    if (mhd_response) {
        MHD_add_response_header(mhd_response, "Content-Type", "application/json");
    }
    return mhd_response;
}

/** Handler for POST /SendMessage */
struct MHD_Response *handle_SendMessage(cJSON *json) {
    if (json == NULL) {
        const char *response = "Error: Invalid JSON\n";
        return MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    }

    printf("Received: %s\n", cJSON_Print(json));
    cJSON *ivItem = cJSON_GetObjectItem(json, "iv");
    cJSON *messageItem = cJSON_GetObjectItem(json, "message");
    if (!cJSON_IsString(ivItem) || !cJSON_IsString(messageItem)) {
        printf("Invalid iv or message\n");
        cJSON_Delete(json);
        const char *response = "Error: Invalid iv or message\n";
        return MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    }
    const char *iv = ivItem->valuestring;
    const char *cipher = messageItem->valuestring;
    printf("Stub: iv=%s, cipher=%s\n", iv, cipher);

    /*
    void *digest = Encryption_getDigest("mySecretKey".encode("utf-8"));
    void *iv_bytes = Serialization_getOriginalBytesFromBase64String(iv);
    void *cipher_bytes = Serialization_getOriginalBytesFromBase64String(cipher);

    printf("%s\n", "{\"iv\": iv_bytes}");
    printf("%s\n", "{\"cipher\": cipher_bytes}");
    printf("%s\n", Encryption_AESDecrypt(digest, iv_bytes, cipher_bytes).decode());
    */
    const char *response = "ok\n";
    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    if (mhd_response) {
        MHD_add_response_header(mhd_response, "Content-Type", "text/plain");
    }
    return mhd_response;
}

/** Handler for POST /CheckDigestParity */
struct MHD_Response *handle_CheckDigestParity(cJSON *json) {
    if (json == NULL) {
        const char *response = "Error: Invalid JSON\n";
        return MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    }

    printf("Received: %s\n", cJSON_Print(json));
    cJSON *publicKeyItem = cJSON_GetObjectItem(json, "publicKey");
    if (!cJSON_IsString(publicKeyItem)) {
        printf("Invalid publicKey\n");
        cJSON_Delete(json);
        const char *response = "Error: No valid publicKey\n";
        return MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    }
    printf("Stub: publicKey=%s\n", publicKeyItem->valuestring);

    /*
    printf("%s\n", Serialization_getOriginalBytesFromBase64String(publicKeyItem->valuestring));

    void *digest = Encryption_getDigest("mySecretKey".encode("utf-8"));
    printf("%s\n", "{\"type2\": type(digest)}");

    char *res = Serialization_getBase64String(digest);
    const char *output = json_dumps("{\"data\": res, \"source\": \"python Digest checker\"}");
    */
    const char *response = "{\"data\": \"stub\", \"source\": \"C Digest checker\"}\n";
    struct MHD_Response *mhd_response = MHD_create_response_from_buffer(strlen(response), (void *)response, MHD_RESPMEM_PERSISTENT);
    if (mhd_response) {
        MHD_add_response_header(mhd_response, "Content-Type", "application/json");
    }
    return mhd_response;
}

// Callback function for handling HTTP requests
enum MHD_Result handle_request(void *cls, struct MHD_Connection *connection,
                               const char *url, const char *method,
                               const char *version, const char *upload_data,
                               size_t *upload_data_size, void **con_cls) {
    struct RequestContext *context = *con_cls;

    // First call: allocate context
    if (context == NULL) {
        context = malloc(sizeof(struct RequestContext));
        if (context == NULL) return MHD_NO;
        context->post_data = NULL;
        context->post_data_size = 0;
        *con_cls = context;
        return MHD_YES;
    }

    // Accumulate POST data if present
    if (*upload_data_size != 0) {
        char *new_data = realloc(context->post_data, context->post_data_size + *upload_data_size + 1);
        if (new_data == NULL) {
            free(context->post_data);
            return MHD_NO;
        }
        context->post_data = new_data;
        memcpy(context->post_data + context->post_data_size, upload_data, *upload_data_size);
        context->post_data_size += *upload_data_size;
        context->post_data[context->post_data_size] = '\0';
        *upload_data_size = 0;
        return MHD_YES;
    }

    // Request is complete, process it
    struct MHD_Response *response;
    if (strcmp(method, "GET") == 0) {
        if (strcmp(url, "/") == 0) {
            response = handle_hello_world();
        } else if (strcmp(url, "/CheckBlockChain") == 0) {
            response = handle_CheckBlockChain();
        } else {
            const char *not_found = "404 Not Found\n";
            response = MHD_create_response_from_buffer(strlen(not_found), (void *)not_found, MHD_RESPMEM_PERSISTENT);
        }
    } else if (strcmp(method, "POST") == 0) {
        cJSON *json = context->post_data ? parse_json_from_data(context->post_data) : NULL;
        if (strcmp(url, "/GetAllGroups") == 0) {
            response = handle_GetAllGroups(json);
        } else if (strcmp(url, "/GetSentMessages") == 0) {
            response = handle_GetSentMessages(json);
        } else if (strcmp(url, "/GetReceivedMessages") == 0) {
            response = handle_GetReceivedMessages(json);
        } else if (strcmp(url, "/SendMessage") == 0) {
            response = handle_SendMessage(json);
        } else if (strcmp(url, "/CheckDigestParity") == 0) {
            response = handle_CheckDigestParity(json);
        } else {
            const char *not_found = "404 Not Found\n";
            response = MHD_create_response_from_buffer(strlen(not_found), (void *)not_found, MHD_RESPMEM_PERSISTENT);
        }
        if (json) cJSON_Delete(json);
    } else {
        const char *method_not_allowed = "Method Not Allowed\n";
        response = MHD_create_response_from_buffer(strlen(method_not_allowed), (void *)method_not_allowed, MHD_RESPMEM_PERSISTENT);
    }

    enum MHD_Result ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
    MHD_destroy_response(response);
    free(context->post_data);
    free(context);
    return ret;
}

// Main server function to start the HTTP server
void start_blockChainQueryApi() {
    struct MHD_Daemon *daemon = MHD_start_daemon(MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL,
                                                 &handle_request, NULL, MHD_OPTION_END);
    if (daemon == NULL) {
        fprintf(stderr, "Failed to start MHD daemon\n");
        exit(EXIT_FAILURE);
    }
    printf("BlockchainQueryApi listening on port %d...\n", PORT);
    getchar(); // Wait for input to stop (for testing)
    MHD_stop_daemon(daemon);
}