#include "userMessagesApi.h"
#include "request_auth.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sodium.h>
#include <time.h>
#include <openssl/sha.h>
#include <sqlite3.h>
#include <cJSON.h>
#include "external/mongoose/mongoose.h"
#include "packages/sql/schema.h"
#include "packages/sql/database_gossip.h"
#include "packages/sql/permissions.h"
#include "packages/sql/message_store.h"
#include "packages/utils/logger.h"
#include "message.pb-c.h"
#include "api.pb-c.h"

// Forward declarations
static void handle_get_recent(struct mg_connection* c, struct mg_http_message* hm);
static void handle_get_conversation(struct mg_connection* c, struct mg_http_message* hm);
static void handle_get_conversations(struct mg_connection* c, struct mg_http_message* hm);
static void handle_get_users(struct mg_connection* c, struct mg_http_message* hm);
static int hex_decode(const char* hex, unsigned char** out, size_t* out_len);

// Main handler function - routes user messaging requests
bool user_messages_api_handler(struct mg_connection* c, struct mg_http_message* hm) {
    if (mg_strcmp(hm->uri, mg_str("/messages/recent")) == 0) {
        if (mg_strcmp(hm->method, mg_str("GET")) == 0) {
            handle_get_recent(c, hm);
            return true;
        }
    } else if (mg_strcmp(hm->uri, mg_str("/messages/conversation")) == 0) {
        if (mg_strcmp(hm->method, mg_str("GET")) == 0) {
            handle_get_conversation(c, hm);
            return true;
        }
    } else if (mg_strcmp(hm->uri, mg_str("/messages/conversations")) == 0) {
        if (mg_strcmp(hm->method, mg_str("GET")) == 0) {
            handle_get_conversations(c, hm);
            return true;
        }
    } else if (mg_strcmp(hm->uri, mg_str("/users")) == 0) {
        if (mg_strcmp(hm->method, mg_str("GET")) == 0) {
            handle_get_users(c, hm);
            return true;
        }
    }
    
    // Support OPTIONS for all routes
    if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
        if (mg_strcmp(hm->uri, mg_str("/messages/recent")) == 0 ||
            mg_strcmp(hm->uri, mg_str("/messages/conversation")) == 0 ||
            mg_strcmp(hm->uri, mg_str("/messages/conversations")) == 0 ||
            mg_strcmp(hm->uri, mg_str("/users")) == 0) {
            mg_http_reply(c, 200,
                          "Access-Control-Allow-Origin: *\r\n"
                          "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
                          "Access-Control-Allow-Headers: Content-Type, X-User-Pubkey, X-Signature, X-Timestamp\r\n",
                          "");
            return true;
        }
    }

    return false; // Not handled
}

static int hex_decode(const char* hex, unsigned char** out, size_t* out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t buffer_len = hex_len / 2;
    unsigned char* buffer = malloc(buffer_len);
    if (!buffer) return -1;
    size_t bin_len = 0;
    if (sodium_hex2bin(buffer, buffer_len, hex, hex_len, NULL, &bin_len, NULL) != 0) {
        free(buffer);
        return -1;
    }
    *out = buffer;
    *out_len = bin_len;
    return 0;
}

static void handle_get_recent(struct mg_connection* c, struct mg_http_message* hm) {
    // Authenticate request
    unsigned char requester_pubkey[PUBKEY_SIZE];
    RequestAuthResult auth_result = validate_request_auth(hm, requester_pubkey);
    if (auth_result != REQUEST_AUTH_OK) {
        mg_http_reply(c, 401, "Access-Control-Allow-Origin: *\r\n", 
                     "{\"error\":\"%s\"}", request_auth_error_string(auth_result));
        return;
    }
    
    unsigned char user_pubkey[PUBKEY_SIZE] = {0};
    bool has_user = false;
    uint32_t limit = 50;
    
    char user_val[128];
    if (mg_http_get_var(&hm->query, "user", user_val, sizeof(user_val)) > 0) {
        unsigned char* decoded = NULL;
        size_t decoded_len = 0;
        if (hex_decode(user_val, &decoded, &decoded_len) == 0 && decoded_len == PUBKEY_SIZE) {
            memcpy(user_pubkey, decoded, PUBKEY_SIZE);
            has_user = true;
            free(decoded);
        }
    }

    char limit_val[16];
    if (mg_http_get_var(&hm->query, "limit", limit_val, sizeof(limit_val)) > 0) {
        int parsed = atoi(limit_val);
        if (parsed > 0 && parsed <= 1000) limit = (uint32_t)parsed;
    }

    if (!has_user) {
        mg_http_reply(c, 400, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Missing user\"}");
        return;
    }

    // Verify requester is requesting their own messages
    if (memcmp(requester_pubkey, user_pubkey, PUBKEY_SIZE) != 0) {
        mg_http_reply(c, 403, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Unauthorized: can only access own messages\"}");
        return;
    }

    Tinyweb__Message** messages = NULL;
    size_t count = 0;
    if (message_store_fetch_recent(user_pubkey, limit, &messages, &count) != 0) {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Store error\"}");
        return;
    }

    Tinyweb__MessageList list = TINYWEB__MESSAGE_LIST__INIT;
    list.messages = messages;
    list.n_messages = count;
    list.total_count = (uint32_t)count;

    size_t packed_size = tinyweb__message_list__get_packed_size(&list);
    unsigned char* packed = malloc(packed_size);
    if (packed) {
        tinyweb__message_list__pack(&list, packed);
        
        // Use mg_printf + mg_send for raw binary protobuf data
        // Cast to unsigned long since mg_printf may not support %zu
        mg_printf(c, "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/x-protobuf\r\n"
                     "Content-Length: %lu\r\n"
                     "Access-Control-Allow-Origin: *\r\n"
                     "\r\n", (unsigned long)packed_size);
        mg_send(c, packed, packed_size);
        free(packed);
    } else {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"OOM\"}");
    }

    if (messages && count > 0) {
        message_store_free_messages(messages, count);
    } else if (messages) {
        free(messages);
    }
}

static void handle_get_conversation(struct mg_connection* c, struct mg_http_message* hm) {
    // Authenticate request
    unsigned char requester_pubkey[PUBKEY_SIZE];
    RequestAuthResult auth_result = validate_request_auth(hm, requester_pubkey);
    if (auth_result != REQUEST_AUTH_OK) {
        mg_http_reply(c, 401, "Access-Control-Allow-Origin: *\r\n", 
                     "{\"error\":\"%s\"}", request_auth_error_string(auth_result));
        return;
    }
    
    unsigned char user_pubkey[PUBKEY_SIZE] = {0};
    unsigned char with_pubkey[PUBKEY_SIZE] = {0};
    bool has_user = false, has_with = false;
    uint32_t limit = 100;
    
    char val[128];
    if (mg_http_get_var(&hm->query, "user", val, sizeof(val)) > 0) {
        unsigned char* decoded = NULL; size_t len = 0;
        if (hex_decode(val, &decoded, &len) == 0 && len == PUBKEY_SIZE) {
            memcpy(user_pubkey, decoded, PUBKEY_SIZE); has_user = true; free(decoded);
        }
    }
    if (mg_http_get_var(&hm->query, "with", val, sizeof(val)) > 0) {
        unsigned char* decoded = NULL; size_t len = 0;
        if (hex_decode(val, &decoded, &len) == 0 && len == PUBKEY_SIZE) {
            memcpy(with_pubkey, decoded, PUBKEY_SIZE); has_with = true; free(decoded);
        }
    }

    if (!has_user || !has_with) {
        mg_http_reply(c, 400, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Missing params\"}");
        return;
    }

    // Verify requester is one of the conversation participants
    if (memcmp(requester_pubkey, user_pubkey, PUBKEY_SIZE) != 0 && 
        memcmp(requester_pubkey, with_pubkey, PUBKEY_SIZE) != 0) {
        mg_http_reply(c, 403, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Unauthorized: must be conversation participant\"}");
        return;
    }
    
    // Validate both users are registered
    if (!user_exists(user_pubkey)) {
        mg_http_reply(c, 403, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"User not registered\"}");
        return;
    }
    if (!user_exists(with_pubkey)) {
        mg_http_reply(c, 403, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Conversation partner not registered\"}");
        return;
    }

    Tinyweb__Message** messages = NULL;
    size_t count = 0;
    if (message_store_fetch_conversation(user_pubkey, with_pubkey, limit, &messages, &count) != 0) {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Store error\"}");
        return;
    }

    Tinyweb__MessageList list = TINYWEB__MESSAGE_LIST__INIT;
    list.messages = messages;
    list.n_messages = count;
    list.total_count = (uint32_t)count;

    size_t packed_size = tinyweb__message_list__get_packed_size(&list);
    unsigned char* packed = malloc(packed_size);
    if (packed) {
        tinyweb__message_list__pack(&list, packed);
        
        // Use mg_printf + mg_send for raw binary protobuf data
        // Cast to unsigned long since mg_printf may not support %zu
        mg_printf(c, "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/x-protobuf\r\n"
                     "Content-Length: %lu\r\n"
                     "Access-Control-Allow-Origin: *\r\n"
                     "\r\n", (unsigned long)packed_size);
        mg_send(c, packed, packed_size);
        free(packed);
    } else {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"OOM\"}");
    }

    if (messages && count > 0) {
        message_store_free_messages(messages, count);
    } else if (messages) {
        free(messages);
    }
}

static void handle_get_conversations(struct mg_connection* c, struct mg_http_message* hm) {
    // Authenticate request
    unsigned char requester_pubkey[PUBKEY_SIZE];
    RequestAuthResult auth_result = validate_request_auth(hm, requester_pubkey);
    if (auth_result != REQUEST_AUTH_OK) {
        mg_http_reply(c, 401, "Access-Control-Allow-Origin: *\r\n", 
                     "{\"error\":\"%s\"}", request_auth_error_string(auth_result));
        return;
    }
    
    unsigned char user_pubkey[PUBKEY_SIZE] = {0};
    bool has_user = false;
    uint32_t limit = 100;
    
    char val[128];
    if (mg_http_get_var(&hm->query, "user", val, sizeof(val)) > 0) {
        unsigned char* decoded = NULL; size_t len = 0;
        if (hex_decode(val, &decoded, &len) == 0 && len == PUBKEY_SIZE) {
            memcpy(user_pubkey, decoded, PUBKEY_SIZE); has_user = true; free(decoded);
        }
    }

    if (!has_user) {
        mg_http_reply(c, 400, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Missing user\"}");
        return;
    }

    // Verify requester is requesting their own conversations
    if (memcmp(requester_pubkey, user_pubkey, PUBKEY_SIZE) != 0) {
        mg_http_reply(c, 403, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Unauthorized: can only access own conversations\"}");
        return;
    }

    Tinyweb__ConversationList* list = NULL;
    if (message_store_fetch_conversations(user_pubkey, limit, &list) != 0) {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Store error\"}");
        return;
    }

    size_t packed_size = tinyweb__conversation_list__get_packed_size(list);
    unsigned char* packed = malloc(packed_size);
    if (packed) {
        tinyweb__conversation_list__pack(list, packed);
        
        // Use mg_printf + mg_send for raw binary protobuf data
        // Cast to unsigned long since mg_printf may not support %zu
        mg_printf(c, "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/x-protobuf\r\n"
                     "Content-Length: %lu\r\n"
                     "Access-Control-Allow-Origin: *\r\n"
                     "\r\n", (unsigned long)packed_size);
        mg_send(c, packed, packed_size);
        free(packed);
    } else {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"OOM\"}");
    }

    message_store_free_conversation_list(list);
}

static void handle_get_users(struct mg_connection* c, struct mg_http_message* hm) {
    // Authenticate request (required for consistency with other messaging endpoints)
    unsigned char requester_pubkey[PUBKEY_SIZE];
    RequestAuthResult auth_result = validate_request_auth(hm, requester_pubkey);
    if (auth_result != REQUEST_AUTH_OK) {
        mg_http_reply(c, 401, "Access-Control-Allow-Origin: *\r\n", 
                     "{\"error\":\"%s\"}", request_auth_error_string(auth_result));
        return;
    }
    
    sqlite3* db = db_get_handle();
    if (!db) {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"DB error\"}");
        return;
    }

    const char* sql = "SELECT pubkey, username, age FROM users WHERE is_active = 1 ORDER BY username;";
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Prepare error\"}");
        return;
    }

    // Still using JSON for user list as it's more of a directory service
    cJSON* json = cJSON_CreateObject();
    cJSON* users_array = cJSON_CreateArray();
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        cJSON* user_obj = cJSON_CreateObject();
        const char* pk = (const char*)sqlite3_column_text(stmt, 0);
        const char* name = (const char*)sqlite3_column_text(stmt, 1);
        if (pk) cJSON_AddStringToObject(user_obj, "pubkey", pk);
        if (name) cJSON_AddStringToObject(user_obj, "username", name);
        if (sqlite3_column_type(stmt, 2) != SQLITE_NULL) {
            cJSON_AddNumberToObject(user_obj, "age", sqlite3_column_int(stmt, 2));
        }
        cJSON_AddItemToArray(users_array, user_obj);
    }
    sqlite3_finalize(stmt);
    
    cJSON_AddItemToObject(json, "users", users_array);
    char* s = cJSON_Print(json);
    mg_http_reply(c, 200, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n", "%s", s);
    free(s);
    cJSON_Delete(json);
}
