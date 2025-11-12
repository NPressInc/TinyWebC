#include "gossipApi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sodium.h>
#include <cjson/cJSON.h>
#include <time.h>
#include "external/mongoose/mongoose.h"
#include "packages/sql/gossip_store.h"
#include "packages/sql/database.h"
#include "packages/transactions/transaction.h"
#include "packages/transactions/envelope.h"
#include "envelope.pb-c.h"
#include "content.pb-c.h"

typedef struct {
    GossipService* service;
    const GossipValidationConfig* config;
    struct mg_mgr mgr;
    struct mg_connection* listener;
    pthread_t thread;
    uint16_t port;
    volatile int running;
    int initialized;
} GossipApiServer;

static GossipApiServer g_server = {0};

static void* gossip_api_loop(void* arg);
static void gossip_api_handler(struct mg_connection* c, int ev, void* ev_data);
static void handle_post_transaction(struct mg_connection* c, struct mg_http_message* hm);
static void handle_get_recent(struct mg_connection* c, struct mg_http_message* hm);
static void handle_get_messages(struct mg_connection* c, struct mg_http_message* hm);
static void handle_get_conversations(struct mg_connection* c, struct mg_http_message* hm);
static int hex_decode(const char* hex, unsigned char** out, size_t* out_len);
static char* hex_encode(const unsigned char* data, size_t len);

int gossip_api_start(uint16_t port,
                     GossipService* service,
                     const GossipValidationConfig* config) {
    if (!service || !config) {
        return -1;
    }

    if (g_server.initialized) {
        return 0;
    }

    memset(&g_server, 0, sizeof(g_server));
    g_server.service = service;
    g_server.config = config;
    g_server.port = port;

    mg_mgr_init(&g_server.mgr);

    char addr[32];
    snprintf(addr, sizeof(addr), "http://0.0.0.0:%u", port);
    g_server.listener = mg_http_listen(&g_server.mgr, addr, gossip_api_handler, NULL);
    if (!g_server.listener) {
        fprintf(stderr, "gossip_api: failed to listen on %s\n", addr);
        mg_mgr_free(&g_server.mgr);
        memset(&g_server, 0, sizeof(g_server));
        return -1;
    }

    g_server.running = 1;
    g_server.initialized = 1;

    if (pthread_create(&g_server.thread, NULL, gossip_api_loop, NULL) != 0) {
        fprintf(stderr, "gossip_api: failed to start HTTP thread\n");
        g_server.running = 0;
        mg_mgr_free(&g_server.mgr);
        memset(&g_server, 0, sizeof(g_server));
        return -1;
    }

    printf("Gossip HTTP API listening on %s\n", addr);
    return 0;
}

void gossip_api_stop(void) {
    if (!g_server.initialized) {
        return;
    }

    g_server.running = 0;
    pthread_join(g_server.thread, NULL);
    mg_mgr_free(&g_server.mgr);
    memset(&g_server, 0, sizeof(g_server));
}

bool gossip_api_is_running(void) {
    return g_server.initialized && g_server.running;
}

static void* gossip_api_loop(void* arg) {
    (void)arg;
    while (g_server.running) {
        mg_mgr_poll(&g_server.mgr, 100);
    }
    return NULL;
}

static void gossip_api_handler(struct mg_connection* c, int ev, void* ev_data) {
    (void)ev_data;
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message* hm = (struct mg_http_message*)ev_data;

        if (mg_strcmp(hm->uri, mg_str("/gossip/transaction")) == 0) {
            if (mg_strcmp(hm->method, mg_str("POST")) == 0) {
                handle_post_transaction(c, hm);
            } else if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
                mg_http_reply(c, 200,
                              "Access-Control-Allow-Origin: *\r\n"
                              "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                              "Access-Control-Allow-Headers: Content-Type\r\n",
                              "");
            } else {
                mg_http_reply(c, 405, "Content-Type: application/json\r\n",
                              "{\"error\":\"Method Not Allowed\"}");
            }
        } else if (mg_strcmp(hm->uri, mg_str("/gossip/envelope")) == 0) {
            if (mg_strcmp(hm->method, mg_str("POST")) == 0) {
                // Accept protobuf envelope
                cJSON* root = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
                if (!root) {
                    mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                                  "{\"error\":\"Invalid JSON payload\"}");
                    return;
                }
                cJSON* hex_item = cJSON_GetObjectItem(root, "envelope_hex");
                if (!cJSON_IsString(hex_item) || hex_item->valuestring == NULL) {
                    cJSON_Delete(root);
                    mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                                  "{\"error\":\"envelope_hex required\"}");
                    return;
                }
                unsigned char* raw = NULL; size_t raw_len = 0;
                if (hex_decode(hex_item->valuestring, &raw, &raw_len) != 0 || raw_len == 0) {
                    cJSON_Delete(root);
                    free(raw);
                    mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                                  "{\"error\":\"Invalid envelope_hex\"}");
                    return;
                }
                Tinyweb__Envelope* env = tinyweb__envelope__unpack(NULL, raw_len, raw);
                free(raw);
                if (!env) {
                    cJSON_Delete(root);
                    mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                                  "{\"error\":\"Failed to parse envelope\"}");
                    return;
                }

                // Verify
                if (tw_envelope_verify(env) != 0) {
                    tinyweb__envelope__free_unpacked(env, NULL);
                    cJSON_Delete(root);
                    mg_http_reply(c, 422, "Content-Type: application/json\r\n",
                                  "{\"error\":\"invalid signature\"}");
                    return;
                }

                // Persist using gossip_store (as raw bytes)
                unsigned char* ser = NULL; size_t ser_len = 0;
                if (tw_envelope_serialize(env, &ser, &ser_len) != 0) {
                    tinyweb__envelope__free_unpacked(env, NULL);
                    cJSON_Delete(root);
                    mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                                  "{\"error\":\"serialize failed\"}");
                    return;
                }

                // Use header timestamp for expiration base
                uint64_t now = (uint64_t)time(NULL);
                uint64_t expires_at = now + 60ULL * 60ULL * 24ULL * 30ULL;
                
                // Store envelope using the new gossip_store API
                if (db_is_initialized()) {
                    const Tinyweb__EnvelopeHeader* hdr = &env->header;
                    if (gossip_store_save_envelope(hdr->version, hdr->content_type, hdr->schema_version,
                                                   hdr->sender_pubkey.data,
                                                   hdr->timestamp,
                                                   ser, ser_len,
                                                   expires_at) != 0) {
                        free(ser);
                        tinyweb__envelope__free_unpacked(env, NULL);
                        cJSON_Delete(root);
                        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                                      "{\"error\":\"store failed\"}");
                        return;
                    }
                }

                free(ser);
                tinyweb__envelope__free_unpacked(env, NULL);
                cJSON_Delete(root);
                mg_http_reply(c, 202,
                              "Content-Type: application/json\r\n"
                              "Access-Control-Allow-Origin: *\r\n",
                              "{\"status\":\"accepted\"}");
            } else if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
                mg_http_reply(c, 200,
                              "Access-Control-Allow-Origin: *\r\n"
                              "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                              "Access-Control-Allow-Headers: Content-Type\r\n",
                              "");
            } else {
                mg_http_reply(c, 405, "Content-Type: application/json\r\n",
                              "{\"error\":\"Method Not Allowed\"}");
            }
        } else if (mg_strcmp(hm->uri, mg_str("/gossip/recent")) == 0) {
            if (mg_strcmp(hm->method, mg_str("GET")) == 0) {
                handle_get_recent(c, hm);
            } else if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
                mg_http_reply(c, 200,
                              "Access-Control-Allow-Origin: *\r\n"
                              "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
                              "Access-Control-Allow-Headers: Content-Type\r\n",
                              "");
            } else {
                mg_http_reply(c, 405, "Content-Type: application/json\r\n",
                              "{\"error\":\"Method Not Allowed\"}");
            }
        } else if (mg_strcmp(hm->uri, mg_str("/gossip/messages")) == 0) {
            if (mg_strcmp(hm->method, mg_str("GET")) == 0) {
                handle_get_messages(c, hm);
            } else if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
                mg_http_reply(c, 200,
                              "Access-Control-Allow-Origin: *\r\n"
                              "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
                              "Access-Control-Allow-Headers: Content-Type\r\n",
                              "");
            } else {
                mg_http_reply(c, 405, "Content-Type: application/json\r\n",
                              "{\"error\":\"Method Not Allowed\"}");
            }
        } else if (mg_strcmp(hm->uri, mg_str("/gossip/conversations")) == 0) {
            if (mg_strcmp(hm->method, mg_str("GET")) == 0) {
                handle_get_conversations(c, hm);
            } else if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
                mg_http_reply(c, 200,
                              "Access-Control-Allow-Origin: *\r\n"
                              "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
                              "Access-Control-Allow-Headers: Content-Type\r\n",
                              "");
            } else {
                mg_http_reply(c, 405, "Content-Type: application/json\r\n",
                              "{\"error\":\"Method Not Allowed\"}");
            }
        } else {
            mg_http_reply(c, 404, "Content-Type: application/json\r\n",
                          "{\"error\":\"Not Found\"}");
        }
    }
}

static void handle_post_transaction(struct mg_connection* c, struct mg_http_message* hm) {
    cJSON* root = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!root) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                      "{\"error\":\"Invalid JSON payload\"}");
        return;
    }

    cJSON* hex_item = cJSON_GetObjectItem(root, "transaction_hex");
    if (!cJSON_IsString(hex_item) || hex_item->valuestring == NULL) {
        cJSON_Delete(root);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                      "{\"error\":\"transaction_hex field required\"}");
        return;
    }

    unsigned char* raw = NULL;
    size_t raw_len = 0;
    if (hex_decode(hex_item->valuestring, &raw, &raw_len) != 0 || raw_len == 0) {
        cJSON_Delete(root);
        free(raw);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                      "{\"error\":\"Invalid transaction_hex value\"}");
        return;
    }

    TW_Transaction* txn = TW_Transaction_deserialize(raw, raw_len);
    free(raw);

    if (!txn) {
        cJSON_Delete(root);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                      "{\"error\":\"Failed to parse transaction\"}");
        return;
    }

    uint64_t now = (uint64_t)time(NULL);
    GossipValidationResult res = gossip_validate_transaction(txn, g_server.config, now);
    if (res != GOSSIP_VALIDATION_OK) {
        const char* msg = gossip_validation_error_string(res);
        TW_Transaction_destroy(txn);
        cJSON_Delete(root);
        mg_http_reply(c, 422, "Content-Type: application/json\r\n",
                      "{\"error\":\"%s\"}", msg);
        return;
    }

    unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE] = {0};
    TW_Transaction_hash(txn, digest);

    int seen = 0;
    if (db_is_initialized()) {
        if (gossip_store_has_seen(digest, &seen) != 0) {
            fprintf(stderr, "gossip_api: failed to check digest cache\n");
        } else if (seen) {
            TW_Transaction_destroy(txn);
            cJSON_Delete(root);
            mg_http_reply(c, 200,
                          "Content-Type: application/json\r\n"
                          "Access-Control-Allow-Origin: *\r\n",
                          "{\"status\":\"duplicate\"}");
            return;
        }
    }

    uint64_t expires_at = gossip_validation_expiration(txn, g_server.config);
    if (gossip_store_save_transaction(txn, expires_at) != 0) {
        TW_Transaction_destroy(txn);
        cJSON_Delete(root);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                      "{\"error\":\"Failed to persist transaction\"}");
        return;
    }

    if (gossip_store_mark_seen(digest, expires_at) != 0) {
        fprintf(stderr, "gossip_api: failed to record digest\n");
    }

    if (gossip_service_rebroadcast_transaction(g_server.service, txn, NULL) != 0) {
        fprintf(stderr, "gossip_api: failed to broadcast transaction\n");
    }

    TW_Transaction_destroy(txn);
    cJSON_Delete(root);

    mg_http_reply(c, 202,
                  "Content-Type: application/json\r\n"
                  "Access-Control-Allow-Origin: *\r\n",
                  "{\"status\":\"accepted\"}");
}

static void handle_get_recent(struct mg_connection* c, struct mg_http_message* hm) {
    char limit_buf[16];
    int limit = 50;
    if (mg_http_get_var(&hm->query, "limit", limit_buf, sizeof(limit_buf)) > 0) {
        int parsed = atoi(limit_buf);
        if (parsed > 0) {
            limit = parsed;
        }
    }

    GossipStoredMessage* messages = NULL;
    size_t count = 0;
    if (gossip_store_fetch_recent((uint32_t)limit, &messages, &count) != 0) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                      "{\"error\":\"Failed to fetch messages\"}");
        return;
    }

    cJSON* root = cJSON_CreateArray();
    if (!root) {
        gossip_store_free_messages(messages, count);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                      "{\"error\":\"Out of memory\"}");
        return;
    }

    for (size_t i = 0; i < count; ++i) {
        cJSON* item = cJSON_CreateObject();
        if (!item) continue;

        cJSON_AddNumberToObject(item, "id", (double)messages[i].id);
        cJSON_AddNumberToObject(item, "type", messages[i].type);
        cJSON_AddNumberToObject(item, "timestamp", (double)messages[i].timestamp);
        cJSON_AddNumberToObject(item, "expiresAt", (double)messages[i].expires_at);

        char sender_hex[PUBKEY_SIZE * 2 + 1];
        sodium_bin2hex(sender_hex, sizeof(sender_hex), messages[i].sender, PUBKEY_SIZE);
        cJSON_AddStringToObject(item, "sender", sender_hex);

        if (messages[i].payload && messages[i].payload_size > 0) {
            char* payload_hex = hex_encode(messages[i].payload, messages[i].payload_size);
            if (payload_hex) {
                cJSON_AddStringToObject(item, "transaction_hex", payload_hex);
                free(payload_hex);
            }
        }

        cJSON_AddItemToArray(root, item);
    }

    char* json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    gossip_store_free_messages(messages, count);

    if (!json) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                      "{\"error\":\"Failed to serialize response\"}");
        return;
    }

    mg_http_reply(c, 200,
                  "Content-Type: application/json\r\n"
                  "Access-Control-Allow-Origin: *\r\n",
                  "%s", json);
    free(json);
}

static int hex_decode(const char* hex, unsigned char** out, size_t* out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) {
        return -1;
    }

    size_t buffer_len = hex_len / 2;
    unsigned char* buffer = malloc(buffer_len);
    if (!buffer) {
        return -1;
    }

    size_t bin_len = 0;
    if (sodium_hex2bin(buffer, buffer_len, hex, hex_len, NULL, &bin_len, NULL) != 0) {
        free(buffer);
        return -1;
    }

    *out = buffer;
    *out_len = bin_len;
    return 0;
}

static char* hex_encode(const unsigned char* data, size_t len) {
    if (!data || len == 0) {
        return NULL;
    }
    size_t out_len = len * 2 + 1;
    char* out = malloc(out_len);
    if (!out) {
        return NULL;
    }
    sodium_bin2hex(out, out_len, data, len);
    return out;
}

static void handle_get_messages(struct mg_connection* c, struct mg_http_message* hm) {
    // Parse query parameters
    char with_user[128] = {0};
    char current_user[128] = {0};

    if (mg_http_get_var(&hm->query, "with", with_user, sizeof(with_user)) <= 0) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                      "{\"error\":\"'with' parameter required (other user's public key)\"}");
        return;
    }

    if (mg_http_get_var(&hm->query, "user", current_user, sizeof(current_user)) <= 0) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                      "{\"error\":\"'user' parameter required (current user's public key)\"}");
        return;
    }

    // Query for messages between these two users
    // This is a simplified implementation - in practice you'd want messages where
    // (sender = current_user AND recipient = with_user) OR (sender = with_user AND recipient = current_user)
    // For now, we'll use the existing query_messages_for_user and filter client-side

    GossipStoredMessage* messages = NULL;
    size_t count = 0;

    // First try to get messages from current user to the other user
    if (gossip_store_fetch_recent(1000, &messages, &count) != 0) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                      "{\"error\":\"Failed to fetch messages\"}");
        return;
    }

    cJSON* root = cJSON_CreateArray();
    if (!root) {
        gossip_store_free_messages(messages, count);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                      "{\"error\":\"Out of memory\"}");
        return;
    }

    // Convert current_user and with_user to binary for comparison
    unsigned char current_user_bin[PUBKEY_SIZE] = {0};
    unsigned char with_user_bin[PUBKEY_SIZE] = {0};

    if (sodium_hex2bin(current_user_bin, sizeof(current_user_bin),
                       current_user, strlen(current_user), NULL, NULL, NULL) != 0) {
        cJSON_Delete(root);
        gossip_store_free_messages(messages, count);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                      "{\"error\":\"Invalid current user public key format\"}");
        return;
    }

    if (sodium_hex2bin(with_user_bin, sizeof(with_user_bin),
                       with_user, strlen(with_user), NULL, NULL, NULL) != 0) {
        cJSON_Delete(root);
        gossip_store_free_messages(messages, count);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                      "{\"error\":\"Invalid 'with' user public key format\"}");
        return;
    }

    // Filter messages between these two users
    for (size_t i = 0; i < count; ++i) {
        // Check if this message is between the two users
        int is_sender_current = memcmp(messages[i].sender, current_user_bin, PUBKEY_SIZE) == 0;
        int is_sender_with = memcmp(messages[i].sender, with_user_bin, PUBKEY_SIZE) == 0;

        if ((is_sender_current || is_sender_with) && messages[i].type == TW_TXN_MESSAGE) {
            cJSON* item = cJSON_CreateObject();
            if (!item) continue;

            cJSON_AddNumberToObject(item, "id", (double)messages[i].id);
            cJSON_AddNumberToObject(item, "type", messages[i].type);
            cJSON_AddNumberToObject(item, "timestamp", (double)messages[i].timestamp);
            cJSON_AddNumberToObject(item, "expiresAt", (double)messages[i].expires_at);

            char sender_hex[PUBKEY_SIZE * 2 + 1];
            sodium_bin2hex(sender_hex, sizeof(sender_hex), messages[i].sender, PUBKEY_SIZE);
            cJSON_AddStringToObject(item, "sender", sender_hex);

            // Determine if this is an outgoing or incoming message
            cJSON_AddBoolToObject(item, "isOutgoing", is_sender_current);

            if (messages[i].payload && messages[i].payload_size > 0) {
                char* payload_hex = hex_encode(messages[i].payload, messages[i].payload_size);
                if (payload_hex) {
                    cJSON_AddStringToObject(item, "transaction_hex", payload_hex);
                    free(payload_hex);
                }
            }

            cJSON_AddItemToArray(root, item);
        }
    }

    char* json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    gossip_store_free_messages(messages, count);

    if (!json) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                      "{\"error\":\"Failed to serialize response\"}");
        return;
    }

    mg_http_reply(c, 200,
                  "Content-Type: application/json\r\n"
                  "Access-Control-Allow-Origin: *\r\n",
                  "%s", json);
    free(json);
}

static void handle_get_conversations(struct mg_connection* c, struct mg_http_message* hm) {
    // Parse query parameter for current user
    char current_user[128] = {0};

    if (mg_http_get_var(&hm->query, "user", current_user, sizeof(current_user)) <= 0) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                      "{\"error\":\"'user' parameter required (current user's public key)\"}");
        return;
    }

    // Get recent messages to find conversation partners
    GossipStoredMessage* messages = NULL;
    size_t count = 0;

    if (gossip_store_fetch_recent(1000, &messages, &count) != 0) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                      "{\"error\":\"Failed to fetch messages\"}");
        return;
    }

    cJSON* root = cJSON_CreateArray();
    if (!root) {
        gossip_store_free_messages(messages, count);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                      "{\"error\":\"Out of memory\"}");
        return;
    }

    // Convert current user to binary for comparison
    unsigned char current_user_bin[PUBKEY_SIZE] = {0};
    if (sodium_hex2bin(current_user_bin, sizeof(current_user_bin),
                       current_user, strlen(current_user), NULL, NULL, NULL) != 0) {
        cJSON_Delete(root);
        gossip_store_free_messages(messages, count);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                      "{\"error\":\"Invalid user public key format\"}");
        return;
    }

    // Use a simple set-like structure to track unique conversation partners
    // In a real implementation, you'd want a proper hash set
    #define MAX_CONVERSATIONS 100
    struct {
        unsigned char pubkey[PUBKEY_SIZE];
        uint64_t last_message_time;
        char last_message_preview[100];
        int message_count;
    } conversations[MAX_CONVERSATIONS];

    int conversation_count = 0;

    for (size_t i = 0; i < count; ++i) {
        if (messages[i].type != TW_TXN_MESSAGE) continue;

        // Check if current user is involved in this message
        int is_sender = memcmp(messages[i].sender, current_user_bin, PUBKEY_SIZE) == 0;

        unsigned char other_user[PUBKEY_SIZE];
        if (is_sender) {
            // For direct messages, we'd need to get recipients from the transaction
            // For now, skip messages sent by current user (we can't easily determine recipients)
            continue;
        } else {
            // Message received by current user - sender is the conversation partner
            memcpy(other_user, messages[i].sender, PUBKEY_SIZE);
        }

        // Check if we already have this conversation
        int found = 0;
        for (int j = 0; j < conversation_count; ++j) {
            if (memcmp(conversations[j].pubkey, other_user, PUBKEY_SIZE) == 0) {
                found = 1;
                // Update with newer message if this one is more recent
                if (messages[i].timestamp > conversations[j].last_message_time) {
                    conversations[j].last_message_time = messages[i].timestamp;
                    conversations[j].message_count++;
                    // Simple preview (first 96 chars of hex payload)
                    if (messages[i].payload && messages[i].payload_size > 0) {
                        size_t preview_len = messages[i].payload_size > 48 ? 48 : messages[i].payload_size;
                        sodium_bin2hex(conversations[j].last_message_preview,
                                     sizeof(conversations[j].last_message_preview),
                                     messages[i].payload, preview_len);
                    }
                }
                break;
            }
        }

        // Add new conversation if not found and we have space
        if (!found && conversation_count < MAX_CONVERSATIONS) {
            memcpy(conversations[conversation_count].pubkey, other_user, PUBKEY_SIZE);
            conversations[conversation_count].last_message_time = messages[i].timestamp;
            conversations[conversation_count].message_count = 1;

            // Simple preview (first 96 chars of hex payload)
            if (messages[i].payload && messages[i].payload_size > 0) {
                size_t preview_len = messages[i].payload_size > 48 ? 48 : messages[i].payload_size;
                sodium_bin2hex(conversations[conversation_count].last_message_preview,
                             sizeof(conversations[conversation_count].last_message_preview),
                             messages[i].payload, preview_len);
            }

            conversation_count++;
        }
    }

    // Sort conversations by last message time (most recent first)
    for (int i = 0; i < conversation_count - 1; ++i) {
        for (int j = 0; j < conversation_count - i - 1; ++j) {
            if (conversations[j].last_message_time < conversations[j + 1].last_message_time) {
                // Swap
                typeof(conversations[0]) temp = conversations[j];
                conversations[j] = conversations[j + 1];
                conversations[j + 1] = temp;
            }
        }
    }

    // Build JSON response
    for (int i = 0; i < conversation_count; ++i) {
        cJSON* conv = cJSON_CreateObject();
        if (!conv) continue;

        char pubkey_hex[PUBKEY_SIZE * 2 + 1];
        sodium_bin2hex(pubkey_hex, sizeof(pubkey_hex), conversations[i].pubkey, PUBKEY_SIZE);

        cJSON_AddStringToObject(conv, "with", pubkey_hex);
        cJSON_AddNumberToObject(conv, "lastMessageTime", (double)conversations[i].last_message_time);
        cJSON_AddNumberToObject(conv, "messageCount", conversations[i].message_count);
        cJSON_AddStringToObject(conv, "lastMessagePreview", conversations[i].last_message_preview);

        cJSON_AddItemToArray(root, conv);
    }

    char* json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    gossip_store_free_messages(messages, count);

    if (!json) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                      "{\"error\":\"Failed to serialize response\"}");
        return;
    }

    mg_http_reply(c, 200,
                  "Content-Type: application/json\r\n"
                  "Access-Control-Allow-Origin: *\r\n",
                  "%s", json);
    free(json);
}

