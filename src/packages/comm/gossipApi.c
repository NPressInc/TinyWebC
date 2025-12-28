#include "gossipApi.h"
#include "userMessagesApi.h"
#include "messagesApi.h"
#include "packages/sql/message_store.h"
#include "packages/validation/message_validation.h"
#include "message.pb-c.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sodium.h>
#include <time.h>
#include <openssl/sha.h>
#include <cJSON.h>
#include "external/mongoose/mongoose.h"
#include "packages/sql/schema.h"
#include "packages/sql/database_gossip.h"
#include "packages/sql/permissions.h"
#include "packages/sql/gossip_peers.h"
#include "packages/transactions/envelope.h"
#include "packages/utils/logger.h"
#include "structs/permission/permission.h"
#include "envelope.pb-c.h"
#include "content.pb-c.h"
#include "api.pb-c.h"

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

GossipService* gossip_api_get_service(void) {
    return g_server.service;
}

static void* gossip_api_loop(void* arg);
static void gossip_api_handler(struct mg_connection* c, int ev, void* ev_data);
static void handle_gossip_message(struct mg_connection* c, struct mg_http_message* hm);
static void handle_get_peers(struct mg_connection* c, struct mg_http_message* hm);
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
        logger_error("http_api", "failed to listen on %s", addr);
        mg_mgr_free(&g_server.mgr);
        memset(&g_server, 0, sizeof(g_server));
        return -1;
    }

    g_server.running = 1;
    g_server.initialized = 1;

    if (pthread_create(&g_server.thread, NULL, gossip_api_loop, NULL) != 0) {
        logger_error("http_api", "failed to start HTTP thread");
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
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message* hm = (struct mg_http_message*)ev_data;
        
        // Log all incoming HTTP requests for debugging
        char uri_buf[256] = {0};
        char method_buf[16] = {0};
        size_t uri_len = hm->uri.len < sizeof(uri_buf) - 1 ? hm->uri.len : sizeof(uri_buf) - 1;
        size_t method_len = hm->method.len < sizeof(method_buf) - 1 ? hm->method.len : sizeof(method_buf) - 1;
        memcpy(uri_buf, hm->uri.buf, uri_len);
        memcpy(method_buf, hm->method.buf, method_len);
        logger_info("http_api", "HTTP request: %s %s (body_len=%zu, message_len=%zu)", 
                     method_buf, uri_buf, hm->body.len, hm->message.len);

        // Handle OPTIONS requests globally (CORS preflight) - must be first
        if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
            logger_info("http_api", "OPTIONS preflight for %s", uri_buf);
            
            // Determine allowed methods based on endpoint
            const char* allowed_methods = "GET, POST, OPTIONS";
            if (mg_strcmp(hm->uri, mg_str("/messages/submit")) == 0 ||
                mg_strcmp(hm->uri, mg_str("/gossip/message")) == 0) {
                allowed_methods = "POST, OPTIONS";
            } else if (mg_strcmp(hm->uri, mg_str("/gossip/peers")) == 0 ||
                       mg_strcmp(hm->uri, mg_str("/health")) == 0 ||
                       mg_strcmp(hm->uri, mg_str("/messages/recent")) == 0 ||
                       mg_strcmp(hm->uri, mg_str("/messages/conversation")) == 0 ||
                       mg_strcmp(hm->uri, mg_str("/messages/conversations")) == 0 ||
                       mg_strcmp(hm->uri, mg_str("/users")) == 0) {
                allowed_methods = "GET, OPTIONS";
            }
            // Build CORS headers string
            char cors_headers[512];
            snprintf(cors_headers, sizeof(cors_headers),
                     "Access-Control-Allow-Origin: *\r\n"
                     "Access-Control-Allow-Methods: %s\r\n"
                     "Access-Control-Allow-Headers: Content-Type, X-User-Pubkey, X-Signature, X-Timestamp\r\n"
                     "Access-Control-Max-Age: 86400\r\n"
                     "Content-Length: 0\r\n",
                     allowed_methods);
            mg_http_reply(c, 200, cors_headers, "");
            logger_info("http_api", "OPTIONS preflight handled for %s", uri_buf);
            return;
        }

        if (mg_strcmp(hm->uri, mg_str("/gossip/message")) == 0) {
            if (mg_strcmp(hm->method, mg_str("POST")) == 0) {
                handle_gossip_message(c, hm);
            } else {
                mg_http_reply(c, 405, "Content-Type: application/json\r\n"
                              "Access-Control-Allow-Origin: *\r\n",
                              "{\"error\":\"Method Not Allowed\"}");
            }
        } else if (mg_strcmp(hm->uri, mg_str("/gossip/peers")) == 0) {
            if (mg_strcmp(hm->method, mg_str("GET")) == 0) {
                handle_get_peers(c, hm);
            } else {
                mg_http_reply(c, 405, "Content-Type: application/json\r\n"
                              "Access-Control-Allow-Origin: *\r\n",
                              "{\"error\":\"Method Not Allowed\"}");
            }
        } else if (mg_strcmp(hm->uri, mg_str("/health")) == 0) {
            // Health check endpoint for Docker healthchecks
            if (mg_strcmp(hm->method, mg_str("GET")) == 0) {
                mg_http_reply(c, 200,
                              "Content-Type: application/json\r\n"
                              "Access-Control-Allow-Origin: *\r\n",
                              "{\"status\":\"healthy\",\"service\":\"tinyweb\"}");
            } else {
                mg_http_reply(c, 405, "Content-Type: application/json\r\n"
                              "Access-Control-Allow-Origin: *\r\n",
                              "{\"error\":\"Method Not Allowed\"}");
            }
        } else {
            // Check messaging API first
            if (messages_api_handler(c, hm)) {
                return;
            }

            // Then, let the user-messages/read API try
            if (user_messages_api_handler(c, hm)) {
                return;
            }

            // Not handled by either module
            logger_info("http_api", "404 Not Found: %.*s %.*s", 
                       (int)hm->method.len, hm->method.buf, (int)hm->uri.len, hm->uri.buf);
            mg_http_reply(c, 404, "Content-Type: application/json\r\n"
                          "Access-Control-Allow-Origin: *\r\n",
                          "{\"error\":\"Not Found\"}");
        }
    }
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

static void handle_get_peers(struct mg_connection* c, struct mg_http_message* hm) {
    (void)hm; // Unused parameter
    
    // Fetch all peers from database
    GossipPeerInfo* peers = NULL;
    size_t peer_count = 0;
    
    if (gossip_peers_fetch_all(&peers, &peer_count) != 0) {
        logger_error("http_api", "handle_get_peers: failed to fetch peers");
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to fetch peers\"}");
        return;
    }
    
    // Build JSON response
    cJSON* json = cJSON_CreateObject();
    cJSON* peers_array = cJSON_CreateArray();
    
    for (size_t i = 0; i < peer_count; i++) {
        cJSON* peer_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(peer_obj, "hostname", peers[i].hostname);
        cJSON_AddNumberToObject(peer_obj, "gossip_port", peers[i].gossip_port);
        cJSON_AddNumberToObject(peer_obj, "api_port", peers[i].api_port);
        cJSON_AddNumberToObject(peer_obj, "first_seen", (double)peers[i].first_seen);
        cJSON_AddNumberToObject(peer_obj, "last_seen", (double)peers[i].last_seen);
        if (strlen(peers[i].tags) > 0) {
            cJSON_AddStringToObject(peer_obj, "tags", peers[i].tags);
        }
        // Add pubkey as hex if present
        if (peers[i].node_pubkey[0] != 0 || memcmp(peers[i].node_pubkey, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 32) != 0) {
            char* pubkey_hex = hex_encode(peers[i].node_pubkey, 32);
            if (pubkey_hex) {
                cJSON_AddStringToObject(peer_obj, "node_pubkey", pubkey_hex);
                free(pubkey_hex);
            }
        }
        cJSON_AddItemToArray(peers_array, peer_obj);
    }
    
    cJSON_AddItemToObject(json, "peers", peers_array);
    cJSON_AddNumberToObject(json, "count", (double)peer_count);
    
    char* json_string = cJSON_Print(json);
    cJSON_Delete(json);
    gossip_peers_free(peers, peer_count);
    
    if (!json_string) {
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to serialize response\"}");
        return;
    }
    
    mg_http_reply(c, 200,
                  "Content-Type: application/json\r\n"
                  "Access-Control-Allow-Origin: *\r\n",
                  "%s", json_string);
    
    free(json_string);
}

static void handle_gossip_message(struct mg_connection* c, struct mg_http_message* hm) {
    if (hm->body.len == 0) {
        mg_http_reply(c, 400, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Empty body\"}");
        return;
    }

    // 1. Unpack Message
    Tinyweb__Message* msg = tinyweb__message__unpack(NULL, hm->body.len, (const uint8_t*)hm->body.buf);
    if (!msg) {
        logger_error("gossip_api", "Failed to unpack message protobuf");
        mg_http_reply(c, 400, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Invalid protobuf\"}");
        return;
    }

    // 2. Validate Message (Signature, Timestamp, Size)
    MessageValidationResult val_res = message_validate(msg);
    if (val_res != MESSAGE_VALIDATION_OK) {
        logger_error("gossip_api", "Message validation failed: %s", message_validation_result_to_string(val_res));
        mg_http_reply(c, 422, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"%s\"}", 
                      message_validation_result_to_string(val_res));
        tinyweb__message__free_unpacked(msg, NULL);
        return;
    }

    // 3. Check Duplicate
    unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE];
    if (message_store_compute_digest(msg, digest) != 0) {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Internal error\"}");
        tinyweb__message__free_unpacked(msg, NULL);
        return;
    }

    int seen = 0;
    if (message_store_has_seen(digest, &seen) == 0 && seen) {
        tinyweb__message__free_unpacked(msg, NULL);
        mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\r\n", "{\"status\":\"duplicate\"}");
        return;
    }

    // 4. Store Message
    uint64_t expires_at = message_validation_get_expiration(msg);
    if (message_store_save(msg, expires_at) != 0) {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Storage failed\"}");
        tinyweb__message__free_unpacked(msg, NULL);
        return;
    }

    // 5. Mark Seen
    message_store_mark_seen(digest, expires_at);

    // 6. Rebroadcast via UDP Gossip
    if (g_server.service) {
        if (gossip_service_rebroadcast_message(g_server.service, msg, NULL) != 0) {
            logger_error("gossip_api", "Failed to rebroadcast message");
        }
    }

    // 7. Success Response
    mg_http_reply(c, 202, "Content-Type: application/json\r\n"
                         "Access-Control-Allow-Origin: *\r\n", 
                  "{\"status\":\"accepted\"}");

    tinyweb__message__free_unpacked(msg, NULL);
}
