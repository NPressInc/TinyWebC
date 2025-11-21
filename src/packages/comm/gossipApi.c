#include "gossipApi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sodium.h>
#include <cjson/cJSON.h>
#include <time.h>
#include <openssl/sha.h>
#include "external/mongoose/mongoose.h"
#include "packages/sql/gossip_store.h"
#include "packages/sql/database_gossip.h"
#include "packages/sql/permissions.h"
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

static void* gossip_api_loop(void* arg);
static void gossip_api_handler(struct mg_connection* c, int ev, void* ev_data);
static void handle_get_recent(struct mg_connection* c, struct mg_http_message* hm);
static void handle_get_messages(struct mg_connection* c, struct mg_http_message* hm);
static void handle_get_conversations(struct mg_connection* c, struct mg_http_message* hm);
static int hex_decode(const char* hex, unsigned char** out, size_t* out_len);
static char* hex_encode(const unsigned char* data, size_t len);
static void compute_envelope_hash(const unsigned char* serialized, size_t len, unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE]);
static Tinyweb__StoredEnvelope* gossip_stored_to_protobuf(const GossipStoredEnvelope* stored);
static void gossip_stored_protobuf_free(Tinyweb__StoredEnvelope* env);
static Tinyweb__EnvelopeList* gossip_create_envelope_list(const GossipStoredEnvelope* stored_envs, size_t count);
static void gossip_envelope_list_free(Tinyweb__EnvelopeList* list);

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
    (void)ev_data;
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message* hm = (struct mg_http_message*)ev_data;

        if (mg_strcmp(hm->uri, mg_str("/gossip/envelope")) == 0) {
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

                // Validate envelope
                uint64_t now = (uint64_t)time(NULL);
                GossipValidationResult res = gossip_validate_envelope(env, g_server.config, now);
                if (res != GOSSIP_VALIDATION_OK) {
                    const char* msg = gossip_validation_error_string(res);
                    tinyweb__envelope__free_unpacked(env, NULL);
                    cJSON_Delete(root);
                    mg_http_reply(c, 422, "Content-Type: application/json\r\n",
                                  "{\"error\":\"%s\"}", msg);
                    return;
                }

                // Check permission: user must have SEND_MESSAGE permission
                if (env->header && env->header->sender_pubkey.data && env->header->sender_pubkey.len == 32) {
                    // Determine scope based on content type
                    permission_scope_t scope = SCOPE_DIRECT; // Default
                    if (env->header->content_type == TINYWEB__CONTENT_TYPE__CONTENT_GROUP_MESSAGE) {
                        scope = SCOPE_PRIMARY_GROUP; // Will check both PRIMARY and EXTENDED in handler
                    }
                    
                    if (!check_user_permission(env->header->sender_pubkey.data, 
                                             PERMISSION_SEND_MESSAGE, scope)) {
                        tinyweb__envelope__free_unpacked(env, NULL);
                        cJSON_Delete(root);
                        mg_http_reply(c, 403, "Content-Type: application/json\r\n",
                                      "{\"error\":\"Permission denied: user does not have permission to send messages\"}");
                        return;
                    }
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

                // Compute digest for duplicate detection
                unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE] = {0};
                compute_envelope_hash(ser, ser_len, digest);

                // Check if we've already seen this envelope
                int seen = 0;
                if (db_is_initialized()) {
                    if (gossip_store_has_seen(digest, &seen) != 0) {
                        logger_error("http_api", "failed to check envelope digest cache");
                    } else if (seen) {
                        free(ser);
                        tinyweb__envelope__free_unpacked(env, NULL);
                        cJSON_Delete(root);
                        mg_http_reply(c, 200,
                                      "Content-Type: application/json\r\n"
                                      "Access-Control-Allow-Origin: *\r\n",
                                      "{\"status\":\"duplicate\"}");
                        return;
                    }
                }

                // Calculate expiration using validation config
                uint64_t expires_at = gossip_validation_expiration(env, g_server.config);
                
                // Store envelope using the new gossip_store API
                if (db_is_initialized()) {
                    const Tinyweb__EnvelopeHeader* hdr = env->header;
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

                // Mark as seen
                if (gossip_store_mark_seen(digest, expires_at) != 0) {
                    logger_error("http_api", "failed to record envelope digest");
                }

                // Rebroadcast via UDP gossip
                if (g_server.service) {
                    if (gossip_service_rebroadcast_envelope(g_server.service, env, NULL) != 0) {
                        logger_error("http_api", "failed to rebroadcast envelope");
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

static void handle_get_recent(struct mg_connection* c, struct mg_http_message* hm) {
    // Parse limit query parameter (default 50)
    uint32_t limit = 50;
    struct mg_str query = hm->query;
    if (query.len > 0) {
        char query_str[256];
        size_t len = query.len < sizeof(query_str) - 1 ? query.len : sizeof(query_str) - 1;
        memcpy(query_str, query.buf, len);
        query_str[len] = '\0';
        
        char* limit_str = strstr(query_str, "limit=");
        if (limit_str) {
            limit_str += 6; // Skip "limit="
            int parsed = atoi(limit_str);
            if (parsed > 0 && parsed <= 1000) {
                limit = (uint32_t)parsed;
            }
        }
    }
    
    // Fetch recent envelopes
    GossipStoredEnvelope* stored_envs = NULL;
    size_t count = 0;
    
    if (gossip_store_fetch_recent_envelopes(limit, &stored_envs, &count) != 0) {
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to fetch envelopes\"}");
        return;
    }
    
    // Convert to protobuf
    Tinyweb__EnvelopeList* list = gossip_create_envelope_list(stored_envs, count);
    gossip_store_free_envelopes(stored_envs, count);
    
    if (!list) {
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to create envelope list\"}");
        return;
    }
    
    // Serialize to protobuf
    size_t packed_size = tinyweb__envelope_list__get_packed_size(list);
    unsigned char* packed = malloc(packed_size);
    if (!packed) {
        gossip_envelope_list_free(list);
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to allocate memory\"}");
        return;
    }
    
    tinyweb__envelope_list__pack(list, packed);
    gossip_envelope_list_free(list);
    
    // Encode as hex for JSON response
    char* hex_encoded = hex_encode(packed, packed_size);
    free(packed);
    
    if (!hex_encoded) {
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to encode response\"}");
        return;
    }
    
    // Create JSON response with hex-encoded protobuf
    char* json_response = malloc(256 + strlen(hex_encoded));
    if (!json_response) {
        free(hex_encoded);
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to allocate memory\"}");
        return;
    }
    
    snprintf(json_response, 256 + strlen(hex_encoded),
             "{\"envelope_list_hex\":\"%s\"}", hex_encoded);
    
    free(hex_encoded);
    
    mg_http_reply(c, 200,
                  "Content-Type: application/json\r\n"
                  "Access-Control-Allow-Origin: *\r\n",
                  "%s", json_response);
    
    free(json_response);
}

static void compute_envelope_hash(const unsigned char* serialized, size_t len, unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE]) {
    // Compute SHA256 hash of the serialized envelope for duplicate detection
    unsigned char full_hash[SHA256_DIGEST_LENGTH];
    SHA256(serialized, len, full_hash);
    // Use first GOSSIP_SEEN_DIGEST_SIZE bytes (typically 32)
    memcpy(digest, full_hash, GOSSIP_SEEN_DIGEST_SIZE);
}

// Convert GossipStoredEnvelope to protobuf StoredEnvelope
static Tinyweb__StoredEnvelope* gossip_stored_to_protobuf(const GossipStoredEnvelope* stored) {
    if (!stored) return NULL;
    
    Tinyweb__StoredEnvelope* proto = calloc(1, sizeof(Tinyweb__StoredEnvelope));
    if (!proto) return NULL;
    
    tinyweb__stored_envelope__init(proto);
    
    proto->id = stored->id;
    proto->version = stored->version;
    proto->content_type = stored->content_type;
    proto->schema_version = stored->schema_version;
    proto->timestamp = stored->timestamp;
    proto->expires_at = stored->expires_at;
    
    // Copy sender pubkey
    proto->sender.data = malloc(PUBKEY_SIZE);
    if (!proto->sender.data) {
        free(proto);
        return NULL;
    }
    proto->sender.len = PUBKEY_SIZE;
    memcpy(proto->sender.data, stored->sender, PUBKEY_SIZE);
    
    // Copy envelope bytes
    if (stored->envelope && stored->envelope_size > 0) {
        proto->envelope.data = malloc(stored->envelope_size);
        if (!proto->envelope.data) {
            free(proto->sender.data);
            free(proto);
            return NULL;
        }
        proto->envelope.len = stored->envelope_size;
        memcpy(proto->envelope.data, stored->envelope, stored->envelope_size);
    }
    
    return proto;
}

// Free a protobuf StoredEnvelope
static void gossip_stored_protobuf_free(Tinyweb__StoredEnvelope* env) {
    if (env) {
        tinyweb__stored_envelope__free_unpacked(env, NULL);
    }
}

// Create EnvelopeList from array of GossipStoredEnvelope
static Tinyweb__EnvelopeList* gossip_create_envelope_list(const GossipStoredEnvelope* stored_envs, size_t count) {
    if (!stored_envs || count == 0) {
        Tinyweb__EnvelopeList* list = calloc(1, sizeof(Tinyweb__EnvelopeList));
        if (list) {
            tinyweb__envelope_list__init(list);
            list->n_envelopes = 0;
            list->total_count = 0;
        }
        return list;
    }
    
    Tinyweb__EnvelopeList* list = calloc(1, sizeof(Tinyweb__EnvelopeList));
    if (!list) return NULL;
    
    tinyweb__envelope_list__init(list);
    
    list->n_envelopes = count;
    list->envelopes = calloc(count, sizeof(Tinyweb__StoredEnvelope*));
    if (!list->envelopes) {
        free(list);
        return NULL;
    }
    
    list->total_count = (uint32_t)count;
    
    for (size_t i = 0; i < count; ++i) {
        list->envelopes[i] = gossip_stored_to_protobuf(&stored_envs[i]);
        if (!list->envelopes[i]) {
            // Cleanup on error
            for (size_t j = 0; j < i; ++j) {
                gossip_stored_protobuf_free(list->envelopes[j]);
            }
            free(list->envelopes);
            free(list);
            return NULL;
        }
    }
    
    return list;
}

// Free EnvelopeList
static void gossip_envelope_list_free(Tinyweb__EnvelopeList* list) {
    if (list) {
        if (list->envelopes) {
            for (size_t i = 0; i < list->n_envelopes; ++i) {
                gossip_stored_protobuf_free(list->envelopes[i]);
            }
            free(list->envelopes);
        }
        tinyweb__envelope_list__free_unpacked(list, NULL);
    }
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
    // Parse query parameters: user=<pubkey>&with=<pubkey>
    unsigned char user_pubkey[PUBKEY_SIZE] = {0};
    unsigned char with_pubkey[PUBKEY_SIZE] = {0};
    bool has_user = false;
    bool has_with = false;
    
    struct mg_str query = hm->query;
    if (query.len > 0) {
        char query_str[512];
        size_t len = query.len < sizeof(query_str) - 1 ? query.len : sizeof(query_str) - 1;
        memcpy(query_str, query.buf, len);
        query_str[len] = '\0';
        
        // Parse user= parameter
        char* user_str = strstr(query_str, "user=");
        if (user_str) {
            user_str += 5; // Skip "user="
            char* end = strchr(user_str, '&');
            if (end) *end = '\0';
            
            unsigned char* decoded = NULL;
            size_t decoded_len = 0;
            if (hex_decode(user_str, &decoded, &decoded_len) == 0 && decoded_len == PUBKEY_SIZE) {
                memcpy(user_pubkey, decoded, PUBKEY_SIZE);
                has_user = true;
                free(decoded);
            }
        }
        
        // Parse with= parameter
        char* with_str = strstr(query_str, "with=");
        if (with_str) {
            with_str += 5; // Skip "with="
            char* end = strchr(with_str, '&');
            if (end) *end = '\0';
            
            unsigned char* decoded = NULL;
            size_t decoded_len = 0;
            if (hex_decode(with_str, &decoded, &decoded_len) == 0 && decoded_len == PUBKEY_SIZE) {
                memcpy(with_pubkey, decoded, PUBKEY_SIZE);
                has_with = true;
                free(decoded);
            }
        }
    }
    
    if (!has_user || !has_with) {
        mg_http_reply(c, 400,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Missing required parameters: user and with\"}");
        return;
    }
    
    // Fetch recent envelopes (we'll filter them)
    GossipStoredEnvelope* stored_envs = NULL;
    size_t count = 0;
    
    if (gossip_store_fetch_recent_envelopes(1000, &stored_envs, &count) != 0) {
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to fetch envelopes\"}");
        return;
    }
    
    // Filter envelopes: must be between user and with
    // Deserialize each envelope to check sender/recipients
    GossipStoredEnvelope* filtered = calloc(count, sizeof(GossipStoredEnvelope));
    size_t filtered_count = 0;
    
    for (size_t i = 0; i < count; ++i) {
        if (!stored_envs[i].envelope || stored_envs[i].envelope_size == 0) continue;
        
        // Deserialize envelope
        Tinyweb__Envelope* env = tinyweb__envelope__unpack(NULL, stored_envs[i].envelope_size, stored_envs[i].envelope);
        if (!env || !env->header) {
            continue;
        }
        
        // Check if sender matches user or with
        bool sender_matches = (env->header->sender_pubkey.len == PUBKEY_SIZE &&
                               (memcmp(env->header->sender_pubkey.data, user_pubkey, PUBKEY_SIZE) == 0 ||
                                memcmp(env->header->sender_pubkey.data, with_pubkey, PUBKEY_SIZE) == 0));
        
        // Check if recipients include the other party
        bool recipient_matches = false;
        if (env->header->n_recipients_pubkey > 0) {
            for (size_t j = 0; j < env->header->n_recipients_pubkey; ++j) {
                if (env->header->recipients_pubkey[j].len == PUBKEY_SIZE) {
                    if (memcmp(env->header->recipients_pubkey[j].data, user_pubkey, PUBKEY_SIZE) == 0 ||
                        memcmp(env->header->recipients_pubkey[j].data, with_pubkey, PUBKEY_SIZE) == 0) {
                        recipient_matches = true;
                        break;
                    }
                }
            }
        }
        
        // Include if it's a message between user and with
        if (sender_matches && recipient_matches) {
            // Copy envelope to filtered list
            filtered[filtered_count] = stored_envs[i];
            filtered[filtered_count].envelope = malloc(stored_envs[i].envelope_size);
            if (filtered[filtered_count].envelope) {
                memcpy(filtered[filtered_count].envelope, stored_envs[i].envelope, stored_envs[i].envelope_size);
                filtered_count++;
            }
        }
        
        tinyweb__envelope__free_unpacked(env, NULL);
    }
    
    // Convert to protobuf
    Tinyweb__EnvelopeList* list = gossip_create_envelope_list(filtered, filtered_count);
    
    // Free filtered envelopes (but not the envelope data, it's shared)
    for (size_t i = 0; i < filtered_count; ++i) {
        free(filtered[i].envelope);
    }
    free(filtered);
    gossip_store_free_envelopes(stored_envs, count);
    
    if (!list) {
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to create envelope list\"}");
        return;
    }
    
    // Serialize to protobuf
    size_t packed_size = tinyweb__envelope_list__get_packed_size(list);
    unsigned char* packed = malloc(packed_size);
    if (!packed) {
        gossip_envelope_list_free(list);
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to allocate memory\"}");
        return;
    }
    
    tinyweb__envelope_list__pack(list, packed);
    gossip_envelope_list_free(list);
    
    // Encode as hex for JSON response
    char* hex_encoded = hex_encode(packed, packed_size);
    free(packed);
    
    if (!hex_encoded) {
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to encode response\"}");
        return;
    }
    
    // Create JSON response with hex-encoded protobuf
    char* json_response = malloc(256 + strlen(hex_encoded));
    if (!json_response) {
        free(hex_encoded);
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to allocate memory\"}");
        return;
    }
    
    snprintf(json_response, 256 + strlen(hex_encoded),
             "{\"envelope_list_hex\":\"%s\"}", hex_encoded);
    
    free(hex_encoded);
    
    mg_http_reply(c, 200,
                  "Content-Type: application/json\r\n"
                  "Access-Control-Allow-Origin: *\r\n",
                  "%s", json_response);
    
    free(json_response);
}

static void handle_get_conversations(struct mg_connection* c, struct mg_http_message* hm) {
    // Parse query parameter: user=<pubkey>
    unsigned char user_pubkey[PUBKEY_SIZE] = {0};
    bool has_user = false;
    
    struct mg_str query = hm->query;
    if (query.len > 0) {
        char query_str[256];
        size_t len = query.len < sizeof(query_str) - 1 ? query.len : sizeof(query_str) - 1;
        memcpy(query_str, query.buf, len);
        query_str[len] = '\0';
        
        // Parse user= parameter
        char* user_str = strstr(query_str, "user=");
        if (user_str) {
            user_str += 5; // Skip "user="
            char* end = strchr(user_str, '&');
            if (end) *end = '\0';
            
            unsigned char* decoded = NULL;
            size_t decoded_len = 0;
            if (hex_decode(user_str, &decoded, &decoded_len) == 0 && decoded_len == PUBKEY_SIZE) {
                memcpy(user_pubkey, decoded, PUBKEY_SIZE);
                has_user = true;
                free(decoded);
            }
        }
    }
    
    if (!has_user) {
        mg_http_reply(c, 400,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Missing required parameter: user\"}");
        return;
    }
    
    // Fetch recent envelopes
    GossipStoredEnvelope* stored_envs = NULL;
    size_t count = 0;
    
    if (gossip_store_fetch_recent_envelopes(1000, &stored_envs, &count) != 0) {
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to fetch envelopes\"}");
        return;
    }
    
    // Group envelopes by conversation partner
    // Use a simple approach: track last message timestamp per partner
    #define MAX_PARTNERS 100
    struct {
        unsigned char pubkey[PUBKEY_SIZE];
        uint64_t last_timestamp;
    } partners[MAX_PARTNERS];
    size_t partner_count = 0;
    
    for (size_t i = 0; i < count; ++i) {
        if (!stored_envs[i].envelope || stored_envs[i].envelope_size == 0) continue;
        
        // Deserialize envelope
        Tinyweb__Envelope* env = tinyweb__envelope__unpack(NULL, stored_envs[i].envelope_size, stored_envs[i].envelope);
        if (!env || !env->header) {
            continue;
        }
        
        // Find the conversation partner (the other person in the conversation)
        unsigned char partner[PUBKEY_SIZE] = {0};
        bool found_partner = false;
        
        // If user is sender, partner is recipient
        if (env->header->sender_pubkey.len == PUBKEY_SIZE &&
            memcmp(env->header->sender_pubkey.data, user_pubkey, PUBKEY_SIZE) == 0) {
            // User is sender, find first recipient
            if (env->header->n_recipients_pubkey > 0 &&
                env->header->recipients_pubkey[0].len == PUBKEY_SIZE) {
                memcpy(partner, env->header->recipients_pubkey[0].data, PUBKEY_SIZE);
                found_partner = true;
            }
        } else {
            // User might be recipient, partner is sender
            if (env->header->sender_pubkey.len == PUBKEY_SIZE) {
                // Check if user is in recipients
                bool user_is_recipient = false;
                for (size_t j = 0; j < env->header->n_recipients_pubkey; ++j) {
                    if (env->header->recipients_pubkey[j].len == PUBKEY_SIZE &&
                        memcmp(env->header->recipients_pubkey[j].data, user_pubkey, PUBKEY_SIZE) == 0) {
                        user_is_recipient = true;
                        break;
                    }
                }
                if (user_is_recipient) {
                    memcpy(partner, env->header->sender_pubkey.data, PUBKEY_SIZE);
                    found_partner = true;
                }
            }
        }
        
        if (found_partner) {
            // Find or add partner
            size_t partner_idx = MAX_PARTNERS;
            for (size_t j = 0; j < partner_count; ++j) {
                if (memcmp(partners[j].pubkey, partner, PUBKEY_SIZE) == 0) {
                    partner_idx = j;
                    break;
                }
            }
            
            if (partner_idx == MAX_PARTNERS && partner_count < MAX_PARTNERS) {
                partner_idx = partner_count++;
                memcpy(partners[partner_idx].pubkey, partner, PUBKEY_SIZE);
                partners[partner_idx].last_timestamp = 0;
            }
            
            // Update last timestamp if this message is newer
            if (partner_idx < MAX_PARTNERS && stored_envs[i].timestamp > partners[partner_idx].last_timestamp) {
                partners[partner_idx].last_timestamp = stored_envs[i].timestamp;
            }
        }
        
        tinyweb__envelope__free_unpacked(env, NULL);
    }
    
    gossip_store_free_envelopes(stored_envs, count);
    
    // Create ConversationList protobuf
    Tinyweb__ConversationList* list = calloc(1, sizeof(Tinyweb__ConversationList));
    if (!list) {
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to allocate memory\"}");
        return;
    }
    
    tinyweb__conversation_list__init(list);
    list->n_conversations = partner_count;
    list->conversations = calloc(partner_count, sizeof(Tinyweb__ConversationSummary*));
    list->total_count = (uint32_t)partner_count;
    
    if (!list->conversations) {
        free(list);
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to allocate memory\"}");
        return;
    }
    
    for (size_t i = 0; i < partner_count; ++i) {
        Tinyweb__ConversationSummary* summary = calloc(1, sizeof(Tinyweb__ConversationSummary));
        if (!summary) {
            // Cleanup on error
            for (size_t j = 0; j < i; ++j) {
                tinyweb__conversation_summary__free_unpacked(list->conversations[j], NULL);
            }
            free(list->conversations);
            free(list);
            mg_http_reply(c, 500,
                          "Content-Type: application/json\r\n"
                          "Access-Control-Allow-Origin: *\r\n",
                          "{\"error\":\"Failed to allocate memory\"}");
            return;
        }
        
        tinyweb__conversation_summary__init(summary);
        
        summary->partner_pubkey.data = malloc(PUBKEY_SIZE);
        if (!summary->partner_pubkey.data) {
            free(summary);
            // Cleanup
            for (size_t j = 0; j < i; ++j) {
                tinyweb__conversation_summary__free_unpacked(list->conversations[j], NULL);
            }
            free(list->conversations);
            free(list);
            mg_http_reply(c, 500,
                          "Content-Type: application/json\r\n"
                          "Access-Control-Allow-Origin: *\r\n",
                          "{\"error\":\"Failed to allocate memory\"}");
            return;
        }
        
        summary->partner_pubkey.len = PUBKEY_SIZE;
        memcpy(summary->partner_pubkey.data, partners[i].pubkey, PUBKEY_SIZE);
        summary->last_message_timestamp = partners[i].last_timestamp;
        summary->unread_count = 0; // TODO: Implement unread count tracking
        
        list->conversations[i] = summary;
    }
    
    // Serialize to protobuf
    size_t packed_size = tinyweb__conversation_list__get_packed_size(list);
    unsigned char* packed = malloc(packed_size);
    if (!packed) {
        // Cleanup
        for (size_t i = 0; i < list->n_conversations; ++i) {
            tinyweb__conversation_summary__free_unpacked(list->conversations[i], NULL);
        }
        free(list->conversations);
        tinyweb__conversation_list__free_unpacked(list, NULL);
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to allocate memory\"}");
        return;
    }
    
    tinyweb__conversation_list__pack(list, packed);
    
    // Cleanup
    for (size_t i = 0; i < list->n_conversations; ++i) {
        tinyweb__conversation_summary__free_unpacked(list->conversations[i], NULL);
    }
    free(list->conversations);
    tinyweb__conversation_list__free_unpacked(list, NULL);
    
    // Encode as hex for JSON response
    char* hex_encoded = hex_encode(packed, packed_size);
    free(packed);
    
    if (!hex_encoded) {
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to encode response\"}");
        return;
    }
    
    // Create JSON response with hex-encoded protobuf
    char* json_response = malloc(256 + strlen(hex_encoded));
    if (!json_response) {
        free(hex_encoded);
        mg_http_reply(c, 500,
                      "Content-Type: application/json\r\n"
                      "Access-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to allocate memory\"}");
        return;
    }
    
    snprintf(json_response, 256 + strlen(hex_encoded),
             "{\"conversation_list_hex\":\"%s\"}", hex_encoded);
    
    free(hex_encoded);
    
    mg_http_reply(c, 200,
                  "Content-Type: application/json\r\n"
                  "Access-Control-Allow-Origin: *\r\n",
                  "%s", json_response);
    
    free(json_response);
}
