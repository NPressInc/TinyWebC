#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sodium.h>
#include <time.h>
#include <openssl/sha.h>

#include "packages/comm/gossip/gossip.h"
#include "packages/sql/database_gossip.h"
#include "packages/sql/gossip_store.h"
#include "packages/sql/gossip_peers.h"
#include "packages/utils/statePaths.h"
#include "packages/utils/logger.h"
#include "packages/validation/gossip_validation.h"
#include "packages/transactions/envelope.h"
#include "packages/comm/gossipApi.h"
#include "packages/comm/envelope_dispatcher.h"

typedef struct {
    uint32_t node_id;
    bool debug_mode;
    uint16_t gossip_port;
    uint16_t api_port;
} AppConfig;

static volatile int g_running = 1;
static GossipService g_gossip_service;
static GossipValidationConfig g_validation_config = {
    .max_clock_skew_seconds = 300,
    .message_ttl_seconds = 60ULL * 60ULL * 24ULL * 30ULL,
    .max_payload_bytes = 1024 * 1024  // 1MB max payload
};
static volatile int g_cleanup_running = 0;
static pthread_t g_cleanup_thread;
static bool g_cleanup_thread_started = false;
static bool g_http_server_running = false;

static void handle_signal(int sig);
static int parse_arguments(int argc, char* argv[], AppConfig* config);
static int initialize_storage(const AppConfig* config, NodeStatePaths* paths, char* db_path, size_t db_path_len);
static int start_gossip_service(uint16_t port);
static void bootstrap_known_peers(GossipService* service);
static void stop_gossip_service(void);
static int start_http_api(uint16_t port);
static void stop_http_api(void);
static int gossip_receive_handler(GossipService* service, Tinyweb__Envelope* envelope, const struct sockaddr_in* source, void* context);
static void* cleanup_loop(void* arg);

static void handle_signal(int sig) {
    (void)sig;
    printf("\nReceived shutdown signal. Stopping services...\n");
    g_running = 0;
    g_cleanup_running = 0;
}

static void print_usage(const char* program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("Options:\n");
    printf("  -i, --id <node_id>       Node identifier (default: 0)\n");
    printf("  -g, --gossip-port <port> Gossip UDP port (default: 9000)\n");
    printf("  -p, --api-port <port>    HTTP API port (default: 8000)\n");
    printf("  -d, --debug              Use test_state/ directories instead of state/\n");
    printf("  -h, --help               Show this help message\n");
}

static int parse_arguments(int argc, char* argv[], AppConfig* config) {
    config->node_id = 0;
    config->debug_mode = false;
    config->gossip_port = 9000;
    config->api_port = 8000;

    for (int i = 1; i < argc; ++i) {
        if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--id") == 0) && i + 1 < argc) {
            config->node_id = (uint32_t)atoi(argv[++i]);
        } else if ((strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--gossip-port") == 0) && i + 1 < argc) {
            uint32_t port = (uint32_t)atoi(argv[++i]);
            if (port < 1024 || port > 65535) {
                logger_error("main", "gossip port must be between 1024 and 65535");
                return -1;
            }
            config->gossip_port = (uint16_t)port;
        } else if ((strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--api-port") == 0) && i + 1 < argc) {
            uint32_t port = (uint32_t)atoi(argv[++i]);
            if (port < 1024 || port > 65535) {
                logger_error("main", "API port must be between 1024 and 65535");
                return -1;
            }
            config->api_port = (uint16_t)port;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--debug") == 0) {
            config->debug_mode = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else {
            logger_error("main", "Unknown option: %s", argv[i]);
            return -1;
        }
    }

    return 0;
}

static int initialize_storage(const AppConfig* config, NodeStatePaths* paths, char* db_path, size_t db_path_len) {
    if (!state_paths_init(config->node_id, config->debug_mode, paths)) {
        logger_error("main", "Failed to initialize state paths for node %u", config->node_id);
        return -1;
    }

    if (!state_paths_get_database_file(paths, db_path, db_path_len)) {
        logger_error("main", "Failed to resolve database path for node %u", config->node_id);
        return -1;
    }
    
    if (db_init_gossip(db_path) != 0) {
        logger_error("main", "Failed to initialize database at %s", db_path);
        return -1;
    }
    
    if (gossip_store_init() != 0) {
        logger_error("main", "Failed to initialize gossip message store");
        return -1;
    }

    if (gossip_peers_init() != 0) {
        logger_error("main", "Failed to initialize gossip peer store");
        return -1;
    }

    return 0;
}

static int start_gossip_service(uint16_t port) {
    if (gossip_service_init(&g_gossip_service, port, gossip_receive_handler, &g_validation_config) != 0) {
        logger_error("main", "Failed to initialize gossip service");
        return -1;
    }

    if (gossip_service_start(&g_gossip_service) != 0) {
        logger_error("main", "Failed to start gossip service");
        return -1;
    }

    bootstrap_known_peers(&g_gossip_service);

    g_cleanup_running = 1;
    if (pthread_create(&g_cleanup_thread, NULL, cleanup_loop, NULL) == 0) {
        g_cleanup_thread_started = true;
    } else {
        logger_error("main", "Failed to start gossip cleanup thread");
        g_cleanup_running = 0;
    }

    return 0;
}

static void stop_gossip_service(void) {
    g_cleanup_running = 0;
    if (g_cleanup_thread_started) {
        pthread_join(g_cleanup_thread, NULL);
        g_cleanup_thread_started = false;
    }
    gossip_service_stop(&g_gossip_service);
}

static int start_http_api(uint16_t port) {
    if (g_http_server_running) {
        return 0;
    }

    if (gossip_api_start(port, &g_gossip_service, &g_validation_config) != 0) {
        return -1;
    }

    g_http_server_running = true;
    return 0;
}

static void stop_http_api(void) {
    if (!g_http_server_running) {
        return;
    }

    gossip_api_stop();
    g_http_server_running = false;
}

static int gossip_receive_handler(GossipService* service, Tinyweb__Envelope* envelope, const struct sockaddr_in* source, void* context) {

    const GossipValidationConfig* config = (const GossipValidationConfig*)context;
    uint64_t now = (uint64_t)time(NULL);

    // Validate envelope
    GossipValidationResult result = gossip_validate_envelope(envelope, config, now);
    if (result != GOSSIP_VALIDATION_OK) {
        logger_error("gossip", "Rejected gossip envelope: %s", gossip_validation_error_string(result));
        return -1;
    }

    // Serialize envelope to compute digest
    unsigned char* ser = NULL;
    size_t ser_len = 0;
    if (tw_envelope_serialize(envelope, &ser, &ser_len) != 0) {
        logger_error("gossip", "Failed to serialize envelope for digest");
        return -1;
    }

    unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE] = {0};
    SHA256(ser, ser_len, digest);

    // Check if we've already seen this envelope
    int seen = 0;
    if (db_is_initialized()) {
        if (gossip_store_has_seen(digest, &seen) != 0) {
            logger_error("gossip", "failed to check gossip digest cache");
        } else if (seen) {
            free(ser);
            return 0;
        }
    }

    uint64_t expires_at = gossip_validation_expiration(envelope, config);
    if (db_is_initialized()) {
        const Tinyweb__EnvelopeHeader* hdr = envelope->header;
        if (gossip_store_save_envelope(hdr->version, hdr->content_type, hdr->schema_version,
                                       hdr->sender_pubkey.data, hdr->timestamp,
                                       ser, ser_len, expires_at) != 0) {
            logger_error("gossip", "Failed to persist gossip envelope");
            free(ser);
            return -1;
        }
        if (gossip_store_mark_seen(digest, expires_at) != 0) {
            logger_error("gossip", "failed to record gossip digest");
        }
    }

    free(ser);

    // Dispatch to content-specific handlers
    if (envelope_dispatch(envelope, NULL) != 0) {
        logger_error("gossip", "envelope dispatch failed, continuing anyway");
    }

    // Rebroadcast to other peers
    if (gossip_service_rebroadcast_envelope(service, envelope, source) != 0) {
        logger_error("gossip", "failed to rebroadcast gossip envelope");
    }

    return 0;
}

static void* cleanup_loop(void* arg) {
    (void)arg;

    while (g_cleanup_running) {
        sleep(60);
        if (!g_cleanup_running || !db_is_initialized()) {
            continue;
        }
        uint64_t now = (uint64_t)time(NULL);
        gossip_store_cleanup(now);
    }

    return NULL;
}

static void bootstrap_known_peers(GossipService* service) {
    if (!service) {
        return;
    }

    GossipPeerInfo* peers = NULL;
    size_t count = 0;
    if (gossip_peers_fetch_all(&peers, &count) != 0) {
        logger_error("main", "Failed to load bootstrap peers from database");
        return;
    }

    if (!peers || count == 0) {
        gossip_peers_free(peers, count);
        return;
    }

    size_t added = 0;
    for (size_t i = 0; i < count; ++i) {
        if (peers[i].hostname[0] == '\0' || peers[i].gossip_port == 0) {
            continue;
        }
        if (gossip_service_add_peer(service, peers[i].hostname, peers[i].gossip_port) == 0) {
            ++added;
        }
    }

    if (added > 0) {
        printf("Loaded %zu bootstrap peers from database\n", added);
    }

    gossip_peers_free(peers, count);
}

int main(int argc, char* argv[]) {
    AppConfig config;
    NodeStatePaths paths;
    char db_path[MAX_STATE_PATH_LEN];

    // Initialize logger first
    if (logger_init() != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return 1;
    }
    
    if (parse_arguments(argc, argv, &config) != 0) {
        print_usage(argv[0]);
        return 1;
    }
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    if (sodium_init() < 0) {
        logger_error("main", "Failed to initialize libsodium");
        return 1;
    }
    
    if (envelope_dispatcher_init() != 0) {
        logger_error("main", "Failed to initialize envelope dispatcher");
        return 1;
    }
    
    if (initialize_storage(&config, &paths, db_path, sizeof(db_path)) != 0) {
        envelope_dispatcher_cleanup();
        return 1;
    }
    
    if (start_gossip_service(config.gossip_port) != 0) {
        stop_gossip_service();
        envelope_dispatcher_cleanup();
        db_close();
        return 1;
    }
    
    if (start_http_api(config.api_port) != 0) {
        logger_error("main", "Failed to start HTTP API on port %u", config.api_port);
        stop_gossip_service();
        envelope_dispatcher_cleanup();
        db_close();
        return 1;
    }
    
    printf("=================================================================\n");
    printf("🚀 TinyWeb Gossip Node Online\n");
    printf("=================================================================\n");
    printf("  Node ID:           %u\n", config.node_id);
    printf("  Gossip UDP Port:   %u\n", config.gossip_port);
    printf("  HTTP API Port:     %u\n", config.api_port);
    printf("  Storage Path:      %s\n", db_path);
    printf("-----------------------------------------------------------------\n");
    printf("Waiting for gossip traffic... Press Ctrl+C to exit.\n");

    while (g_running) {
        sleep(1);
    }

    stop_http_api();
    stop_gossip_service();

    envelope_dispatcher_cleanup();

    if (db_is_initialized()) {
        gossip_store_cleanup((uint64_t)time(NULL));
        db_close();
    }

    logger_cleanup();
    printf("Shutdown complete. Goodbye!\n");
    return 0;
}