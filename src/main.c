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
#include "packages/sql/schema.h"
#include "packages/sql/gossip_peers.h"
#include "packages/utils/statePaths.h"
#include "packages/utils/logger.h"
#include "packages/validation/gossip_validation.h"
#include "packages/transactions/envelope.h"
#include "packages/comm/gossipApi.h"
#include "packages/comm/envelope_dispatcher.h"
#include "packages/utils/config.h"
#include "packages/discovery/discovery.h"
#include "packages/transactions/envelope.h"
#include "packages/keystore/keystore.h"
#include "packages/encryption/encryption.h"
#include "content.pb-c.h"  // For Tinyweb__NodeRegistration
#include <netdb.h>  // For gethostbyaddr
#include <arpa/inet.h>  // For inet_ntoa

static volatile int g_running = 1;
static GossipService g_gossip_service;
static volatile int g_cleanup_running = 0;
static pthread_t g_cleanup_thread;
static bool g_cleanup_thread_started = false;
static bool g_http_server_running = false;

static void handle_signal(int sig);
static int parse_arguments(int argc, char* argv[], NodeConfig* config);
static int initialize_storage(const NodeConfig* config, NodeStatePaths* paths, char* db_path, size_t db_path_len);
static int load_node_config(NodeConfig* config, uint32_t node_id, bool debug_mode);
static int start_gossip_service(uint16_t port, const GossipValidationConfig* validation_config, const NodeConfig* config);
static void bootstrap_known_peers(GossipService* service);
static void stop_gossip_service(void);
static int start_http_api(uint16_t port, const GossipValidationConfig* validation_config);
static void stop_http_api(void);
static int gossip_receive_handler(GossipService* service, Tinyweb__Envelope* envelope, const struct sockaddr_in* source, void* context);
static void discover_peer_from_source(GossipService* service, const struct sockaddr_in* source);
static void handle_node_announcement(GossipService* service, const Tinyweb__Envelope* envelope, const struct sockaddr_in* source);
static int send_node_announcement(GossipService* service, const NodeConfig* config);
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
    printf("  -d, --debug              Enable debug logging (deprecated, kept for compatibility)\n");
    printf("  -h, --help               Show this help message\n");
}

static int parse_arguments(int argc, char* argv[], NodeConfig* config) {
    // Set defaults first
    config_set_defaults(config);
    
    // Parse node_id from command line (required for loading config)
    uint32_t node_id = 0;
    bool debug_mode = false;

    for (int i = 1; i < argc; ++i) {
        if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--id") == 0) && i + 1 < argc) {
            node_id = (uint32_t)atoi(argv[++i]);
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
            debug_mode = true;
            config->debug_mode = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else {
            logger_error("main", "Unknown option: %s", argv[i]);
            return -1;
        }
    }
    
    // Load config from network_config.json
    if (load_node_config(config, node_id, debug_mode) != 0) {
        logger_error("main", "Failed to load node configuration");
        return -1;
    }
    
    // Load environment variable overrides
    NodeConfig env_config;
    memset(&env_config, 0, sizeof(env_config));
    config_load_from_env(&env_config);
    config_merge(config, &env_config);
    
    // Command-line arguments override everything
    if (node_id > 0) {
        snprintf(config->node_id, sizeof(config->node_id), "node_%02u", node_id);
    }
    if (config->gossip_port == 0) {
        config->gossip_port = 9000; // Default
    }
    if (config->api_port == 0) {
        config->api_port = 8000; // Default
    }

    return 0;
}

static int load_node_config(NodeConfig* config, uint32_t node_id, bool debug_mode) {
    if (!config) {
        return -1;
    }
    
    // Set defaults first
    config_set_defaults(config);
    config->debug_mode = debug_mode;
    
    // Determine node_id
    if (node_id == 0) {
        // Try to get from environment
        const char* env_node_id = getenv("TINYWEB_NODE_ID");
        if (env_node_id) {
            node_id = (uint32_t)atoi(env_node_id);
        }
    }
    
    char node_id_str[64];
    if (node_id > 0) {
        snprintf(node_id_str, sizeof(node_id_str), "node_%02u", node_id);
        strncpy(config->node_id, node_id_str, sizeof(config->node_id) - 1);
    } else {
        // Default to node_01 if not specified
        strncpy(node_id_str, "node_01", sizeof(node_id_str) - 1);
        strncpy(config->node_id, node_id_str, sizeof(config->node_id) - 1);
    }
    
    // Note: Configuration should be loaded from database, not from network_config.json
    // network_config.json is only used during initialization (init_tool)
    // The main application reads from the database which was populated during init
    
    // Try to load from database (database must be initialized first)
    // This will be called after initialize_storage(), so DB should be available
    // For now, we'll load it after DB initialization in the main() function
    
    return 0; // Success - defaults are set, will load from DB later if available
}

static int initialize_storage(const NodeConfig* config, NodeStatePaths* paths, char* db_path, size_t db_path_len) {
    // Extract node_id from config->node_id (format: "node_01")
    uint32_t node_id = 0;
    if (config->node_id[0] != '\0' && sscanf(config->node_id, "node_%u", &node_id) == 1) {
        // Successfully parsed
    }
    
    if (!state_paths_init(node_id, config->debug_mode, paths)) {
        logger_error("main", "Failed to initialize state paths for node %s", config->node_id);
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

static int start_gossip_service(uint16_t port, const GossipValidationConfig* validation_config, const NodeConfig* config) {
    if (gossip_service_init(&g_gossip_service, port, gossip_receive_handler, validation_config) != 0) {
        logger_error("main", "Failed to initialize gossip service");
        return -1;
    }

    if (gossip_service_start(&g_gossip_service) != 0) {
        logger_error("main", "Failed to start gossip service");
        return -1;
    }

    // Run discovery before loading peers from database
    // This ensures discovery-discovered peers are added first, then DB peers loaded
    if (config) {
        int discovery_result = discover_peers(&g_gossip_service, config);
        if (discovery_result != 0) {
            // Discovery failed, but continue with graceful fallback to DB peers only
            logger_info("main", "Discovery failed, falling back to database peers only");
        }
    }

    bootstrap_known_peers(&g_gossip_service);

    // Phase 2.2: Send node announcement after discovery completes
    if (config) {
        if (send_node_announcement(&g_gossip_service, config) != 0) {
            logger_info("main", "Failed to send node announcement (non-fatal)");
        }
    }

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

static int start_http_api(uint16_t port, const GossipValidationConfig* validation_config) {
    if (g_http_server_running) {
        return 0;
    }

    if (gossip_api_start(port, &g_gossip_service, validation_config) != 0) {
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

    // Authorization check: Only accept messages from nodes whose public key is in gossip_peers whitelist
    if (envelope->header && envelope->header->sender_pubkey.data && envelope->header->sender_pubkey.len == 32) {
        GossipPeerInfo peer;
        if (gossip_peers_get_by_pubkey(envelope->header->sender_pubkey.data, &peer) != 0) {
            logger_error("gossip", "Rejected message from unauthorized node (public key not in whitelist)");
            return -1;
        }
    } else {
        logger_error("gossip", "Rejected message with invalid sender public key");
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

    // Phase 2.1: Dynamic Peer Addition on Message Receive
    // Check if source peer is known, if not, discover and add it
    if (source) {
        discover_peer_from_source(service, source);
    }

    // Phase 2.3: Handle Node Announcement Messages
    // Check if this is a node registration announcement
    if (envelope->header && 
        envelope->header->content_type == TINYWEB__CONTENT_TYPE__CONTENT_NODE_REGISTRATION) {
        handle_node_announcement(service, envelope, source);
    }

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

// Phase 2.1: Discover and add peer from source address
static void discover_peer_from_source(GossipService* service, const struct sockaddr_in* source) {
    if (!service || !source) {
        return;
    }

    // Extract source IP and port
    char source_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &source->sin_addr, source_ip, sizeof(source_ip));
    uint16_t source_port = ntohs(source->sin_port);

    // Check if peer already exists in peer list
    pthread_mutex_lock(&service->peer_lock);
    bool peer_exists = false;
    for (size_t i = 0; i < service->peer_count; ++i) {
        // Check if IP matches (we'll resolve hostname below)
        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        
        struct addrinfo* result = NULL;
        if (getaddrinfo(service->peers[i].address, NULL, &hints, &result) == 0) {
            for (struct addrinfo* ai = result; ai != NULL; ai = ai->ai_next) {
                if (ai->ai_family == AF_INET) {
                    const struct sockaddr_in* peer_addr = (const struct sockaddr_in*)ai->ai_addr;
                    if (memcmp(&peer_addr->sin_addr, &source->sin_addr, sizeof(struct in_addr)) == 0 &&
                        service->peers[i].port == source_port) {
                        peer_exists = true;
                        break;
                    }
                }
            }
            freeaddrinfo(result);
            if (peer_exists) {
                break;
            }
        }
    }
    pthread_mutex_unlock(&service->peer_lock);

    if (peer_exists) {
        return; // Peer already known
    }

    // Unknown peer - resolve hostname via reverse DNS
    char hostname[256] = {0};
    struct hostent* host = gethostbyaddr(&source->sin_addr, sizeof(struct in_addr), AF_INET);
    if (host && host->h_name) {
        strncpy(hostname, host->h_name, sizeof(hostname) - 1);
    } else {
        // Fallback to IP address if DNS resolution fails
        strncpy(hostname, source_ip, sizeof(hostname) - 1);
    }

    // Use fixed gossip port (9000) as per plan
    uint16_t gossip_port = 9000;

    // Add peer dynamically
    if (gossip_service_add_peer(service, hostname, gossip_port) == 0) {
        logger_info("gossip", "Discovered new peer dynamically: %s:%u (from %s:%u)", 
                   hostname, gossip_port, source_ip, source_port);
        
        // Store in database for persistence
        if (db_is_initialized()) {
            if (gossip_peers_add_or_update(hostname, gossip_port, 0, NULL, NULL) == 0) {
                logger_info("gossip", "Stored discovered peer in database: %s:%u", hostname, gossip_port);
            } else {
                logger_info("gossip", "Failed to store discovered peer in database (non-fatal)");
            }
        }
    } else {
        logger_info("gossip", "Failed to add discovered peer %s:%u (may already exist or peer list full)", 
                   hostname, gossip_port);
    }
}

// Phase 2.3: Handle Node Announcement Messages
static void handle_node_announcement(GossipService* service, const Tinyweb__Envelope* envelope, const struct sockaddr_in* source) {
    if (!service || !envelope || !envelope->header || !source) {
        return;
    }

    // Attempt to decrypt the payload
    unsigned char* decrypted = NULL;
    size_t decrypted_len = 0;
    if (decrypt_envelope_payload(envelope, &decrypted, &decrypted_len) != 0) {
        // If decryption fails, we may not be a recipient (non-fatal)
        logger_info("gossip", "Could not decrypt node announcement (may not be a recipient)");
        return;
    }

    // Parse NodeRegistration protobuf message
    Tinyweb__NodeRegistration* node_reg = tinyweb__node_registration__unpack(NULL, decrypted_len, decrypted);
    free(decrypted);
    
    if (!node_reg) {
        logger_error("gossip", "Failed to parse NodeRegistration from announcement");
        return;
    }

    // Extract node info from payload
    const char* node_address = node_reg->node_address ? node_reg->node_address : NULL;
    uint32_t node_port = node_reg->node_port;  // Gossip port
    uint32_t api_port = node_reg->api_port;     // API port
    
    if (!node_address || node_port == 0) {
        logger_error("gossip", "Invalid NodeRegistration: missing address or gossip port");
        tinyweb__node_registration__free_unpacked(node_reg, NULL);
        return;
    }
    
    // Log API port if provided (for future use - nodes may need to make HTTP API calls to each other)
    if (api_port > 0) {
        logger_info("gossip", "Node announcement includes API port: %u", api_port);
    }

    // Extract source address for hostname verification
    char source_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &source->sin_addr, source_ip, sizeof(source_ip));
    uint16_t source_port = ntohs(source->sin_port);

    // Resolve hostname from source (for verification)
    char resolved_hostname[256] = {0};
    struct hostent* host = gethostbyaddr(&source->sin_addr, sizeof(struct in_addr), AF_INET);
    if (host && host->h_name) {
        strncpy(resolved_hostname, host->h_name, sizeof(resolved_hostname) - 1);
    } else {
        // Fallback to IP
        strncpy(resolved_hostname, source_ip, sizeof(resolved_hostname) - 1);
    }

    // Use the hostname from the announcement, or fallback to resolved hostname
    const char* peer_hostname = node_address;
    if (!peer_hostname || peer_hostname[0] == '\0') {
        peer_hostname = resolved_hostname;
    }

    // Use fixed gossip port (9000) as per plan, or use the port from announcement if it matches
    uint16_t gossip_port = (node_port == 9000) ? 9000 : 9000;  // Always use 9000 per plan

    // Add announcer as peer if not already known
    if (gossip_service_add_peer(service, peer_hostname, gossip_port) == 0) {
        logger_info("gossip", "Added peer from node announcement: %s:%u (from %s:%u)", 
                   peer_hostname, gossip_port, source_ip, source_port);
        
        // Store in database for persistence
        if (db_is_initialized()) {
            if (gossip_peers_add_or_update(peer_hostname, gossip_port, 0, NULL, NULL) == 0) {
                logger_info("gossip", "Stored announced peer in database: %s:%u", peer_hostname, gossip_port);
            } else {
                logger_info("gossip", "Failed to store announced peer in database (non-fatal)");
            }
        }
    } else {
        logger_info("gossip", "Peer from announcement already known or peer list full: %s:%u", 
                   peer_hostname, gossip_port);
    }

    tinyweb__node_registration__free_unpacked(node_reg, NULL);
}

// Phase 2.2: Send node announcement to all known peers
static int send_node_announcement(GossipService* service, const NodeConfig* config) {
    if (!service || !config) {
        return -1;
    }

    // Get node's public key from keystore
    unsigned char node_pubkey[32];
    if (keystore_get_public_key(node_pubkey) != 0) {
        logger_error("main", "Failed to get node public key for announcement");
        return -1;
    }

    // Create NodeRegistration protobuf message
    Tinyweb__NodeRegistration node_reg = TINYWEB__NODE_REGISTRATION__INIT;
    
    // Set node_pubkey (32 bytes)
    node_reg.node_pubkey.data = node_pubkey;
    node_reg.node_pubkey.len = 32;
    
    // Set node_address (hostname from config, or node_id as fallback)
    // Use static buffer to ensure it persists (protobuf will copy it during pack)
    static char node_address[256];
    if (config->hostname[0] != '\0') {
        snprintf(node_address, sizeof(node_address), "%s", config->hostname);
    } else if (config->node_id[0] != '\0') {
        snprintf(node_address, sizeof(node_address), "%s", config->node_id);
    } else {
        strncpy(node_address, "unknown", sizeof(node_address) - 1);
    }
    node_reg.node_address = node_address;
    
    // Set node_port (gossip_port, default 9000)
    node_reg.node_port = config->gossip_port > 0 ? config->gossip_port : 9000;
    
    // Set api_port (HTTP API port, default 8000)
    node_reg.api_port = config->api_port > 0 ? config->api_port : 8000;
    
    // Set node_version (optional, can be empty or a version string)
    node_reg.node_version = "1.0";  // Can be made configurable later
    
    // stake_proof is optional, leave it unset (NULL/empty)
    node_reg.stake_proof.data = NULL;
    node_reg.stake_proof.len = 0;

    // Pack the NodeRegistration message
    size_t content_size = tinyweb__node_registration__get_packed_size(&node_reg);
    if (content_size == 0) {
        logger_error("main", "Failed to get packed size for NodeRegistration");
        return -1;
    }

    unsigned char* content_data = malloc(content_size);
    if (!content_data) {
        logger_error("main", "Failed to allocate content buffer for NodeRegistration");
        return -1;
    }

    tinyweb__node_registration__pack(&node_reg, content_data);

    // Create envelope header
    // For broadcast, encrypt for sender (self) - peers will need to be able to decrypt
    // TODO: In future, collect peer public keys and encrypt for all known peers
    tw_envelope_header_view_t header = {
        .version = 1,
        .content_type = TINYWEB__CONTENT_TYPE__CONTENT_NODE_REGISTRATION,
        .schema_version = 1,
        .timestamp = (uint64_t)time(NULL),
        .sender_pubkey = node_pubkey,
        .recipients_pubkeys = node_pubkey,  // Encrypt for self (broadcast - all peers should be able to decrypt)
        .num_recipients = 1,
        .group_id = NULL,
        .group_id_len = 0
    };

    // Build and sign envelope
    Tinyweb__Envelope* envelope = NULL;
    int result = tw_envelope_build_and_sign(&header, content_data, content_size, &envelope);
    free(content_data);

    if (result != 0 || !envelope) {
        logger_error("main", "Failed to build and sign node announcement envelope");
        return -1;
    }

    // Broadcast to all currently known peers
    if (gossip_service_broadcast_envelope(service, envelope) != 0) {
        logger_error("main", "Failed to broadcast node announcement");
        tw_envelope_free(envelope);
        return -1;
    }

    logger_info("main", "Sent node announcement: %s (port %u)", node_address, node_reg.node_port);
    tw_envelope_free(envelope);
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
    NodeConfig config;
    NodeStatePaths paths;
    char db_path[MAX_STATE_PATH_LEN];
    GossipValidationConfig validation_config;

    // Initialize logger first
    if (logger_init() != 0) {
        fprintf(stderr, "Failed to initialize logger\n");
        return 1;
    }
    
    if (parse_arguments(argc, argv, &config) != 0) {
        print_usage(argv[0]);
        config_free(&config);
        return 1;
    }
    
    // Validate configuration
    if (config_validate(&config) != 0) {
        logger_error("main", "Configuration validation failed");
        config_free(&config);
        return 1;
    }
    
    // Set up validation config from node config
    validation_config.max_clock_skew_seconds = config.max_clock_skew_seconds;
    validation_config.message_ttl_seconds = config.message_ttl_seconds;
    validation_config.max_payload_bytes = config.max_payload_bytes;
    
    // Set log level from config
    logger_set_level(config.log_level);
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    if (sodium_init() < 0) {
        logger_error("main", "Failed to initialize libsodium");
        config_free(&config);
        return 1;
    }
    
    if (envelope_dispatcher_init() != 0) {
        logger_error("main", "Failed to initialize envelope dispatcher");
        config_free(&config);
        return 1;
    }
    
    if (initialize_storage(&config, &paths, db_path, sizeof(db_path)) != 0) {
        envelope_dispatcher_cleanup();
        config_free(&config);
        return 1;
    }
    
    // Load node configuration from database (populated during initialization)
    // If not found in database, use defaults that were already set
    char db_node_name[128] = {0};
    char db_hostname[256] = {0};
    char db_discovery_mode[32] = {0};
    char db_hostname_prefix[64] = {0};
    char db_dns_domain[256] = {0};
    uint16_t db_gossip_port = 0;
    uint16_t db_api_port = 0;
    
    if (nodes_get_by_id(config.node_id,
                       db_node_name, sizeof(db_node_name),
                       db_hostname, sizeof(db_hostname),
                       &db_gossip_port, &db_api_port,
                       db_discovery_mode, sizeof(db_discovery_mode),
                       db_hostname_prefix, sizeof(db_hostname_prefix),
                       db_dns_domain, sizeof(db_dns_domain)) == 0) {
        // Found in database, use those values
        if (db_node_name[0] != '\0') {
            strncpy(config.node_name, db_node_name, sizeof(config.node_name) - 1);
        }
        if (db_hostname[0] != '\0') {
            strncpy(config.hostname, db_hostname, sizeof(config.hostname) - 1);
        }
        if (db_gossip_port > 0) {
            config.gossip_port = db_gossip_port;
        }
        if (db_api_port > 0) {
            config.api_port = db_api_port;
        }
        if (db_discovery_mode[0] != '\0') {
            strncpy(config.discovery_mode, db_discovery_mode, sizeof(config.discovery_mode) - 1);
        }
        if (db_hostname_prefix[0] != '\0') {
            strncpy(config.hostname_prefix, db_hostname_prefix, sizeof(config.hostname_prefix) - 1);
        }
        if (db_dns_domain[0] != '\0') {
            strncpy(config.dns_domain, db_dns_domain, sizeof(config.dns_domain) - 1);
        }
        logger_info("main", "Loaded node configuration from database for %s", config.node_id);
    } else {
        // Not found in database, use defaults and store them
        logger_info("main", "Node configuration not found in database for %s, using defaults", config.node_id);
        
        // Store current configuration in database for future runs
        if (nodes_insert_or_update(
                config.node_id,
                config.node_name[0] != '\0' ? config.node_name : "Unknown Node",
                config.hostname[0] != '\0' ? config.hostname : config.node_id,
                config.gossip_port > 0 ? config.gossip_port : 9000,
                config.api_port > 0 ? config.api_port : 8000,
                config.discovery_mode[0] != '\0' ? config.discovery_mode : "static",
                config.hostname_prefix[0] != '\0' ? config.hostname_prefix : NULL,
                config.dns_domain[0] != '\0' ? config.dns_domain : NULL) != 0) {
            logger_info("main", "Failed to store node configuration in database (non-fatal)");
            // Non-fatal, continue
        }
    }
    
    if (start_gossip_service(config.gossip_port, &validation_config, &config) != 0) {
        stop_gossip_service();
        envelope_dispatcher_cleanup();
        db_close();
        config_free(&config);
        return 1;
    }
    
    if (start_http_api(config.api_port, &validation_config) != 0) {
        logger_error("main", "Failed to start HTTP API on port %u", config.api_port);
        stop_gossip_service();
        envelope_dispatcher_cleanup();
        db_close();
        config_free(&config);
        return 1;
    }
    
    printf("=================================================================\n");
    printf("🚀 TinyWeb Gossip Node Online\n");
    printf("=================================================================\n");
    printf("  Node ID:           %s\n", config.node_id);
    printf("  Node Name:         %s\n", config.node_name);
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

    config_free(&config);
    logger_cleanup();
    printf("Shutdown complete. Goodbye!\n");
    return 0;
}