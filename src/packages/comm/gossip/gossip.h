#ifndef TW_GOSSIP_H
#define TW_GOSSIP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>

#include "envelope.pb-c.h"

// Forward declaration for the new message type
struct Tinyweb__Message;

#define GOSSIP_MAX_PEERS 32
#define GOSSIP_MAX_MESSAGE_SIZE 8192

typedef struct {
    char address[256];
    uint16_t port;
    time_t last_success;        // Last successful message
    time_t last_failure;        // Last failure
    int consecutive_failures;   // Consecutive failure count
    bool is_healthy;            // Health status
    time_t last_health_check;   // Last health check time
} GossipPeer;

struct GossipService;

typedef int (*GossipEnvelopeHandler)(struct GossipService* service,
                                     Tinyweb__Envelope* envelope,
                                     const struct sockaddr_in* source,
                                     void* context);

typedef int (*GossipMessageHandler)(struct GossipService* service,
                                   struct Tinyweb__Message* message,
                                   const struct sockaddr_in* source,
                                   void* context);

typedef struct GossipService {
    int socket_fd;
    uint16_t listen_port;
    volatile bool running;

    GossipPeer peers[GOSSIP_MAX_PEERS];
    size_t peer_count;
    pthread_mutex_t peer_lock;

    pthread_t receive_thread;

    GossipEnvelopeHandler envelope_handler;
    GossipMessageHandler message_handler;
    void* handler_context;
} GossipService;

int gossip_service_init(GossipService* service,
                        uint16_t listen_port,
                        GossipEnvelopeHandler envelope_handler,
                        GossipMessageHandler message_handler,
                        void* handler_context);

int gossip_service_add_peer(GossipService* service,
                            const char* address,
                            uint16_t port);

int gossip_service_start(GossipService* service);

void gossip_service_stop(GossipService* service);

int gossip_service_broadcast_envelope(GossipService* service,
                                      Tinyweb__Envelope* envelope);

int gossip_service_rebroadcast_envelope(GossipService* service,
                                        Tinyweb__Envelope* envelope,
                                        const struct sockaddr_in* source);

// Forward declaration for Message protobuf
struct Tinyweb__Message;
typedef struct Tinyweb__Message Tinyweb__Message;

// Message broadcast functions (implemented in gossip.c)
int gossip_service_broadcast_message(GossipService* service,
                                     const Tinyweb__Message* message);

int gossip_service_rebroadcast_message(GossipService* service,
                                       const Tinyweb__Message* message,
                                       const struct sockaddr_in* source);

size_t gossip_service_peer_count(const GossipService* service);

#endif // TW_GOSSIP_H

