#ifndef TW_GOSSIP_H
#define TW_GOSSIP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <netinet/in.h>

#include "packages/transactions/transaction.h"

#define GOSSIP_MAX_PEERS 32
#define GOSSIP_MAX_MESSAGE_SIZE 8192

typedef struct {
    char address[64];
    uint16_t port;
} GossipPeer;

struct GossipService;

typedef int (*GossipMessageHandler)(struct GossipService* service,
                                    TW_Transaction* transaction,
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

    GossipMessageHandler handler;
    void* handler_context;
} GossipService;

int gossip_service_init(GossipService* service,
                        uint16_t listen_port,
                        GossipMessageHandler handler,
                        void* handler_context);

int gossip_service_add_peer(GossipService* service,
                            const char* address,
                            uint16_t port);

int gossip_service_start(GossipService* service);

void gossip_service_stop(GossipService* service);

int gossip_service_broadcast_transaction(GossipService* service,
                                         TW_Transaction* transaction);

size_t gossip_service_peer_count(const GossipService* service);

#endif // TW_GOSSIP_H

