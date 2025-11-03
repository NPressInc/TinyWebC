#include "gossip.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

typedef struct {
    GossipService* service;
} GossipThreadArgs;

static void* gossip_receive_loop(void* arg);
static void gossip_service_clear_peers(GossipService* service);

int gossip_service_init(GossipService* service,
                        uint16_t listen_port,
                        GossipMessageHandler handler,
                        void* handler_context) {
    if (!service) {
        return -1;
    }

    memset(service, 0, sizeof(*service));
    service->listen_port = listen_port;
    service->handler = handler;
    service->handler_context = handler_context;
    service->socket_fd = -1;

    if (pthread_mutex_init(&service->peer_lock, NULL) != 0) {
        return -1;
    }

    return 0;
}

int gossip_service_add_peer(GossipService* service,
                            const char* address,
                            uint16_t port) {
    if (!service || !address) {
        return -1;
    }

    pthread_mutex_lock(&service->peer_lock);

    if (service->peer_count >= GOSSIP_MAX_PEERS) {
        pthread_mutex_unlock(&service->peer_lock);
        return -1;
    }

    for (size_t i = 0; i < service->peer_count; ++i) {
        if (strncmp(service->peers[i].address, address, sizeof(service->peers[i].address)) == 0 &&
            service->peers[i].port == port) {
            pthread_mutex_unlock(&service->peer_lock);
            return 0;
        }
    }

    GossipPeer* peer = &service->peers[service->peer_count++];
    strncpy(peer->address, address, sizeof(peer->address) - 1);
    peer->address[sizeof(peer->address) - 1] = '\0';
    peer->port = port;

    pthread_mutex_unlock(&service->peer_lock);
    return 0;
}

int gossip_service_start(GossipService* service) {
    if (!service) {
        return -1;
    }

    if (service->running) {
        return 0;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("gossip socket");
        return -1;
    }

    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("gossip reuseaddr");
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(service->listen_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("gossip bind");
        close(fd);
        return -1;
    }

    service->socket_fd = fd;
    service->running = true;

    if (pthread_create(&service->receive_thread, NULL, gossip_receive_loop, service) != 0) {
        perror("gossip pthread_create");
        close(fd);
        service->socket_fd = -1;
        service->running = false;
        return -1;
    }

    return 0;
}

void gossip_service_stop(GossipService* service) {
    if (!service) {
        return;
    }

    if (service->running) {
        service->running = false;

        if (service->socket_fd >= 0) {
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(service->listen_port);
            addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

            sendto(service->socket_fd, "\0", 1, 0, (struct sockaddr*)&addr, sizeof(addr));

            pthread_join(service->receive_thread, NULL);
        }
    }

    if (service->socket_fd >= 0) {
        close(service->socket_fd);
        service->socket_fd = -1;
    }

    gossip_service_clear_peers(service);
    pthread_mutex_destroy(&service->peer_lock);
}

int gossip_service_broadcast_transaction(GossipService* service,
                                         TW_Transaction* transaction) {
    if (!service || service->socket_fd < 0 || !transaction) {
        return -1;
    }

    size_t serialized_size = TW_Transaction_get_size(transaction);
    if (serialized_size == 0 || serialized_size > GOSSIP_MAX_MESSAGE_SIZE) {
        return -1;
    }

    unsigned char* buffer = malloc(serialized_size);
    if (!buffer) {
        return -1;
    }

    unsigned char* write_ptr = buffer;
    if (TW_Transaction_serialize(transaction, &write_ptr) != 0) {
        free(buffer);
        return -1;
    }

    pthread_mutex_lock(&service->peer_lock);

    for (size_t i = 0; i < service->peer_count; ++i) {
        struct sockaddr_in dest;
        memset(&dest, 0, sizeof(dest));
        dest.sin_family = AF_INET;
        dest.sin_port = htons(service->peers[i].port);

        if (inet_pton(AF_INET, service->peers[i].address, &dest.sin_addr) <= 0) {
            continue;
        }

        ssize_t sent = sendto(service->socket_fd,
                              buffer,
                              serialized_size,
                              0,
                              (struct sockaddr*)&dest,
                              sizeof(dest));

        if (sent < 0) {
            perror("gossip sendto");
        }
    }

    pthread_mutex_unlock(&service->peer_lock);

    free(buffer);
    return 0;
}

size_t gossip_service_peer_count(const GossipService* service) {
    if (!service) {
        return 0;
    }
    return service->peer_count;
}

static void* gossip_receive_loop(void* arg) {
    GossipService* service = (GossipService*)arg;
    unsigned char buffer[GOSSIP_MAX_MESSAGE_SIZE];

    while (service->running) {
        struct sockaddr_in source;
        socklen_t source_len = sizeof(source);
        ssize_t bytes = recvfrom(service->socket_fd,
                                 buffer,
                                 sizeof(buffer),
                                 0,
                                 (struct sockaddr*)&source,
                                 &source_len);

        if (bytes <= 0) {
            if (!service->running) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            perror("gossip recvfrom");
            continue;
        }

        TW_Transaction* txn = TW_Transaction_deserialize(buffer, (size_t)bytes);
        if (!txn) {
            continue;
        }

        if (service->handler) {
            if (service->handler(service, txn, &source, service->handler_context) != 0) {
                fprintf(stderr, "gossip: handler rejected transaction type %d\n", txn->type);
            }
        }

        TW_Transaction_destroy(txn);
    }

    return NULL;
}

static void gossip_service_clear_peers(GossipService* service) {
    pthread_mutex_lock(&service->peer_lock);
    memset(service->peers, 0, sizeof(service->peers));
    service->peer_count = 0;
    pthread_mutex_unlock(&service->peer_lock);
}

