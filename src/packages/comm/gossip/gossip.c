#include "gossip.h"
#include "message.pb-c.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include "packages/utils/logger.h"
#include "packages/utils/error.h"
#include "packages/utils/retry.h"
#include <time.h>

typedef struct {
    GossipService* service;
} GossipThreadArgs;

static void* gossip_receive_loop(void* arg);
static void gossip_service_clear_peers(GossipService* service);

int gossip_service_init(GossipService* service,
                        uint16_t listen_port,
                        GossipEnvelopeHandler envelope_handler,
                        GossipMessageHandler message_handler,
                        void* handler_context) {
    if (!service) {
        return -1;
    }

    memset(service, 0, sizeof(*service));
    service->listen_port = listen_port;
    service->envelope_handler = envelope_handler;
    service->message_handler = message_handler;
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
    peer->last_success = 0;
    peer->last_failure = 0;
    peer->consecutive_failures = 0;
    peer->is_healthy = true;
    peer->last_health_check = 0;

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
        tw_error_create(TW_ERROR_NETWORK_ERROR, "gossip", __func__, __LINE__, "Failed to create socket: %s", strerror(errno));
        logger_error("gossip", "Failed to create socket: %s", strerror(errno));
        return -1;
    }

    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        tw_error_create(TW_ERROR_NETWORK_ERROR, "gossip", __func__, __LINE__, "Failed to set SO_REUSEADDR: %s", strerror(errno));
        logger_error("gossip", "Failed to set SO_REUSEADDR: %s", strerror(errno));
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(service->listen_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        tw_error_create(TW_ERROR_NETWORK_ERROR, "gossip", __func__, __LINE__, "Failed to bind to port %u: %s", service->listen_port, strerror(errno));
        logger_error("gossip", "Failed to bind to port %u: %s", service->listen_port, strerror(errno));
        close(fd);
        return -1;
    }

    service->socket_fd = fd;
    service->running = true;

    if (pthread_create(&service->receive_thread, NULL, gossip_receive_loop, service) != 0) {
        tw_error_create(TW_ERROR_NETWORK_ERROR, "gossip", __func__, __LINE__, "Failed to create receive thread: %s", strerror(errno));
        logger_error("gossip", "Failed to create receive thread: %s", strerror(errno));
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

static int gossip_service_send_data(GossipService* service,
                                    const unsigned char* buffer,
                                    size_t serialized_size,
                                    const struct sockaddr_in* exclude_source) {
    if (!service || service->socket_fd < 0 || !buffer || serialized_size == 0) {
        return -1;
    }

    pthread_mutex_lock(&service->peer_lock);

    for (size_t i = 0; i < service->peer_count; ++i) {
        // Skip unhealthy peers (circuit breaker pattern)
        if (!service->peers[i].is_healthy) {
            // Periodically retry unhealthy peers (every 60 seconds)
            time_t now = time(NULL);
            if (now - service->peers[i].last_health_check > 60) {
                service->peers[i].last_health_check = now;
                // Will try this peer
            } else {
                continue; // Skip unhealthy peer
            }
        }
        
        char port_str[6];
        snprintf(port_str, sizeof(port_str), "%u", service->peers[i].port);

        struct addrinfo hints;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET; // Force IPv4 for simplicity in memcmp below
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        struct addrinfo* result = NULL;
        int rc = getaddrinfo(service->peers[i].address, port_str, &hints, &result);
        if (rc != 0) {
            logger_error("gossip", "failed to resolve %s: %s", service->peers[i].address, gai_strerror(rc));
            continue;
        }

        for (struct addrinfo* ai = result; ai != NULL; ai = ai->ai_next) {
            if (exclude_source && ai->ai_family == AF_INET) {
                const struct sockaddr_in* dest = (const struct sockaddr_in*)ai->ai_addr;
                if (dest->sin_port == exclude_source->sin_port &&
                    memcmp(&dest->sin_addr, &exclude_source->sin_addr, sizeof(struct in_addr)) == 0) {
                    continue;
                }
            }

            ssize_t sent = sendto(service->socket_fd,
                                  buffer,
                                  serialized_size,
                                  0,
                                  ai->ai_addr,
                                  ai->ai_addrlen);
            time_t now = time(NULL);
            if (sent < 0) {
                // Track failure
                service->peers[i].last_failure = now;
                service->peers[i].consecutive_failures++;
                if (service->peers[i].consecutive_failures >= 3) {
                    service->peers[i].is_healthy = false;
                }
                tw_error_create(TW_ERROR_NETWORK_ERROR, "gossip", __func__, __LINE__, "Failed to send to %s:%u: %s", service->peers[i].address, service->peers[i].port, strerror(errno));
                logger_error("gossip", "Failed to send to %s:%u: %s", service->peers[i].address, service->peers[i].port, strerror(errno));
                continue;
            } else {
                // Track success
                service->peers[i].last_success = now;
                service->peers[i].consecutive_failures = 0;
                service->peers[i].is_healthy = true;
            }
        }

        freeaddrinfo(result);
    }

    pthread_mutex_unlock(&service->peer_lock);
    return 0;
}

static int gossip_service_send_envelope(GossipService* service,
                                         Tinyweb__Envelope* envelope,
                                         const struct sockaddr_in* exclude_source) {
    if (!service || !envelope) return -1;

    size_t size = tinyweb__envelope__get_packed_size(envelope);
    if (size == 0 || size > GOSSIP_MAX_MESSAGE_SIZE) return -1;

    unsigned char* buf = malloc(size);
    if (!buf) return -1;

    tinyweb__envelope__pack(envelope, buf);
    int rc = gossip_service_send_data(service, buf, size, exclude_source);
    free(buf);
    return rc;
}

int gossip_service_broadcast_envelope(GossipService* service,
                                      Tinyweb__Envelope* envelope) {
    return gossip_service_send_envelope(service, envelope, NULL);
}

int gossip_service_rebroadcast_envelope(GossipService* service,
                                        Tinyweb__Envelope* envelope,
                                        const struct sockaddr_in* source) {
    return gossip_service_send_envelope(service, envelope, source);
}

int gossip_service_broadcast_message(GossipService* service,
                                     const Tinyweb__Message* message) {
    if (!service || !message) return -1;

    size_t size = tinyweb__message__get_packed_size((Tinyweb__Message*)message);
    if (size == 0 || size > GOSSIP_MAX_MESSAGE_SIZE) return -1;

    unsigned char* buf = malloc(size);
    if (!buf) return -1;

    tinyweb__message__pack((Tinyweb__Message*)message, buf);
    int rc = gossip_service_send_data(service, buf, size, NULL);
    free(buf);
    return rc;
}

int gossip_service_rebroadcast_message(GossipService* service,
                                       const Tinyweb__Message* message,
                                       const struct sockaddr_in* source) {
    if (!service || !message) return -1;

    size_t size = tinyweb__message__get_packed_size((Tinyweb__Message*)message);
    if (size == 0 || size > GOSSIP_MAX_MESSAGE_SIZE) return -1;

    unsigned char* buf = malloc(size);
    if (!buf) return -1;

    tinyweb__message__pack((Tinyweb__Message*)message, buf);
    int rc = gossip_service_send_data(service, buf, size, source);
    free(buf);
    return rc;
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
            tw_error_create(TW_ERROR_NETWORK_ERROR, "gossip", __func__, __LINE__, "Failed to receive: %s", strerror(errno));
            logger_error("gossip", "Failed to receive: %s", strerror(errno));
            continue;
        }

        // 1. Try unpacking as Message first (new standard)
        Tinyweb__Message* message = tinyweb__message__unpack(NULL, (size_t)bytes, buffer);
        if (message && message->header && message->header->sender_pubkey.len == 32) {
            // Sane message - handle it
            if (service->message_handler) {
                if (service->message_handler(service, message, &source, service->handler_context) != 0) {
                    logger_error("gossip", "message handler rejected message from %s:%d",
                               inet_ntoa(source.sin_addr), ntohs(source.sin_port));
                }
            }
            tinyweb__message__free_unpacked(message, NULL);
            continue;
        }
        if (message) tinyweb__message__free_unpacked(message, NULL);

        // 2. Fallback to legacy Envelope
        Tinyweb__Envelope* envelope = tinyweb__envelope__unpack(NULL, (size_t)bytes, buffer);
        if (envelope) {
            // Sane envelope - handle it
            if (service->envelope_handler) {
                if (service->envelope_handler(service, envelope, &source, service->handler_context) != 0) {
                    logger_error("gossip", "envelope handler rejected envelope content_type %u",
                                envelope->header ? envelope->header->content_type : 0);
                }
            }
            tinyweb__envelope__free_unpacked(envelope, NULL);
            continue;
        }

        logger_error("gossip", "Failed to deserialize as either Message or Envelope from %s:%d (%zd bytes)",
                   inet_ntoa(source.sin_addr), ntohs(source.sin_port), bytes);
    }

    return NULL;
}

static void gossip_service_clear_peers(GossipService* service) {
    pthread_mutex_lock(&service->peer_lock);
    memset(service->peers, 0, sizeof(service->peers));
    service->peer_count = 0;
    pthread_mutex_unlock(&service->peer_lock);
}

