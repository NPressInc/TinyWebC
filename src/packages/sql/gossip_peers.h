#ifndef TW_GOSSIP_PEERS_H
#define TW_GOSSIP_PEERS_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char hostname[256];
    uint16_t gossip_port;
    uint16_t api_port;
    uint64_t first_seen;
    uint64_t last_seen;
    char tags[128];
} GossipPeerInfo;

int gossip_peers_init(void);
int gossip_peers_add_or_update(const char* hostname, uint16_t gossip_port, uint16_t api_port, const char* tags);
int gossip_peers_touch(const char* hostname);
int gossip_peers_fetch_all(GossipPeerInfo** peers, size_t* count);
void gossip_peers_free(GossipPeerInfo* peers, size_t count);

#endif // TW_GOSSIP_PEERS_H

