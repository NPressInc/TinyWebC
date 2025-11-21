#ifndef TW_GOSSIP_STORE_H
#define TW_GOSSIP_STORE_H

#include <stddef.h>
#include <stdint.h>

#define GOSSIP_SEEN_DIGEST_SIZE 32
#ifndef PUBKEY_SIZE
#define PUBKEY_SIZE 32  // Ed25519 public key size
#endif

typedef struct {
    uint64_t id;
    uint32_t version;
    uint32_t content_type;
    uint32_t schema_version;
    uint64_t timestamp;
    unsigned char sender[PUBKEY_SIZE];
    unsigned char* envelope;
    size_t envelope_size;
    uint64_t expires_at;
} GossipStoredEnvelope;

int gossip_store_init(void);

int gossip_store_cleanup(uint64_t now_epoch);

int gossip_store_has_seen(const unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE], int* is_seen);
int gossip_store_mark_seen(const unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE], uint64_t expires_at);

// Envelope APIs
int gossip_store_save_envelope(uint32_t version, uint32_t content_type, uint32_t schema_version,
                               const unsigned char sender[PUBKEY_SIZE],
                               uint64_t timestamp,
                               const unsigned char* envelope, size_t envelope_size,
                               uint64_t expires_at);

int gossip_store_fetch_recent_envelopes(uint32_t limit,
                                        GossipStoredEnvelope** out,
                                        size_t* count);

void gossip_store_free_envelopes(GossipStoredEnvelope* envs, size_t count);

#endif // TW_GOSSIP_STORE_H

