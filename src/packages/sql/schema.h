#ifndef SCHEMA_H
#define SCHEMA_H

#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>

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

// SQL query constants (for use by permissions.c and other modules)
extern const char* SQL_SELECT_USER_BY_PUBKEY;
extern const char* SQL_SELECT_USER_ROLES;
extern const char* SQL_SELECT_ROLE_PERMISSIONS;
extern const char* SQL_INSERT_ROLE_PERMISSION;

// SQL query constants for nodes table
extern const char* SQL_INSERT_OR_UPDATE_NODE;
extern const char* SQL_SELECT_NODE_BY_ID;

// Schema versioning functions (for migration support)
#define CURRENT_SCHEMA_VERSION 2  // Updated to 2 when nodes table was added
int schema_check_version(sqlite3* db, int* version);
int schema_set_version(sqlite3* db, int version);
int schema_migrate(sqlite3* db, int from_version, int to_version);

// Nodes table functions
int nodes_insert_or_update(const char* node_id, const char* node_name, const char* hostname,
                          uint16_t gossip_port, uint16_t api_port, const char* discovery_mode,
                          const char* hostname_prefix, const char* dns_domain);
int nodes_get_by_id(const char* node_id, char* node_name, size_t name_len, char* hostname,
                   size_t hostname_len, uint16_t* gossip_port, uint16_t* api_port,
                   char* discovery_mode, size_t mode_len, char* hostname_prefix,
                   size_t prefix_len, char* dns_domain, size_t domain_len);

#endif // SCHEMA_H

