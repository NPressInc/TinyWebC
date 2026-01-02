#ifndef LOCATION_STORE_H
#define LOCATION_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>

#ifndef PUBKEY_SIZE
#define PUBKEY_SIZE 32  // Ed25519 public key size
#endif

#ifndef GOSSIP_SEEN_DIGEST_SIZE
#define GOSSIP_SEEN_DIGEST_SIZE 32
#endif

// Forward declarations - actual definitions in protobuf headers (when generated)
struct Tinyweb__ClientRequest;
typedef struct Tinyweb__ClientRequest Tinyweb__ClientRequest;
struct Tinyweb__Envelope;
typedef struct Tinyweb__Envelope Tinyweb__Envelope;

// Location store initialization
int location_store_init(void);

// Compute SHA256 digest of serialized ClientRequest or Envelope for deduplication
int location_store_compute_digest_client_request(const Tinyweb__ClientRequest* request, unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE]);
int location_store_compute_digest_envelope(const Tinyweb__Envelope* envelope, unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE]);

// Check if location update digest has been seen (for deduplication)
int location_store_has_seen(const unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE], int* is_seen);

// Mark location update digest as seen (for deduplication)
int location_store_mark_seen(const unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE], uint64_t expires_at);

// Save encrypted ClientRequest to database (for HTTP API path)
int location_store_save(const Tinyweb__ClientRequest* request, uint64_t expires_at);

// Save encrypted Envelope to database (for gossip path)
int location_store_save_envelope(const Tinyweb__Envelope* envelope, uint64_t expires_at);

// Get latest encrypted location for a user (returns ClientRequest or Envelope as serialized blob)
// Caller must free the returned data
int location_store_get_latest(const unsigned char user_pubkey[PUBKEY_SIZE],
                              unsigned char** out_data,
                              size_t* out_len,
                              int* is_envelope);  // 1 if envelope, 0 if client_request

// Get location history for a user (returns array of serialized ClientRequest or Envelope blobs)
// Caller must free the returned data array and each blob
int location_store_get_history(const unsigned char user_pubkey[PUBKEY_SIZE],
                               uint32_t limit,
                               uint32_t offset,
                               unsigned char*** out_data_array,
                               size_t** out_len_array,
                               size_t* count,
                               int** is_envelope_array);  // Array indicating if each entry is envelope (1) or client_request (0)

// Free location data returned by get functions
void location_store_free_data(unsigned char* data);
void location_store_free_data_array(unsigned char** data_array, size_t* len_array, size_t count, int* is_envelope_array);

#endif // LOCATION_STORE_H

