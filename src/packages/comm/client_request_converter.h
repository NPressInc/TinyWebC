#ifndef CLIENT_REQUEST_CONVERTER_H
#define CLIENT_REQUEST_CONVERTER_H

#include <stdint.h>

// Forward declarations
struct Tinyweb__ClientRequest;
typedef struct Tinyweb__ClientRequest Tinyweb__ClientRequest;
struct Tinyweb__Envelope;
typedef struct Tinyweb__Envelope Tinyweb__Envelope;

// Convert ClientRequest to Envelope format for gossip broadcast
// The returned envelope must be freed using tinyweb__envelope__free_unpacked()
// Returns NULL on error
Tinyweb__Envelope* client_request_to_envelope(const Tinyweb__ClientRequest* request);

#endif // CLIENT_REQUEST_CONVERTER_H

