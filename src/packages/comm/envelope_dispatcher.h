#ifndef ENVELOPE_DISPATCHER_H
#define ENVELOPE_DISPATCHER_H

#include "envelope.pb-c.h"
#include "content.pb-c.h"

// Handler function signature for content-specific processing
// Returns 0 on success, -1 on error
typedef int (*EnvelopeContentHandler)(
    const Tinyweb__Envelope* envelope,
    const unsigned char* decrypted_payload,
    size_t payload_len,
    void* context
);

// Main dispatcher - routes envelope to appropriate handler
int envelope_dispatch(const Tinyweb__Envelope* envelope, void* context);

// Register a handler for a specific content type
int envelope_register_handler(uint32_t content_type, EnvelopeContentHandler handler);

// Unregister a handler
void envelope_unregister_handler(uint32_t content_type);

// Get content type name (for logging/debugging)
const char* envelope_content_type_name(uint32_t content_type);

// Initialize dispatcher (sets up default handlers)
int envelope_dispatcher_init(void);

// Cleanup dispatcher
void envelope_dispatcher_cleanup(void);

#endif // ENVELOPE_DISPATCHER_H

