#ifndef BYTEORDER_H
#define BYTEORDER_H

#include <arpa/inet.h> // For htonl, ntohl
#include <stdint.h>    // For uint64_t

// Declare 64-bit host-to-network and network-to-host conversions
// Only define if not already provided by the system
#ifndef htonll
uint64_t htonll(uint64_t value);
#endif

#ifndef ntohll
uint64_t ntohll(uint64_t value);
#endif

#endif // BYTEORDER_H