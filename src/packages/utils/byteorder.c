#include "byteorder.h"

// Define 64-bit host-to-network conversion
#ifndef htonll
uint64_t htonll(uint64_t value) {
    if (htonl(1) != 1) { // Little-endian
        return ((uint64_t)htonl((uint32_t)value) << 32) | htonl((uint32_t)(value >> 32));
    }
    return value; // Big-endian
}
#endif

// Define 64-bit network-to-host conversion
#ifndef ntohll
uint64_t ntohll(uint64_t value) {
    if (htonl(1) != 1) { // Little-endian
        return ((uint64_t)ntohl((uint32_t)value) << 32) | ntohl((uint32_t)(value >> 32));
    }
    return value; // Big-endian
}
#endif