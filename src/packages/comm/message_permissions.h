#ifndef MESSAGE_PERMISSIONS_H
#define MESSAGE_PERMISSIONS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifndef PUBKEY_SIZE
#define PUBKEY_SIZE 32
#endif

// Check if a sender has permission to message a recipient
// Rules:
// 1. Parent can message child (and vice versa)
// 2. Peers can message each other if they have a relationship
// 3. Group members can message the group
bool message_permissions_check(const unsigned char sender_pubkey[PUBKEY_SIZE],
                               const unsigned char* recipient_pubkey, // Can be NULL for group messages
                               const unsigned char* group_id,         // Can be NULL for direct messages
                               size_t num_recipients);

#endif // MESSAGE_PERMISSIONS_H

