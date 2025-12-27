#ifndef MESSAGE_STORE_H
#define MESSAGE_STORE_H

#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>

#ifndef PUBKEY_SIZE
#ifndef PUBKEY_SIZE
#ifndef PUBKEY_SIZE
#define PUBKEY_SIZE 32  // Ed25519 public key size
#endif
#endif
#endif

#ifndef GOSSIP_SEEN_DIGEST_SIZE
#define GOSSIP_SEEN_DIGEST_SIZE 32
#endif

// Forward declaration - actual definition in message.pb-c.h (when generated)
struct Tinyweb__Message;
typedef struct Tinyweb__Message Tinyweb__Message;
struct Tinyweb__MessageList;
typedef struct Tinyweb__MessageList Tinyweb__MessageList;
struct Tinyweb__ConversationList;
typedef struct Tinyweb__ConversationList Tinyweb__ConversationList;

// Message store initialization
int message_store_init(void);

// Message storage functions
// Save message by extracting fields from Tinyweb__Message structure
// This stores header fields and encrypted payload separately for efficient SQL queries
int message_store_save(const Tinyweb__Message* message, uint64_t expires_at);

// Compute SHA256 digest of serialized Message for deduplication
int message_store_compute_digest(const Tinyweb__Message* message, unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE]);

// Check if message digest has been seen (for deduplication)
int message_store_has_seen(const unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE], int* is_seen);

// Mark message digest as seen (for deduplication)
int message_store_mark_seen(const unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE], uint64_t expires_at);

// Fetch recent messages for a user (sender OR recipient)
int message_store_fetch_recent(const unsigned char user_pubkey[PUBKEY_SIZE],
                               uint32_t limit,
                               Tinyweb__Message*** out,
                               size_t* count);

// Fetch conversation between two users (both directions)
int message_store_fetch_conversation(const unsigned char user1_pubkey[PUBKEY_SIZE],
                                     const unsigned char user2_pubkey[PUBKEY_SIZE],
                                     uint32_t limit,
                                     Tinyweb__Message*** out,
                                     size_t* count);

// Fetch conversation partner list for a user
int message_store_fetch_conversations(const unsigned char user_pubkey[PUBKEY_SIZE],
                                      uint32_t limit,
                                      Tinyweb__ConversationList** out);

// Free array of messages returned by fetch functions
void message_store_free_messages(Tinyweb__Message** messages, size_t count);

// Free ConversationList
void message_store_free_conversation_list(Tinyweb__ConversationList* list);

#endif // MESSAGE_STORE_H

