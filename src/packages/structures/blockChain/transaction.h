#ifndef TW_TRANSACTION_H
#define TW_TRANSACTION_H

#include <stddef.h>  // For size_t
#include <stdint.h>

#define PUBKEY_SIZE 33         // ECC public key size
#define SIG_SIZE 64            // Signature size
#define MAX_RECIPIENTS 8       // Max recipients for group messages
#define MAX_PAYLOAD_SIZE_EXTERNAL 1024   // Max payload size
#define GROUP_ID_SIZE 16       // Fixed-size group identifier

typedef enum {
    TW_TXN_MESSAGE,
    TW_TXN_GROUP_MESSAGE,
    TW_TXN_VOICE_CALL_REQ,
    TW_TXN_VIDEO_CALL_REQ,
    TW_TXN_MEDIA_DOWNLOAD,
    TW_TXN_PERMISSION_EDIT,
} TW_TransactionType;

typedef struct {
    TW_TransactionType type;
    unsigned char sender[PUBKEY_SIZE];
    uint64_t timestamp;
    unsigned char recipients[PUBKEY_SIZE * MAX_RECIPIENTS];
    uint8_t recipient_count;
    unsigned char group_id[GROUP_ID_SIZE];
    unsigned char payload[MAX_PAYLOAD_SIZE_EXTERNAL]; // Can be encrypted externally
    uint16_t payload_len;
    unsigned char signature[SIG_SIZE];       // Set externally
} TW_Transaction;

// Basic functions
TW_Transaction* TW_Transaction_create(TW_TransactionType type, const unsigned char* sender, 
                                     const unsigned char* recipients, uint8_t recipient_count, 
                                     const unsigned char* group_id, const unsigned char* payload, 
                                     uint16_t payload_len, const unsigned char* signature);
void TW_Transaction_destroy(TW_Transaction* tx);
void TW_Transaction_hash(TW_Transaction* tx, unsigned char* hash_out);
size_t TW_Transaction_to_bytes(TW_Transaction* tx, unsigned char** buffer);
TW_Transaction* TW_Transaction_deserialize(const unsigned char* buffer, size_t buffer_size);

#endif