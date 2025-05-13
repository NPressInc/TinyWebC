#ifndef TW_TRANSACTION_H
#define TW_TRANSACTION_H

#include <stddef.h>  // For size_t
#include <stdint.h>
#include "packages/keystore/keystore.h"
#include "packages/encryption/encryption.h"
#include "packages/signing/signing.h"

#define MAX_RECIPIENTS 50       // Max recipients for group messages
#define MAX_PAYLOAD_SIZE_EXTERNAL 4096   // Max payload size
#define GROUP_ID_SIZE 16       // Fixed-size group identifier

typedef enum {
    TW_TXN_MISC,
    TW_TXN_MESSAGE,
    TW_TXN_GROUP_MESSAGE,
    TW_TXN_VOICE_CALL_REQ,
    TW_TXN_VIDEO_CALL_REQ,
    TW_TXN_MEDIA_DOWNLOAD,
    TW_TXN_PERMISSION_EDIT,
    TW_TXN_GROUP_INVITE,
    TW_TXN_GROUP_REMOVE,
    TW_TXN_GROUP_LEAVE,
    TW_TXN_GROUP_ADD,
} TW_TransactionType;

typedef struct {
    TW_TransactionType type;
    unsigned char sender[PUBKEY_SIZE];
    uint64_t timestamp;
    unsigned char* recipients; // pubkey size * max recipients is max size
    uint8_t recipient_count;
    unsigned char group_id[GROUP_ID_SIZE];
    EncryptedPayload* payload;
    size_t payload_size;
    unsigned char signature[SIGNATURE_SIZE];       // Set externally
} TW_Transaction;

// Basic functions
TW_Transaction* TW_Transaction_create(TW_TransactionType type, const unsigned char* sender, 
                                     const unsigned char* recipients, uint8_t recipient_count, 
                                     const unsigned char* group_id, const EncryptedPayload* payload, 
                                     const unsigned char* signature);
void TW_Transaction_destroy(TW_Transaction* tx);

size_t TW_Transaction_get_size(const TW_Transaction* tx);
void TW_Transaction_hash(TW_Transaction* tx, unsigned char* hash_out);

int TW_Transaction_serialize(TW_Transaction* tx, unsigned char** out_buffer);
TW_Transaction* TW_Transaction_deserialize(const unsigned char* buffer, size_t buffer_size);

void TW_Transaction_add_signature(TW_Transaction* txn);

#endif