#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <arpa/inet.h>  // For htonl
#include "transaction.h"
#include "packages/signing/signing.h"

/** Creates a transaction with pre-prepared data (no encryption here). */
TW_Transaction* TW_Transaction_create(TW_TransactionType type, const unsigned char* sender, 
                                     const unsigned char* recipients, uint8_t recipient_count, 
                                     const unsigned char* group_id, const EncryptedPayload* payload, 
                                     const unsigned char* signature) {
    TW_Transaction* tx = malloc(sizeof(TW_Transaction));
    if (!tx) return NULL;

    tx->type = type;
    memcpy(tx->sender, sender, PUBKEY_SIZE);
    tx->timestamp = time(NULL);
    tx->recipient_count = (recipient_count > MAX_RECIPIENTS) ? MAX_RECIPIENTS : recipient_count;
    tx->payload = payload;
    
    if (recipients && tx->recipient_count > 0) {
        tx->recipients = malloc(PUBKEY_SIZE * tx->recipient_count);
        if (!tx->recipients) {
            perror("malloc failed");
            free(tx);
            return NULL;
        }
        memcpy(tx->recipients, recipients, PUBKEY_SIZE * tx->recipient_count);
    } else {
        tx->recipients = NULL; // No recipients, set to NULL
        tx->recipient_count = 0; // Ensure count reflects no recipients
    }

    if (group_id) {
        memcpy(tx->group_id, group_id, GROUP_ID_SIZE);
    } else {
        memset(tx->group_id, 0, GROUP_ID_SIZE);
    }
    

    if (signature) {
        memcpy(tx->signature, signature, SIGNATURE_SIZE);
    } else {
        memset(tx->signature, 0, SIGNATURE_SIZE);
    }

    return tx;
}

void TW_Transaction_add_signature(TW_Transaction* txn){

    unsigned char txn_hash[SIGNATURE_SIZE];

    TW_Transaction_hash(txn, txn_hash);

    sign_message(txn_hash, txn->signature);
}

size_t TW_Transaction_get_size(const TW_Transaction* tx) {
    if (!tx || !tx->payload) return 0;

    size_t size = 0;

    size += sizeof(tx->type);                      // Transaction type
    size += PUBKEY_SIZE;                           // Sender
    size += sizeof(tx->timestamp);                 // Timestamp
    size += PUBKEY_SIZE * tx->recipient_count;     // Recipients
    size += sizeof(tx->recipient_count);           // Recipient count (uint8_t)
    size += GROUP_ID_SIZE;                         // Group ID
    size += encrypted_payload_get_size(tx->payload); // EncryptedPayload content
    size += sizeof(tx->payload_size);              // Payload size metadata
    size += SIGNATURE_SIZE;                        // Signature

    return size;
}


void TW_Transaction_hash(TW_Transaction* tx, unsigned char* hash_out) {
    if (!tx || !hash_out) return;

    // First, calculate the size of the buffer, excluding the signature
    size_t buffer_size = TW_Transaction_get_size(tx) - SIGNATURE_SIZE;
    
    unsigned char* buffer = malloc(buffer_size);
    if (!buffer) {
        printf("malloc failed\n");
        return;
    }

    size_t offset = 0;

    // Copy the transaction fields into the buffer
    memcpy(buffer + offset, &tx->type, sizeof(tx->type));
    offset += sizeof(tx->type);
    
    memcpy(buffer + offset, tx->sender, PUBKEY_SIZE);
    offset += PUBKEY_SIZE;
    
    memcpy(buffer + offset, &tx->timestamp, sizeof(tx->timestamp));
    offset += sizeof(tx->timestamp);
    
    memcpy(buffer + offset, tx->recipients, PUBKEY_SIZE * tx->recipient_count);
    offset += PUBKEY_SIZE * tx->recipient_count;
    
    memcpy(buffer + offset, &tx->recipient_count, sizeof(tx->recipient_count));
    offset += sizeof(tx->recipient_count);
    
    memcpy(buffer + offset, tx->group_id, GROUP_ID_SIZE);
    offset += GROUP_ID_SIZE;
    
    // Serialize the payload
    memcpy(buffer + offset, &tx->payload_size, sizeof(tx->payload_size));
    offset += sizeof(tx->payload_size);
    
    // Avoid including the signature
    memcpy(buffer + offset, tx->payload, encrypted_payload_get_size(tx->payload));
    offset += encrypted_payload_get_size(tx->payload);

    // Now, compute the hash using SHA256
    SHA256(buffer, offset, hash_out);

    // Clean up the allocated buffer
    free(buffer);
}



size_t TW_Transaction_serialize(TW_Transaction* txn, char** out_buffer) {
    // The total size includes all the fields and lengths for serialized data
    size_t buffer_size = TW_Transaction_get_size(txn);

    // Allocate memory for the buffer
    *out_buffer = malloc(buffer_size);
    if (!*out_buffer) {
        printf("Memory allocation failed for transaction serialization\n");
        return 0;
    }

    char* ptr = *out_buffer;

    // Serialize the type
    memcpy(ptr, &txn->type, sizeof(txn->type));
    ptr += sizeof(txn->type);

    // Serialize the sender public key
    memcpy(ptr, txn->sender, PUBKEY_SIZE);
    ptr += PUBKEY_SIZE;

    // Serialize the timestamp (Convert to network byte order using htonll)
    uint64_t timestamp_net = htonll(txn->timestamp);
    memcpy(ptr, &timestamp_net, sizeof(timestamp_net));
    ptr += sizeof(timestamp_net);

    // Serialize recipient_count (Convert to network byte order using htonl)
    uint8_t recipient_count_net = txn->recipient_count;
    memcpy(ptr, &recipient_count_net, sizeof(recipient_count_net));
    ptr += sizeof(recipient_count_net);

    // Serialize the recipients (this is the list of public keys, no need for network order here)
    memcpy(ptr, txn->recipients, PUBKEY_SIZE * txn->recipient_count);
    ptr += PUBKEY_SIZE * txn->recipient_count;

    // Serialize the group ID
    memcpy(ptr, txn->group_id, GROUP_ID_SIZE);
    ptr += GROUP_ID_SIZE;

    // Serialize the length of the payload (Convert to network byte order using htonl)
    size_t payload_size_net = htonl(txn->payload_size);  // Convert size to network byte order
    memcpy(ptr, &payload_size_net, sizeof(payload_size_net));
    ptr += sizeof(payload_size_net);

    // Serialize the encrypted payload
    if (txn->payload_size > 0) {
        encrypted_payload_serialize(txn->payload, &ptr);
    }

    // Serialize the signature
    memcpy(ptr, txn->signature, SIGNATURE_SIZE);
    ptr += SIGNATURE_SIZE;

    return buffer_size;
}


TW_Transaction* TW_Transaction_deserialize(const unsigned char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size < sizeof(TW_Transaction)) return NULL;

    TW_Transaction* tx = malloc(sizeof(TW_Transaction));
    if (!tx) return NULL;

    memcpy(tx, buffer, sizeof(TW_Transaction));
    return tx;
}

/** Frees the memory allocated for the transaction. */
void TW_Transaction_destroy(TW_Transaction* tx) {
    if (!tx) return;
    
    free(tx);
}