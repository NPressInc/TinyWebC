#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include "transaction.h"
#include "packages/signing/signing.h"
#include "packages/utils/byteorder.h"

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
    tx->payload = (EncryptedPayload*)payload;
    if (payload) {
        tx->payload_size = encrypted_payload_get_size((EncryptedPayload*)payload);
    } else {
        tx->payload_size = 0;
    }
    
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
    if (!tx) {
        return 0;
    }
    
    if (!tx->payload) {
        return 0;
    }

    size_t size = 0;

    size += sizeof(tx->type);                      // Transaction type
    size += PUBKEY_SIZE;                           // Sender
    size += sizeof(tx->timestamp);                 // Timestamp
    size += PUBKEY_SIZE * tx->recipient_count;     // Recipients
    size += sizeof(tx->recipient_count);           // Recipient count (uint8_t)
    size += GROUP_ID_SIZE;                         // Group ID
    
    size_t payload_size = encrypted_payload_get_size(tx->payload);
    
    if (payload_size == 0) {
        return 0;
    }
    
    size += payload_size;                          // EncryptedPayload content
    size += sizeof(tx->payload_size);              // Payload size metadata
    size += SIGNATURE_SIZE;                        // Signature

    return size;
}



void TW_Transaction_hash(TW_Transaction* tx, unsigned char* hash_out) {
    if (!tx || !hash_out) {
        if (hash_out) memset(hash_out, 0, SHA256_DIGEST_LENGTH);
        return;
    }

    // Calculate buffer size for hashing
    size_t buffer_alloc_size = 0;
    buffer_alloc_size += sizeof(tx->type);
    buffer_alloc_size += PUBKEY_SIZE; // sender
    buffer_alloc_size += sizeof(tx->timestamp);
    buffer_alloc_size += sizeof(tx->recipient_count);
    if (tx->recipient_count > 0 && tx->recipients) {
        buffer_alloc_size += PUBKEY_SIZE * tx->recipient_count;
    }
    buffer_alloc_size += GROUP_ID_SIZE;

    // Add size for payload if it exists
    if (tx->payload && tx->payload_size > 0) {
        buffer_alloc_size += tx->payload_size;
    }

    unsigned char* buffer = malloc(buffer_alloc_size);
    if (!buffer) {
        fprintf(stderr, "TW_Transaction_hash: malloc failed\n");
        if (hash_out) memset(hash_out, 0, SHA256_DIGEST_LENGTH);
        return;
    }

    unsigned char* ptr = buffer; // Use a temporary pointer for filling the buffer

    // Copy transaction fields into buffer
    memcpy(ptr, &tx->type, sizeof(tx->type));
    ptr += sizeof(tx->type);

    memcpy(ptr, tx->sender, PUBKEY_SIZE);
    ptr += PUBKEY_SIZE;

    uint64_t timestamp_net = htonll(tx->timestamp); // Use network byte order for consistency
    memcpy(ptr, &timestamp_net, sizeof(timestamp_net));
    ptr += sizeof(timestamp_net);
    
    memcpy(ptr, &tx->recipient_count, sizeof(tx->recipient_count));
    ptr += sizeof(tx->recipient_count);

    if (tx->recipient_count > 0 && tx->recipients) {
        memcpy(ptr, tx->recipients, PUBKEY_SIZE * tx->recipient_count);
        ptr += PUBKEY_SIZE * tx->recipient_count;
    }

    memcpy(ptr, tx->group_id, GROUP_ID_SIZE);
    ptr += GROUP_ID_SIZE;

    // Serialize the EncryptedPayload if it exists
    if (tx->payload && tx->payload_size > 0) {
        // The 'ptr' is advanced by encrypted_payload_serialize itself
        if (encrypted_payload_serialize(tx->payload, &ptr) != 0) {
            fprintf(stderr, "TW_Transaction_hash: Error serializing encrypted payload for hashing\n");
            free(buffer);
            memset(hash_out, 0, SHA256_DIGEST_LENGTH);
            return;
        }
    }

    // Compute hash using SHA256 on the actual number of bytes written
    size_t actual_bytes_written = ptr - buffer;
    SHA256(buffer, actual_bytes_written, hash_out);

    free(buffer);
}



int TW_Transaction_serialize(TW_Transaction* txn, unsigned char** out_buffer) {
    if(!txn){
        printf("transaction is empty \n");
        return 1;
    }

    if (!out_buffer) {
        printf("Memory allocation failed for transaction serialization\n");
        return 1;
    }

    unsigned char* ptr = *out_buffer;

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

    // Serialize recipient_count
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
    size_t payload_size_net = htonll(txn->payload_size);  // Convert size to network byte order
    memcpy(ptr, &payload_size_net, sizeof(payload_size_net));
    ptr += sizeof(payload_size_net);

    // Serialize the encrypted payload
    if (txn->payload_size > 0) {
        encrypted_payload_serialize(txn->payload, &ptr);
    }

    // Serialize the signature
    memcpy(ptr, txn->signature, SIGNATURE_SIZE);
    ptr += SIGNATURE_SIZE;

    // Update the caller's buffer pointer
    *out_buffer = ptr;

    return 0;
}


TW_Transaction* TW_Transaction_deserialize(const unsigned char* buffer, size_t buffer_size) {
    if (!buffer || buffer_size < sizeof(TW_Transaction)) {
        printf("Invalid buffer or buffer size too small\n");
        return NULL;
    }

    // Allocate memory for the transaction
    TW_Transaction* txn = (TW_Transaction*)malloc(sizeof(TW_Transaction));
    if (!txn) {
        printf("Memory allocation failed for transaction\n");
        return NULL;
    }
    // Initialize fields to avoid undefined behavior
    memset(txn, 0, sizeof(TW_Transaction));

    const unsigned char* ptr = buffer;

    // Deserialize the type
    memcpy(&txn->type, ptr, sizeof(txn->type));
    ptr += sizeof(txn->type);

    // Deserialize the sender public key
    memcpy(txn->sender, ptr, PUBKEY_SIZE);
    ptr += PUBKEY_SIZE;

    // Deserialize the timestamp (Convert from network byte order using ntohll)
    uint64_t timestamp_net;
    memcpy(&timestamp_net, ptr, sizeof(timestamp_net));
    txn->timestamp = ntohll(timestamp_net);
    ptr += sizeof(timestamp_net);

    // Deserialize recipient_count
    uint8_t recipient_count_net;
    memcpy(&recipient_count_net, ptr, sizeof(recipient_count_net));
    txn->recipient_count = recipient_count_net;
    ptr += sizeof(recipient_count_net);

    // Allocate and deserialize the recipients (list of public keys)
    if (txn->recipient_count > 0) {
        txn->recipients = (uint8_t*)malloc(PUBKEY_SIZE * txn->recipient_count);
        if (!txn->recipients) {
            printf("Memory allocation failed for recipients\n");
            free(txn);
            return NULL;
        }
        memcpy(txn->recipients, ptr, PUBKEY_SIZE * txn->recipient_count);
    } else {
        txn->recipients = NULL;
    }
    ptr += PUBKEY_SIZE * txn->recipient_count;

    // Deserialize the group ID
    memcpy(txn->group_id, ptr, GROUP_ID_SIZE);
    ptr += GROUP_ID_SIZE;

    // Deserialize the length of the payload (Convert from network byte order using ntohl)
    size_t payload_size_net;
    memcpy(&payload_size_net, ptr, sizeof(payload_size_net));
    txn->payload_size = ntohll(payload_size_net);
    ptr += sizeof(payload_size_net);

    // Deserialize the encrypted payload
    if (txn->payload_size > 0) {
        const char** char_ptr = (const char**)&ptr;
        txn->payload = encrypted_payload_deserialize(char_ptr);
        ptr = (const unsigned char*)(*char_ptr);
        if (!txn->payload) {
            printf("Failed to deserialize encrypted payload\n");
            if (txn->recipients) {
                free(txn->recipients);
            }
            free(txn);
            return NULL;
        }
    } else {
        txn->payload = NULL;
    }

    // Deserialize the signature
    memcpy(txn->signature, ptr, SIGNATURE_SIZE);
    ptr += SIGNATURE_SIZE;

    return txn;
}

/** Frees the memory allocated for the transaction. */
void TW_Transaction_destroy(TW_Transaction* tx) {
    if (!tx) return;
    
    // Free the recipients array
    if (tx->recipients) {
        free(tx->recipients);
        tx->recipients = NULL;
    }
    
    // Free the payload
    if (tx->payload) {
        free_encrypted_payload(tx->payload);
        tx->payload = NULL;
    }
    
    free(tx);
}