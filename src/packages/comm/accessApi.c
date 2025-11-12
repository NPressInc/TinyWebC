#include "accessApi.h"
#include "features/blockchain/core/transaction_types.h"
#include "packages/validation/transaction_validation.h"
#include "packages/signing/signing.h"
#include "packages/encryption/encryption.h"
#include "packages/utils/jsonUtils.h"
#include <cjson/cJSON.h>
#include <string.h>
#include <time.h>

// Submit an access request transaction to the blockchain via PBFT
void handle_access_request_submit_pbft(struct mg_connection* c, struct mg_http_message* hm) {
    printf("PBFT access request submit endpoint called\n");
    
    // Parse JSON request
    cJSON* json = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!json) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Invalid JSON\",\"status\":\"error\"}");
        return;
    }
    
    // Extract required fields for PBFT transaction
    cJSON* type_json = cJSON_GetObjectItem(json, "type");
    cJSON* sender_json = cJSON_GetObjectItem(json, "sender");
    cJSON* timestamp_json = cJSON_GetObjectItem(json, "timestamp");
    cJSON* recipients_json = cJSON_GetObjectItem(json, "recipients");
    cJSON* group_id_json = cJSON_GetObjectItem(json, "groupId");
    cJSON* payload_json = cJSON_GetObjectItem(json, "payload");
    cJSON* resource_id_json = cJSON_GetObjectItem(json, "resource_id");
    cJSON* signature_json = cJSON_GetObjectItem(json, "signature");
    
    if (!type_json || !sender_json || !timestamp_json || !recipients_json || 
        !payload_json || !signature_json) {
        cJSON_Delete(json);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Missing required fields: type, sender, timestamp, recipients, payload, signature\",\"status\":\"error\"}");
        return;
    }
    
    // Validate transaction type
    int transaction_type = cJSON_GetNumberValue(type_json);
    if (transaction_type != TW_TXN_ACCESS_REQUEST) {
        cJSON_Delete(json);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Invalid transaction type for access request\",\"status\":\"error\"}");
        return;
    }
    
    const char* sender_hex = cJSON_GetStringValue(sender_json);
    const char* payload_hex = cJSON_GetStringValue(payload_json);
    const char* signature_hex = cJSON_GetStringValue(signature_json);
    uint64_t timestamp = (uint64_t)cJSON_GetNumberValue(timestamp_json);
    
    if (!sender_hex || !payload_hex || !signature_hex) {
        cJSON_Delete(json);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Invalid field values\",\"status\":\"error\"}");
        return;
    }
    
    // Convert hex strings to binary
    unsigned char sender_pubkey[PUBKEY_SIZE];
    unsigned char signature[SIGNATURE_SIZE];
    
    if (strlen(sender_hex) != PUBKEY_SIZE * 2 || 
        strlen(signature_hex) != SIGNATURE_SIZE * 2) {
        cJSON_Delete(json);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Invalid sender key or signature length\",\"status\":\"error\"}");
        return;
    }
    
    // Convert hex to binary
    for (int i = 0; i < PUBKEY_SIZE; i++) {
        sscanf(sender_hex + (i * 2), "%2hhx", &sender_pubkey[i]);
    }
    for (int i = 0; i < SIGNATURE_SIZE; i++) {
        sscanf(signature_hex + (i * 2), "%2hhx", &signature[i]);
    }
    
    // Parse recipients array
    if (!cJSON_IsArray(recipients_json)) {
        cJSON_Delete(json);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Recipients must be an array\",\"status\":\"error\"}");
        return;
    }
    
    int num_recipients = cJSON_GetArraySize(recipients_json);
    if (num_recipients == 0 || num_recipients > 32) {
        cJSON_Delete(json);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Invalid number of recipients (1-32 allowed)\",\"status\":\"error\"}");
        return;
    }
    
    // Convert recipients to flat array
    unsigned char* recipients_flat = malloc(num_recipients * PUBKEY_SIZE);
    if (!recipients_flat) {
        cJSON_Delete(json);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Memory allocation failed\",\"status\":\"error\"}");
        return;
    }
    
    for (int i = 0; i < num_recipients; i++) {
        cJSON* recipient = cJSON_GetArrayItem(recipients_json, i);
        const char* recipient_hex = cJSON_GetStringValue(recipient);
        
        if (!recipient_hex || strlen(recipient_hex) != PUBKEY_SIZE * 2) {
            free(recipients_flat);
            cJSON_Delete(json);
            mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                         "{\"error\":\"Invalid recipient key format\",\"status\":\"error\"}");
            return;
        }
        
        for (int j = 0; j < PUBKEY_SIZE; j++) {
            sscanf(recipient_hex + (j * 2), "%2hhx", &recipients_flat[i * PUBKEY_SIZE + j]);
        }
    }
    
    // Convert encrypted payload from hex to binary
    int payload_len = strlen(payload_hex) / 2;
    unsigned char* payload_binary = malloc(payload_len);
    if (!payload_binary) {
        free(recipients_flat);
        cJSON_Delete(json);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Memory allocation failed for payload\",\"status\":\"error\"}");
        return;
    }
    
    for (int i = 0; i < payload_len; i++) {
        sscanf(payload_hex + (i * 2), "%2hhx", &payload_binary[i]);
    }
    
    // Deserialize the EncryptedPayload structure from the frontend
    const char* payload_ptr = (const char*)payload_binary;
    EncryptedPayload* enc_payload = encrypted_payload_deserialize(&payload_ptr);
    
    if (!enc_payload) {
        printf("[ERROR] Failed to deserialize EncryptedPayload from frontend (payload_len=%d bytes)\n", payload_len);
        free(recipients_flat);
        free(payload_binary);
        cJSON_Delete(json);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Invalid encrypted payload format\",\"status\":\"error\"}");
        return;
    }
    
    printf("[DEBUG] Successfully deserialized EncryptedPayload: num_recipients=%zu, ciphertext_len=%zu\n", 
           enc_payload->num_recipients, enc_payload->ciphertext_len);
    
    // Verify the number of recipients matches
    if (enc_payload->num_recipients != num_recipients) {
        printf("[ERROR] Mismatch: payload has %zu recipients but transaction has %d recipients\n", 
               enc_payload->num_recipients, num_recipients);
        free_encrypted_payload(enc_payload);
        free(recipients_flat);
        free(payload_binary);
        cJSON_Delete(json);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Recipient count mismatch between payload and transaction\",\"status\":\"error\"}");
        return;
    }
    
    // Free the temporary binary payload buffer (enc_payload now owns the data)
    free(payload_binary);
    
    // Create transaction
    TW_Transaction* transaction = TW_Transaction_create(
        TW_TXN_ACCESS_REQUEST,
        sender_pubkey,
        recipients_flat,
        num_recipients,
        NULL,           // No group ID for access requests
        enc_payload,
        signature
    );
    
    if (!transaction) {
        free(recipients_flat);
        free_encrypted_payload(enc_payload);
        cJSON_Delete(json);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Failed to create transaction\",\"status\":\"error\"}");
        return;
    }
    
    // Set optional resource_id on transaction (plaintext metadata for validation)
    if (resource_id_json && cJSON_IsString(resource_id_json)) {
        const char* resource_id_str = cJSON_GetStringValue(resource_id_json);
        if (resource_id_str) {
            strncpy(transaction->resource_id, resource_id_str, sizeof(transaction->resource_id) - 1);
            transaction->resource_id[sizeof(transaction->resource_id) - 1] = '\0';
        }
    }

    // Calculate transaction hash for response
    unsigned char tx_hash[HASH_SIZE];
    TW_Transaction_hash(transaction, tx_hash);
    
    // Convert hash to hex string
    char tx_hash_hex[HASH_SIZE * 2 + 1];
    for (int i = 0; i < HASH_SIZE; i++) {
        sprintf(tx_hash_hex + (i * 2), "%02x", tx_hash[i]);
    }
    tx_hash_hex[HASH_SIZE * 2] = '\0';
    
    // Add transaction to PBFT processing queue
    int queue_result = add_to_transaction_queue(tx_hash_hex, transaction);
    if (queue_result != 0) {
        TW_Transaction_destroy(transaction);
        free(recipients_flat);
        cJSON_Delete(json);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Failed to add transaction to PBFT queue\",\"status\":\"error\"}");
        return;
    }
    
    printf("[DEBUG] Encrypted access request submitted to PBFT, tx_hash: %s\n", tx_hash_hex);
    printf("[DEBUG] Sender: %s\n", sender_hex);
    printf("[DEBUG] Recipients: %d\n", num_recipients);
    printf("[DEBUG] Payload length: %d bytes\n", payload_len);
    
    // Send response with transaction hash for polling
    char response[512];
    snprintf(response, sizeof(response), 
             "{\"status\":\"submitted\",\"transaction_hash\":\"%s\",\"message\":\"Encrypted access request submitted to blockchain. Use polling endpoint to check status.\"}",
             tx_hash_hex);
    
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", response);
    
    // Cleanup - Do NOT destroy transaction as it's now owned by the transaction queue
    // TW_Transaction_destroy(transaction);  // REMOVED: queue now owns this transaction
    free(recipients_flat);
    cJSON_Delete(json);
}

// Poll for access request status by checking the blockchain
void handle_access_request_poll(struct mg_connection* c, struct mg_http_message* hm) {
    printf("Access request poll endpoint called\n");
    
    // Parse query parameters
    struct mg_str query = hm->query;
    char public_key_hex[PUBKEY_SIZE * 2 + 1] = {0};
    char resource_id[65] = {0};
    
    // Extract public_key parameter
    struct mg_str public_key_param = mg_str("public_key");
    if (mg_http_get_var(&query, public_key_param.buf, public_key_hex, sizeof(public_key_hex)) <= 0) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Missing public_key parameter\",\"status\":\"error\"}");
        return;
    }
    
    // Extract resource_id parameter
    struct mg_str resource_id_param = mg_str("resource_id");
    if (mg_http_get_var(&query, resource_id_param.buf, resource_id, sizeof(resource_id)) <= 0) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Missing resource_id parameter\",\"status\":\"error\"}");
        return;
    }
    
    // Convert public key from hex to binary
    if (strlen(public_key_hex) != PUBKEY_SIZE * 2) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Invalid public key length\",\"status\":\"error\"}");
        return;
    }
    
    unsigned char public_key[PUBKEY_SIZE];
    for (int i = 0; i < PUBKEY_SIZE; i++) {
        sscanf(public_key_hex + (i * 2), "%2hhx", &public_key[i]);
    }
    
    // Query database for successful access requests in the last 24 hours
    // Ensure database is initialized
    // TODO: This should use node-specific database path when node context is available
    if (db_init("state/blockchain/blockchain.db") != 0) {
        printf("[ERROR] Failed to initialize database for access request polling\n");
    }
    
    sqlite3* database = db_get_handle();
    if (!database) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Database not available\",\"status\":\"error\"}");
        return;
    }
    
    printf("[DEBUG] Access poll request for pubkey: %s, resource: %s\n", public_key_hex, resource_id);
    
    // Check for valid access request transactions in the last 1 hour
    const char* sql = 
        "SELECT timestamp, content_hash FROM transactions "
        "WHERE type = ? AND sender = ? AND resource_id = ? AND timestamp > (strftime('%s', 'now') - 3600) "
        "AND NOT EXISTS ("
        "  SELECT 1 FROM transactions revoke "
        "  WHERE revoke.sender = transactions.sender "
        "  AND revoke.type = ? "  // Would be TW_TXN_ACCESS_REVOKE if implemented
        "  AND revoke.timestamp > transactions.timestamp"
        ") "
        "ORDER BY timestamp DESC LIMIT 1";
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(database, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        printf("Failed to prepare access query: %s\n", sqlite3_errmsg(database));
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Database query failed\",\"status\":\"error\"}");
        return;
    }
    
    sqlite3_bind_int(stmt, 1, TW_TXN_ACCESS_REQUEST);
    sqlite3_bind_text(stmt, 2, public_key_hex, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, resource_id, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, -1); // Placeholder for revocation type (not implemented yet)
    
    printf("[DEBUG] Executing SQL query with TXN_TYPE=%d, PUBKEY=%s, RESOURCE=%s\n", TW_TXN_ACCESS_REQUEST, public_key_hex, resource_id);
    
    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        // Access granted
        uint64_t timestamp = sqlite3_column_int64(stmt, 0);
        const char* content_hash = (const char*)sqlite3_column_text(stmt, 1);
        
        printf("[DEBUG] Access GRANTED - timestamp: %lu, content_hash: %s\n", timestamp, content_hash ? content_hash : "NULL");
        
        char response[512];
        snprintf(response, sizeof(response), 
                 "{\"status\":\"granted\",\"resource_id\":\"%s\",\"granted_at\":%lu,\"transaction_hash\":\"%s\",\"expires_at\":%lu}",
                 resource_id, timestamp, content_hash ? content_hash : "", timestamp + 3600);
        
        mg_http_reply(c, 200, "Content-Type: application/json\r\n", response);
    } else if (rc == SQLITE_DONE) {
        // No valid access found - return "pending" to indicate frontend should keep polling
        printf("[DEBUG] Access PENDING - no valid transactions found yet (rc=%d)\n", rc);
        mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                     "{\"status\":\"pending\",\"message\":\"No access request transaction found yet. Transaction may still be processing.\"}");
    } else {
        printf("[DEBUG] Database error in access query: %s (rc=%d)\n", sqlite3_errmsg(database), rc);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Database query failed\",\"status\":\"error\"}");
    }
    
    sqlite3_finalize(stmt);
    
            // Keep database connection open for application lifetime
        // db_close(); // Removed - database should stay open
} 