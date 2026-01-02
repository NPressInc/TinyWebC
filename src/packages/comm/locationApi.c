#include "locationApi.h"
#include "gossipApi.h"
#include "request_auth.h"
#include "client_request.pb-c.h"
#include "envelope.pb-c.h"
#include "content.pb-c.h"
#include "packages/sql/location_store.h"
#include "packages/validation/client_request_validation.h"
#include "packages/comm/client_request_converter.h"
#include "packages/comm/location_permissions.h"
#include "packages/sql/permissions.h"
#include "packages/comm/gossip/gossip.h"
#include "packages/encryption/encryption.h"
#include "packages/utils/logger.h"
#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include <cJSON.h>

static void handle_submit_location_update(struct mg_connection* c, struct mg_http_message* hm);
static void handle_get_location(struct mg_connection* c, struct mg_http_message* hm);
static void handle_get_location_history(struct mg_connection* c, struct mg_http_message* hm);
static int parse_user_id_from_uri(const struct mg_str* uri, unsigned char* out_pubkey);
static int hex_decode(const char* hex, unsigned char** out, size_t* out_len);

bool location_api_handler(struct mg_connection* c, struct mg_http_message* hm) {
    // Check for POST /location/update
    if (mg_strcmp(hm->uri, mg_str("/location/update")) == 0) {
        char method_buf[16] = {0};
        size_t method_len = hm->method.len < sizeof(method_buf) - 1 ? hm->method.len : sizeof(method_buf) - 1;
        if (hm->method.buf && method_len > 0) {
            memcpy(method_buf, hm->method.buf, method_len);
        }
        logger_info("location_api", "location_api_handler: /location/update method=%s body_len=%zu", 
                    method_buf, hm->body.len);
        if (mg_strcmp(hm->method, mg_str("POST")) == 0) {
            logger_info("location_api", "Calling handle_submit_location_update");
            handle_submit_location_update(c, hm);
            return true;
        } else if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
            mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\r\n"
                                 "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                                 "Access-Control-Allow-Headers: Content-Type, X-User-Pubkey, X-Signature, X-Timestamp\r\n", "");
            return true;
        } else {
            mg_http_reply(c, 405, "Access-Control-Allow-Origin: *\r\n", "Method Not Allowed");
            return true;
        }
    }
    
    // Check for GET /location/:user_id (URI starts with /location/ and has hex pubkey)
    char uri_buf[256] = {0};
    size_t uri_len = hm->uri.len < sizeof(uri_buf) - 1 ? hm->uri.len : sizeof(uri_buf) - 1;
    if (hm->uri.buf && uri_len > 0) {
        memcpy(uri_buf, hm->uri.buf, uri_len);
        uri_buf[uri_len] = '\0';
    }
    
    if (strncmp(uri_buf, "/location/", 10) == 0) {
        if (mg_strcmp(hm->method, mg_str("GET")) == 0) {
            // Check if it's /location/history/:user_id
            if (strncmp(uri_buf, "/location/history/", 18) == 0) {
                handle_get_location_history(c, hm);
                return true;
            } else {
                // It's /location/:user_id
                handle_get_location(c, hm);
                return true;
            }
        } else if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
            mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\r\n"
                                 "Access-Control-Allow-Methods: GET, OPTIONS\r\n"
                                 "Access-Control-Allow-Headers: Content-Type, X-User-Pubkey, X-Signature, X-Timestamp\r\n", "");
            return true;
        } else {
            mg_http_reply(c, 405, "Access-Control-Allow-Origin: *\r\n", "Method Not Allowed");
            return true;
        }
    }
    
    return false;
}

static int hex_decode(const char* hex, unsigned char** out, size_t* out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1;
    size_t buffer_len = hex_len / 2;
    unsigned char* buffer = malloc(buffer_len);
    if (!buffer) return -1;
    size_t bin_len = 0;
    if (sodium_hex2bin(buffer, buffer_len, hex, hex_len, NULL, &bin_len, NULL) != 0) {
        free(buffer);
        return -1;
    }
    *out = buffer;
    *out_len = bin_len;
    return 0;
}

static int parse_user_id_from_uri(const struct mg_str* uri, unsigned char* out_pubkey) {
    if (!uri || !out_pubkey) return -1;
    
    // Find the last / in the URI
    const char* last_slash = NULL;
    for (size_t i = 0; i < uri->len; i++) {
        if (uri->buf[i] == '/') {
            last_slash = uri->buf + i;
        }
    }
    
    if (!last_slash || last_slash == uri->buf + uri->len - 1) {
        return -1; // No slash found or it's at the end
    }
    
    // Extract hex string after last slash
    const char* hex_start = last_slash + 1;
    size_t hex_len = uri->buf + uri->len - hex_start;
    
    if (hex_len == 0) return -1;
    
    char hex_buf[128] = {0};
    if (hex_len >= sizeof(hex_buf)) return -1;
    memcpy(hex_buf, hex_start, hex_len);
    hex_buf[hex_len] = '\0';
    
    // Decode hex to binary
    unsigned char* decoded = NULL;
    size_t decoded_len = 0;
    if (hex_decode(hex_buf, &decoded, &decoded_len) != 0) {
        return -1;
    }
    
    if (decoded_len != PUBKEY_SIZE) {
        free(decoded);
        return -1;
    }
    
    memcpy(out_pubkey, decoded, PUBKEY_SIZE);
    free(decoded);
    return 0;
}

static void handle_submit_location_update(struct mg_connection* c, struct mg_http_message* hm) {
    // Authenticate request (optional but recommended - validates requester is registered)
    // Note: ClientRequest itself is also signed, providing additional authentication
    unsigned char requester_pubkey[PUBKEY_SIZE];
    RequestAuthResult auth_result = validate_request_auth(hm, requester_pubkey);
    if (auth_result != REQUEST_AUTH_OK) {
        mg_http_reply(c, 401, "Access-Control-Allow-Origin: *\r\n", 
                     "{\"error\":\"%s\"}", request_auth_error_string(auth_result));
        return;
    }
    
    struct mg_str body = hm->body;
    if (body.len == 0) {
        mg_http_reply(c, 400, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Empty body\"}");
        return;
    }

    // Protection: reject oversized bodies before unpacking (1MB limit)
    if (body.len > 1024 * 1024) {
        mg_http_reply(c, 413, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Payload too large\"}");
        return;
    }

    // 1. Unpack ClientRequest
    Tinyweb__ClientRequest* request = tinyweb__client_request__unpack(NULL, body.len, (const uint8_t*)body.buf);
    if (!request) {
        logger_error("location_api", "Failed to unpack client request protobuf");
        mg_http_reply(c, 400, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Invalid protobuf\"}");
        return;
    }

    // 2. Validate ClientRequest (Signature, Timestamp, Size)
    ClientRequestValidationResult val_res = client_request_validate(request);
    if (val_res != CLIENT_REQUEST_VALIDATION_OK) {
        logger_error("location_api", "ClientRequest validation failed: %s", client_request_validation_result_to_string(val_res));
        mg_http_reply(c, 400, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"%s\"}", 
                      client_request_validation_result_to_string(val_res));
        tinyweb__client_request__free_unpacked(request, NULL);
        return;
    }

    // 2.5. Verify requester matches request sender
    const unsigned char* sender = request->header->sender_pubkey.data;
    if (memcmp(requester_pubkey, sender, PUBKEY_SIZE) != 0) {
        logger_error("location_api", "Requester does not match request sender");
        mg_http_reply(c, 403, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Requester must match request sender\"}");
        tinyweb__client_request__free_unpacked(request, NULL);
        return;
    }

    // 2.6. Validate sender is a registered user
    if (!user_exists(sender)) {
        logger_error("location_api", "Sender is not a registered user");
        mg_http_reply(c, 403, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Sender not registered\"}");
        tinyweb__client_request__free_unpacked(request, NULL);
        return;
    }

    // 2.7. Check permissions: sender can submit location updates
    if (!location_permissions_check_submit(sender)) {
        logger_error("location_api", "Sender does not have permission to submit location updates");
        mg_http_reply(c, 403, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Permission denied\"}");
        tinyweb__client_request__free_unpacked(request, NULL);
        return;
    }

    // 2.8. Validate all recipients are registered users
    for (size_t i = 0; i < request->header->n_recipients_pubkey; i++) {
        const unsigned char* recipient = request->header->recipients_pubkey[i].data;
        if (!user_exists(recipient)) {
            logger_error("location_api", "Recipient %zu is not a registered user", i);
            mg_http_reply(c, 403, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Recipient not registered\"}");
            tinyweb__client_request__free_unpacked(request, NULL);
            return;
        }
    }

    // 3. Validate recipients (check all required recipients are in keywraps)
    ClientRequestValidationResult recip_res = client_request_validate_recipients(request);
    if (recip_res != CLIENT_REQUEST_VALIDATION_OK) {
        logger_error("location_api", "Recipient validation failed: %s", client_request_validation_result_to_string(recip_res));
        mg_http_reply(c, 400, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"%s\"}", 
                      client_request_validation_result_to_string(recip_res));
        tinyweb__client_request__free_unpacked(request, NULL);
        return;
    }

    // 4. Check Duplicate
    unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE];
    if (location_store_compute_digest_client_request(request, digest) != 0) {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Internal error\"}");
        tinyweb__client_request__free_unpacked(request, NULL);
        return;
    }

    int seen = 0;
    if (location_store_has_seen(digest, &seen) == 0 && seen) {
        mg_http_reply(c, 202, "Access-Control-Allow-Origin: *\r\n", "{\"status\":\"duplicate\"}");
        tinyweb__client_request__free_unpacked(request, NULL);
        return;
    }

    // 5. Store Location Update
    uint64_t expires_at = client_request_get_expiration(request);
    if (location_store_save(request, expires_at) != 0) {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Storage failed\"}");
        tinyweb__client_request__free_unpacked(request, NULL);
        return;
    }

    // 6. Mark Seen
    location_store_mark_seen(digest, expires_at);

    // 7. Success Response (send immediately, before gossip broadcast)
    // This prevents blocking the HTTP response on network I/O (DNS lookups, sendto calls)
    mg_http_reply(c, 202, "Content-Type: application/json\r\n"
                         "Access-Control-Allow-Origin: *\r\n", 
                  "{\"status\":\"accepted\"}");

    // 8. Broadcast via Gossip (after response sent to client)
    // Note: This is still synchronous but happens after the client gets the response
    // The gossip broadcast involves DNS lookups (getaddrinfo) and UDP sends (sendto)
    // which can be slow, but the client already has its response
    GossipService* gossip_service = gossip_api_get_service();
    if (gossip_service) {
        // Convert ClientRequest to Envelope for gossip broadcast
        Tinyweb__Envelope* envelope = client_request_to_envelope(request);
        if (envelope) {
            if (gossip_service_broadcast_envelope(gossip_service, envelope) != 0) {
                logger_error("location_api", "Failed to broadcast location update");
            }
            tinyweb__envelope__free_unpacked(envelope, NULL);
        } else {
            logger_error("location_api", "Failed to convert ClientRequest to Envelope");
        }
    }

    tinyweb__client_request__free_unpacked(request, NULL);
}

static void handle_get_location(struct mg_connection* c, struct mg_http_message* hm) {
    // Authenticate requester
    unsigned char requester_pubkey[PUBKEY_SIZE];
    RequestAuthResult auth_result = validate_request_auth(hm, requester_pubkey);
    if (auth_result != REQUEST_AUTH_OK) {
        mg_http_reply(c, 401, "Access-Control-Allow-Origin: *\r\n", 
                     "{\"error\":\"%s\"}", request_auth_error_string(auth_result));
        return;
    }
    
    // Parse user_id from URI
    unsigned char user_pubkey[PUBKEY_SIZE];
    if (parse_user_id_from_uri(&hm->uri, user_pubkey) != 0) {
        mg_http_reply(c, 400, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Invalid user_id format\"}");
        return;
    }
    
    // Check permissions (must be admin/parent or the user themselves)
    if (!location_permissions_check_view(requester_pubkey, user_pubkey)) {
        logger_error("location_api", "Requester does not have permission to view location for user");
        mg_http_reply(c, 403, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Forbidden\"}");
        return;
    }
    
    // Query latest encrypted location
    unsigned char* encrypted_data = NULL;
    size_t encrypted_len = 0;
    int is_envelope = 0;
    
    if (location_store_get_latest(user_pubkey, &encrypted_data, &encrypted_len, &is_envelope) != 0 || !encrypted_data) {
        mg_http_reply(c, 404, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Location not found\"}");
        return;
    }
    
    // Unpack the encrypted structure
    Tinyweb__ClientRequest* request = NULL;
    Tinyweb__Envelope* envelope = NULL;
    
    if (is_envelope) {
        envelope = tinyweb__envelope__unpack(NULL, encrypted_len, encrypted_data);
        if (!envelope) {
            location_store_free_data(encrypted_data);
            mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Failed to unpack envelope\"}");
            return;
        }
    } else {
        request = tinyweb__client_request__unpack(NULL, encrypted_len, encrypted_data);
        if (!request) {
            location_store_free_data(encrypted_data);
            mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Failed to unpack client request\"}");
            return;
        }
    }
    
    location_store_free_data(encrypted_data);
    
    // Decrypt the payload (try to decrypt using requester's key)
    unsigned char* decrypted = NULL;
    size_t decrypted_len = 0;
    int decrypt_result = -1;
    
    if (is_envelope) {
        decrypt_result = decrypt_envelope_payload(envelope, &decrypted, &decrypted_len);
    } else {
        // For ClientRequest, we need to decrypt using decrypt_message_payload logic
        // But ClientRequest uses ClientRequestKeyWrap, not MessageRecipientKeyWrap
        // For now, convert to envelope and decrypt
        Tinyweb__Envelope* temp_envelope = client_request_to_envelope(request);
        if (temp_envelope) {
            decrypt_result = decrypt_envelope_payload(temp_envelope, &decrypted, &decrypted_len);
            tinyweb__envelope__free_unpacked(temp_envelope, NULL);
        }
    }
    
    if (decrypt_result != 0 || !decrypted) {
        if (envelope) tinyweb__envelope__free_unpacked(envelope, NULL);
        if (request) tinyweb__client_request__free_unpacked(request, NULL);
        mg_http_reply(c, 403, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Decryption failed (not a recipient?)\"}");
        return;
    }
    
    // Unpack LocationUpdate from decrypted payload
    Tinyweb__LocationUpdate* location = tinyweb__location_update__unpack(NULL, decrypted_len, decrypted);
    free(decrypted);
    
    if (!location) {
        if (envelope) tinyweb__envelope__free_unpacked(envelope, NULL);
        if (request) tinyweb__client_request__free_unpacked(request, NULL);
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Failed to unpack LocationUpdate\"}");
        return;
    }
    
    // Build JSON response
    cJSON* json = cJSON_CreateObject();
    cJSON_AddNumberToObject(json, "lat", location->lat);
    cJSON_AddNumberToObject(json, "lon", location->lon);
    cJSON_AddNumberToObject(json, "accuracy_m", location->accuracy_m);
    cJSON_AddNumberToObject(json, "timestamp", (double)location->timestamp);
    if (location->location_name && strlen(location->location_name) > 0) {
        cJSON_AddStringToObject(json, "location_name", location->location_name);
    }
    
    char* json_string = cJSON_Print(json);
    cJSON_Delete(json);
    tinyweb__location_update__free_unpacked(location, NULL);
    if (envelope) tinyweb__envelope__free_unpacked(envelope, NULL);
    if (request) tinyweb__client_request__free_unpacked(request, NULL);
    
    if (!json_string) {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Failed to serialize response\"}");
        return;
    }
    
    mg_http_reply(c, 200, "Content-Type: application/json\r\n"
                         "Access-Control-Allow-Origin: *\r\n",
                  "%s", json_string);
    free(json_string);
}

static void handle_get_location_history(struct mg_connection* c, struct mg_http_message* hm) {
    // Authenticate requester
    unsigned char requester_pubkey[PUBKEY_SIZE];
    RequestAuthResult auth_result = validate_request_auth(hm, requester_pubkey);
    if (auth_result != REQUEST_AUTH_OK) {
        mg_http_reply(c, 401, "Access-Control-Allow-Origin: *\r\n", 
                     "{\"error\":\"%s\"}", request_auth_error_string(auth_result));
        return;
    }
    
    // Parse user_id from URI
    unsigned char user_pubkey[PUBKEY_SIZE];
    if (parse_user_id_from_uri(&hm->uri, user_pubkey) != 0) {
        mg_http_reply(c, 400, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Invalid user_id format\"}");
        return;
    }
    
    // Check permissions (must be admin/parent or the user themselves)
    if (!location_permissions_check_view(requester_pubkey, user_pubkey)) {
        logger_error("location_api", "Requester does not have permission to view location history for user");
        mg_http_reply(c, 403, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Forbidden\"}");
        return;
    }
    
    // Parse query parameters
    uint32_t limit = 50;
    uint32_t offset = 0;
    
    char limit_val[32] = {0};
    if (mg_http_get_var(&hm->query, "limit", limit_val, sizeof(limit_val)) > 0) {
        int parsed = atoi(limit_val);
        if (parsed > 0 && parsed <= 1000) limit = (uint32_t)parsed;
    }
    
    char offset_val[32] = {0};
    if (mg_http_get_var(&hm->query, "offset", offset_val, sizeof(offset_val)) > 0) {
        int parsed = atoi(offset_val);
        if (parsed >= 0) offset = (uint32_t)parsed;
    }
    
    // Query encrypted history
    unsigned char** encrypted_data_array = NULL;
    size_t* encrypted_len_array = NULL;
    size_t count = 0;
    int* is_envelope_array = NULL;
    
    if (location_store_get_history(user_pubkey, limit, offset, &encrypted_data_array, &encrypted_len_array, &count, &is_envelope_array) != 0) {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Failed to query history\"}");
        return;
    }
    
    if (count == 0) {
        mg_http_reply(c, 200, "Content-Type: application/json\r\n"
                             "Access-Control-Allow-Origin: *\r\n",
                      "{\"locations\":[],\"count\":0}");
        return;
    }
    
    // Build JSON array of decrypted locations
    cJSON* json = cJSON_CreateObject();
    cJSON* locations_array = cJSON_CreateArray();
    
    size_t decrypted_count = 0;
    for (size_t i = 0; i < count; i++) {
        if (!encrypted_data_array[i]) continue;
        
        // Unpack the encrypted structure
        Tinyweb__ClientRequest* request = NULL;
        Tinyweb__Envelope* envelope = NULL;
        
        if (is_envelope_array[i]) {
            envelope = tinyweb__envelope__unpack(NULL, encrypted_len_array[i], encrypted_data_array[i]);
        } else {
            request = tinyweb__client_request__unpack(NULL, encrypted_len_array[i], encrypted_data_array[i]);
        }
        
        if (!envelope && !request) continue;
        
        // Decrypt the payload
        unsigned char* decrypted = NULL;
        size_t decrypted_len = 0;
        int decrypt_result = -1;
        
        if (is_envelope_array[i]) {
            decrypt_result = decrypt_envelope_payload(envelope, &decrypted, &decrypted_len);
        } else {
            Tinyweb__Envelope* temp_envelope = client_request_to_envelope(request);
            if (temp_envelope) {
                decrypt_result = decrypt_envelope_payload(temp_envelope, &decrypted, &decrypted_len);
                tinyweb__envelope__free_unpacked(temp_envelope, NULL);
            }
        }
        
        if (decrypt_result != 0 || !decrypted) {
            if (envelope) tinyweb__envelope__free_unpacked(envelope, NULL);
            if (request) tinyweb__client_request__free_unpacked(request, NULL);
            continue; // Skip entries we can't decrypt
        }
        
        // Unpack LocationUpdate
        Tinyweb__LocationUpdate* location = tinyweb__location_update__unpack(NULL, decrypted_len, decrypted);
        free(decrypted);
        
        if (!location) {
            if (envelope) tinyweb__envelope__free_unpacked(envelope, NULL);
            if (request) tinyweb__client_request__free_unpacked(request, NULL);
            continue;
        }
        
        // Add to JSON array
        cJSON* loc_json = cJSON_CreateObject();
        cJSON_AddNumberToObject(loc_json, "lat", location->lat);
        cJSON_AddNumberToObject(loc_json, "lon", location->lon);
        cJSON_AddNumberToObject(loc_json, "accuracy_m", location->accuracy_m);
        cJSON_AddNumberToObject(loc_json, "timestamp", (double)location->timestamp);
        if (location->location_name && strlen(location->location_name) > 0) {
            cJSON_AddStringToObject(loc_json, "location_name", location->location_name);
        }
        cJSON_AddItemToArray(locations_array, loc_json);
        
        tinyweb__location_update__free_unpacked(location, NULL);
        if (envelope) tinyweb__envelope__free_unpacked(envelope, NULL);
        if (request) tinyweb__client_request__free_unpacked(request, NULL);
        
        decrypted_count++;
    }
    
    cJSON_AddItemToObject(json, "locations", locations_array);
    cJSON_AddNumberToObject(json, "count", (double)decrypted_count);
    
    // Free encrypted data
    location_store_free_data_array(encrypted_data_array, encrypted_len_array, count, is_envelope_array);
    
    char* json_string = cJSON_Print(json);
    cJSON_Delete(json);
    
    if (!json_string) {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Failed to serialize response\"}");
        return;
    }
    
    mg_http_reply(c, 200, "Content-Type: application/json\r\n"
                         "Access-Control-Allow-Origin: *\r\n",
                  "%s", json_string);
    free(json_string);
}

