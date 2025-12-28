#include "messagesApi.h"
#include "gossipApi.h"
#include "message.pb-c.h"
#include "packages/sql/message_store.h"
#include "packages/validation/message_validation.h"
#include "message_permissions.h"
#include "packages/comm/gossip/gossip.h"
#include "packages/utils/logger.h"
#include <string.h>
#include <stdlib.h>

static void handle_submit_message(struct mg_connection* c, struct mg_http_message* hm);

bool messages_api_handler(struct mg_connection* c, struct mg_http_message* hm) {
    if (mg_strcmp(hm->uri, mg_str("/messages/submit")) == 0) {
        char method_buf[16] = {0};
        size_t method_len = hm->method.len < sizeof(method_buf) - 1 ? hm->method.len : sizeof(method_buf) - 1;
        if (hm->method.buf && method_len > 0) {
            memcpy(method_buf, hm->method.buf, method_len);
        }
        logger_info("msg_api", "messages_api_handler: /messages/submit method=%s body_len=%zu", 
                    method_buf, hm->body.len);
        if (mg_strcmp(hm->method, mg_str("POST")) == 0) {
            logger_info("msg_api", "Calling handle_submit_message");
            handle_submit_message(c, hm);
            return true;
        } else if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
            mg_http_reply(c, 200, "Access-Control-Allow-Origin: *\r\n"
                                 "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                                 "Access-Control-Allow-Headers: Content-Type\r\n", "");
            return true;
        } else {
            mg_http_reply(c, 405, "Access-Control-Allow-Origin: *\r\n", "Method Not Allowed");
            return true;
        }
    }
    return false;
}

static void handle_submit_message(struct mg_connection* c, struct mg_http_message* hm) {
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

    // 1. Unpack Message
    Tinyweb__Message* msg = tinyweb__message__unpack(NULL, body.len, (const uint8_t*)body.buf);
    if (!msg) {
        logger_error("msg_api", "Failed to unpack message protobuf");
        mg_http_reply(c, 400, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Invalid protobuf\"}");
        return;
    }

    // 2. Validate Message (Signature, Timestamp, Size)
    MessageValidationResult val_res = message_validate(msg);
    if (val_res != MESSAGE_VALIDATION_OK) {
        logger_error("msg_api", "Message validation failed: %s", message_validation_result_to_string(val_res));
        mg_http_reply(c, 400, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"%s\"}", 
                      message_validation_result_to_string(val_res));
        tinyweb__message__free_unpacked(msg, NULL);
        return;
    }

    // 3. Check Permissions
    const unsigned char* sender = msg->header->sender_pubkey.data;
    const unsigned char* group_id = msg->header->group_id.len > 0 ? msg->header->group_id.data : NULL;
    size_t num_recipients = msg->header->n_recipients_pubkey;
    
    // Note: In our current design, we check if the sender can message the recipients
    if (!message_permissions_check(sender, NULL, group_id, num_recipients)) {
        logger_error("msg_api", "Permission denied for messaging");
        mg_http_reply(c, 403, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Forbidden\"}");
        tinyweb__message__free_unpacked(msg, NULL);
        return;
    }

    // 4. Check Duplicate
    unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE];
    if (message_store_compute_digest(msg, digest) != 0) {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Internal error\"}");
        tinyweb__message__free_unpacked(msg, NULL);
        return;
    }

    int seen = 0;
    if (message_store_has_seen(digest, &seen) == 0 && seen) {
        mg_http_reply(c, 202, "Access-Control-Allow-Origin: *\r\n", "{\"status\":\"duplicate\"}");
        tinyweb__message__free_unpacked(msg, NULL);
        return;
    }

    // 5. Store Message
    uint64_t expires_at = message_validation_get_expiration(msg);
    if (message_store_save(msg, expires_at) != 0) {
        mg_http_reply(c, 500, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Storage failed\"}");
        tinyweb__message__free_unpacked(msg, NULL);
        return;
    }

    // 6. Mark Seen
    message_store_mark_seen(digest, expires_at);

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
        if (gossip_service_broadcast_message(gossip_service, msg) != 0) {
            logger_error("msg_api", "Failed to broadcast message");
        }
    }

    tinyweb__message__free_unpacked(msg, NULL);
}

