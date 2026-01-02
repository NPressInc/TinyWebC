#include "authApi.h"
#include "request_auth.h"
#include "packages/sql/permissions.h"
#include "packages/utils/logger.h"
#include <sodium.h>
#include <string.h>
#include <stdlib.h>

static void handle_login(struct mg_connection* c, struct mg_http_message* hm);

bool auth_api_handler(struct mg_connection* c, struct mg_http_message* hm) {
    if (mg_strcmp(hm->uri, mg_str("/auth/login")) == 0) {
        if (mg_strcmp(hm->method, mg_str("POST")) == 0) {
            handle_login(c, hm);
            return true;
        } else if (mg_strcmp(hm->method, mg_str("OPTIONS")) == 0) {
            mg_http_reply(c, 200,
                          "Access-Control-Allow-Origin: *\r\n"
                          "Access-Control-Allow-Methods: POST, OPTIONS\r\n"
                          "Access-Control-Allow-Headers: Content-Type, X-User-Pubkey, X-Signature, X-Timestamp\r\n",
                          "");
            return true;
        } else {
            mg_http_reply(c, 405, "Access-Control-Allow-Origin: *\r\n", "{\"error\":\"Method Not Allowed\"}");
            return true;
        }
    }
    return false;
}

static void handle_login(struct mg_connection* c, struct mg_http_message* hm) {
    // Authenticate request using standard request auth
    // This verifies the signature and checks that the user is registered
    unsigned char requester_pubkey[32];
    RequestAuthResult auth_result = validate_request_auth(hm, requester_pubkey);
    
    if (auth_result != REQUEST_AUTH_OK) {
        logger_error("auth_api", "Login failed: %s", request_auth_error_string(auth_result));
        mg_http_reply(c, 401, "Access-Control-Allow-Origin: *\r\n", 
                     "{\"error\":\"%s\"}", request_auth_error_string(auth_result));
        return;
    }
    
    // Verify user is registered
    if (!user_exists(requester_pubkey)) {
        logger_error("auth_api", "Login failed: user not registered");
        mg_http_reply(c, 403, "Access-Control-Allow-Origin: *\r\n", 
                     "{\"error\":\"User not registered\"}");
        return;
    }
    
    // Login successful - return success with user info
    // Convert pubkey to hex for response
    char pubkey_hex[65];
    sodium_bin2hex(pubkey_hex, sizeof(pubkey_hex), requester_pubkey, 32);
    
    logger_info("auth_api", "Login successful for user: %s", pubkey_hex);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n"
                          "Access-Control-Allow-Origin: *\r\n",
                  "{\"status\":\"success\",\"pubkey\":\"%s\"}", pubkey_hex);
}

