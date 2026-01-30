#include "authApi.h"
#include "request_auth.h"
#include "packages/sql/permissions.h"
#include "packages/sql/database_gossip.h"
#include "packages/utils/logger.h"
#include "structs/permission/permission.h"
#include <cJSON.h>
#include <sodium.h>
#include <string.h>
#include <stdlib.h>
#include <sqlite3.h>

#define PUBKEY_SIZE 32
#define CREATE_USER_MAX_USERNAME 128
#define CREATE_USER_MAX_ROLE 32

static void handle_login(struct mg_connection* c, struct mg_http_message* hm);
static void handle_create_user(struct mg_connection* c, struct mg_http_message* hm);

static int get_role_id(sqlite3* db, const char* role_name, int* out_role_id) {
    const char* sql = "SELECT id FROM roles WHERE name = ?";
    sqlite3_stmt* stmt = NULL;
    *out_role_id = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, role_name, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *out_role_id = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return (*out_role_id > 0) ? 0 : -1;
}

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
    if (mg_strcmp(hm->uri, mg_str("/users/create")) == 0) {
        if (mg_strcmp(hm->method, mg_str("POST")) == 0) {
            handle_create_user(c, hm);
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

static void handle_create_user(struct mg_connection* c, struct mg_http_message* hm) {
    unsigned char admin_pubkey[PUBKEY_SIZE];
    RequestAuthResult auth_result = validate_request_auth(hm, admin_pubkey);
    if (auth_result != REQUEST_AUTH_OK) {
        mg_http_reply(c, 401, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"%s\"}", request_auth_error_string(auth_result));
        return;
    }
    if (!check_user_permission(admin_pubkey, PERMISSION_MANAGE_ROLES, SCOPE_GLOBAL)) {
        mg_http_reply(c, 403, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Forbidden: admin permission required to create users\"}");
        return;
    }
    if (hm->body.len == 0) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Missing JSON body\"}");
        return;
    }
    cJSON* root = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!root || !cJSON_IsObject(root)) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Invalid JSON\"}");
        if (root) cJSON_Delete(root);
        return;
    }
    cJSON* username_j = cJSON_GetObjectItem(root, "username");
    const char* username = username_j && cJSON_IsString(username_j) ? username_j->valuestring : NULL;
    if (!username || strlen(username) == 0 || strlen(username) >= CREATE_USER_MAX_USERNAME) {
        cJSON_Delete(root);
        mg_http_reply(c, 400, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Missing or invalid username\"}");
        return;
    }
    cJSON* role_j = cJSON_GetObjectItem(root, "role");
    const char* role_name = role_j && cJSON_IsString(role_j) ? role_j->valuestring : "member";
    if (strlen(role_name) >= CREATE_USER_MAX_ROLE) role_name = "member";
    cJSON* age_j = cJSON_GetObjectItem(root, "age");
    int age = (age_j && cJSON_IsNumber(age_j)) ? age_j->valueint : 0;
    cJSON_Delete(root);

    sqlite3* db = db_get_handle();
    if (!db) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Database unavailable\"}");
        return;
    }
    int role_id = -1;
    if (get_role_id(db, role_name, &role_id) != 0) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Invalid role\"}");
        return;
    }

    unsigned char new_pk[PUBKEY_SIZE];
    unsigned char new_sk[crypto_sign_SECRETKEYBYTES];
    if (crypto_sign_keypair(new_pk, new_sk) != 0) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Key generation failed\"}");
        return;
    }

    char pubkey_hex[PUBKEY_SIZE * 2 + 1];
    sodium_bin2hex(pubkey_hex, sizeof(pubkey_hex), new_pk, PUBKEY_SIZE);

    const char* insert_user_sql = "INSERT INTO users (pubkey, username, age, is_active) VALUES (?, ?, ?, 1)";
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, insert_user_sql, -1, &stmt, NULL) != SQLITE_OK) {
        logger_error("auth_api", "create_user: insert user failed: %s", sqlite3_errmsg(db));
        sodium_memzero(new_sk, sizeof(new_sk));
        mg_http_reply(c, 500, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to create user\"}");
        return;
    }
    sqlite3_bind_text(stmt, 1, pubkey_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, username, -1, SQLITE_TRANSIENT);
    if (age > 0) {
        sqlite3_bind_int(stmt, 3, age);
    } else {
        sqlite3_bind_null(stmt, 3);
    }
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sodium_memzero(new_sk, sizeof(new_sk));
        mg_http_reply(c, 409, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"User already exists or conflict\"}");
        return;
    }
    sqlite3_finalize(stmt);

    sqlite3_int64 user_id = sqlite3_last_insert_rowid(db);
    const char* insert_role_sql = "INSERT INTO user_roles (user_id, role_id, is_active) VALUES (?, ?, 1)";
    if (sqlite3_prepare_v2(db, insert_role_sql, -1, &stmt, NULL) != SQLITE_OK) {
        sodium_memzero(new_sk, sizeof(new_sk));
        mg_http_reply(c, 500, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to assign role\"}");
        return;
    }
    sqlite3_bind_int64(stmt, 1, user_id);
    sqlite3_bind_int(stmt, 2, role_id);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sodium_memzero(new_sk, sizeof(new_sk));
        mg_http_reply(c, 500, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Failed to assign role\"}");
        return;
    }
    sqlite3_finalize(stmt);

    unsigned char admin_curve_pk[crypto_box_PUBLICKEYBYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(admin_curve_pk, admin_pubkey) != 0) {
        sodium_memzero(new_sk, sizeof(new_sk));
        mg_http_reply(c, 500, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Encryption setup failed\"}");
        return;
    }
    size_t sealed_len = crypto_box_SEALBYTES + crypto_sign_SECRETKEYBYTES;
    unsigned char* sealed = (unsigned char*)malloc(sealed_len);
    if (!sealed) {
        sodium_memzero(new_sk, sizeof(new_sk));
        mg_http_reply(c, 500, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Out of memory\"}");
        return;
    }
    if (crypto_box_seal(sealed, new_sk, crypto_sign_SECRETKEYBYTES, admin_curve_pk) != 0) {
        sodium_memzero(new_sk, sizeof(new_sk));
        free(sealed);
        mg_http_reply(c, 500, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Encryption failed\"}");
        return;
    }
    sodium_memzero(new_sk, sizeof(new_sk));

    size_t b64_len = sodium_base64_encoded_len(sealed_len, sodium_base64_VARIANT_ORIGINAL);
    char* b64 = (char*)malloc(b64_len);
    if (!b64) {
        free(sealed);
        mg_http_reply(c, 500, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Out of memory\"}");
        return;
    }
    sodium_bin2base64(b64, b64_len, sealed, sealed_len, sodium_base64_VARIANT_ORIGINAL);
    free(sealed);

    cJSON* out = cJSON_CreateObject();
    cJSON_AddStringToObject(out, "pubkey", pubkey_hex);
    cJSON_AddStringToObject(out, "encrypted_private_key", b64);
    cJSON_AddStringToObject(out, "username", username);
    cJSON_AddStringToObject(out, "role", role_name);
    char* json_str = cJSON_PrintUnformatted(out);
    cJSON_Delete(out);
    free(b64);
    if (!json_str) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n",
                      "{\"error\":\"Serialization failed\"}");
        return;
    }
    mg_http_reply(c, 201, "Content-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n", "%s", json_str);
    free(json_str);
}

