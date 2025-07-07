#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <sqlite3.h>
#include "external/mongoose/mongoose.h"
#include "nodeApi.h"
#include "../sql/database.h"
#include "../keystore/keystore.h"



void handle_json(struct mg_connection* c, struct mg_http_message* hm) {
    // Print JSON data
    printf("Received JSON: %.*s\n", (int)hm->body.len, hm->body.buf);
    
    // Send response
    mg_http_reply(c, 200, "Content-Type: application/json\r\n",
                 "{\"status\": \"received\"}");
}

void handle_binary(struct mg_connection* c, struct mg_http_message* hm) {
    // Print binary data as hex
    printf("Received binary data (%zu bytes):\n", hm->body.len);
    for (size_t i = 0; i < hm->body.len; i++) {
        printf("%02x ", (unsigned char)hm->body.buf[i]);
    }
    printf("\n");
    
    // Send binary response
    mg_http_reply(c, 200, 
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: 1\r\n",
        "\x01");  // Simple binary response
}

/**
 * GET /api/v1/recipients/keys - Get X25519 public keys for transaction recipients
 * Returns admin users and node keys for access request encryption
 */
void handle_get_recipient_keys(struct mg_connection *c, struct mg_http_message *hm) {
    char response[4096];
    char admin_keys_json[2048] = "";
    char node_keys_json[1024] = "";
    
    // Get admin users using direct SQL query
    // Ensure database is initialized
    if (db_init("state/blockchain/blockchain.db") != 0) {
        printf("[ERROR] Failed to initialize database for recipient keys query\n");
    }
    
    sqlite3* db = db_get_handle();
    if (db) {
        sqlite3_stmt* stmt;
        const char* admin_query = 
            "SELECT DISTINCT u.pubkey, u.username "
            "FROM users u "
            "JOIN user_roles ur ON u.id = ur.user_id "
            "JOIN roles r ON ur.role_id = r.id "
            "WHERE r.name = 'admin' AND u.is_active = 1 AND ur.is_active = 1";
        
        if (sqlite3_prepare_v2(db, admin_query, -1, &stmt, NULL) == SQLITE_OK) {
            int admin_count = 0;
            
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* ed25519_pubkey_hex = (const char*)sqlite3_column_text(stmt, 0);
                const char* username = (const char*)sqlite3_column_text(stmt, 1);
                
                if (ed25519_pubkey_hex && username) {
                    // Convert Ed25519 public key to X25519 for encryption
                    unsigned char ed25519_pubkey[32];
                    unsigned char x25519_pubkey[32];
                    
                    // Decode hex Ed25519 public key from database
                    if (db_hex_decode(ed25519_pubkey_hex, ed25519_pubkey, 32) == 32) {
                        // Convert Ed25519 to X25519
                        if (crypto_sign_ed25519_pk_to_curve25519(x25519_pubkey, ed25519_pubkey) == 0) {
                            // Convert X25519 to hex
                            char x25519_hex[65];
                            if (db_hex_encode(x25519_pubkey, 32, x25519_hex, sizeof(x25519_hex)) == 0) {
                                if (admin_count > 0) {
                                    strncat(admin_keys_json, ",", sizeof(admin_keys_json) - strlen(admin_keys_json) - 1);
                                }
                                char key_entry[256];
                                snprintf(key_entry, sizeof(key_entry), 
                                        "{\"username\":\"%s\",\"ed25519_pubkey\":\"%s\",\"x25519_pubkey\":\"%s\"}",
                                        username, ed25519_pubkey_hex, x25519_hex);
                                strncat(admin_keys_json, key_entry, sizeof(admin_keys_json) - strlen(admin_keys_json) - 1);
                                admin_count++;
                            }
                        }
                    }
                }
            }
            
            sqlite3_finalize(stmt);
        }
        
        // Keep database connection open for application lifetime
        // db_close(); // Removed - database should stay open
    }
    
    // Get current node's X25519 key
    if (keystore_is_keypair_loaded()) {
        unsigned char node_x25519_pubkey[32];
        if (keystore_get_encryption_public_key(node_x25519_pubkey)) {
            char node_x25519_hex[65];
            if (db_hex_encode(node_x25519_pubkey, 32, node_x25519_hex, sizeof(node_x25519_hex)) == 0) {
                unsigned char node_ed25519_pubkey[32];
                if (keystore_get_public_key(node_ed25519_pubkey)) {
                    char node_ed25519_hex[65];
                    if (db_hex_encode(node_ed25519_pubkey, 32, node_ed25519_hex, sizeof(node_ed25519_hex)) == 0) {
                        snprintf(node_keys_json, sizeof(node_keys_json),
                                "{\"node_id\":\"current_node\",\"ed25519_pubkey\":\"%s\",\"x25519_pubkey\":\"%s\"}",
                                node_ed25519_hex, node_x25519_hex);
                    }
                }
            }
        }
    }
    
    // Build complete response
    snprintf(response, sizeof(response),
        "{"
        "\"status\":\"success\","
        "\"data\":{"
            "\"admin_users\":[%s],"
            "\"nodes\":[%s],"
            "\"note\":\"X25519 keys are for encryption, Ed25519 keys are for verification\""
        "}"
        "}",
        admin_keys_json, node_keys_json);
    
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", response);
}

// Route table
Route routes[] = {
    {"/api/json", "POST", handle_json},
    {"/api/binary", "POST", handle_binary},
    {NULL, NULL, NULL}
};

// Main event handler
static void fn(struct mg_connection* c, int ev, void* ev_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message* hm = (struct mg_http_message*)ev_data;
        
        // Find and call matching route
        for (Route* r = routes; r->path != NULL; r++) {
            struct mg_str path = mg_str(r->path);
            if (mg_match(hm->uri, path, NULL) && 
                mg_strcmp(hm->method, mg_str(r->method)) == 0) {
                r->handler(c, hm);
                return;
            }
        }
        
        // No route found
        mg_http_reply(c, 404, NULL, "Not Found");
    }
}

void start_node_api(const char* port) {
    struct mg_mgr mgr;
    mg_mgr_init(&mgr);
    
    // Start HTTP server
    mg_http_listen(&mgr, port, fn, NULL);
    
    printf("Server running on %s\n", port);
    
    // Main event loop
    for (;;) {
        mg_mgr_poll(&mgr, 1000);
    }
    
    mg_mgr_free(&mgr);
}