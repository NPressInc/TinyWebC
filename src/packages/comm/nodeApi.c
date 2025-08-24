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