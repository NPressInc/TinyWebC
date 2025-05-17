#ifndef TW_NODE_API_H
#define TW_NODE_API_H

#include "external/mongoose/mongoose.h"
#include <stdio.h>
#include <stdlib.h>

// Route handler type
typedef void (*RouteHandler)(struct mg_connection* c, struct mg_http_message* hm);

// Route structure
typedef struct {
    const char* path;
    const char* method;
    RouteHandler handler;
} Route;

// Function declarations
void handle_json(struct mg_connection* c, struct mg_http_message* hm);
void handle_binary(struct mg_connection* c, struct mg_http_message* hm);
static void fn(struct mg_connection* c, int ev, void* ev_data);
void start_node_api(const char* port);

#endif // TW_NODE_API_H