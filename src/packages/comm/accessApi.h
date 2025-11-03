#ifndef TW_ACCESS_API_H
#define TW_ACCESS_API_H

#include "external/mongoose/mongoose.h"
#include "packages/transactions/transaction.h"
#include "features/blockchain/core/blockchain.h"
#include "packages/sql/database.h"
#include <stdio.h>
#include <stdlib.h>

// Route handler type (using the same as nodeApi.h)
typedef void (*RouteHandler)(struct mg_connection* c, struct mg_http_message* hm);

// Function declarations for access request endpoints
void handle_access_request_submit_pbft(struct mg_connection* c, struct mg_http_message* hm);
void handle_access_request_poll(struct mg_connection* c, struct mg_http_message* hm);

#endif // TW_ACCESS_API_H 