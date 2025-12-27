#ifndef MESSAGES_API_H
#define MESSAGES_API_H

#include <mongoose.h>
#include <stdbool.h>

// Handle all messaging-related routes
// Currently handles: POST /messages/submit
bool messages_api_handler(struct mg_connection* c, struct mg_http_message* hm);

#endif // MESSAGES_API_H

