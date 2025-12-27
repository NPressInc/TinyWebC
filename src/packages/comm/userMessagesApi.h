#ifndef USER_MESSAGES_API_H
#define USER_MESSAGES_API_H

#include <stdint.h>
#include <stdbool.h>
#include "external/mongoose/mongoose.h"

// Handler function for user messaging routes
// Returns true if the request was handled, false otherwise
bool user_messages_api_handler(struct mg_connection* c, struct mg_http_message* hm);

#endif // USER_MESSAGES_API_H

