#ifndef AUTH_API_H
#define AUTH_API_H

#include <mongoose.h>
#include <stdbool.h>

// Auth API handler - handles login/authentication endpoints
// Returns true if request was handled, false otherwise
bool auth_api_handler(struct mg_connection* c, struct mg_http_message* hm);

#endif // AUTH_API_H

