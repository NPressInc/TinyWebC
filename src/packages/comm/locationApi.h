#ifndef LOCATION_API_H
#define LOCATION_API_H

#include <mongoose.h>
#include <stdbool.h>

// Handle all location-related routes
// Handles: POST /location/update, GET /location/:user_id, GET /location/history/:user_id
bool location_api_handler(struct mg_connection* c, struct mg_http_message* hm);

#endif // LOCATION_API_H

