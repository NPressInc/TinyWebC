#ifndef INVITATION_API_H
#define INVITATION_API_H

#include "invitation.h"
#include "../../external/mongoose/mongoose.h"

// =============================================================================
// HTTP API ENDPOINTS FOR INVITATION SYSTEM
// =============================================================================

/**
 * Initialize invitation API endpoints
 * @return 1 on success, 0 on failure
 */
int invitation_api_init(void);

/**
 * Register invitation API routes with HTTP server
 * @param connection HTTP server connection to register routes with
 */
void invitation_api_register_routes(struct mg_connection* connection);

// =============================================================================
// REST API HANDLERS
// =============================================================================

/**
 * POST /invitation/create
 * Create a new invitation
 * 
 * Request body:
 * {
 *   "invited_name": "Emma Smith",
 *   "invitation_message": "Welcome to our family network!",
 *   "type": "family_member|family_admin|family_node|emergency_contact|community_member",
 *   "granted_permissions": 123456789,
 *   "requires_supervision": true,
 *   "proposed_ip": "192.168.1.100",     // For node invitations only
 *   "proposed_port": 8002               // For node invitations only
 * }
 * 
 * Response:
 * {
 *   "success": true,
 *   "invitation_code": "ABC123DEF456...",
 *   "expires_at": 1640995200,
 *   "message": "Invitation created successfully"
 * }
 */
void invitation_api_create(struct mg_connection* c, struct mg_http_message* hm);

/**
 * GET /invitation/pending
 * Get all pending invitations (admin only)
 * 
 * Response:
 * {
 *   "success": true,
 *   "invitations": [
 *     {
 *       "invitation_code": "ABC123...",
 *       "invited_name": "Emma Smith",
 *       "type": "family_member",
 *       "status": "pending",
 *       "created_at": 1640995200,
 *       "expires_at": 1641253200
 *     }
 *   ]
 * }
 */
void invitation_api_get_pending(struct mg_connection* c, struct mg_http_message* hm);

/**
 * GET /invitation/{code}
 * Get details of a specific invitation
 * 
 * Response:
 * {
 *   "success": true,
 *   "invitation": {
 *     "invitation_code": "ABC123...",
 *     "family_name": "Smith Family Network",
 *     "invited_name": "Emma Smith",
 *     "invitation_message": "Welcome!",
 *     "type": "family_member",
 *     "status": "pending",
 *     "created_at": 1640995200,
 *     "expires_at": 1641253200,
 *     "requires_supervision": true
 *   }
 * }
 */
void invitation_api_get_details(struct mg_connection* c, struct mg_http_message* hm);

/**
 * POST /invitation/accept/{code}
 * Accept an invitation
 * 
 * Request body:
 * {
 *   "acceptor_name": "Emma Smith",
 *   "acceptor_pubkey": "base64_encoded_public_key"
 * }
 * 
 * Response:
 * {
 *   "success": true,
 *   "message": "Invitation accepted successfully",
 *   "user_id": "generated_user_id",
 *   "granted_permissions": 123456789
 * }
 */
void invitation_api_accept(struct mg_connection* c, struct mg_http_message* hm);

/**
 * POST /invitation/reject/{code}
 * Reject an invitation
 * 
 * Request body:
 * {
 *   "rejector_pubkey": "base64_encoded_public_key"
 * }
 * 
 * Response:
 * {
 *   "success": true,
 *   "message": "Invitation rejected"
 * }
 */
void invitation_api_reject(struct mg_connection* c, struct mg_http_message* hm);

/**
 * DELETE /invitation/{code}
 * Revoke an invitation (admin only)
 * 
 * Request body:
 * {
 *   "reason": "No longer needed"
 * }
 * 
 * Response:
 * {
 *   "success": true,
 *   "message": "Invitation revoked"
 * }
 */
void invitation_api_revoke(struct mg_connection* c, struct mg_http_message* hm);

/**
 * GET /invitation/stats
 * Get invitation statistics (admin only)
 * 
 * Response:
 * {
 *   "success": true,
 *   "stats": {
 *     "total_created": 15,
 *     "total_accepted": 10,
 *     "total_pending": 3,
 *     "total_expired": 2
 *   }
 * }
 */
void invitation_api_get_stats(struct mg_connection* c, struct mg_http_message* hm);

/**
 * GET /invitation/my
 * Get invitations created by the current user
 * 
 * Response:
 * {
 *   "success": true,
 *   "invitations": [
 *     {
 *       "invitation_code": "ABC123...",
 *       "invited_name": "Emma Smith",
 *       "status": "pending",
 *       "created_at": 1640995200
 *     }
 *   ]
 * }
 */
void invitation_api_get_my_invitations(struct mg_connection* c, struct mg_http_message* hm);

// =============================================================================
// UTILITY FUNCTIONS FOR API
// =============================================================================

/**
 * Extract invitation code from URL path
 * @param uri The HTTP URI (e.g., "/invitation/ABC123")
 * @param code_out Buffer to store extracted code
 * @param code_size Size of the code buffer
 * @return 1 on success, 0 on failure
 */
int invitation_api_extract_code_from_path(struct mg_str uri, char* code_out, size_t code_size);

/**
 * Validate API request permissions
 * @param hm HTTP message containing the request
 * @param required_permissions Permissions required for this operation
 * @return 1 if authorized, 0 if not authorized
 */
int invitation_api_check_permissions(struct mg_http_message* hm, uint64_t required_permissions);

/**
 * Send JSON error response
 * @param c HTTP connection
 * @param status_code HTTP status code
 * @param error_message Error message to include
 */
void invitation_api_send_error(struct mg_connection* c, int status_code, const char* error_message);

/**
 * Send JSON success response
 * @param c HTTP connection
 * @param json_data JSON data to include in response
 */
void invitation_api_send_success(struct mg_connection* c, const char* json_data);

// Note: JSON parsing helper functions are implemented in invitationApi.c

// =============================================================================
// INTEGRATION WITH EXISTING API SYSTEM
// =============================================================================

/**
 * Route invitation API calls from main HTTP handler
 * @param c HTTP connection
 * @param hm HTTP message
 * @return 1 if handled, 0 if not an invitation API call
 */
int invitation_api_route_request(struct mg_connection* c, struct mg_http_message* hm);

#endif // INVITATION_API_H 