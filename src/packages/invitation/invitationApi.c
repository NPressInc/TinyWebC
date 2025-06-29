#include "invitationApi.h"
#include "invitation.h"
#include "invitationTypes.h"
#include "../keystore/keystore.h"
#include "../utils/jsonUtils.h"
#include "../../external/mongoose/mongoose.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

// Static helper functions
static void send_json_response(struct mg_connection *c, int status_code, const char* json_str);
static void send_error_response(struct mg_connection *c, int status_code, const char* error_msg);
static char* invitation_to_json_string(const FamilyInvitation* invitation);
static char* create_success_response(const char* message, const char* data);

// =============================================================================
// HTTP ENDPOINT HANDLERS
// =============================================================================

void handle_invitation_create(struct mg_connection *c, struct mg_http_message *hm) {
    printf("🎯 Processing invitation create request\n");
    
    // Parse JSON request body
    char body[1024];
    size_t body_len = hm->body.len < sizeof(body) - 1 ? hm->body.len : sizeof(body) - 1;
    strncpy(body, hm->body.buf, body_len);
    body[body_len] = '\0';
    
    cJSON *json = cJSON_Parse(body);
    if (!json) {
        send_error_response(c, 400, "Invalid JSON format");
        return;
    }
    
    // Extract parameters
    cJSON *invitation_type = cJSON_GetObjectItem(json, "invitation_type");
    cJSON *invited_name = cJSON_GetObjectItem(json, "invited_name");
    cJSON *invitation_message = cJSON_GetObjectItem(json, "invitation_message");
    cJSON *family_name = cJSON_GetObjectItem(json, "family_name");
    
    if (!invitation_type || !cJSON_IsString(invitation_type) ||
        !invited_name || !cJSON_IsString(invited_name) ||
        !invitation_message || !cJSON_IsString(invitation_message)) {
        send_error_response(c, 400, "Missing required fields: invitation_type, invited_name, invitation_message");
        cJSON_Delete(json);
        return;
    }
    
    // Get current user's public key (TODO: implement proper authentication)
    unsigned char creator_pubkey[32];
    if (!keystore_get_public_key(creator_pubkey)) {
        send_error_response(c, 500, "Failed to get creator public key");
        cJSON_Delete(json);
        return;
    }
    
    // Parse proximity requirements
    cJSON *requires_proximity_json = cJSON_GetObjectItem(json, "requires_proximity");
    uint8_t requires_proximity = 0;
    if (requires_proximity_json && cJSON_IsBool(requires_proximity_json)) {
        requires_proximity = cJSON_IsTrue(requires_proximity_json) ? 1 : 0;
    }
    
    // Parse proximity proofs
    ProximityProof proximity_proofs[MAX_PROXIMITY_PROOFS];
    uint8_t proof_count = 0;
    
    cJSON *proximity_proofs_json = cJSON_GetObjectItem(json, "proximity_proofs");
    if (proximity_proofs_json && cJSON_IsArray(proximity_proofs_json)) {
        cJSON *proof_item = NULL;
        cJSON_ArrayForEach(proof_item, proximity_proofs_json) {
            if (proof_count >= MAX_PROXIMITY_PROOFS) break;
            
            cJSON *type_json = cJSON_GetObjectItem(proof_item, "type");
            cJSON *timestamp_json = cJSON_GetObjectItem(proof_item, "timestamp");
            cJSON *proof_data_json = cJSON_GetObjectItem(proof_item, "proof_data");
            cJSON *signature_json = cJSON_GetObjectItem(proof_item, "proof_signature");
            
            if (type_json && timestamp_json && proof_data_json && signature_json) {
                ProximityProof *proof = &proximity_proofs[proof_count];
                memset(proof, 0, sizeof(ProximityProof));
                
                // Parse proof type
                const char* type_str = cJSON_GetStringValue(type_json);
                if (strcmp(type_str, "nfc") == 0) proof->type = PROXIMITY_PROOF_NFC;
                else if (strcmp(type_str, "ble") == 0) proof->type = PROXIMITY_PROOF_BLE;
                else if (strcmp(type_str, "ultrasonic") == 0) proof->type = PROXIMITY_PROOF_ULTRASONIC;
                else if (strcmp(type_str, "gps") == 0) proof->type = PROXIMITY_PROOF_GPS;
                else if (strcmp(type_str, "qr_code") == 0) proof->type = PROXIMITY_PROOF_QR_CODE;
                else if (strcmp(type_str, "env_context") == 0) proof->type = PROXIMITY_PROOF_ENV_CONTEXT;
                else continue; // Skip unknown types
                
                proof->timestamp = (uint64_t)cJSON_GetNumberValue(timestamp_json);
                
                // TODO: Parse base64 proof_data and signature
                // For now, just mark as having data
                proof->proof_data[0] = 1; // Non-zero indicates data present
                
                proof_count++;
            }
        }
    }

    FamilyInvitation invitation;
    int success = 0;
    
    // Handle different invitation types with proximity support
    const char* type_str = cJSON_GetStringValue(invitation_type);
    if (strcmp(type_str, "family_member") == 0) {
        // User invitation
        success = invitation_create_with_proximity(
            creator_pubkey,
            cJSON_GetStringValue(invited_name),
            cJSON_GetStringValue(invitation_message),
            INVITATION_TYPE_FAMILY_MEMBER,
            0x03, // Default permissions (message + location)
            1, // Requires supervision
            requires_proximity,
            proximity_proofs,
            proof_count,
            &invitation
        );
    } else if (strcmp(type_str, "family_admin") == 0) {
        // Admin invitation
        success = invitation_create_with_proximity(
            creator_pubkey,
            cJSON_GetStringValue(invited_name),
            cJSON_GetStringValue(invitation_message),
            INVITATION_TYPE_FAMILY_ADMIN,
            0xFFFF, // Admin gets all permissions
            0, // No supervision required
            requires_proximity,
            proximity_proofs,
            proof_count,
            &invitation
        );
    } else if (strcmp(type_str, "family_node") == 0) {
        // Node invitation
        cJSON *proposed_ip = cJSON_GetObjectItem(json, "proposed_ip");
        cJSON *proposed_port = cJSON_GetObjectItem(json, "proposed_port");
        
        if (!proposed_ip || !cJSON_IsString(proposed_ip) ||
            !proposed_port || !cJSON_IsNumber(proposed_port)) {
            send_error_response(c, 400, "Node invitations require proposed_ip and proposed_port");
            cJSON_Delete(json);
            return;
        }
        
        // For node invitations, create a temporary invitation and then set network info
        success = invitation_create_with_proximity(
            creator_pubkey,
            cJSON_GetStringValue(invited_name),
            "Join as PBFT consensus node",
            INVITATION_TYPE_FAMILY_NODE,
            0, // Nodes don't get user permissions
            0, // No supervision required
            requires_proximity,
            proximity_proofs,
            proof_count,
            &invitation
        );
        
        if (success) {
            // Set network information for node invitations
            strncpy(invitation.proposed_ip, cJSON_GetStringValue(proposed_ip), 15);
            invitation.proposed_ip[15] = '\0';
            invitation.proposed_port = (uint16_t)cJSON_GetNumberValue(proposed_port);
            invitation.proposed_node_id = rand() % 1000 + 100; // Generate node ID
        }
    } else {
        send_error_response(c, 400, "Invalid invitation type. Supported: family_member, family_admin, family_node");
        cJSON_Delete(json);
        return;
    }
    
    cJSON_Delete(json);
    
    if (success) {
        // Create response JSON
        cJSON *response = cJSON_CreateObject();
        cJSON *status = cJSON_CreateString("success");
        cJSON *message = cJSON_CreateString("Invitation created successfully");
        cJSON *code = cJSON_CreateString(invitation.invitation_code);
        cJSON *expires_at = cJSON_CreateNumber((double)invitation.expires_at);
        
        cJSON_AddItemToObject(response, "status", status);
        cJSON_AddItemToObject(response, "message", message);
        cJSON_AddItemToObject(response, "invitation_code", code);
        cJSON_AddItemToObject(response, "expires_at", expires_at);
        
        char *response_str = cJSON_Print(response);
        send_json_response(c, 200, response_str);
        
        free(response_str);
        cJSON_Delete(response);
        
        printf("✅ Invitation created: %s for %s\n", invitation.invitation_code, invitation.invited_name);
    } else {
        send_error_response(c, 500, "Failed to create invitation");
    }
}

void handle_invitation_accept(struct mg_connection *c, struct mg_http_message *hm, const char* invitation_code) {
    printf("🤝 Processing invitation accept request for code: %s\n", invitation_code);
    
    // Parse JSON request body
    char body[512];
    size_t body_len = hm->body.len < sizeof(body) - 1 ? hm->body.len : sizeof(body) - 1;
    strncpy(body, hm->body.buf, body_len);
    body[body_len] = '\0';
    
    cJSON *json = cJSON_Parse(body);
    if (!json) {
        send_error_response(c, 400, "Invalid JSON format");
        return;
    }
    
    cJSON *acceptor_name = cJSON_GetObjectItem(json, "acceptor_name");
    if (!acceptor_name || !cJSON_IsString(acceptor_name)) {
        send_error_response(c, 400, "Missing required field: acceptor_name");
        cJSON_Delete(json);
        return;
    }
    
    // Get acceptor's public key (TODO: implement proper authentication)
    unsigned char acceptor_pubkey[32];
    if (!keystore_get_public_key(acceptor_pubkey)) {
        send_error_response(c, 500, "Failed to get acceptor public key");
        cJSON_Delete(json);
        return;
    }
    
    InvitationAcceptance acceptance;
    int success = invitation_accept(
        invitation_code,
        acceptor_pubkey,
        cJSON_GetStringValue(acceptor_name),
        &acceptance
    );
    
    cJSON_Delete(json);
    
    if (success) {
        // Find the original invitation to determine processing
        FamilyInvitation* original_invitation = invitation_find_by_code(invitation_code);
        if (original_invitation) {
            // Process based on invitation type
            if (is_user_invitation(original_invitation->type)) {
                invitation_process_user_acceptance(&acceptance, original_invitation);
            } else if (is_node_invitation(original_invitation->type)) {
                invitation_process_node_acceptance(&acceptance, original_invitation);
            }
        }
        
        // Create response JSON
        cJSON *response = cJSON_CreateObject();
        cJSON *status = cJSON_CreateString("success");
        cJSON *message = cJSON_CreateString("Invitation accepted successfully");
        cJSON *timestamp = cJSON_CreateNumber((double)acceptance.timestamp);
        
        cJSON_AddItemToObject(response, "status", status);
        cJSON_AddItemToObject(response, "message", message);
        cJSON_AddItemToObject(response, "accepted_at", timestamp);
        
        char *response_str = cJSON_Print(response);
        send_json_response(c, 200, response_str);
        
        free(response_str);
        cJSON_Delete(response);
        
        printf("✅ Invitation %s accepted by %s\n", invitation_code, acceptance.invitee_name);
    } else {
        send_error_response(c, 400, "Failed to accept invitation (not found, expired, or already processed)");
    }
}

void handle_invitation_revoke(struct mg_connection *c, struct mg_http_message *hm, const char* invitation_code) {
    printf("🚫 Processing invitation revoke request for code: %s\n", invitation_code);
    
    // Parse JSON request body
    char body[512];
    size_t body_len = hm->body.len < sizeof(body) - 1 ? hm->body.len : sizeof(body) - 1;
    strncpy(body, hm->body.buf, body_len);
    body[body_len] = '\0';
    
    cJSON *json = cJSON_Parse(body);
    if (!json) {
        send_error_response(c, 400, "Invalid JSON format");
        return;
    }
    
    cJSON *reason = cJSON_GetObjectItem(json, "reason");
    if (!reason || !cJSON_IsString(reason)) {
        send_error_response(c, 400, "Missing required field: reason");
        cJSON_Delete(json);
        return;
    }
    
    // Get revoker's public key (TODO: implement proper authentication)
    unsigned char revoker_pubkey[32];
    if (!keystore_get_public_key(revoker_pubkey)) {
        send_error_response(c, 500, "Failed to get revoker public key");
        cJSON_Delete(json);
        return;
    }
    
    InvitationRevocation revocation;
    int success = invitation_revoke(
        invitation_code,
        revoker_pubkey,
        cJSON_GetStringValue(reason),
        &revocation
    );
    
    cJSON_Delete(json);
    
    if (success) {
        // Create response JSON
        cJSON *response = cJSON_CreateObject();
        cJSON *status = cJSON_CreateString("success");
        cJSON *message = cJSON_CreateString("Invitation revoked successfully");
        cJSON *timestamp = cJSON_CreateNumber((double)revocation.timestamp);
        
        cJSON_AddItemToObject(response, "status", status);
        cJSON_AddItemToObject(response, "message", message);
        cJSON_AddItemToObject(response, "revoked_at", timestamp);
        
        char *response_str = cJSON_Print(response);
        send_json_response(c, 200, response_str);
        
        free(response_str);
        cJSON_Delete(response);
        
        printf("✅ Invitation %s revoked\n", invitation_code);
    } else {
        send_error_response(c, 400, "Failed to revoke invitation (not found or not pending)");
    }
}

void handle_invitation_get_pending(struct mg_connection *c, struct mg_http_message *hm) {
    printf("📋 Processing get pending invitations request\n");
    
    FamilyInvitation invitations[MAX_PENDING_INVITATIONS];
    int count = invitation_get_pending(invitations, MAX_PENDING_INVITATIONS);
    
    if (count < 0) {
        send_error_response(c, 500, "Failed to get pending invitations");
        return;
    }
    
    // Create response JSON
    cJSON *response = cJSON_CreateObject();
    cJSON *status = cJSON_CreateString("success");
    cJSON *invitations_array = cJSON_CreateArray();
    
    for (int i = 0; i < count; i++) {
        cJSON *invitation_json = cJSON_CreateObject();
        
        cJSON_AddStringToObject(invitation_json, "invitation_code", invitations[i].invitation_code);
        cJSON_AddStringToObject(invitation_json, "invited_name", invitations[i].invited_name);
        cJSON_AddStringToObject(invitation_json, "invitation_message", invitations[i].invitation_message);
        cJSON_AddStringToObject(invitation_json, "type", get_invitation_type_name(invitations[i].type));
        cJSON_AddNumberToObject(invitation_json, "created_at", (double)invitations[i].created_at);
        cJSON_AddNumberToObject(invitation_json, "expires_at", (double)invitations[i].expires_at);
        cJSON_AddBoolToObject(invitation_json, "requires_supervision", invitations[i].requires_supervision);
        
        if (is_node_invitation(invitations[i].type)) {
            cJSON_AddStringToObject(invitation_json, "proposed_ip", invitations[i].proposed_ip);
            cJSON_AddNumberToObject(invitation_json, "proposed_port", invitations[i].proposed_port);
        }
        
        cJSON_AddItemToArray(invitations_array, invitation_json);
    }
    
    cJSON_AddItemToObject(response, "status", status);
    cJSON_AddItemToObject(response, "invitations", invitations_array);
    cJSON_AddNumberToObject(response, "count", count);
    
    char *response_str = cJSON_Print(response);
    send_json_response(c, 200, response_str);
    
    free(response_str);
    cJSON_Delete(response);
    
    printf("✅ Returned %d pending invitations\n", count);
}

void handle_invitation_get_stats(struct mg_connection *c, struct mg_http_message *hm) {
    printf("📊 Processing get invitation stats request\n");
    
    uint32_t total_created, total_accepted, total_pending, total_expired;
    invitation_get_stats(&total_created, &total_accepted, &total_pending, &total_expired);
    
    // Cleanup expired invitations while we're here
    invitation_cleanup_expired();
    
    // Create response JSON
    cJSON *response = cJSON_CreateObject();
    cJSON *status = cJSON_CreateString("success");
    cJSON *stats = cJSON_CreateObject();
    
    cJSON_AddNumberToObject(stats, "total_created", total_created);
    cJSON_AddNumberToObject(stats, "total_accepted", total_accepted);
    cJSON_AddNumberToObject(stats, "total_pending", total_pending);
    cJSON_AddNumberToObject(stats, "total_expired", total_expired);
    cJSON_AddNumberToObject(stats, "total_rejected", total_created - total_accepted - total_pending - total_expired);
    
    cJSON_AddItemToObject(response, "status", status);
    cJSON_AddItemToObject(response, "stats", stats);
    
    char *response_str = cJSON_Print(response);
    send_json_response(c, 200, response_str);
    
    free(response_str);
    cJSON_Delete(response);
    
    printf("✅ Returned invitation statistics\n");
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

static void send_json_response(struct mg_connection *c, int status_code, const char* json_str) {
    mg_printf(c, "HTTP/1.1 %d %s\r\n"
                 "Content-Type: application/json\r\n"
                 "Content-Length: %d\r\n"
                 "Access-Control-Allow-Origin: *\r\n"
                 "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
                 "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                 "\r\n"
                 "%s",
              status_code,
              status_code == 200 ? "OK" : "Error",
              (int)strlen(json_str),
              json_str);
}

static void send_error_response(struct mg_connection *c, int status_code, const char* error_msg) {
    cJSON *response = cJSON_CreateObject();
    cJSON *status = cJSON_CreateString("error");
    cJSON *message = cJSON_CreateString(error_msg);
    
    cJSON_AddItemToObject(response, "status", status);
    cJSON_AddItemToObject(response, "message", message);
    
    char *response_str = cJSON_Print(response);
    send_json_response(c, status_code, response_str);
    
    free(response_str);
    cJSON_Delete(response);
}

static char* invitation_to_json_string(const FamilyInvitation* invitation) {
    if (!invitation) return NULL;
    
    cJSON *json = cJSON_CreateObject();
    
    cJSON_AddStringToObject(json, "invitation_code", invitation->invitation_code);
    cJSON_AddStringToObject(json, "family_name", invitation->family_name);
    cJSON_AddStringToObject(json, "invited_name", invitation->invited_name);
    cJSON_AddStringToObject(json, "invitation_message", invitation->invitation_message);
    cJSON_AddStringToObject(json, "type", get_invitation_type_name(invitation->type));
    cJSON_AddNumberToObject(json, "status", invitation->status);
    cJSON_AddNumberToObject(json, "created_at", (double)invitation->created_at);
    cJSON_AddNumberToObject(json, "expires_at", (double)invitation->expires_at);
    
    if (invitation->responded_at > 0) {
        cJSON_AddNumberToObject(json, "responded_at", (double)invitation->responded_at);
    }
    
    cJSON_AddNumberToObject(json, "granted_permissions", (double)invitation->granted_permissions);
    cJSON_AddNumberToObject(json, "permission_scope", invitation->permission_scope);
    cJSON_AddBoolToObject(json, "requires_supervision", invitation->requires_supervision);
    
    if (is_node_invitation(invitation->type)) {
        cJSON_AddStringToObject(json, "proposed_ip", invitation->proposed_ip);
        cJSON_AddNumberToObject(json, "proposed_port", invitation->proposed_port);
        cJSON_AddNumberToObject(json, "proposed_node_id", invitation->proposed_node_id);
    }
    
    char *json_str = cJSON_Print(json);
    cJSON_Delete(json);
    
    return json_str;
}

static char* create_success_response(const char* message, const char* data) {
    cJSON *response = cJSON_CreateObject();
    cJSON *status = cJSON_CreateString("success");
    cJSON *msg = cJSON_CreateString(message);
    
    cJSON_AddItemToObject(response, "status", status);
    cJSON_AddItemToObject(response, "message", msg);
    
    if (data) {
        cJSON *data_json = cJSON_Parse(data);
        if (data_json) {
            cJSON_AddItemToObject(response, "data", data_json);
        }
    }
    
    char *response_str = cJSON_Print(response);
    cJSON_Delete(response);
    
    return response_str;
} 