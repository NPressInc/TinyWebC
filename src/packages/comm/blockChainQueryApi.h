#ifndef BLOCKCHAIN_QUERY_API_H
#define BLOCKCHAIN_QUERY_API_H

#include "../../external/mongoose/mongoose.h"
#include "../structures/blockChain/block.h"
#include "../structures/blockChain/transaction.h"

// JSON response helper functions
void send_json_response(struct mg_connection* c, int status, const char* json_response);
void send_error_response(struct mg_connection* c, const char* error_message);

// JSON serialization helpers
char* block_to_json_string(TW_Block* block);
char* transaction_to_json_string(TW_Transaction* tx);

// REST API endpoint handlers for blockchain data queries
void handle_get_network_stats(struct mg_connection* c, struct mg_http_message* hm);
void handle_get_block_by_hash(struct mg_connection* c, struct mg_http_message* hm);
void handle_get_invitation_stats(struct mg_connection* c, struct mg_http_message* hm);
void handle_get_family_members(struct mg_connection* c, struct mg_http_message* hm);
void handle_get_activity(struct mg_connection* c, struct mg_http_message* hm);
void handle_get_blocks(struct mg_connection* c, struct mg_http_message* hm);
void handle_get_transactions(struct mg_connection* c, struct mg_http_message* hm);
void handle_health_check(struct mg_connection* c, struct mg_http_message* hm);
void handle_get_blockchain_info(struct mg_connection* c, struct mg_http_message* hm);
void handle_get_transaction_by_hash(struct mg_connection* c, struct mg_http_message* hm);

// Utility function to get configuration info
uint32_t get_configured_node_count(void);

#endif // BLOCKCHAIN_QUERY_API_H
