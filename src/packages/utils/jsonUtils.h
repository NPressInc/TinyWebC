#ifndef JSON_UTILS_H
#define JSON_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include "external/mongoose/mongoose.h"
#include "packages/structures/blockChain/blockchain.h"
#include "packages/structures/blockChain/block.h"
#include "packages/structures/blockChain/transaction.h"

// JSON builder structure for constructing JSON strings
typedef struct {
    char* buffer;
    size_t capacity;
    size_t length;
    int error;
} JsonBuilder;

// JSON parsing context
typedef struct {
    struct mg_str json;
    int error;
} JsonParser;

// JSON Builder functions
JsonBuilder* json_builder_create(size_t initial_capacity);
void json_builder_destroy(JsonBuilder* builder);
int json_builder_start_object(JsonBuilder* builder);
int json_builder_end_object(JsonBuilder* builder);
int json_builder_start_array(JsonBuilder* builder);
int json_builder_end_array(JsonBuilder* builder);
int json_builder_add_string(JsonBuilder* builder, const char* key, const char* value);
int json_builder_add_int(JsonBuilder* builder, const char* key, int value);
int json_builder_add_uint(JsonBuilder* builder, const char* key, uint32_t value);
int json_builder_add_double(JsonBuilder* builder, const char* key, double value);
int json_builder_add_bool(JsonBuilder* builder, const char* key, int value);
int json_builder_add_hex_bytes(JsonBuilder* builder, const char* key, const unsigned char* bytes, size_t len);
char* json_builder_get_string(JsonBuilder* builder);

// JSON Parser functions
JsonParser* json_parser_create(const char* json_string);
JsonParser* json_parser_create_from_mg_str(struct mg_str json);
void json_parser_destroy(JsonParser* parser);
int json_parser_get_string(JsonParser* parser, const char* path, char* buffer, size_t buffer_size);
int json_parser_get_int(JsonParser* parser, const char* path, int* value);
int json_parser_get_uint(JsonParser* parser, const char* path, uint32_t* value);
int json_parser_get_double(JsonParser* parser, const char* path, double* value);
int json_parser_get_bool(JsonParser* parser, const char* path, int* value);
int json_parser_get_hex_bytes(JsonParser* parser, const char* path, unsigned char* bytes, size_t max_len);

// Blockchain-specific JSON serialization
char* json_serialize_transaction(const TW_Transaction* transaction);
char* json_serialize_block(const TW_Block* block);
char* json_serialize_blockchain(const TW_BlockChain* blockchain);

// Blockchain-specific JSON deserialization
TW_Transaction* json_deserialize_transaction(const char* json_string);
TW_Block* json_deserialize_block(const char* json_string);
TW_BlockChain* json_deserialize_blockchain(const char* json_string);

// PBFT-specific JSON message creation
char* json_create_transaction_message(const TW_Transaction* transaction, const char* signature);
char* json_create_block_proposal_message(const TW_Block* block, const char* block_hash, 
                                        const char* sender_pubkey, const char* signature);
char* json_create_vote_message(const char* block_hash, const char* block_data,
                              const char* sender_pubkey, const char* signature);
char* json_create_blockchain_request_message(const char* sender_pubkey, const char* signature);
char* json_create_missing_blocks_request(const char* last_hash, const char* sender_pubkey, const char* signature);

// PBFT response parsing
int json_parse_transaction_message(const char* json_string, TW_Transaction** transaction, 
                                  char* sender_pubkey, char* signature);
int json_parse_block_proposal_message(const char* json_string, TW_Block** block, 
                                     char* block_hash, char* sender_pubkey, char* signature);
int json_parse_vote_message(const char* json_string, char* block_hash, char* block_data,
                           char* sender_pubkey, char* signature);

// Response message creation
char* json_create_response(const char* status, const char* message);
char* json_create_error_response(const char* error_message);
char* json_create_success_response(const char* data);

// Utility functions
int json_validate_signature_fields(const char* json_string);
char* json_extract_field(const char* json_string, const char* field_name);
int json_has_field(const char* json_string, const char* field_name);

// Hash and signature utilities for JSON
void json_hash_object(const char* json_string, unsigned char* hash_out);
int json_verify_message_signature(const char* json_string, const char* expected_pubkey);

// Array handling
int json_get_array_size(JsonParser* parser, const char* path);
int json_get_array_string(JsonParser* parser, const char* path, int index, char* buffer, size_t buffer_size);

#endif // JSON_UTILS_H 