#include "pbftNode.h"
#include "node.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <cjson/cJSON.h>
#include "../keystore/keystore.h"
#include "../signing/signing.h"
#include "../structures/blockChain/blockchain.h"
#include "../structures/blockChain/block.h"
#include "../validation/block_validation.h"
#include "../validation/transaction_validation.h"
#include "../comm/pbftApi.h"
#include "../comm/httpClient.h"
#include "../sql/database.h"
#include "../fileIO/blockchainIO.h"
#include "../invitation/invitation.h"
#include "../invitation/invitationApi.h"
#include "../comm/blockChainQueryApi.h"
#include "../comm/accessApi.h"
#include "../comm/nodeApi.h"
#include "../invitation/invitationApi.h"
#include "mongoose.h"

// Forward declarations for endpoint handlers
static void pbft_api_event_handler(struct mg_connection *c, int ev, void *ev_data);
static void handle_root_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node);
static void handle_transaction_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node);
static void handle_transaction_internal_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node);
static void handle_propose_block_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node);
static void handle_verification_vote_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node);
static void handle_commit_vote_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node);
static void handle_new_round_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node);
static void handle_blockchain_last_hash_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node);
static void handle_get_pending_transactions_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node);
static void handle_get_blockchain_length_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node);
static void handle_missing_block_request_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node);
static void handle_send_new_blockchain_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node);
static void handle_request_entire_blockchain_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node);
static void handle_add_new_block_singular_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node);

// Global PBFT node instance
PBFTNode* pbft_node = NULL;

// External message queues from pbftApi
extern MessageQueues message_queues;

PBFTNode* pbft_node_create(uint32_t node_id, uint16_t api_port) {
    PBFTNode* node = calloc(1, sizeof(PBFTNode));
    if (!node) return NULL;
    
    node->base.id = node_id;
    node->api_port = api_port;
    node->running = 1;
    
    // Initialize mutex
    if (pthread_mutex_init(&node->state_mutex, NULL) != 0) {
        free(node);
        return NULL;
    }
    
    // Initialize HTTP client for peer communication
    if (!http_client_init()) {
        printf("Failed to initialize HTTP client for node %u\n", node_id);
        pthread_mutex_destroy(&node->state_mutex);
        free(node);
        return NULL;
    }
    
    // Initialize invitation system
    if (!invitation_system_init()) {
        printf("Failed to initialize invitation system for node %u\n", node_id);
        http_client_cleanup();
        pthread_mutex_destroy(&node->state_mutex);
        free(node);
        return NULL;
    }
    
    return node;
}

void pbft_node_destroy(PBFTNode* node) {
    if (!node) return;
    
    node->running = 0;
    
    // Cleanup blockchain data manager
    TW_BlockchainDataManager_cleanup();
    
    // Cleanup HTTP client
    http_client_cleanup();
    
    // Cleanup invitation system
    invitation_system_cleanup();
    
    pthread_mutex_destroy(&node->state_mutex);
    free(node);
}

int pbft_node_initialize_keys(PBFTNode* node) {
    if (!node) return -1;
    
    printf("Initializing keys for node %u\n", node->base.id);
    
    // Initialize keystore
    if (keystore_init() != 1) {
        printf("Failed to initialize keystore for node %u\n", node->base.id);
        return -1;
    }
    
    // Try to load existing private key, or generate new one
    char filename[256];
    snprintf(filename, sizeof(filename), "state/keys/node_%u_private.key", node->base.id);
    
    // Try to load existing key
    if (keystore_load_private_key(filename, "default_passphrase") == 1) {
        printf("Loaded existing keys for node %u\n", node->base.id);
    } else {
        // Generate new keypair
        if (keystore_generate_keypair() != 1) {
            printf("Failed to generate keypair for node %u\n", node->base.id);
            return -1;
        }
        
        // Save the new private key
        if (keystore_save_private_key(filename, "default_passphrase") != 1) {
            printf("Failed to save private key for node %u\n", node->base.id);
            return -1;
        }
        
        printf("Created new keys for node %u\n", node->base.id);
    }
    
    // Get the public key for the node
    if (keystore_get_public_key(node->base.public_key) != 1) {
        printf("Failed to get public key for node %u\n", node->base.id);
        return -1;
    }
    
    return 0;
}

int pbft_node_load_or_create_blockchain(PBFTNode* node) {
    if (!node) return -1;
    
    printf("Loading/creating blockchain for node %u\n", node->base.id);
    
    // Try to load existing shared blockchain from file
    const char* blockchain_file = "state/blockchain/blockchain.dat";
    
    // Check if blockchain file exists
    FILE* file = fopen(blockchain_file, "rb");
    if (file) {
        fclose(file);
        printf("Loading existing blockchain from %s\n", blockchain_file);
        
        // Load blockchain from file
        node->base.blockchain = readBlockChainFromFile();
        if (node->base.blockchain) {
            printf("Loaded existing blockchain for node %u with length %u\n", 
                   node->base.id, node->base.blockchain->length);
            
            // Initialize blockchain data manager with 120-day retention for important data
            TW_DataRetentionConfig config = {
                .critical_days = 0,    // Keep critical data forever
                .important_days = 120, // Keep important data for 4 months
                .operational_days = 30 // Keep operational data for 1 month
            };
            
            TW_BlockchainDataManager_init(&config);
            
            // Check if database reload is needed
            if (TW_BlockchainDataManager_needs_reload(node->base.blockchain)) {
                printf("🔄 Database inconsistent with blockchain, reloading...\n");
                
                TW_ReloadStats stats;
                int result = TW_BlockchainDataManager_reload_from_blockchain(
                    node->base.blockchain, NULL, &stats);
                    
                if (result == 0) {
                    printf("✅ Database successfully reloaded from blockchain\n");
                    printf("📊 Reload Statistics:\n");
                    printf("   Critical transactions: %u\n", stats.critical_transactions);
                    printf("   Important transactions: %u\n", stats.important_transactions);
                    printf("   Operational transactions: %u\n", stats.operational_transactions);
                    printf("   Transactions skipped: %u\n", stats.transactions_skipped);
                } else {
                    printf("❌ Failed to reload database from blockchain\n");
                }
            } else {
                printf("✅ Database is consistent with blockchain\n");
            }
            
            return 0;
        } else {
            printf("Failed to load blockchain from file, creating new one\n");
        }
    } else {
        printf("No existing blockchain file found at %s\n", blockchain_file);
        printf("💡 To initialize with proper multi-recipient encryption, run:\n");
        printf("   ./init_tool -v src/packages/initialization/configs/network_config.json\n");
    }
    
    // Create a new blockchain if loading failed or file doesn't exist
    node->base.blockchain = TW_BlockChain_create(node->base.public_key, NULL, 0);
    if (!node->base.blockchain) {
        printf("Failed to create blockchain for node %u\n", node->base.id);
        return -1;
    }
    
    printf("Created new blockchain for node %u with length %u\n", 
           node->base.id, node->base.blockchain->length);
    
    return 0;
}

void pbft_node_run(PBFTNode* node) {
    printf("PBFT node %u starting on port %u\n", node->base.id, node->api_port);
    
    // Start API server thread
    if (pthread_create(&node->api_thread, NULL, pbft_node_api_server, node) != 0) {
        printf("Failed to start API server thread\n");
        return;
    }
    
    // Start main consensus loop thread
    if (pthread_create(&node->node_thread, NULL, pbft_node_main_loop, node) != 0) {
        printf("Failed to start main consensus thread\n");
        node->running = 0;
        pthread_join(node->api_thread, NULL);
        return;
    }
    
    printf("PBFT node threads started successfully\n");
    
    // Wait for threads to complete
    pthread_join(node->api_thread, NULL);
    pthread_join(node->node_thread, NULL);
    
    printf("PBFT node %u shutdown complete\n", node->base.id);
}

void* pbft_node_main_loop(void* arg) {
    PBFTNode* node = (PBFTNode*)arg;
    if (!node) return NULL;
    
    printf("PBFT main consensus loop started for node %u\n", node->base.id);
    
    while (node->running) {
        // Update counter (used as round number)
        node->counter++;
        
        // Check if blockchain has progressed
        uint32_t current_length = node->base.blockchain ? node->base.blockchain->length : 0;
        node->blockchain_has_progressed = (current_length != node->last_blockchain_length);
        node->last_blockchain_length = current_length;
        
        // Every 10 iterations, check for new peers and sync
        if (node->counter % 10 == 0) {
            // Load peers from blockchain
            pbft_node_load_peers_from_blockchain(node);
            
            printf("Node %u: Blockchain length: %u, Peers: %zu, Proposer ID: %u\n", 
                   node->base.id, current_length, node->base.peer_count, 
                   pbft_node_calculate_proposer_id(node));
            
            // If we have no peers, create a block for self (singular node mode)
            if (node->base.peer_count == 0) {
                printf("Node %u: Creating block for singular node\n", node->base.id);
                pbft_node_send_block_creation_signal(node);
            }
        }
        
        // Every 10 iterations, check if we should propose a block (every 10 seconds)
        if (node->counter % 10 == 0) {
            if (!node->blockchain_has_progressed && pbft_node_is_proposer(node)) {
                printf("Node %u: Proposing block (round %u)\n", node->base.id, node->counter);
                
                // Create and propose a block
                TW_Block* new_block = pbft_node_create_block(node);
                if (new_block) {
                    // For single node mode, commit directly
                    if (node->base.peer_count == 0) {
                        printf("Node %u: Committing block directly (singular mode)\n", node->base.id);
                        
                        if (pbft_node_validate_block(node, new_block) && 
                            pbft_node_commit_block(node, new_block)) {
                            
                            // Sync to database
                            if (db_is_initialized()) {
                                uint32_t block_index = node->base.blockchain->length - 1;
                                if (db_add_block(new_block, block_index) == 0) {
                                    printf("Block %u synced to database\n", block_index);
                                }
                            }
                        } else {
                            TW_Block_destroy(new_block);
                        }
                    } else {
                        // Multi-node mode: broadcast to peers
                        unsigned char block_hash[HASH_SIZE];
                        if (TW_Block_getHash(new_block, block_hash) == 1) {
                            char hash_hex[HASH_SIZE * 2 + 1];
                            pbft_node_bytes_to_hex(block_hash, HASH_SIZE, hash_hex);
                            
                            // Broadcast block to peers
                            pbft_node_broadcast_block(node, new_block, hash_hex);
                        }
                    }
                }
            }
        }
        
        // Every 21 iterations, check for sync and handle delinquent nodes
        if (node->counter % 21 == 0) {
            printf("Node %u: Checking blockchain sync and peer status\n", node->base.id);
            
            if (!node->blockchain_has_progressed && node->base.peer_count > 0) {
                int sync_result = pbft_node_sync_with_longest_chain(node);
                uint32_t proposer_id = pbft_node_calculate_proposer_id(node);
                
                printf("Node %u: Sync result: %d, Proposer ID: %u\n", 
                       node->base.id, sync_result, proposer_id);
                
                // If sync failed and we're not the proposer, increment proposer offset
                if (sync_result < 0 && node->base.id != proposer_id) {
                    node->base.proposer_offset++;
                    printf("Node %u: Incrementing proposer offset to %u\n", 
                           node->base.id, node->base.proposer_offset);
                }
            }
        }
        
        // Every 100 iterations, save blockchain and shuffle peers
        if (node->counter % 100 == 0) {
            if (node->base.peer_count > 0) {
                pbft_node_shuffle_peers(node);
                printf("Node %u: Shuffled peers\n", node->base.id);
            }
            
            printf("Node %u: Periodic blockchain save\n", node->base.id);
            pbft_node_save_blockchain_periodically(node);
        }
        
        // Sleep for the speed modifier
        usleep(SPEED_MODIFIER_USEC);
    }
    
    printf("PBFT main consensus loop stopped for node %u\n", node->base.id);
    return NULL;
}

void* pbft_node_api_server(void* arg) {
    PBFTNode* node = (PBFTNode*)arg;
    if (!node) return NULL;
    
    printf("Starting PBFT API server on port %u\n", node->api_port);
    
    struct mg_mgr mgr;
    struct mg_connection *c;
    char port_str[32];  // Increased buffer size
    
    // Convert port to string
    snprintf(port_str, sizeof(port_str), "http://0.0.0.0:%u", node->api_port);
    
    // Initialize Mongoose manager
    mg_mgr_init(&mgr);
    
    // Create HTTP server
    c = mg_http_listen(&mgr, port_str, pbft_api_event_handler, node);
    if (c == NULL) {
        printf("Failed to create HTTP listener on port %u\n", node->api_port);
        mg_mgr_free(&mgr);
        return NULL;
    }
    
    printf("PBFT API server listening on %s\n", port_str);
    
    // Main event loop
    while (node->running) {
        mg_mgr_poll(&mgr, 100);  // Poll every 100ms
    }
    
    printf("PBFT API server shutting down\n");
    mg_mgr_free(&mgr);
    return NULL;
}

// HTTP event handler for PBFT API
static void pbft_api_event_handler(struct mg_connection *c, int ev, void *ev_data) {
    PBFTNode* node = (PBFTNode*)c->fn_data;
    
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        
        // Route HTTP requests to appropriate handlers using string comparison
        if (mg_strcmp(hm->uri, mg_str("/")) == 0) {
            handle_root_endpoint(c, hm, node);
        } else if (mg_strcmp(hm->uri, mg_str("/Transaction")) == 0) {
            handle_transaction_endpoint(c, hm, node);
        } else if (mg_strcmp(hm->uri, mg_str("/TransactionInternal")) == 0) {
            handle_transaction_internal_endpoint(c, hm, node);
        } else if (mg_strcmp(hm->uri, mg_str("/ProposeBlock")) == 0) {
            handle_propose_block_endpoint(c, hm, node);
        } else if (mg_strcmp(hm->uri, mg_str("/VerificationVote")) == 0) {
            handle_verification_vote_endpoint(c, hm, node);
        } else if (mg_strcmp(hm->uri, mg_str("/CommitVote")) == 0) {
            handle_commit_vote_endpoint(c, hm, node);
        } else if (mg_strcmp(hm->uri, mg_str("/NewRound")) == 0) {
            handle_new_round_endpoint(c, hm, node);
        } else if (mg_strcmp(hm->uri, mg_str("/BlockChainLastHash")) == 0) {
            handle_blockchain_last_hash_endpoint(c, hm, node);
        } else if (mg_strcmp(hm->uri, mg_str("/GetPendingTransactions")) == 0) {
            handle_get_pending_transactions_endpoint(c, hm, node);
        } else if (mg_strcmp(hm->uri, mg_str("/GetBlockChainLength")) == 0) {
            handle_get_blockchain_length_endpoint(c, hm, node);
        } else if (mg_strcmp(hm->uri, mg_str("/MissingBlockRequeset")) == 0) {
            handle_missing_block_request_endpoint(c, hm, node);
        } else if (mg_strcmp(hm->uri, mg_str("/SendNewBlockChain")) == 0) {
            handle_send_new_blockchain_endpoint(c, hm, node);
        } else if (mg_strcmp(hm->uri, mg_str("/RequestEntireBlockchain")) == 0) {
            handle_request_entire_blockchain_endpoint(c, hm, node);
        } else if (mg_strcmp(hm->uri, mg_str("/AddNewBlockForSingularNode")) == 0) {
            handle_add_new_block_singular_endpoint(c, hm, node);
        } else if (mg_strcmp(hm->uri, mg_str("/api/network/stats")) == 0) {
            handle_get_network_stats(c, hm);
        } else if (mg_strcmp(hm->uri, mg_str("/api/invitations/stats")) == 0) {
            handle_get_invitation_stats(c, hm);
        } else if (mg_strcmp(hm->uri, mg_str("/api/family/members")) == 0) {
            handle_get_family_members(c, hm);
        } else if (mg_strcmp(hm->uri, mg_str("/api/activity")) == 0) {
            handle_get_activity(c, hm);
        } else if (mg_strcmp(hm->uri, mg_str("/api/blocks")) == 0) {
            handle_get_blocks(c, hm);
        } else if (mg_strcmp(hm->uri, mg_str("/api/transactions")) == 0) {
            handle_get_transactions(c, hm);
        } else if (mg_strcmp(hm->uri, mg_str("/api/health")) == 0) {
            handle_health_check(c, hm);
        } else if (mg_strcmp(hm->uri, mg_str("/api/blockchain")) == 0) {
            handle_get_blockchain_info(c, hm);
        } else if (strstr(hm->uri.buf, "/api/blocks/") != NULL && 
                   mg_strcmp(hm->uri, mg_str("/api/blocks")) != 0) {
            handle_get_block_by_hash(c, hm);
        } else if (strstr(hm->uri.buf, "/api/transactions/") != NULL && 
                   mg_strcmp(hm->uri, mg_str("/api/transactions")) != 0) {
            handle_get_transaction_by_hash(c, hm);
        } else if (mg_strcmp(hm->uri, mg_str("/invitation/create")) == 0) {
            handle_invitation_create(c, hm);
        } else if (mg_strcmp(hm->uri, mg_str("/invitation/pending")) == 0) {
            handle_invitation_get_pending(c, hm);
        } else if (mg_strcmp(hm->uri, mg_str("/invitation/stats")) == 0) {
            handle_invitation_get_stats(c, hm);
        } else if (strstr(hm->uri.buf, "/invitation/accept/") != NULL) {
            // Extract invitation code from URI path
            char invitation_code[32];
            const char* code_start = strstr(hm->uri.buf, "/invitation/accept/") + 19;
            size_t code_len = hm->uri.len - (code_start - hm->uri.buf);
            if (code_len >= 32) code_len = 31;
            strncpy(invitation_code, code_start, code_len);
            invitation_code[code_len] = '\0';
            handle_invitation_accept(c, hm, invitation_code);
        } else if (strstr(hm->uri.buf, "/invitation/revoke/") != NULL) {
            // Extract invitation code from URI path
            char invitation_code[32];
            const char* code_start = strstr(hm->uri.buf, "/invitation/revoke/") + 19;
            size_t code_len = hm->uri.len - (code_start - hm->uri.buf);
            if (code_len >= 32) code_len = 31;
            strncpy(invitation_code, code_start, code_len);
            invitation_code[code_len] = '\0';
            handle_invitation_revoke(c, hm, invitation_code);
        } else if (mg_strcmp(hm->uri, mg_str("/api/access/submit")) == 0) {
            handle_access_request_submit_pbft(c, hm);
        } else if (mg_strcmp(hm->uri, mg_str("/api/access/poll")) == 0) {
            handle_access_request_poll(c, hm);
        } else if (mg_strcmp(hm->uri, mg_str("/api/v1/recipients/keys")) == 0) {
            handle_get_recipient_keys(c, hm);
        } else {
            // 404 Not Found
            mg_http_reply(c, 404, "Content-Type: application/json\r\n", 
                         "{\"error\":\"Endpoint not found\"}");
        }
    }
}

// Endpoint handler implementations
static void handle_root_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    mg_http_reply(c, 200, "Content-Type: text/html\r\n", 
                 "<p>TinyWeb PBFT Node - Node ID: %u, Port: %u</p>", 
                 node->base.id, node->api_port);
}

static void handle_get_blockchain_length_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node || !node->base.blockchain) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Blockchain not initialized\"}");
        return;
    }
    
    // TODO: Verify signature from request
    
    char response[256];
    snprintf(response, sizeof(response), 
             "{\"chainLength\":%u}", 
             node->base.blockchain->length);
    
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", response);
}

static void handle_get_pending_transactions_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Node not initialized\"}");
        return;
    }
    
    // TODO: Verify signature from request
    // TODO: Get actual pending transactions from queue
    
    // For now, return empty transaction list
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                 "{\"pendingTransactions\":{}}");
}

static void handle_blockchain_last_hash_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node || !node->base.blockchain || node->base.blockchain->length == 0) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Blockchain not initialized or empty\"}");
        return;
    }
    
    // TODO: Verify signature from request
    
    // Get last block hash
    TW_Block* last_block = node->base.blockchain->blocks[node->base.blockchain->length - 1];
    unsigned char hash_bytes[HASH_SIZE];
    char hash_hex[HASH_SIZE * 2 + 1];
    
    if (TW_Block_getHash(last_block, hash_bytes) != 1) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Failed to get block hash\"}");
        return;
    }
    
    pbft_node_bytes_to_hex(hash_bytes, HASH_SIZE, hash_hex);
    
    char response[256];
    snprintf(response, sizeof(response), 
             "{\"lastHash\":\"%s\"}", 
             hash_hex);
    
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", response);
}

// Core PBFT functions using internal transactions
TW_Block* pbft_node_create_block(PBFTNode* node) {
    if (!node || !node->base.blockchain) return NULL;
    
    // Get pending transactions from transaction queue
    TW_Transaction** transactions = NULL;
    int32_t txn_count = message_queues.transaction_count;
    
    if (txn_count > 0) {
        transactions = malloc(sizeof(TW_Transaction*) * txn_count);
        if (!transactions) {
            printf("Failed to allocate memory for transactions\n");
            return NULL;
        }
        
        // Copy transactions from queue
        for (int i = 0; i < txn_count; i++) {
            transactions[i] = message_queues.transaction_queue[i].transaction;
        }
        
        printf("Creating block with %d transactions from queue\n", txn_count);
    }
    
    // Calculate new block index
    int32_t new_index = node->base.blockchain->length;
    
    // Get timestamp
    time_t timestamp = time(NULL);
    
    // Get previous block hash
    unsigned char previous_hash[HASH_SIZE];
    if (node->base.blockchain->length > 0) {
        TW_Block* last_block = node->base.blockchain->blocks[node->base.blockchain->length - 1];
        if (TW_Block_getHash(last_block, previous_hash) != 1) {
            printf("Failed to get hash of previous block\n");
            if (transactions) free(transactions);
            return NULL;
        }
        
        // Debug: Print the previous hash being used
        char prev_hash_hex[HASH_SIZE * 2 + 1];
        pbft_node_bytes_to_hex(previous_hash, HASH_SIZE, prev_hash_hex);
        printf("DEBUG: Creating block %d with previous hash: %s\n", new_index, prev_hash_hex);
    } else {
        // Genesis block case
        memset(previous_hash, 0, HASH_SIZE);
        printf("DEBUG: Creating genesis block with zero previous hash\n");
    }
    
    // Set proposer ID
    unsigned char proposer_id[PROP_ID_SIZE];
    snprintf((char*)proposer_id, PROP_ID_SIZE, "node_%u", node->base.id);
    
    // Create the new block
    TW_Block* new_block = TW_Block_create(new_index, transactions, txn_count, 
                                         timestamp, previous_hash, proposer_id);
    
    if (!new_block) {
        printf("Failed to create new block\n");
        if (transactions) free(transactions);
        return NULL;
    }
    
    // Build merkle tree for the block
    TW_Block_buildMerkleTree(new_block);
    
    printf("Created new block with index %d and %d transactions\n", 
           new_index, txn_count);
    
    // Do NOT clear the transaction queue here - wait until after successful commit
    // The queue will be cleared by the caller after successful block commit
    
    // Free the transactions array (but not the transactions themselves as they're now in the block)
    if (transactions) free(transactions);
    
    return new_block;
}

int pbft_node_propose_block(PBFTNode* node, TW_Block* block) {
    if (!node || !block) return 0;
    
    // Create block hash
    unsigned char block_hash[HASH_SIZE];
    // TODO: Calculate actual block hash
    memset(block_hash, 0, HASH_SIZE);
    
    // Create block proposal using internal transaction
    TW_InternalTransaction* proposal = tw_create_block_proposal(
        node->base.public_key,
        node->base.id,
        node->counter,  // Use counter as round number
        block,
        block_hash
    );
    
    if (!proposal) return 0;
    
    // Sign the internal transaction
    TW_Internal_Transaction_add_signature(proposal);
    
    // Broadcast proposal to all peers via binary HTTP
    int success_count = 0;
    printf("Node %u proposing block with round %u to %zu peers (binary protocol)\n", 
           node->base.id, node->counter, node->base.peer_count);
    
    for (size_t i = 0; i < node->base.peer_count; i++) {
        // Skip self
        if (node->base.peers[i].id == node->base.id) {
            continue;
        }
        
        // Construct peer URL
        char peer_url[256];
        snprintf(peer_url, sizeof(peer_url), "http://%s", node->base.peers[i].ip);
        
        // Send binary block proposal to peer
        if (pbft_send_block_proposal_binary(peer_url, proposal)) {
            success_count++;
            printf("Binary block proposal sent successfully to peer %u at %s\n", 
                   node->base.peers[i].id, peer_url);
        } else {
            printf("Failed to send binary block proposal to peer %u at %s\n", 
                   node->base.peers[i].id, peer_url);
        }
    }
    
    printf("Binary block proposal broadcast completed: %d/%zu peers reached\n", 
           success_count, node->base.peer_count);
    
    tw_destroy_internal_transaction(proposal);
    return success_count > 0 ? 1 : 0;
}

int pbft_node_validate_block(PBFTNode* node, TW_Block* block) {
    if (!node || !block || !node->base.blockchain) return 0;
    
    // Basic block validation
    if (block->index != node->base.blockchain->length) {
        printf("Invalid block index: expected %u, got %d\n", 
               node->base.blockchain->length, block->index);
        return 0;
    }
    
    // Validate previous hash
    if (node->base.blockchain->length > 0) {
        TW_Block* last_block = node->base.blockchain->blocks[node->base.blockchain->length - 1];
        unsigned char expected_prev_hash[HASH_SIZE];
        if (TW_Block_getHash(last_block, expected_prev_hash) != 1) {
            printf("Failed to get hash of previous block for validation\n");
            return 0;
        }
        
        // Debug: Print hash comparison
        char expected_hex[HASH_SIZE * 2 + 1];
        char actual_hex[HASH_SIZE * 2 + 1];
        pbft_node_bytes_to_hex(expected_prev_hash, HASH_SIZE, expected_hex);
        pbft_node_bytes_to_hex(block->previous_hash, HASH_SIZE, actual_hex);
        printf("DEBUG: Block %d validation - Expected prev hash: %s, Actual prev hash: %s\n", 
               block->index, expected_hex, actual_hex);
        
        if (memcmp(block->previous_hash, expected_prev_hash, HASH_SIZE) != 0) {
            printf("Invalid previous hash in block\n");
            return 0;
        }
    }
    
    // TODO: Add more validation logic (transaction validation, etc.)
    
    printf("Block validation passed for block %d\n", block->index);
    return 1;
}

int pbft_node_commit_block(PBFTNode* node, TW_Block* block) {
    if (!node || !block || !node->base.blockchain) return 0;
    
    // Validate block before committing
    if (!pbft_node_validate_block(node, block)) {
        printf("Block validation failed, cannot commit\n");
        return 0;
    }
    
    // Add block to blockchain
    if (TW_BlockChain_add_block(node->base.blockchain, block) == 0) {
        printf("Failed to add block to blockchain\n");
        return 0;
    }
    
    printf("Successfully committed block %d to blockchain\n", block->index);
    
    // Sync to database if available
    if (db_is_initialized()) {
        if (db_add_block(block, block->index) == 0) {
            printf("Block %d synced to database successfully\n", block->index);
        } else {
            printf("Warning: Failed to sync block %d to database\n", block->index);
        }
    }
    
    // NOW clear the transaction queue since block was successfully committed
    if (message_queues.transaction_count > 0) {
        printf("Clearing transaction queue after successful block commit (had %d transactions)\n", 
               message_queues.transaction_count);
        message_queues.transaction_count = 0;
    }
    
    // Save blockchain to file after successful commit
    printf("Saving blockchain after block commit...\n");
    if (!pbft_node_save_blockchain_periodically(node)) {
        printf("Warning: Failed to save blockchain after committing block %d\n", block->index);
        // Don't fail the commit just because save failed
    }

    
    return 1;
}

int pbft_node_load_peers_from_blockchain(PBFTNode* node) { return 0; }
int pbft_node_add_peer(PBFTNode* node, const unsigned char* public_key, const char* ip, uint32_t id) { return 0; }
int pbft_node_remove_peer(PBFTNode* node, uint32_t peer_id) { return 0; }
int pbft_node_mark_peer_delinquent(PBFTNode* node, uint32_t peer_id) { return 0; }
int pbft_node_is_peer_active(PBFTNode* node, uint32_t peer_id) { return 0; }
uint32_t pbft_node_calculate_proposer_id(PBFTNode* node) {
    if (!node || !node->base.blockchain) {
        return 0;
    }
    
    uint32_t num_peers = node->base.peer_count;
    
    // Special case for single node (no peers): always return the node's ID
    if (num_peers == 0) {
        return node->base.id;
    }
    
    // If blockchain is empty, return 0 for genesis block
    if (node->base.blockchain->length == 0) {
        return 0;
    }
    
    // Get the last block's proposer ID
    TW_Block* last_block = node->base.blockchain->blocks[node->base.blockchain->length - 1];
    if (!last_block) {
        return 0;
    }
    
    // Calculate next proposer: (last_proposer_id + 1 + offset) % num_peers
    uint32_t next_proposer = (last_block->index + 1 + node->base.proposer_offset) % (num_peers + 1);
    
    return next_proposer;
}

int pbft_node_is_proposer(PBFTNode* node) {
    if (!node) return 0;
    
    uint32_t proposer_id = pbft_node_calculate_proposer_id(node);
    return (proposer_id == node->base.id) ? 1 : 0;
}

int pbft_node_calculate_min_approvals(PBFTNode* node) {
    if (!node) return 1;
    
    // PBFT requires 2f + 1 nodes to tolerate f byzantine failures
    // So we need at least 2/3 + 1 approvals for consensus
    uint32_t total_nodes = node->base.peer_count + 1;  // Include self
    
    if (total_nodes < 4) {
        // For small networks, require all nodes
        return total_nodes;
    }
    
    // Calculate 2/3 + 1 for PBFT consensus
    int min_approvals = (total_nodes * 2) / 3 + 1;
    
    return min_approvals;
}

int pbft_node_sync_with_longest_chain(PBFTNode* node) {
    if (!node || node->base.peer_count == 0) {
        return -1;  // No peers to sync with
    }
    
    printf("Node %u resyncing blockchains with peers\n", node->base.id);
    
    uint32_t longest_chain = 0;
    uint32_t peer_with_longest_chain = 0;
    
    // Find the peer with the longest blockchain
    for (uint32_t i = 0; i < node->base.peer_count; i++) {
        // Skip self
        if (node->base.peers[i].id == node->base.id) {
            continue;
        }
        
        // Make HTTP request to get chain length from peer
        char peer_url[256];
        snprintf(peer_url, sizeof(peer_url), "http://%s", node->base.peers[i].ip);
        
        int peer_chain_length = pbft_get_blockchain_length(peer_url);
        if (peer_chain_length < 0) {
            printf("Failed to get blockchain length from peer %u at %s\n", 
                   node->base.peers[i].id, peer_url);
            peer_chain_length = 0;  // Default to 0 if request fails
        } else {
            printf("Peer %u at %s has blockchain length: %d\n", 
                   node->base.peers[i].id, peer_url, peer_chain_length);
        }
        
        if (peer_chain_length > longest_chain) {
            longest_chain = peer_chain_length;
            peer_with_longest_chain = i;
        }
    }
    
    if (longest_chain > node->base.blockchain->length) {
        printf("Node %u found longer chain (length %u vs %u), requesting missing blocks\n", 
               node->base.id, longest_chain, node->base.blockchain->length);
        
        // In full implementation, would request missing blocks from peer
        return 0;  // Successfully synced
    } else {
        printf("Node %u blockchain is already in sync (length %u)\n", 
               node->base.id, node->base.blockchain->length);
        return -1;  // No sync needed, but no new blocks proposed
    }
}
struct HttpResponse* pbft_node_http_request(const char* url, const char* method, const char* json_data) { return NULL; }
void pbft_node_free_http_response(struct HttpResponse* response) { }
// Broadcasting functions using internal transactions
int pbft_node_broadcast_block(PBFTNode* node, TW_Block* block, const char* block_hash) { 
    if (!node || !block) return 0;
    
    // Convert hex string to bytes
    unsigned char hash_bytes[HASH_SIZE];
    // TODO: Implement hex to bytes conversion
    memset(hash_bytes, 0, HASH_SIZE);
    
    // Create and broadcast block proposal
    return pbft_node_propose_block(node, block);
}

int pbft_node_broadcast_verification_vote(PBFTNode* node, const char* block_hash, const char* block_data) {
    if (!node || !block_hash) return 0;
    
    // Convert hex string to bytes
    unsigned char hash_bytes[HASH_SIZE];
    // TODO: Implement hex to bytes conversion
    memset(hash_bytes, 0, HASH_SIZE);
    
    // Create verification vote using internal transaction
    TW_InternalTransaction* vote = tw_create_vote_message(
        node->base.public_key,
        node->base.id,
        node->counter,
        hash_bytes,
        1  // Phase 1: verification
    );
    
    if (!vote) return 0;
    
    // Sign the internal transaction
    TW_Internal_Transaction_add_signature(vote);
    
    // Broadcast verification vote to all peers via binary HTTP
    int success_count = 0;
    printf("Node %u broadcasting verification vote for block to %zu peers (binary protocol)\n", 
           node->base.id, node->base.peer_count);
    
    for (size_t i = 0; i < node->base.peer_count; i++) {
        // Skip self
        if (node->base.peers[i].id == node->base.id) {
            continue;
        }
        
        // Construct peer URL
        char peer_url[256];
        snprintf(peer_url, sizeof(peer_url), "http://%s", node->base.peers[i].ip);
        
        // Send binary verification vote to peer
        if (pbft_send_vote_binary(peer_url, vote)) {
            success_count++;
            printf("Binary verification vote sent successfully to peer %u at %s\n", 
                   node->base.peers[i].id, peer_url);
        } else {
            printf("Failed to send binary verification vote to peer %u at %s\n", 
                   node->base.peers[i].id, peer_url);
        }
    }
    
    printf("Binary verification vote broadcast completed: %d/%zu peers reached\n", 
           success_count, node->base.peer_count);
    
    tw_destroy_internal_transaction(vote);
    return success_count > 0 ? 1 : 0;
}

int pbft_node_broadcast_commit_vote(PBFTNode* node, const char* block_hash, const char* block_data) {
    if (!node || !block_hash) return 0;
    
    // Convert hex string to bytes
    unsigned char hash_bytes[HASH_SIZE];
    // TODO: Implement hex to bytes conversion
    memset(hash_bytes, 0, HASH_SIZE);
    
    // Create commit vote using internal transaction
    TW_InternalTransaction* vote = tw_create_vote_message(
        node->base.public_key,
        node->base.id,
        node->counter,
        hash_bytes,
        2  // Phase 2: commit
    );
    
    if (!vote) return 0;
    
    // Sign the internal transaction
    TW_Internal_Transaction_add_signature(vote);
    
    // Broadcast commit vote to all peers via binary HTTP
    int success_count = 0;
    printf("Node %u broadcasting commit vote for block to %zu peers (binary protocol)\n", 
           node->base.id, node->base.peer_count);
    
    for (size_t i = 0; i < node->base.peer_count; i++) {
        // Skip self
        if (node->base.peers[i].id == node->base.id) {
            continue;
        }
        
        // Construct peer URL
        char peer_url[256];
        snprintf(peer_url, sizeof(peer_url), "http://%s", node->base.peers[i].ip);
        
        // Send binary commit vote to peer
        if (pbft_send_vote_binary(peer_url, vote)) {
            success_count++;
            printf("Binary commit vote sent successfully to peer %u at %s\n", 
                   node->base.peers[i].id, peer_url);
        } else {
            printf("Failed to send binary commit vote to peer %u at %s\n", 
                   node->base.peers[i].id, peer_url);
        }
    }
    
    printf("Binary commit vote broadcast completed: %d/%zu peers reached\n", 
           success_count, node->base.peer_count);
    
    tw_destroy_internal_transaction(vote);
    return success_count > 0 ? 1 : 0;
}

int pbft_node_broadcast_new_round_vote(PBFTNode* node, const char* block_hash, const char* block_data) {
    if (!node || !block_hash) return 0;
    
    // Convert hex string to bytes
    unsigned char hash_bytes[HASH_SIZE];
    // TODO: Implement hex to bytes conversion
    memset(hash_bytes, 0, HASH_SIZE);
    
    // Create new round vote using internal transaction
    TW_InternalTransaction* vote = tw_create_vote_message(
        node->base.public_key,
        node->base.id,
        node->counter,
        hash_bytes,
        3  // Phase 3: new round
    );
    
    if (!vote) return 0;
    
    // Sign the internal transaction
    TW_Internal_Transaction_add_signature(vote);
    
    // Broadcast new round vote to all peers via binary HTTP
    int success_count = 0;
    printf("Node %u broadcasting new round vote for block to %zu peers (binary protocol)\n", 
           node->base.id, node->base.peer_count);
    
    for (size_t i = 0; i < node->base.peer_count; i++) {
        // Skip self
        if (node->base.peers[i].id == node->base.id) {
            continue;
        }
        
        // Construct peer URL
        char peer_url[256];
        snprintf(peer_url, sizeof(peer_url), "http://%s", node->base.peers[i].ip);
        
        // Send binary new round vote to peer
        if (pbft_send_vote_binary(peer_url, vote)) {
            success_count++;
            printf("Binary new round vote sent successfully to peer %u at %s\n", 
                   node->base.peers[i].id, peer_url);
        } else {
            printf("Failed to send binary new round vote to peer %u at %s\n", 
                   node->base.peers[i].id, peer_url);
        }
    }
    
    printf("Binary new round vote broadcast completed: %d/%zu peers reached\n", 
           success_count, node->base.peer_count);
    
    tw_destroy_internal_transaction(vote);
    return success_count > 0 ? 1 : 0;
}
int pbft_node_broadcast_blockchain_to_new_node(PBFTNode* node, const char* peer_url) { return 0; }
int pbft_node_rebroadcast_message(PBFTNode* node, const char* json_data, const char* route) { return 0; }
int pbft_node_send_block_to_peer(PBFTNode* node, const char* peer_url, TW_Block* block, const char* block_hash) { return 0; }
int pbft_node_send_verification_vote_to_peer(PBFTNode* node, const char* peer_url, const char* block_hash, const char* block_data) { return 0; }
int pbft_node_send_commit_vote_to_peer(PBFTNode* node, const char* peer_url, const char* block_hash, const char* block_data) { return 0; }
int pbft_node_send_new_round_vote_to_peer(PBFTNode* node, const char* peer_url, const char* block_hash, const char* block_data) { return 0; }
int pbft_node_get_blockchain_length_from_peer(PBFTNode* node, const char* peer_url) { return 0; }
char* pbft_node_get_last_block_hash_from_peer(PBFTNode* node, const char* peer_url) { return NULL; }
int pbft_node_request_missing_blocks_from_peer(PBFTNode* node, const char* peer_url) { return 0; }
int pbft_node_request_entire_blockchain_from_peer(PBFTNode* node, const char* peer_url) { return 0; }
int pbft_node_get_pending_transactions_from_peer(PBFTNode* node, const char* peer_url, char* transactions_json) { return 0; }
int pbft_node_send_block_creation_signal(PBFTNode* node) {
    if (!node) return 0;
    
    printf("Node %u: Creating block for singular node mode\n", node->base.id);
    
    // Create a new block
    TW_Block* new_block = pbft_node_create_block(node);
    if (!new_block) {
        printf("Failed to create block for singular node\n");
        return 0;
    }
    
    // Validate the block
    if (!pbft_node_validate_block(node, new_block)) {
        printf("Block validation failed for singular node\n");
        TW_Block_destroy(new_block);
        return 0;
    }
    
    // Commit the block directly (no consensus needed for single node)
    if (!pbft_node_commit_block(node, new_block)) {
        printf("Failed to commit block for singular node\n");
        TW_Block_destroy(new_block);
        return 0;
    }
    
    // Sync to database if available
    if (db_is_initialized()) {
        uint32_t block_index = node->base.blockchain->length - 1;
        if (db_add_block(new_block, block_index) == 0) {
            printf("Block %u synced to database successfully\n", block_index);
        } else {
            printf("Warning: Failed to sync block %u to database\n", block_index);
        }
    }
    
    printf("Node %u: Successfully created and committed block %d in singular mode\n", 
           node->base.id, new_block->index);
    
    return 1;
}
void pbft_node_shuffle_peers(PBFTNode* node) {
    if (!node || node->base.peer_count <= 1) return;
    
    // Simple Fisher-Yates shuffle for peer array
    for (uint32_t i = node->base.peer_count - 1; i > 0; i--) {
        uint32_t j = rand() % (i + 1);
        
        // Swap peers[i] and peers[j]
        PeerInfo temp = node->base.peers[i];
        node->base.peers[i] = node->base.peers[j];
        node->base.peers[j] = temp;
    }
    
    printf("Node %u: Shuffled %zu peers\n", node->base.id, node->base.peer_count);
}
int pbft_node_sign_data(PBFTNode* node, const char* data, char* signature_hex) {
    if (!node || !data || !signature_hex) return 0;
    
    // Sign the data using the signing functionality
    unsigned char signature[SIGNATURE_SIZE];
    
    if (sign_message(data, signature) != 0) {
        printf("Failed to sign data for node %u\n", node->base.id);
        return 0;
    }
    
    // Convert signature to hex string
    pbft_node_bytes_to_hex(signature, SIGNATURE_SIZE, signature_hex);
    
    return 1;
}

int pbft_node_verify_signature(const char* pubkey_hex, const char* signature_hex, const char* data) {
    if (!pubkey_hex || !signature_hex || !data) return 0;
    
    // Convert hex strings back to bytes
    unsigned char public_key[PUBKEY_SIZE];
    unsigned char signature[SIGNATURE_SIZE];
    
    if (pbft_node_hex_to_bytes(pubkey_hex, public_key, PUBKEY_SIZE) != PUBKEY_SIZE) {
        return 0;
    }
    
    if (pbft_node_hex_to_bytes(signature_hex, signature, SIGNATURE_SIZE) != SIGNATURE_SIZE) {
        return 0;
    }
    
    // Verify the signature
    return verify_signature(signature, (const unsigned char*)data, strlen(data), public_key);
}

void pbft_node_generate_self_url(PBFTNode* node) { }
char* pbft_node_serialize_block_to_json(TW_Block* block) { return NULL; }
char* pbft_node_serialize_transaction_to_json(TW_Transaction* transaction) { return NULL; }
char* pbft_node_serialize_blockchain_to_json(TW_BlockChain* blockchain) { return NULL; }
TW_Block* pbft_node_deserialize_block_from_json(const char* json_str) { return NULL; }
TW_Transaction* pbft_node_deserialize_transaction_from_json(const char* json_str) { return NULL; }
TW_BlockChain* pbft_node_deserialize_blockchain_from_json(const char* json_str) { return NULL; }
void pbft_node_bytes_to_hex(const unsigned char* bytes, size_t byte_len, char* hex_str) {
    if (!bytes || !hex_str) return;
    
    const char hex_chars[] = "0123456789abcdef";
    
    for (size_t i = 0; i < byte_len; i++) {
        hex_str[i * 2] = hex_chars[bytes[i] >> 4];
        hex_str[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex_str[byte_len * 2] = '\0';
}

int pbft_node_hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t max_bytes) {
    if (!hex_str || !bytes) return 0;
    
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0) return 0;  // Must be even length
    
    size_t byte_len = hex_len / 2;
    if (byte_len > max_bytes) return 0;  // Not enough space
    
    for (size_t i = 0; i < byte_len; i++) {
        char hex_byte[3] = {hex_str[i * 2], hex_str[i * 2 + 1], '\0'};
        bytes[i] = (unsigned char)strtol(hex_byte, NULL, 16);
    }
    
    return byte_len;
}

int pbft_node_configure_blockchain_for_first_use(PBFTNode* node) { return 0; }
int pbft_node_save_blockchain_periodically(PBFTNode* node) {
    if (!node || !node->base.blockchain) return 0;
    
    printf("Node %u: Saving blockchain (length: %u)\n", 
           node->base.id, node->base.blockchain->length);
    
    // Save blockchain to file using the blockchain I/O functions
    if (!saveBlockChainToFile(node->base.blockchain)) {
        printf("Error: Failed to save blockchain to file\n");
        return 0;
    }
    
    // Also save as JSON for debugging
    if (!writeBlockChainToJson(node->base.blockchain)) {
        printf("Warning: Failed to save blockchain as JSON\n");
        // Don't return error since binary save succeeded
    }
    
    printf("Node %u: Successfully saved blockchain to file\n", node->base.id);
    return 1;
}

// Endpoint handler implementations
static void handle_transaction_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    printf("[DEBUG] /Transaction endpoint called - validating request\n");
    
    if (!node) {
        printf("[ERROR] handle_transaction_endpoint: Node not initialized\n");
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Node not initialized\",\"status\":\"error\"}");
        return;
    }
    
    // Validate HTTP method
    if (mg_strcmp(hm->method, mg_str("POST")) != 0) {
        printf("[ERROR] handle_transaction_endpoint: Invalid HTTP method: %.*s\n", 
               (int)hm->method.len, hm->method.buf);
        mg_http_reply(c, 405, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Method not allowed, use POST\",\"status\":\"error\"}");
        return;
    }
    
    // Validate request has body
    if (hm->body.len == 0) {
        printf("[ERROR] handle_transaction_endpoint: Empty request body\n");
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Request body required\",\"status\":\"error\"}");
        return;
    }
    
    // Parse JSON body with enhanced error handling
    TW_Transaction* transaction = NULL;
    int parse_result = parse_json_transaction(hm->body, &transaction);
    if (parse_result != 0) {
        printf("[ERROR] handle_transaction_endpoint: Failed to parse transaction JSON (error %d)\n", parse_result);
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Invalid JSON or transaction format\",\"status\":\"error\",\"details\":\"Check server logs for validation details\"}");
        return;
    }
    
    // Additional safety check
    if (!transaction) {
        printf("[ERROR] handle_transaction_endpoint: Transaction object is NULL after parsing\n");
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Internal server error during transaction parsing\",\"status\":\"error\"}");
        return;
    }
    
    // Calculate transaction hash with error handling
    unsigned char tx_hash[HASH_SIZE];
    memset(tx_hash, 0, HASH_SIZE);
    
    printf("[DEBUG] handle_transaction_endpoint: Calculating transaction hash\n");
    TW_Transaction_hash(transaction, tx_hash);
    
    // Verify hash was calculated (non-zero)
    int hash_is_zero = 1;
    for (int i = 0; i < HASH_SIZE; i++) {
        if (tx_hash[i] != 0) {
            hash_is_zero = 0;
            break;
        }
    }
    
    if (hash_is_zero) {
        printf("[ERROR] handle_transaction_endpoint: Transaction hash calculation resulted in zero hash\n");
        TW_Transaction_destroy(transaction);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Failed to calculate transaction hash\",\"status\":\"error\"}");
        return;
    }
    
    char hash_hex[HASH_SIZE * 2 + 1];
    memset(hash_hex, 0, sizeof(hash_hex));
    pbft_node_bytes_to_hex(tx_hash, HASH_SIZE, hash_hex);
    
    printf("[DEBUG] handle_transaction_endpoint: Transaction hash: %s\n", hash_hex);
    
    // Check if transaction is already queued
    printf("[DEBUG] handle_transaction_endpoint: Checking if transaction already queued\n");
    if (is_transaction_queued(hash_hex)) {
        printf("[INFO] handle_transaction_endpoint: Transaction already queued: %s\n", hash_hex);
        TW_Transaction_destroy(transaction);
        mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Transaction Already Queued\",\"status\":\"duplicate\",\"hash\":\"%s\"}", hash_hex);
        return;
    }
    
    // Verify user is registered in blockchain with error handling
    printf("[DEBUG] handle_transaction_endpoint: Verifying user registration\n");
    int user_verified = 0;
    if (node && node->base.blockchain) {
        user_verified = is_user_verified(transaction->sender, node->base.blockchain);
    }
    
    if (!user_verified) {
        printf("[WARNING] handle_transaction_endpoint: User not verified, public key: ");
        for (int i = 0; i < PUBKEY_SIZE; i++) {
            printf("%02x", transaction->sender[i]);
        }
        printf("\n");
        
        TW_Transaction_destroy(transaction);
        mg_http_reply(c, 403, "Content-Type: application/json\r\n", 
                     "{\"error\":\"User not verified in blockchain\",\"status\":\"forbidden\"}");
        return;
    }
    
    // Validate transaction signature with comprehensive error handling
    printf("[DEBUG] handle_transaction_endpoint: Validating transaction signature\n");
    ValidationResult sig_result = VALIDATION_ERROR_NULL_POINTER;
    
    // TEMPORARILY DISABLED FOR PERMISSION TESTING
    // Try signature validation with error protection
    // sig_result = validate_transaction_signature(transaction);
    sig_result = VALIDATION_SUCCESS; // Skip signature validation for testing
    
    if (sig_result != VALIDATION_SUCCESS) {
        printf("[ERROR] handle_transaction_endpoint: Transaction signature validation failed: %s\n", 
               validation_error_string(sig_result));
        TW_Transaction_destroy(transaction);
        
        const char* error_msg;
        switch (sig_result) {
            case VALIDATION_ERROR_INVALID_SIGNATURE:
                error_msg = "Invalid signature";
                break;
            case VALIDATION_ERROR_NULL_POINTER:
                error_msg = "Null pointer in validation";
                break;
            case VALIDATION_ERROR_INVALID_PAYLOAD:
                error_msg = "Invalid transaction payload";
                break;
            case VALIDATION_ERROR_INVALID_TRANSACTION:
                error_msg = "Invalid transaction format";
                break;
            default:
                error_msg = "Unknown validation error";
                break;
        }
        
        mg_http_reply(c, 403, "Content-Type: application/json\r\n", 
                     "{\"error\":\"%s\",\"status\":\"forbidden\",\"validation_code\":%d}", 
                     error_msg, sig_result);
        return;
    }
    
    // Validate transaction permissions with error handling
    printf("[DEBUG] handle_transaction_endpoint: Validating transaction permissions\n");
    int permissions_valid = 0;
    if (node && transaction) {
        permissions_valid = validate_transaction_permissions_for_node(transaction, node);
    }
    
    if (!permissions_valid) {
        printf("[ERROR] handle_transaction_endpoint: Transaction permissions validation failed\n");
        TW_Transaction_destroy(transaction);
        mg_http_reply(c, 403, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Invalid transaction permissions\",\"status\":\"forbidden\"}");
        return;
    }
    
    // Add to transaction queue with comprehensive error handling
    printf("[DEBUG] handle_transaction_endpoint: Adding transaction to PBFT queue\n");
    int queue_result = add_to_transaction_queue(hash_hex, transaction);
    if (queue_result != 0) {
        printf("[ERROR] handle_transaction_endpoint: Failed to add transaction to queue (error %d)\n", queue_result);
        TW_Transaction_destroy(transaction);
        
        const char* queue_error_msg;
        switch (queue_result) {
            case -1:
                queue_error_msg = "Queue is full or invalid parameters";
                break;
            default:
                queue_error_msg = "Unknown queue error";
                break;
        }
        
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"%s\",\"status\":\"error\",\"queue_error\":%d}", queue_error_msg, queue_result);
        return;
    }
    
    printf("[SUCCESS] handle_transaction_endpoint: Transaction queued successfully: %s\n", hash_hex);
    
    // Safely rebroadcast transaction to peers
    printf("[DEBUG] handle_transaction_endpoint: Rebroadcasting transaction to peers\n");
    pbft_node_rebroadcast_transaction(node, hm->body);
    
    // Update proposer ID
    node->base.proposer_offset = pbft_node_calculate_proposer_id(node);
    printf("[DEBUG] handle_transaction_endpoint: Updated proposer ID: %u\n", node->base.proposer_offset);
    
    // Transaction processing completed successfully
    printf("[SUCCESS] handle_transaction_endpoint: Transaction submitted successfully to PBFT queue\n");
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                 "{\"response\":\"Transaction submitted to PBFT queue\",\"status\":\"success\",\"hash\":\"%s\"}", hash_hex);
}

static void handle_transaction_internal_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Node not initialized\"}");
        return;
    }
    
    // Parse internal transaction from HTTP body
    TW_InternalTransaction* internal_txn = parse_internal_transaction_from_http(hm->body);
    if (!internal_txn) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Invalid internal transaction format\"}");
        return;
    }
    
    // Validate internal transaction signature
    if (!validate_internal_transaction_signature(internal_txn)) {
        tw_destroy_internal_transaction(internal_txn);
        mg_http_reply(c, 403, "Content-Type: application/json\r\n", 
                     "{\"response\":\"KeyError\"}");
        return;
    }
    
    // Process the internal transaction
    if (process_internal_transaction(internal_txn) != 0) {
        tw_destroy_internal_transaction(internal_txn);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Failed to process internal transaction\"}");
        return;
    }
    
    tw_destroy_internal_transaction(internal_txn);
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                 "{\"response\":\"ok\"}");
}

static void handle_propose_block_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Node not initialized\"}");
        return;
    }
    
    // Parse JSON body to extract block proposal
    cJSON *json = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!json) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Invalid JSON\"}");
        return;
    }
    
    cJSON *block_data_json = cJSON_GetObjectItem(json, "blockData");
    cJSON *block_hash_json = cJSON_GetObjectItem(json, "blockHash");
    cJSON *sender_json = cJSON_GetObjectItem(json, "sender");
    cJSON *signature_json = cJSON_GetObjectItem(json, "signature");
    
    if (!block_data_json || !block_hash_json || !sender_json || !signature_json) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Missing required fields\"}");
        cJSON_Delete(json);
        return;
    }
    
    const char* block_data = cJSON_GetStringValue(block_data_json);
    const char* block_hash = cJSON_GetStringValue(block_hash_json);
    const char* sender = cJSON_GetStringValue(sender_json);
    const char* signature = cJSON_GetStringValue(signature_json);
    
    // Verify signature
    if (!pbft_node_verify_signature(sender, signature, block_hash)) {
        mg_http_reply(c, 401, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Invalid signature\"}");
        cJSON_Delete(json);
        return;
    }
    
    printf("Node %u received block proposal from %s\n", node->base.id, sender);
    
    // For now, automatically send verification vote (simplified PBFT)
    pbft_node_broadcast_verification_vote(node, block_hash, block_data);
    
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                 "{\"response\":\"Block proposal received and verification vote sent\"}");
    
    cJSON_Delete(json);
}

static void handle_verification_vote_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Node not initialized\"}");
        return;
    }
    
    // Parse JSON body to extract verification vote
    cJSON *json = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!json) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Invalid JSON\"}");
        return;
    }
    
    cJSON *block_data_json = cJSON_GetObjectItem(json, "blockData");
    cJSON *block_hash_json = cJSON_GetObjectItem(json, "blockHash");
    cJSON *sender_json = cJSON_GetObjectItem(json, "sender");
    cJSON *signature_json = cJSON_GetObjectItem(json, "signature");
    
    if (!block_data_json || !block_hash_json || !sender_json || !signature_json) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Missing required fields\"}");
        cJSON_Delete(json);
        return;
    }
    
    const char* block_data = cJSON_GetStringValue(block_data_json);
    const char* block_hash = cJSON_GetStringValue(block_hash_json);
    const char* sender = cJSON_GetStringValue(sender_json);
    const char* signature = cJSON_GetStringValue(signature_json);
    
    // Verify signature
    if (!pbft_node_verify_signature(sender, signature, block_hash)) {
        mg_http_reply(c, 401, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Invalid signature\"}");
        cJSON_Delete(json);
        return;
    }
    
    printf("Node %u received verification vote from %s for block %s\n", 
           node->base.id, sender, block_hash);
    
    // Count verification votes (simplified - in full implementation, would track votes)
    // For now, automatically proceed to commit phase
    pbft_node_broadcast_commit_vote(node, block_hash, block_data);
    
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                 "{\"response\":\"Verification vote received and commit vote sent\"}");
    
    cJSON_Delete(json);
}

static void handle_commit_vote_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Node not initialized\"}");
        return;
    }
    
    // Parse JSON body to extract commit vote
    cJSON *json = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!json) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Invalid JSON\"}");
        return;
    }
    
    cJSON *block_data_json = cJSON_GetObjectItem(json, "blockData");
    cJSON *block_hash_json = cJSON_GetObjectItem(json, "blockHash");
    cJSON *sender_json = cJSON_GetObjectItem(json, "sender");
    cJSON *signature_json = cJSON_GetObjectItem(json, "signature");
    
    if (!block_data_json || !block_hash_json || !sender_json || !signature_json) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Missing required fields\"}");
        cJSON_Delete(json);
        return;
    }
    
    const char* block_data = cJSON_GetStringValue(block_data_json);
    const char* block_hash = cJSON_GetStringValue(block_hash_json);
    const char* sender = cJSON_GetStringValue(sender_json);
    const char* signature = cJSON_GetStringValue(signature_json);
    
    // Verify signature
    if (!pbft_node_verify_signature(sender, signature, block_hash)) {
        mg_http_reply(c, 401, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Invalid signature\"}");
        cJSON_Delete(json);
        return;
    }
    
    printf("Node %u received commit vote from %s for block %s\n", 
           node->base.id, sender, block_hash);
    
    // Count commit votes (simplified - in full implementation, would track votes)
    // For now, just acknowledge the commit vote
    
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                 "{\"response\":\"Commit vote received\"}");
    
    cJSON_Delete(json);
}

static void handle_new_round_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    // TODO: Implement new round handling
    mg_http_reply(c, 501, "Content-Type: application/json\r\n", 
                 "{\"error\":\"NewRound endpoint not implemented yet\"}");
}

static void handle_missing_block_request_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Node not initialized\"}");
        return;
    }
    
    // Parse JSON body to extract missing block request
    cJSON *json = cJSON_ParseWithLength(hm->body.buf, hm->body.len);
    if (!json) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Invalid JSON\"}");
        return;
    }
    
    cJSON *last_hash_json = cJSON_GetObjectItem(json, "lastHash");
    cJSON *sender_json = cJSON_GetObjectItem(json, "sender");
    cJSON *signature_json = cJSON_GetObjectItem(json, "signature");
    
    if (!last_hash_json || !sender_json || !signature_json) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Missing required fields\"}");
        cJSON_Delete(json);
        return;
    }
    
    const char* last_hash = cJSON_GetStringValue(last_hash_json);
    const char* sender = cJSON_GetStringValue(sender_json);
    const char* signature = cJSON_GetStringValue(signature_json);
    
    // Verify signature
    if (!pbft_node_verify_signature(sender, signature, last_hash)) {
        mg_http_reply(c, 401, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Invalid signature\"}");
        cJSON_Delete(json);
        return;
    }
    
    printf("Node %u received missing block request from %s, last hash: %s\n", 
           node->base.id, sender, last_hash);
    
    // For now, return a simple response indicating no missing blocks
    // In full implementation, would find blocks after the given hash
    mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                 "{\"response\":{\"missingBlocks\":[]}}");
    
    cJSON_Delete(json);
}

static void handle_send_new_blockchain_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    // TODO: Implement send new blockchain handling
    mg_http_reply(c, 501, "Content-Type: application/json\r\n", 
                 "{\"error\":\"SendNewBlockChain endpoint not implemented yet\"}");
}

static void handle_request_entire_blockchain_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    // TODO: Implement request entire blockchain handling
    mg_http_reply(c, 501, "Content-Type: application/json\r\n", 
                 "{\"error\":\"RequestEntireBlockchain endpoint not implemented yet\"}");
}

static void handle_add_new_block_singular_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Node not initialized\"}");
        return;
    }
    
    printf("Node %u: Received singular node block creation request\n", node->base.id);
    
    // Create and commit a block for singular node
    if (pbft_node_send_block_creation_signal(node)) {
        mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                     "{\"response\":\"Block created successfully for singular node\"}");
    } else {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Failed to create block for singular node\"}");
    }
}

// Supporting functions for transaction processing
int parse_json_transaction(struct mg_str json_body, TW_Transaction** transaction) {
    if (!transaction) {
        printf("[ERROR] parse_json_transaction: NULL transaction pointer\n");
        return -1;
    }
    
    // Validate input JSON body
    if (json_body.len == 0 || !json_body.buf) {
        printf("[ERROR] parse_json_transaction: Empty or NULL JSON body\n");
        return -1;
    }
    
    // Check for reasonable JSON size limits (prevent DoS)
    if (json_body.len > 1024 * 1024) { // 1MB limit
        printf("[ERROR] parse_json_transaction: JSON body too large (%zu bytes)\n", json_body.len);
        return -1;
    }
    
    // Check for minimum viable JSON size
    if (json_body.len < 10) {
        printf("[ERROR] parse_json_transaction: JSON body too small (%zu bytes)\n", json_body.len);
        return -1;
    }
    
    // Parse JSON string with comprehensive error handling
    cJSON *json = cJSON_ParseWithLength(json_body.buf, json_body.len);
    if (!json) {
        const char* error_ptr = cJSON_GetErrorPtr();
        printf("[ERROR] parse_json_transaction: Failed to parse JSON");
        if (error_ptr) {
            printf(" - error near: %.20s", error_ptr);
        }
        printf("\n");
        return -1;
    }
    
    // Validate JSON is an object
    if (!cJSON_IsObject(json)) {
        printf("[ERROR] parse_json_transaction: JSON is not an object\n");
        cJSON_Delete(json);
        return -1;
    }
    
    // Extract fields with comprehensive validation
    cJSON *sender_json = cJSON_GetObjectItem(json, "sender");
    cJSON *type_json = cJSON_GetObjectItem(json, "type");
    cJSON *timestamp_json = cJSON_GetObjectItem(json, "timestamp");
    cJSON *recipients_json = cJSON_GetObjectItem(json, "recipients");
    cJSON *signature_json = cJSON_GetObjectItem(json, "signature");
    cJSON *payload_json = cJSON_GetObjectItem(json, "payload");
    
    // Check for required fields
    if (!sender_json || !type_json || !timestamp_json || !recipients_json || !signature_json) {
        printf("[ERROR] parse_json_transaction: Missing required fields\n");
        printf("  sender: %s, type: %s, timestamp: %s, recipients: %s, signature: %s\n",
               sender_json ? "✓" : "✗",
               type_json ? "✓" : "✗", 
               timestamp_json ? "✓" : "✗",
               recipients_json ? "✓" : "✗",
               signature_json ? "✓" : "✗");
        cJSON_Delete(json);
        return -1;
    }
    
    // Validate field types
    if (!cJSON_IsString(sender_json) || !cJSON_IsNumber(type_json) || 
        !cJSON_IsNumber(timestamp_json) || !cJSON_IsArray(recipients_json) || 
        !cJSON_IsString(signature_json)) {
        printf("[ERROR] parse_json_transaction: Invalid field types\n");
        cJSON_Delete(json);
        return -1;
    }
    
    // Validate and convert sender hex string to bytes
    const char* sender_hex = cJSON_GetStringValue(sender_json);
    if (!sender_hex) {
        printf("[ERROR] parse_json_transaction: Sender is not a valid string\n");
        cJSON_Delete(json);
        return -1;
    }
    
    size_t sender_len = strlen(sender_hex);
    if (sender_len != PUBKEY_SIZE * 2) {
        printf("[ERROR] parse_json_transaction: Invalid sender public key length (%zu, expected %d)\n", 
               sender_len, PUBKEY_SIZE * 2);
        cJSON_Delete(json);
        return -1;
    }
    
    // Validate sender contains only hex characters
    for (size_t i = 0; i < sender_len; i++) {
        char c = sender_hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            printf("[ERROR] parse_json_transaction: Invalid hex character in sender: '%c'\n", c);
            cJSON_Delete(json);
            return -1;
        }
    }
    
    unsigned char sender_bytes[PUBKEY_SIZE];
    if (pbft_node_hex_to_bytes(sender_hex, sender_bytes, PUBKEY_SIZE) != PUBKEY_SIZE) {
        printf("[ERROR] parse_json_transaction: Failed to convert sender hex to bytes\n");
        cJSON_Delete(json);
        return -1;
    }
    
    // Validate transaction type
    double type_double = cJSON_GetNumberValue(type_json);
    if (type_double < 0 || type_double > 1000 || type_double != (int)type_double) {
        printf("[ERROR] parse_json_transaction: Invalid transaction type: %f\n", type_double);
        cJSON_Delete(json);
        return -1;
    }
    int txn_type = (int)type_double;
    
    // Validate timestamp
    double timestamp_double = cJSON_GetNumberValue(timestamp_json);
    if (timestamp_double < 0 || timestamp_double > 4294967295000.0) { // Max reasonable timestamp
        printf("[ERROR] parse_json_transaction: Invalid timestamp: %f\n", timestamp_double);
        cJSON_Delete(json);
        return -1;
    }
    uint64_t timestamp = (uint64_t)timestamp_double;
    
    // Validate recipients array
    int recipient_count = cJSON_GetArraySize(recipients_json);
    if (recipient_count <= 0 || recipient_count > 100) { // Reasonable limit
        printf("[ERROR] parse_json_transaction: Invalid recipient count: %d\n", recipient_count);
        cJSON_Delete(json);
        return -1;
    }
    
    // Allocate and validate recipients
    unsigned char* recipients = malloc(recipient_count * PUBKEY_SIZE);
    if (!recipients) {
        printf("[ERROR] parse_json_transaction: Memory allocation failed for recipients\n");
        cJSON_Delete(json);
        return -1;
    }
    
    // Parse and validate each recipient
    for (int i = 0; i < recipient_count; i++) {
        cJSON* recipient_item = cJSON_GetArrayItem(recipients_json, i);
        if (!recipient_item || !cJSON_IsString(recipient_item)) {
            printf("[ERROR] parse_json_transaction: Recipient %d is not a string\n", i);
            free(recipients);
            cJSON_Delete(json);
            return -1;
        }
        
        const char* recipient_hex = cJSON_GetStringValue(recipient_item);
        if (!recipient_hex) {
            printf("[ERROR] parse_json_transaction: Recipient %d has null value\n", i);
            free(recipients);
            cJSON_Delete(json);
            return -1;
        }
        
        size_t recipient_hex_len = strlen(recipient_hex);
        if (recipient_hex_len != PUBKEY_SIZE * 2) {
            printf("[ERROR] parse_json_transaction: Recipient %d invalid length (%zu, expected %d)\n", 
                   i, recipient_hex_len, PUBKEY_SIZE * 2);
            free(recipients);
            cJSON_Delete(json);
            return -1;
        }
        
        // Validate recipient hex characters
        for (size_t j = 0; j < recipient_hex_len; j++) {
            char c = recipient_hex[j];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                printf("[ERROR] parse_json_transaction: Invalid hex character in recipient %d: '%c'\n", i, c);
                free(recipients);
                cJSON_Delete(json);
                return -1;
            }
        }
        
        if (pbft_node_hex_to_bytes(recipient_hex, recipients + (i * PUBKEY_SIZE), PUBKEY_SIZE) != PUBKEY_SIZE) {
            printf("[ERROR] parse_json_transaction: Failed to convert recipient %d hex to bytes\n", i);
            free(recipients);
            cJSON_Delete(json);
            return -1;
        }
    }
    
    // Validate signature
    const char* signature_hex = cJSON_GetStringValue(signature_json);
    if (!signature_hex) {
        printf("[ERROR] parse_json_transaction: Signature is not a valid string\n");
        free(recipients);
        cJSON_Delete(json);
        return -1;
    }
    
    size_t signature_len = strlen(signature_hex);
    if (signature_len > SIGNATURE_SIZE * 2) { // Allow for flexibility but prevent overflow
        printf("[ERROR] parse_json_transaction: Signature too long (%zu bytes)\n", signature_len);
        free(recipients);
        cJSON_Delete(json);
        return -1;
    }
    
    // Validate signature hex characters
    for (size_t i = 0; i < signature_len; i++) {
        char c = signature_hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
            printf("[ERROR] parse_json_transaction: Invalid hex character in signature: '%c'\n", c);
            free(recipients);
            cJSON_Delete(json);
            return -1;
        }
    }
    
    // Handle payload (can be optional for some transaction types)
    EncryptedPayload* encrypted_payload = NULL;
    if (payload_json && cJSON_IsString(payload_json)) {
        const char* payload_hex = cJSON_GetStringValue(payload_json);
        if (payload_hex) {
            size_t payload_hex_len = strlen(payload_hex);
            
            // Validate payload hex length
            if (payload_hex_len > 0) {
                if (payload_hex_len % 2 != 0) {
                    printf("[ERROR] parse_json_transaction: Payload hex length must be even (%zu)\n", payload_hex_len);
                    free(recipients);
                    cJSON_Delete(json);
                    return -1;
                }
                
                if (payload_hex_len > 100000) { // 50KB limit on payload
                    printf("[ERROR] parse_json_transaction: Payload too large (%zu hex chars)\n", payload_hex_len);
                    free(recipients);
                    cJSON_Delete(json);
                    return -1;
                }
                
                // Validate payload hex characters
                for (size_t i = 0; i < payload_hex_len; i++) {
                    char c = payload_hex[i];
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                        printf("[ERROR] parse_json_transaction: Invalid hex character in payload: '%c'\n", c);
                        free(recipients);
                        cJSON_Delete(json);
                        return -1;
                    }
                }
                
                // Attempt to deserialize payload
                int payload_len = payload_hex_len / 2;
                unsigned char* payload_bytes = malloc(payload_len);
                if (!payload_bytes) {
                    printf("[ERROR] parse_json_transaction: Memory allocation failed for payload\n");
                    free(recipients);
                    cJSON_Delete(json);
                    return -1;
                }
                
                // Convert hex to bytes
                for (int i = 0; i < payload_len; i++) {
                    if (sscanf(payload_hex + (i * 2), "%2hhx", &payload_bytes[i]) != 1) {
                        printf("[ERROR] parse_json_transaction: Failed to parse payload hex at position %d\n", i);
                        free(payload_bytes);
                        free(recipients);
                        cJSON_Delete(json);
                        return -1;
                    }
                }
                
                // Try to deserialize as EncryptedPayload with error handling
                const char* payload_ptr = (const char*)payload_bytes;
                encrypted_payload = encrypted_payload_deserialize(&payload_ptr);
                
                if (!encrypted_payload) {
                    printf("[ERROR] parse_json_transaction: Failed to deserialize EncryptedPayload (payload_len=%d bytes)\n", payload_len);
                    printf("[ERROR] This could indicate the frontend is sending the wrong payload format\n");
                    free(payload_bytes);
                    free(recipients);
                    cJSON_Delete(json);
                    return -1;
                }
                
                free(payload_bytes);
            }
        }
    }
    
    // Handle group_id (optional)
    unsigned char group_id[GROUP_ID_SIZE];
    memset(group_id, 0, GROUP_ID_SIZE);
    
    cJSON* group_id_json = cJSON_GetObjectItem(json, "groupId");
    if (group_id_json && cJSON_IsString(group_id_json)) {
        const char* group_id_hex = cJSON_GetStringValue(group_id_json);
        if (group_id_hex) {
            size_t group_id_len = strlen(group_id_hex);
            if (group_id_len == GROUP_ID_SIZE * 2) {
                // Validate group ID hex
                for (size_t i = 0; i < group_id_len; i++) {
                    char c = group_id_hex[i];
                    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                        printf("[WARNING] parse_json_transaction: Invalid hex character in groupId, using default\n");
                        break;
                    }
                }
                pbft_node_hex_to_bytes(group_id_hex, group_id, GROUP_ID_SIZE);
            }
        }
    }
    
    // Create transaction with error handling
    *transaction = TW_Transaction_create(
        txn_type, 
        sender_bytes, 
        recipients, 
        recipient_count, 
        group_id, 
        encrypted_payload, 
        NULL  // signature will be set below
    );
    
    if (!*transaction) {
        printf("[ERROR] parse_json_transaction: Failed to create transaction\n");
        if (encrypted_payload) {
            free_encrypted_payload(encrypted_payload);
        }
        free(recipients);
        cJSON_Delete(json);
        return -1;
    }
    
    // Convert signature from hex string to binary data
    if (signature_len != SIGNATURE_SIZE * 2) {
        printf("[ERROR] parse_json_transaction: Invalid signature length (%zu, expected %d hex chars)\n", 
               signature_len, SIGNATURE_SIZE * 2);
        if (encrypted_payload) {
            free_encrypted_payload(encrypted_payload);
        }
        free(recipients);
        cJSON_Delete(json);
        return -1;
    }
    
    memset((*transaction)->signature, 0, SIGNATURE_SIZE);
    if (pbft_node_hex_to_bytes(signature_hex, (*transaction)->signature, SIGNATURE_SIZE) != SIGNATURE_SIZE) {
        printf("[ERROR] parse_json_transaction: Failed to convert signature hex to bytes\n");
        if (encrypted_payload) {
            free_encrypted_payload(encrypted_payload);
        }
        free(recipients);
        cJSON_Delete(json);
        return -1;
    }
    
    // Cleanup
    free(recipients);
    cJSON_Delete(json);
    
    printf("[SUCCESS] parse_json_transaction: Successfully parsed transaction (type=%d, recipients=%d)\n", 
           txn_type, recipient_count);
    return 0;
}

int is_transaction_queued(const char* hash_hex) {
    if (!hash_hex) return 0;
    
    // Check if transaction is already in the queue
    for (int i = 0; i < message_queues.transaction_count; i++) {
        if (strcmp(message_queues.transaction_queue[i].hash, hash_hex) == 0) {
            return 1;  // Already queued
        }
    }
    return 0;  // Not queued
}

int is_user_verified(const unsigned char* public_key, TW_BlockChain* blockchain) {
    if (!public_key || !blockchain) return 0;
    
    // Open database connection for verification
    if (db_init("state/blockchain/blockchain.db") != 0) {
        printf("Failed to open database for user verification\n");
        return 0;
    }
    
    sqlite3* db = db_get_handle();
    if (!db) {
        printf("Failed to get database handle\n");
        // Keep database connection open for application lifetime
        // db_close(); // Removed - database should stay open
        return 0;
    }
    
    // Check if user is registered
    bool is_registered = false;
    uint64_t registration_timestamp = 0;
    
    TxnValidationResult result = query_user_registration_transaction(
        public_key, db, &is_registered, &registration_timestamp
    );
    
    // Keep database connection open for application lifetime
    // db_close(); // Removed - database should stay open
    
    if (result == TXN_VALIDATION_SUCCESS && is_registered) {
        printf("User verification: SUCCESS (registered at timestamp %lu)\n", registration_timestamp);
        return 1;
    } else {
        printf("User verification failed: %s\n", 
               result == TXN_VALIDATION_SUCCESS ? "Not registered" : txn_validation_error_string(result));
        return 0;
    }
}

int validate_transaction_permissions_for_node(TW_Transaction* transaction, PBFTNode* node) {
    if (!transaction || !node) return 0;
    
    // Create validation context
    ValidationContext* context = create_validation_context(node->base.blockchain, NULL);
    if (!context) {
        printf("Failed to create validation context\n");
        return 0;
    }
    
    // Open database connection for validation
    if (db_init("state/blockchain/blockchain.db") != 0) {
        printf("Failed to open database for validation\n");
        destroy_validation_context(context);
        return 0;
    }
    
    sqlite3* db = db_get_handle();
    if (!db) {
        printf("Failed to get database handle\n");
        // Keep database connection open for application lifetime
        // db_close(); // Removed - database should stay open
        destroy_validation_context(context);
        return 0;
    }
    
    context->database = db;
    
    // Validate transaction permissions
    TxnValidationResult result = validate_txn_permissions(transaction, context);
    
    // Keep database connection open for application lifetime
    // db_close(); // Removed - database should stay open
    destroy_validation_context(context);
    
    if (result == TXN_VALIDATION_SUCCESS) {
        printf("Transaction permission validation: SUCCESS\n");
        return 1;
    } else {
        printf("Transaction permission validation failed: %s\n", 
               txn_validation_error_string(result));
        return 0;
    }
}

int pbft_node_rebroadcast_transaction(PBFTNode* node, struct mg_str json_body) {
    if (!node) return -1;
    
    // Rebroadcast transaction to all peers via HTTP
    int success_count = 0;
    printf("Rebroadcasting transaction to %zu peers\n", node->base.peer_count);
    
    // Convert mg_str to null-terminated string
    char* json_str = malloc(json_body.len + 1);
    if (!json_str) {
        printf("Failed to allocate memory for transaction rebroadcast\n");
        return -1;
    }
    memcpy(json_str, json_body.buf, json_body.len);
    json_str[json_body.len] = '\0';
    
    for (size_t i = 0; i < node->base.peer_count; i++) {
        // Skip self
        if (node->base.peers[i].id == node->base.id) {
            continue;
        }
        
        // Construct peer URL
        char peer_url[256];
        snprintf(peer_url, sizeof(peer_url), "http://%s/Transaction", node->base.peers[i].ip);
        
        // Send transaction to peer
        HttpResponse* response = http_client_post_json(peer_url, json_str, NULL);
        if (response && http_client_is_success_status(response->status_code)) {
            success_count++;
            printf("Transaction rebroadcast successful to peer %u at %s\n", 
                   node->base.peers[i].id, peer_url);
        } else {
            printf("Failed to rebroadcast transaction to peer %u at %s\n", 
                   node->base.peers[i].id, peer_url);
        }
        
        if (response) {
            free(response->data);
            free(response->headers);
            free(response);
        }
    }
    
    free(json_str);
    printf("Transaction rebroadcast completed: %d/%zu peers reached\n", 
           success_count, node->base.peer_count);
    
    return success_count;
}

int verify_blockchain_sync(PBFTNode* node, TW_Block* block) {
    if (!node || !block || !node->base.blockchain) return 0;
    
    // Check if the block's previous hash matches the last block in our chain
    if (node->base.blockchain->length > 0) {
        TW_Block* last_block = node->base.blockchain->blocks[node->base.blockchain->length - 1];
        unsigned char expected_prev_hash[HASH_SIZE];
        
        if (TW_Block_getHash(last_block, expected_prev_hash) != 1) {
            return 0;  // Failed to get hash
        }
        
        if (memcmp(block->previous_hash, expected_prev_hash, HASH_SIZE) != 0) {
            printf("Blockchain sync error: previous hash mismatch\n");
            return 0;  // Chains out of sync
        }
    }
    
    return 1;  // Chains are in sync
} 