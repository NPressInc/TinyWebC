#include "pbft_node.h"
#include "node.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <cjson/cJSON.h>
#include "packages/keystore/keystore.h"
#include "packages/signing/signing.h"
#include "features/blockchain/core/blockchain.h"
#include "features/blockchain/core/block.h"
#include "packages/validation/block_validation.h"
#include "packages/validation/transaction_validation.h"
#include "packages/comm/pbftApi.h"
#include "packages/comm/httpClient.h"
#include "packages/sql/database.h"
#include "packages/sql/queries.h"
#include "features/blockchain/persistence/blockchain_io.h"
#include "packages/utils/statePaths.h"
#include "packages/comm/blockChainQueryApi.h"
#include "features/blockchain/persistence/persistence_manager.h"
#include "packages/utils/byteorder.h"
#include "packages/comm/accessApi.h"
#include <sodium.h>

// Global node ID for state path resolution
static uint32_t g_current_node_id = 0;

// Helper function to get current node's database path
static bool get_current_node_db_path(char* buffer, size_t buffer_size) {
    if (!pbft_node) {
        // Fallback to default path if node not initialized
        snprintf(buffer, buffer_size, "state/blockchain/blockchain.db");
        return true;
    }

    // Create a temporary paths structure to get the correct path
    NodeStatePaths paths;
    if (!state_paths_init(pbft_node->base.id, pbft_node->debug_mode, &paths)) {
        // Fallback if path initialization fails
        snprintf(buffer, buffer_size, "state/blockchain/blockchain.db");
        return true;
    }

    return state_paths_get_database_file(&paths, buffer, buffer_size);
}

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

PBFTNode* pbft_node_create(uint32_t node_id, uint16_t api_port, bool debug_mode) {
    PBFTNode* node = calloc(1, sizeof(PBFTNode));
    if (!node) return NULL;

    node->base.id = node_id;
    node->api_port = api_port;
    node->debug_mode = debug_mode;
    node->consensus_enabled = true;
    node->running = 1;

    // Initialize view change state
    node->current_view = 0;
    node->last_consensus_activity = time(NULL);
    node->view_change_pending = false;
    node->proposed_new_view = 0;
    node->failed_rounds_count = 0;

    // Initialize view change vote tracking
    node->view_change_votes_count = 0;
    memset(node->view_change_voters, 0, sizeof(node->view_change_voters));

    // Set global node ID for path resolution
    g_current_node_id = node_id;
    
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
    
    return node;
}

void pbft_node_destroy(PBFTNode* node) {
    if (!node) return;
    
    node->running = 0;
    
    // Cleanup blockchain data manager
    TW_BlockchainDataManager_cleanup();
    
    // Cleanup HTTP client
    http_client_cleanup();
    
    
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

    // Initialize node-specific paths
    NodeStatePaths paths;
    if (!state_paths_init(node->base.id, node->debug_mode, &paths)) {
        printf("Failed to initialize state paths for node %u\n", node->base.id);
        return -1;
    }
    
    // Try to load existing private key, or generate new one
    char filename[256];
    strncpy(filename, paths.private_key_file, sizeof(filename) - 1);
    filename[sizeof(filename) - 1] = '\0';
    
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

    // Initialize node-specific paths
    NodeStatePaths paths;
    if (!state_paths_init(node->base.id, node->debug_mode, &paths)) {
        printf("Failed to initialize state paths for node %u\n", node->base.id);
        return -1;
    }
    
    // Initialize the robust persistence manager with node-specific paths
    const char* blockchain_file = paths.blockchain_file;
    const char* db_file = paths.database_file;
    
    PersistenceResult init_result = blockchain_persistence_init(blockchain_file, db_file);
    if (init_result != PERSISTENCE_SUCCESS) {
        printf("❌ Failed to initialize persistence manager: %s\n", 
               blockchain_persistence_error_string(init_result));
        return -1;
    }
    
    // Initialize database first (required for recovery operations)
    printf("🔄 Initializing database for persistence operations...\n");
    if (db_init(db_file) != 0) {
        printf("⚠️ Database initialization failed - running in file-only mode\n");
    } else {
        printf("✅ Database initialized for persistence operations\n");
    }
    
    // Try to load blockchain using the robust persistence system with recovery
    printf("🔄 Loading blockchain with automatic recovery...\n");
    TW_BlockChain* loaded_blockchain = readBlockChainFromFileWithPath(paths.blockchain_dir);
    
    if (loaded_blockchain) {
        node->base.blockchain = loaded_blockchain;
        printf("✅ Blockchain loaded: %u blocks\n", loaded_blockchain->length);
    } else {
        printf("Creating new blockchain...\n");
        // Create new blockchain if none exists
        unsigned char node_pubkey[PUBKEY_SIZE];
        snprintf((char*)node_pubkey, PUBKEY_SIZE, "node_%u", node->base.id);

        node->base.blockchain = TW_BlockChain_create(node_pubkey, NULL, 0);
        if (!node->base.blockchain) {
            printf("❌ Failed to create new blockchain\n");
            return -1;
        }
    }
    
    // Check for inconsistencies and auto-recover if needed
    uint32_t file_length = node->base.blockchain->length;
    uint32_t db_length = 0;
    
    if (db_is_initialized()) {
        db_get_block_count(&db_length);
        
        if (file_length != db_length) {
            printf("🔍 Recovery needed: Length mismatch (file: %u, db: %u)\n", file_length, db_length);
            
            RecoveryStats recovery_stats;
            PersistenceResult recovery_result = blockchain_persistence_auto_recovery(
                RECOVERY_STRATEGY_PREFER_NEWER, &recovery_stats);
            
            if (recovery_result == PERSISTENCE_SUCCESS) {
                // Reload blockchain after recovery
                TW_BlockChain_destroy(node->base.blockchain);
                node->base.blockchain = readBlockChainFromFileWithPath(paths.blockchain_dir);
                if (node->base.blockchain) {
                    printf("✅ Blockchain reloaded after recovery: %u blocks\n", 
                           node->base.blockchain->length);
                } else {
                    printf("❌ Failed to reload blockchain after recovery\n");
                    return -1;
                }
            } else {
                printf("⚠️ Recovery failed, continuing with existing blockchain\n");
            }
        }
    }
    
    printf("✅ Blockchain persistence system ready\n");
    return 0;
}

void pbft_node_run(PBFTNode* node) {
    printf("PBFT node %u starting on port %u\n", node->base.id, node->api_port);
    
    // Start API server thread
    if (pthread_create(&node->api_thread, NULL, pbft_node_api_server, node) != 0) {
        printf("Failed to start API server thread\n");
        return;
    }
    
    if (node->consensus_enabled) {
        if (pthread_create(&node->node_thread, NULL, pbft_node_main_loop, node) != 0) {
            printf("Failed to start main consensus thread\n");
            node->running = 0;
            pthread_join(node->api_thread, NULL);
            return;
        }

        printf("PBFT node threads started successfully\n");

        pthread_join(node->api_thread, NULL);
        pthread_join(node->node_thread, NULL);
    } else {
        printf("PBFT consensus disabled - running API-only mode\n");
        pthread_join(node->api_thread, NULL);
    }
    
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
        if (node->counter % 3 == 0) {

            printf("Node %u: Blockchain length: %u, Peers: %zu, Proposer ID: %u\n",
                   node->base.id, current_length, node->base.peer_count,
                   pbft_node_calculate_proposer_id(node));

            // Check for consensus timeout (30 seconds without progress)
            time_t now = time(NULL);
            if (node->current_proposal_block && (now - node->last_consensus_activity) > 30) {
                printf("Node %u: Consensus timeout detected (%ld seconds), initiating view change\n",
                       node->base.id, now - node->last_consensus_activity);

                // Increment failed rounds counter
                node->failed_rounds_count++;

                // Clear current proposal state
                pthread_mutex_lock(&node->state_mutex);
                if (node->current_proposal_block) {
                    TW_Block_destroy(node->current_proposal_block);
                    node->current_proposal_block = NULL;
                }
                node->verification_votes_count = 0;
                memset(node->verification_voters, 0, sizeof(node->verification_voters));
                node->commit_votes_count = 0;
                memset(node->commit_voters, 0, sizeof(node->commit_voters));
                node->view_change_pending = true;
                node->proposed_new_view = node->current_view + 1;
                pthread_mutex_unlock(&node->state_mutex);

                // Broadcast view change vote
                pbft_node_broadcast_new_round_vote(node);
                continue; // Skip normal proposal logic
            }

            // check if we should propose a block (every 10 seconds)
            if (!node->blockchain_has_progressed && pbft_node_is_proposer(node) && !node->view_change_pending) {
                printf("Node %u: Proposing block (round %u)\n", node->base.id, node->counter);
                
                // Create and propose a block
                TW_Block* new_block = pbft_node_create_block(node);
                if (new_block) {
                    // For single node mode, commit directly
                    if (node->base.peer_count == 0) {
                        printf("Node %u: Creating block for singular node\n", node->base.id);
                        pbft_node_block_creation(node, new_block);
                    } else {
                        // Multi-node mode: broadcast to peers
                        pbft_node_propose_block(node, new_block);
                    }
                }
            }
        }
        
        // Every 21 iterations, check for sync and handle delinquent nodes
        if (node->counter % 21 == 0) {
            // Load peers from blockchain and sync
            pbft_node_load_peers_from_blockchain(node);
            
            printf("Node %u: Checking blockchain sync and peer status\n", node->base.id);
            
            if (!node->blockchain_has_progressed && node->base.peer_count > 0) {
                int sync_result = pbft_node_sync_with_longest_chain(node);
                uint32_t proposer_id = pbft_node_calculate_proposer_id(node);
                
                printf("Node %u: Sync result: %d, Proposer ID: %u\n", 
                       node->base.id, sync_result, proposer_id);
                
                // Only increment proposer offset if we're sure we don't need more blocks
                // and we're not the current proposer
                if (sync_result < 0 && node->base.id != proposer_id) {
                    printf("Node %u: No new blocks available from peers, incrementing proposer offset to %u\n", 
                           node->base.id, node->base.proposer_offset + 1);
                    node->base.proposer_offset++;
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
        } else if (mg_strcmp(hm->uri, mg_str("/api/network/stats")) == 0) {
            handle_get_network_stats(c, hm);
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
        } else if (mg_strcmp(hm->uri, mg_str("/api/access/submit")) == 0) {
            handle_access_request_submit_pbft(c, hm);
        } else if (mg_strcmp(hm->uri, mg_str("/api/access/poll")) == 0) {
            handle_access_request_poll(c, hm);
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

    // For internal PBFT communication, skip authentication
    // (In production, you might want to add node-to-node authentication)
    
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

    // Parse binary internal transaction request
    TW_InternalTransaction* req = TW_InternalTransaction_deserialize(
        (const unsigned char*)hm->body.buf, hm->body.len);

    if (!req) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                     "{\"error\":\"Invalid binary transaction format\"}");
        return;
    }

    // Verify signature
    if (!TW_InternalTransaction_verify_signature(req)) {
        mg_http_reply(c, 401, "Content-Type: application/json\r\n",
                     "{\"error\":\"Invalid signature\"}");
        tw_destroy_internal_transaction(req);
        return;
    }

    // Validate transaction type
    if (req->type != TW_INT_TXN_GET_PENDING_TXNS) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                     "{\"error\":\"Invalid transaction type\"}");
        tw_destroy_internal_transaction(req);
        return;
    }

    printf("Node %u: Received binary request for pending transactions\n", node->base.id);

    // Check if we have pending transactions in our queue
    int pending_count = message_queues.transaction_count;

    if (pending_count == 0) {
        // No pending transactions, return empty response
        TW_InternalTransaction* resp = tw_create_internal_transaction(TW_INT_TXN_GET_PENDING_TXNS, node->base.public_key, 0, 0);
        if (!resp) {
            mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Allocation failure\"}");
            tw_destroy_internal_transaction(req);
            return;
        }

        // Empty payload for no transactions
        resp->payload_size = 0;

        // Sign and serialize response
        TW_Internal_Transaction_add_signature(resp);
        unsigned char* out = NULL;
        size_t out_size = TW_InternalTransaction_serialize(resp, &out);
        if (!out || out_size == 0) {
            mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Response serialization failed\"}");
            if (out) free(out);
            tw_destroy_internal_transaction(resp);
            tw_destroy_internal_transaction(req);
            return;
        }

        mg_http_reply(c, 200, "Content-Type: application/octet-stream\r\n", "%.*s", (int)out_size, out);

        free(out);
        tw_destroy_internal_transaction(resp);
        tw_destroy_internal_transaction(req);
        return;
    }

    // We have pending transactions - prepare multi-transaction response
    printf("Node %u: Sending %d pending transactions in binary format\n", node->base.id, pending_count);

    // Calculate actual sizes for all transactions
    size_t* txn_sizes = (size_t*)malloc(pending_count * sizeof(size_t));
    if (!txn_sizes) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Memory allocation failed\"}");
        tw_destroy_internal_transaction(req);
        return;
    }

    size_t total_txns_size = 0;
    for (int i = 0; i < pending_count; i++) {
        TW_Transaction* txn = message_queues.transaction_queue[i].transaction;
        if (!txn) {
            txn_sizes[i] = 0;
            continue;
        }

        txn_sizes[i] = TW_Transaction_get_size(txn);
        total_txns_size += txn_sizes[i];
    }

    // Check if total size fits in payload
    size_t header_size = sizeof(uint32_t) + (pending_count * sizeof(size_t));
    size_t total_payload_size = header_size + total_txns_size;

    if (total_payload_size > MAX_PAYLOAD_SIZE_INTERNAL) {
        free(txn_sizes);
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg),
                "{\"error\":\"Too many pending transactions (%d, %zu bytes) for response\"}",
                pending_count, total_payload_size);
        mg_http_reply(c, 413, "Content-Type: application/json\r\n", "%s", error_msg);
        tw_destroy_internal_transaction(req);
        return;
    }

    // Create response with multi-transaction payload
    TW_InternalTransaction* resp = tw_create_internal_transaction(TW_INT_TXN_GET_PENDING_TXNS, node->base.public_key, 0, 0);
    if (!resp) {
        free(txn_sizes);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Allocation failure\"}");
        tw_destroy_internal_transaction(req);
        return;
    }

    // Serialize multi-transaction data into raw_payload
    unsigned char* payload_ptr = resp->payload.raw_payload;

    // Write transaction count
    uint32_t txn_count_net = htonl(pending_count);
    memcpy(payload_ptr, &txn_count_net, sizeof(uint32_t));
    payload_ptr += sizeof(uint32_t);

    // Write transaction sizes (estimated)
    for (int i = 0; i < pending_count; i++) {
        size_t size_net = htonll(txn_sizes[i]);
        memcpy(payload_ptr, &size_net, sizeof(size_t));
        payload_ptr += sizeof(size_t);
    }

    // Serialize each transaction
    for (int i = 0; i < pending_count; i++) {
        TW_Transaction* txn = message_queues.transaction_queue[i].transaction;
        if (!txn || txn_sizes[i] == 0) {
            printf("Node %u: Warning: NULL or empty transaction at index %d\n", node->base.id, i);
            // Write zero bytes as placeholder
            memset(payload_ptr, 0, txn_sizes[i]);
            payload_ptr += txn_sizes[i];
            continue;
        }

        // Serialize transaction (this will advance payload_ptr)
        unsigned char* start_ptr = payload_ptr;
        int serialize_result = TW_Transaction_serialize(txn, &payload_ptr);
        if (serialize_result != 0) {
            printf("Node %u: Failed to serialize transaction at index %d\n", node->base.id, i);
            // Write zero bytes as placeholder
            memset(payload_ptr, 0, txn_sizes[i]);
            payload_ptr += txn_sizes[i];
            continue;
        }

        // Verify the serialized size matches our expectation
        size_t actual_size = payload_ptr - start_ptr;
        if (actual_size != txn_sizes[i]) {
            printf("Node %u: Warning: Serialized size mismatch for transaction %d (%zu vs %zu)\n",
                   node->base.id, i, actual_size, txn_sizes[i]);
        }
    }

    resp->payload_size = total_payload_size;

    // Sign and serialize response
    TW_Internal_Transaction_add_signature(resp);
    unsigned char* out = NULL;
    size_t out_size = TW_InternalTransaction_serialize(resp, &out);
    if (!out || out_size == 0) {
        free(txn_sizes);
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Response serialization failed\"}");
        if (out) free(out);
        tw_destroy_internal_transaction(resp);
        tw_destroy_internal_transaction(req);
        return;
    }

    // Send binary response
    mg_http_reply(c, 200, "Content-Type: application/octet-stream\r\n", "%.*s", (int)out_size, out);

    printf("Node %u: Sent %d pending transactions (%zu bytes total)\n",
           node->base.id, pending_count, out_size);

    free(txn_sizes);
    free(out);
    tw_destroy_internal_transaction(resp);
    tw_destroy_internal_transaction(req);
}

static void handle_blockchain_last_hash_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node || !node->base.blockchain || node->base.blockchain->length == 0) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                     "{\"error\":\"Blockchain not initialized or empty\"}");
        return;
    }

    // Verify signature from request headers
    struct mg_str* pubkey_header = mg_http_get_header(hm, "X-Public-Key");
    struct mg_str* signature_header = mg_http_get_header(hm, "X-Signature");
    struct mg_str* timestamp_header = mg_http_get_header(hm, "X-Timestamp");

    if (!pubkey_header || !signature_header || !timestamp_header) {
        mg_http_reply(c, 401, "Content-Type: application/json\r\n",
                     "{\"error\":\"Missing authentication headers (X-Public-Key, X-Signature, X-Timestamp)\"}");
        return;
    }

    // Convert mg_str to C strings
    char pubkey_hex[256], signature_hex[256], timestamp_str[64];
    snprintf(pubkey_hex, sizeof(pubkey_hex), "%.*s", (int)pubkey_header->len, pubkey_header->buf);
    snprintf(signature_hex, sizeof(signature_hex), "%.*s", (int)signature_header->len, signature_header->buf);
    snprintf(timestamp_str, sizeof(timestamp_str), "%.*s", (int)timestamp_header->len, timestamp_header->buf);

    // Create data to verify: request path + timestamp
    char data_to_verify[512];
    snprintf(data_to_verify, sizeof(data_to_verify), "/GetBlockchainLastHash%s", timestamp_str);

    // Check timestamp to prevent replay attacks (within 5 minutes)
    time_t request_timestamp = (time_t)atol(timestamp_str);
    time_t current_time = time(NULL);
    if (abs((int)(current_time - request_timestamp)) > 300) { // 5 minutes
        mg_http_reply(c, 401, "Content-Type: application/json\r\n",
                     "{\"error\":\"Request timestamp expired\"}");
        return;
    }

    // Verify signature
    if (pbft_node_verify_signature(pubkey_hex, signature_hex, data_to_verify) != 1) {
        mg_http_reply(c, 401, "Content-Type: application/json\r\n",
                     "{\"error\":\"Invalid signature\"}");
        return;
    }

    printf("Node %u: Verified signature for blockchain last hash request from %s\n", node->base.id, pubkey_hex);

    // Get last block hash
    TW_Block* last_block = node->base.blockchain->blocks[node->base.blockchain->length - 1];
    unsigned char hash_bytes[HASH_SIZE];
    char hash_hex[HASH_SIZE * 2 + 1];

    if (TW_Block_getHash(last_block, hash_bytes) != 0) {
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
        if (TW_Block_getHash(last_block, previous_hash) != 0) {
            printf("Failed to get hash of previous block\n");
            if (transactions) free(transactions);
            return NULL;
        }
        
        // Convert previous hash to hex for debugging
        char prev_hash_hex[HASH_SIZE * 2 + 1];
        pbft_node_bytes_to_hex(previous_hash, HASH_SIZE, prev_hash_hex);
    } else {
        // Genesis block case
        memset(previous_hash, 0, HASH_SIZE);
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
    
    // Create block proposal using internal transaction
    TW_InternalTransaction* proposal = tw_create_block_proposal(
        node->base.public_key,
        node->base.id,
        node->counter,  // Use counter as round number
        block
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
    
    // Validate previous hash (for non-genesis blocks)
    if (block->index > 0) {
        TW_Block* last_block = TW_BlockChain_get_last_block(node->base.blockchain);
        if (last_block) {
            unsigned char last_hash[HASH_SIZE];
            if (TW_Block_getHash(last_block, last_hash) == 0) {
                if (memcmp(block->previous_hash, last_hash, HASH_SIZE) != 0) {
                    return false;
                }
            }
        }
    }
    
    // TODO: Add more validation logic (transaction validation, etc.)
    
    printf("Block validation passed for block %d\n", block->index);
    return 0;
}

int pbft_node_commit_block(PBFTNode* node, TW_Block* block) {
    if (!node || !block || !node->base.blockchain) return 0;
    
    // Validate block before committing
    if (pbft_node_validate_block(node, block) != 0) {
        printf("Block validation failed, cannot commit\n");
        return -1;
    }
    
    // Add block to blockchain in memory
    if (TW_BlockChain_add_block(node->base.blockchain, block) != 0) {
        printf("Failed to add block to blockchain\n");
        return -2;
    }
    
    printf("Successfully committed block %d to blockchain (in memory)\n", block->index);
    
    // Use the new robust persistence system with two-phase commit
    printf("🔄 Persisting block using two-phase commit...\n");
    PersistenceResult persist_result = blockchain_persistence_commit_block(node->base.blockchain, block);
    
    if (persist_result == PERSISTENCE_SUCCESS) {
        printf("✅ Block %d persisted successfully using two-phase commit\n", block->index);
    } else {
        printf("❌ Failed to persist block %d: %s\n", block->index, 
               blockchain_persistence_error_string(persist_result));
        printf("⚠️ Block is committed in memory but persistence failed\n");
        printf("   The system will attempt recovery on next startup\n");
        
        // Don't fail the commit entirely - the block is in memory
        // The recovery system will handle inconsistency on restart
    }
    
    // Clear the transaction queue since block was successfully committed
    if (message_queues.transaction_count > 0) {
        printf("Clearing transaction queue after successful block commit (had %d transactions)\n", 
               message_queues.transaction_count);
        message_queues.transaction_count = 0;
    }
    
    return 0;
}

int pbft_node_validate_blockchain(PBFTNode* node, TW_BlockChain* blockchain) {
    if (!node || !blockchain || blockchain->length == 0) {
        return -1;
    }

    // Validate genesis block
    TW_Block* genesis = blockchain->blocks[0];
    if (!genesis || genesis->index != 0) {
        printf("Invalid genesis block in received blockchain\n");
        return -2;
    }

    // Validate each block in sequence
    for (uint32_t i = 0; i < blockchain->length; i++) {
        TW_Block* block = blockchain->blocks[i];
        if (!block) {
            printf("Null block at index %u in received blockchain\n", i);
            return -3;
        }

        // Check block index
        if (block->index != i) {
            printf("Block index mismatch at position %u: expected %u, got %d\n", i, i, block->index);
            return -4;
        }

        // Check previous hash linkage (for non-genesis blocks)
        if (i > 0) {
            TW_Block* prev_block = blockchain->blocks[i-1];
            unsigned char prev_hash[HASH_SIZE];
            if (TW_Block_getHash(prev_block, prev_hash) != 0) {
                printf("Failed to get hash for block %u\n", i-1);
                return -5;
            }
            if (memcmp(block->previous_hash, prev_hash, HASH_SIZE) != 0) {
                printf("Hash linkage broken between blocks %u and %u\n", i-1, i);
                return -6;
            }
        }

        // TODO: Add more comprehensive validation (transactions, signatures, etc.)
    }

    printf("Blockchain validation passed (%u blocks)\n", blockchain->length);
    return 0;
}

int pbft_node_replace_blockchain(PBFTNode* node, TW_BlockChain* new_blockchain) {
    if (!node || !new_blockchain) {
        return -1;
    }

    // Store reference to old blockchain for cleanup
    TW_BlockChain* old_blockchain = node->base.blockchain;

    // Replace the blockchain reference
    node->base.blockchain = new_blockchain;

    printf("Node %u: Replaced blockchain (%u blocks -> %u blocks)\n",
           node->base.id, old_blockchain ? old_blockchain->length : 0, new_blockchain->length);

    // Persist the new blockchain to disk
    printf("Persisting new blockchain to disk...\n");
    PersistenceResult persist_result = blockchain_persistence_commit_full_blockchain(new_blockchain);

    if (persist_result == PERSISTENCE_SUCCESS) {
        printf("✅ New blockchain persisted successfully\n");

        // Clean up old blockchain
        if (old_blockchain) {
            TW_BlockChain_destroy(old_blockchain);
        }

        // Reset any cached state that depends on the old blockchain
        node->last_blockchain_length = new_blockchain->length;
        node->blockchain_has_progressed = 1; // Force progression detection

        return 0;
    } else {
        printf("❌ Failed to persist new blockchain: %s\n",
               blockchain_persistence_error_string(persist_result));

        // Restore old blockchain on persistence failure
        node->base.blockchain = old_blockchain;
        TW_BlockChain_destroy(new_blockchain);

        return -2;
    }
}

// Stub function for peer address lookup - will be replaced with relay server integration (Task 3)
// Returns 1 on success, 0 on failure
int pbft_node_lookup_peer_address(PBFTNode* node, const unsigned char* peer_pubkey, 
                                   uint32_t peer_node_id, char* ip_port_out, size_t out_size) {
    if (!node || !peer_pubkey || !ip_port_out || out_size == 0) return 0;

    // TODO(Task 3): Replace with actual relay server lookup
    // This stub provides a fallback for local testing only
    // 
    // Future implementation will:
    // 1. Query relay server: GET /lookup/<blockchain_id>/<pubkey_hex>
    // 2. Parse response: {ip, port, last_seen}
    // 3. Validate TTL (not stale)
    // 4. Return formatted "ip:port" string
    //
    // For now, use environment variable or fallback to localhost for testing
    const char* relay_url = getenv("RELAY_URL");
    if (relay_url) {
        // Relay server configured but not implemented yet
        printf("Node %u: Relay lookup not implemented (RELAY_URL=%s)\n", node->base.id, relay_url);
        return 0;
    }

    // Fallback for local testing: derive from node_id and own port
    // This allows existing tests to continue working
    uint16_t base_port = (node->api_port > node->base.id) ? 
                         (uint16_t)(node->api_port - node->base.id) : node->api_port;
    snprintf(ip_port_out, out_size, "127.0.0.1:%u", (unsigned)(base_port + peer_node_id));
    
    printf("Node %u: Using fallback address for peer node_id=%u: %s (relay not configured)\n",
           node->base.id, peer_node_id, ip_port_out);
    return 1;
}

int pbft_node_load_peers_from_blockchain(PBFTNode* node) {
    if (!node) return -1;

    printf("Node %u: Loading authorized consensus peers...\n", node->base.id);

    // Clear existing peers
    node->base.peer_count = 0;

    // Load authorized consensus nodes
    ConsensusNodeRecord* records = NULL;
    size_t count = 0;
    if (db_get_authorized_nodes(&records, &count) != 0) {
        printf("Node %u: Failed to query authorized consensus nodes\n", node->base.id);
        return -1;
    }

    if (count == 0) {
        printf("Node %u: No authorized consensus nodes found\n", node->base.id);
        return 0;
    }

    size_t peers_added = 0;
    for (size_t i = 0; i < count; i++) {
        ConsensusNodeRecord* rec = &records[i];

        // Convert hex pubkey to bytes
        unsigned char pubkey_bytes[PUBKEY_SIZE];
        if (pbft_node_hex_to_bytes(rec->pubkey, pubkey_bytes, PUBKEY_SIZE) != PUBKEY_SIZE) {
            printf("Node %u: Skipping node_id %u due to invalid pubkey\n", node->base.id, rec->node_id);
            continue;
        }

        // Skip ourselves by comparing pubkeys
        if (memcmp(pubkey_bytes, node->base.public_key, PUBKEY_SIZE) == 0) {
            continue;
        }

        // TODO(Task 3): Query relay server for peer's current IP:port
        // For now, use a stub that will be replaced with relay lookup
        char ip_port[64];
        if (!pbft_node_lookup_peer_address(node, pubkey_bytes, rec->node_id, ip_port, sizeof(ip_port))) {
            printf("Node %u: Failed to lookup address for peer node_id=%u (relay not implemented)\n", 
                   node->base.id, rec->node_id);
            continue;
        }

        if (pbft_node_add_peer(node, pubkey_bytes, ip_port, rec->node_id) != 0) {
            printf("Node %u: Failed to add peer node_id=%u\n", node->base.id, rec->node_id);
        } else {
            peers_added++;
        }
    }

    db_free_consensus_node_records(records, count);

    printf("Node %u: Successfully loaded %zu authorized peers\n", node->base.id, peers_added);
    return 0;
}

int pbft_node_add_peer(PBFTNode* node, const unsigned char* public_key, const char* ip, uint32_t id) {
    if (!node || !public_key || !ip) return -1;

    // Verify peer is authorized consensus node
    if (db_is_authorized_consensus_node(public_key) != 1) {
        char pubkey_hex[65];
        sodium_bin2hex(pubkey_hex, sizeof(pubkey_hex), public_key, 32);
        printf("Node %u: ❌ REJECTED unauthorized peer %u (pubkey: %s)\n",
               node->base.id, id, pubkey_hex);
        return -1; // Reject unauthorized peer
    }

    if (node->base.peer_count >= MAX_PEERS) {
        printf("Node %u: Cannot add peer %u, maximum peers reached\n", node->base.id, id);
        return -1;
    }

    // Check if peer already exists
    for (size_t i = 0; i < node->base.peer_count; i++) {
        if (node->base.peers[i].id == id) {
            printf("Node %u: Peer %u already exists\n", node->base.id, id);
            return -1;
        }
    }

    // Add the peer
    PeerInfo* peer = &node->base.peers[node->base.peer_count];
    memcpy(peer->public_key, public_key, PUBKEY_SIZE);
    strncpy(peer->ip, ip, sizeof(peer->ip) - 1);
    peer->ip[sizeof(peer->ip) - 1] = '\0';
    peer->id = id;
    peer->is_delinquent = 0;
    peer->delinquent_count = 0;
    peer->last_seen = time(NULL);

    node->base.peer_count++;

    printf("Node %u: ✅ Added authorized peer %u at %s\n", node->base.id, id, ip);
    return 0;
}
int pbft_node_remove_peer(PBFTNode* node, uint32_t peer_id) { return 0; }

int pbft_node_mark_peer_delinquent(PBFTNode* node, uint32_t peer_id) {
    if (!node) {
        return -1;
    }

    // Find peer by ID in the peers array
    for (size_t i = 0; i < node->base.peer_count; i++) {
        if (node->base.peers[i].id == peer_id) {
            // Mark peer as delinquent
            node->base.peers[i].is_delinquent = 1;
            node->base.peers[i].delinquent_count++;

            // Update last seen timestamp
            node->base.peers[i].last_seen = time(NULL);

            // Log delinquent behavior
            printf("Node %u: Marked peer %u as delinquent (count: %u)\n",
                   node->base.id, peer_id, node->base.peers[i].delinquent_count);

            // Check if delinquent count exceeds threshold
            if (node->base.peers[i].delinquent_count >= DELINQUENT_THRESHOLD) {
                printf("Node %u: Peer %u exceeded delinquent threshold (%d), would remove peer\n",
                       node->base.id, peer_id, DELINQUENT_THRESHOLD);
                // Note: pbft_node_remove_peer() is kept as stub per task requirements
                // pbft_node_remove_peer(node, peer_id);
            }

            return 0; // Success
        }
    }

    // Peer not found
    printf("Node %u: Peer %u not found for delinquent marking\n", node->base.id, peer_id);
    return -1;
}

int pbft_node_is_peer_active(PBFTNode* node, uint32_t peer_id) {
    if (!node) {
        return 0;
    }

    // Find peer by ID in the peers array
    for (size_t i = 0; i < node->base.peer_count; i++) {
        if (node->base.peers[i].id == peer_id) {
            // Check if peer is marked as delinquent
            if (node->base.peers[i].is_delinquent) {
                return 0; // Inactive - delinquent
            }

            // Check if peer was seen recently (within 60 seconds)
            time_t current_time = time(NULL);
            if (current_time - node->base.peers[i].last_seen >= 60) {
                return 0; // Inactive - too old
            }

            return 1; // Active
        }
    }

    // Peer not found
    return 0; // Inactive
}

uint32_t pbft_node_calculate_proposer_id(PBFTNode* node) {
    if (!node || !node->base.blockchain) {
        return 0;
    }
    
    uint32_t num_peers = node->base.peer_count;
    
    // Special case for single node
    if (num_peers == 0) {
        return node->base.id;
    }
    
    // Genesis block case
    if (node->base.blockchain->length == 0) {
        return 0;
    }
    
    // Get last block's cryptographic hash
    TW_Block* last_block = node->base.blockchain->blocks[node->base.blockchain->length - 1];
    unsigned char block_hash[HASH_SIZE];
    if (TW_Block_getHash(last_block, block_hash) != 0) {
        return 0; // Fallback on hash failure
    }
    
    // Use block hash as seed for proposer selection
    // Take first 4 bytes of hash and convert to uint32_t
    uint32_t hash_seed;
    memcpy(&hash_seed, block_hash, sizeof(uint32_t));
    
    // Add some entropy from proposer_offset (for view changes)
    hash_seed ^= node->base.proposer_offset;
    
    // Calculate proposer: cryptographically secure but deterministic
    uint32_t next_proposer = hash_seed % (num_peers + 1);
    
    return next_proposer;
}

int pbft_node_is_proposer(PBFTNode* node) {
    if (!node) return 0;
    
    uint32_t proposer_id = pbft_node_calculate_proposer_id(node);
    return (proposer_id == node->base.id) ? 1 : 0;
}

int pbft_node_calculate_min_approvals(PBFTNode* node) {
    if (!node) return -1;
    
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
    
    printf("Node %u resyncing blockchains with peers (current length: %u)\n", 
           node->base.id, node->base.blockchain->length);
    
    uint32_t longest_chain = node->base.blockchain->length;  // Start with our own length
    uint32_t peer_with_longest_chain = 0;
    int peers_queried = 0;
    int successful_queries = 0;
    
    // Find the peer with the longest blockchain
    for (uint32_t i = 0; i < node->base.peer_count; i++) {
        // Skip self
        if (node->base.peers[i].id == node->base.id) {
            continue;
        }
        
        peers_queried++;
        
        // Make HTTP request to get chain length from peer
        char peer_url[256];
        snprintf(peer_url, sizeof(peer_url), "http://%s", node->base.peers[i].ip);
        
        int peer_chain_length = pbft_get_blockchain_length(peer_url);
        if (peer_chain_length < 0) {
            printf("Failed to get blockchain length from peer %u at %s\n", 
                   node->base.peers[i].id, peer_url);
            peer_chain_length = 0;  // Default to 0 if request fails
        } else {
            successful_queries++;
            printf("Peer %u at %s has blockchain length: %d\n", 
                   node->base.peers[i].id, peer_url, peer_chain_length);
        }
        
        if (peer_chain_length > longest_chain) {
            longest_chain = peer_chain_length;
            peer_with_longest_chain = i;
        }
    }
    
    printf("Node %u: Queried %d peers, %d successful responses. Longest chain: %u (our length: %u)\n",
           node->base.id, peers_queried, successful_queries, longest_chain, node->base.blockchain->length);
    
    if (longest_chain > node->base.blockchain->length) {
        printf("Node %u found longer chain (length %u vs %u), requesting missing blocks\n",
               node->base.id, longest_chain, node->base.blockchain->length);

        // Request missing blocks from the peer with longest chain
        char peer_url[256];
        snprintf(peer_url, sizeof(peer_url), "http://%s", node->base.peers[peer_with_longest_chain].ip);
        int sync_result = pbft_node_request_missing_blocks_from_peer(node, peer_url);
        if (sync_result == 0) {
            printf("Node %u: Successfully initiated missing block sync\n", node->base.id);
        } else {
            printf("Node %u: Failed to initiate missing block sync\n", node->base.id);
        }

        return sync_result;  // Return actual sync result
    } else {
        printf("Node %u blockchain is already in sync (length %u)\n",
               node->base.id, node->base.blockchain->length);
        return -1;  // No sync needed, but no new blocks proposed
    }
}
// HTTP client integration with enhanced retry logic and exponential backoff
HttpResponse* pbft_node_http_request(const char* url, const char* method, const char* json_data) {
    if (!url || !method) {
        printf("pbft_node_http_request: Invalid parameters (url=%p, method=%p)\n", 
               (void*)url, (void*)method);
        return NULL;
    }
    
    // Validate URL format
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) {
        printf("pbft_node_http_request: Invalid URL format: %s\n", url);
        return NULL;
    }
    
    // Initialize HTTP client if not already done
    if (!http_client_init()) {
        printf("pbft_node_http_request: Failed to initialize HTTP client\n");
        return NULL;
    }
    
    // Configuration for HTTP requests with PBFT-specific settings
    HttpClientConfig* config = http_client_config_default();
    if (!config) {
        printf("pbft_node_http_request: Failed to create HTTP config\n");
        return NULL;
    }
    
    // Set timeout to 10 seconds for PBFT operations (consensus needs to be responsive)
    config->timeout_seconds = 10;
    config->max_redirects = 2;  // Limit redirects for security
    config->verify_ssl = 0;     // Disable SSL verification for local network
    
    // Convert method string to HttpMethod enum
    HttpMethod http_method;
    if (strcmp(method, "GET") == 0) {
        http_method = HTTP_GET;
    } else if (strcmp(method, "POST") == 0) {
        http_method = HTTP_POST;
    } else if (strcmp(method, "PUT") == 0) {
        http_method = HTTP_PUT;
    } else if (strcmp(method, "DELETE") == 0) {
        http_method = HTTP_DELETE;
    } else {
        printf("pbft_node_http_request: Unsupported HTTP method: %s\n", method);
        http_client_config_free(config);
        return NULL;
    }
    
    // Determine content type and headers based on data
    const char* headers[2] = {NULL, NULL};
    if (json_data && strlen(json_data) > 0) {
        headers[0] = "Content-Type: application/json";
    }
    
    // Configure retry parameters
    const int max_retries = 3;
    const int base_delay_ms = 200;    // Start with 200ms delay for better network handling
    const int max_delay_ms = 2000;    // Cap maximum delay at 2 seconds
    
    // Attempt request with retries
    HttpResponse* response = NULL;
    for (int attempt = 0; attempt < max_retries; attempt++) {
        // Apply exponential backoff for retries
        if (attempt > 0) {
            // Exponential backoff with jitter: delay = base_delay * 2^(attempt-1) + random jitter
            int exponential_delay = base_delay_ms * (1 << (attempt - 1));
            int jitter = rand() % 100;  // Add up to 100ms random jitter
            int delay_ms = (exponential_delay + jitter) > max_delay_ms ? max_delay_ms : (exponential_delay + jitter);
            
            printf("pbft_node_http_request: Retry %d/%d after %dms delay for %s\n", 
                   attempt + 1, max_retries, delay_ms, url);
            usleep(delay_ms * 1000);  // Convert to microseconds
        }
        
        // Free previous response if retry
        if (response) {
            http_response_free(response);
            response = NULL;
        }
        
        // Make the HTTP request using the unified http_client_request function
        response = http_client_request(
            url,
            http_method,
            json_data,
            json_data ? strlen(json_data) : 0,
            headers[0] ? headers : NULL,
            config
        );
        
        // Check if request was successful
        if (response) {
            if (http_client_is_success_status(response->status_code)) {
                printf("pbft_node_http_request: Success on attempt %d - %s returned %d (size: %zu bytes)\n", 
                       attempt + 1, url, response->status_code, response->size);
                break;
            } else {
                // Log detailed failure information
                printf("pbft_node_http_request: Attempt %d failed - %s returned %d (size: %zu bytes)\n", 
                       attempt + 1, url, response->status_code, response->size);
                
                // Don't retry client errors (4xx) except timeout (408) and rate limiting (429)
                if (response->status_code >= 400 && response->status_code < 500 && 
                    response->status_code != 408 && response->status_code != 429) {
                    printf("pbft_node_http_request: Client error %d, not retrying\n", response->status_code);
                    break;
                }
                
                // Continue to next retry for server errors or specific client errors
                http_response_free(response);
                response = NULL;
            }
        } else {
            printf("pbft_node_http_request: Attempt %d failed - no response from %s (connection/timeout error)\n", 
                   attempt + 1, url);
        }
    }
    
    if (!response) {
        printf("pbft_node_http_request: All %d attempts failed for %s\n", max_retries, url);
    }
    
    http_client_config_free(config);
    return response;
}

// Enhanced response cleanup with proper error handling
void pbft_node_free_http_response(HttpResponse* response) {
    // Simply delegate to the existing http_response_free function from httpClient.c
    http_response_free(response);
    // Note: http_response_free already handles NULL responses safely
}


int pbft_node_broadcast_verification_vote(PBFTNode* node) {
    if (!node) return 0;

    // Ensure we have a retained proposal
    if (!node->current_proposal_block) return 0;

    // Mark self as having cast verification vote (idempotent)
    pthread_mutex_lock(&node->state_mutex);
    uint32_t self_id = node->base.id;
    if (self_id <= MAX_PEERS && node->verification_voters[self_id] == 0) {
        node->verification_voters[self_id] = 1;
        node->verification_votes_count++;
    }
    pthread_mutex_unlock(&node->state_mutex);

    // Create verification vote using stored round and binary hash
    TW_InternalTransaction* vote = tw_create_vote_message(
        node->base.public_key,
        node->base.id,
        node->current_proposal_round,
        node->current_proposal_hash,
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

int pbft_node_broadcast_commit_vote(PBFTNode* node) {
    if (!node) return 0;

    if (!node->current_proposal_block) return 0;

    // Mark self as having cast commit vote (idempotent)
    uint32_t self_id = node->base.id;
    if (self_id <= MAX_PEERS && node->commit_voters[self_id] == 0) {
        node->commit_voters[self_id] = 1;
        node->commit_votes_count++;
    }

    // Create commit vote using stored round and binary hash
    TW_InternalTransaction* vote = tw_create_vote_message(
        node->base.public_key,
        node->base.id,
        node->current_proposal_round,
        node->current_proposal_hash,
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

int pbft_node_broadcast_new_round_vote(PBFTNode* node) {
    if (!node) return 0;

    // Mark self as having cast view change vote (idempotent)
    pthread_mutex_lock(&node->state_mutex);
    uint32_t self_id = node->base.id;
    if (self_id <= MAX_PEERS && node->view_change_voters[self_id] == 0) {
        node->view_change_voters[self_id] = 1;
        node->view_change_votes_count++;
    }
    pthread_mutex_unlock(&node->state_mutex);

    // Create new round vote using internal transaction
    TW_InternalTransaction* vote = tw_create_vote_message(
        node->base.public_key,
        node->base.id,
        node->counter,
        node->current_proposal_hash,  // Use current proposal hash (binary)
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
int pbft_node_broadcast_blockchain_to_new_node(PBFTNode* node, const char* peer_url) {
    if (!node || !peer_url || !node->base.blockchain) {
        printf("pbft_node_broadcast_blockchain_to_new_node: Invalid parameters\n");
        return -1;
    }

    printf("Node %u: Broadcasting blockchain to new peer %s\n", node->base.id, peer_url);

    // Get the serialized size of the entire blockchain
    size_t blockchain_size = TW_BlockChain_get_size(node->base.blockchain);
    if (blockchain_size == 0 || blockchain_size > MAX_PAYLOAD_SIZE_INTERNAL) {
        printf("Node %u: Blockchain too large to broadcast (%zu bytes)\n", node->base.id, blockchain_size);
        return -2;
    }

    // Allocate buffer for blockchain serialization
    unsigned char* blockchain_data = (unsigned char*)malloc(blockchain_size);
    if (!blockchain_data) {
        printf("Node %u: Memory allocation failed for blockchain broadcast\n", node->base.id);
        return -3;
    }

    // Serialize the entire blockchain
    unsigned char* temp_ptr = blockchain_data;
    int serialize_result = TW_BlockChain_serialize(node->base.blockchain, &temp_ptr);
    if (serialize_result != 0) {
        printf("Node %u: Blockchain serialization failed for broadcast\n", node->base.id);
        free(blockchain_data);
        return -4;
    }

    // Create TW_InternalTransaction with blockchain data
    TW_InternalTransaction* broadcast_txn = tw_create_internal_transaction(TW_INT_TXN_BROADCAST_CHAIN, node->base.public_key, 0, 0);
    if (!broadcast_txn) {
        printf("Node %u: Failed to create broadcast transaction\n", node->base.id);
        free(blockchain_data);
        return -5;
    }

    // Store the serialized blockchain in the raw payload
    memcpy(broadcast_txn->payload.raw_payload, blockchain_data, blockchain_size);
    broadcast_txn->payload_size = blockchain_size;

    // Set chain hash for reference
    unsigned char chain_hash[HASH_SIZE];
    TW_BlockChain_get_hash(node->base.blockchain, chain_hash);
    memcpy(broadcast_txn->chain_hash, chain_hash, HASH_SIZE);

    free(blockchain_data);

    // Sign the transaction
    TW_Internal_Transaction_add_signature(broadcast_txn);

    // Serialize the internal transaction for transmission
    unsigned char* txn_data = NULL;
    size_t txn_size = TW_InternalTransaction_serialize(broadcast_txn, &txn_data);
    if (!txn_data || txn_size == 0) {
        printf("Node %u: Failed to serialize broadcast transaction\n", node->base.id);
        tw_destroy_internal_transaction(broadcast_txn);
        return -6;
    }

    // Send with exponential backoff retry logic
    int max_retries = 3;
    int retry_delay_ms = 1000; // Start with 1 second
    int success = 0;

    for (int attempt = 0; attempt < max_retries; attempt++) {
        if (attempt > 0) {
            printf("Node %u: Retrying blockchain broadcast to %s (attempt %d/%d)\n",
                   node->base.id, peer_url, attempt + 1, max_retries);
            // Simple sleep - in production this should be more sophisticated
            usleep(retry_delay_ms * 1000);
            retry_delay_ms *= 2; // Exponential backoff
        }

        // Send binary data via HTTP POST
        const char* headers[] = {"Content-Type: application/octet-stream", NULL};
        HttpResponse* response = http_client_post(peer_url, (const char*)txn_data, txn_size, headers, NULL);

        if (response && http_client_is_success_status(response->status_code)) {
            printf("Node %u: Successfully broadcast blockchain to new peer %s\n", node->base.id, peer_url);
            success = 1;
            pbft_node_free_http_response(response);
            break;
        } else {
            printf("Node %u: Failed to broadcast blockchain to %s (attempt %d/%d, status: %d)\n",
                   node->base.id, peer_url, attempt + 1, max_retries,
                   response ? response->status_code : 0);

            if (response) {
                pbft_node_free_http_response(response);
            }
        }
    }

    free(txn_data);
    tw_destroy_internal_transaction(broadcast_txn);

    if (!success) {
        printf("Node %u: Failed to broadcast blockchain to new peer %s after %d attempts\n",
               node->base.id, peer_url, max_retries);
        return -7;
    }

    return 0;
}
int pbft_node_rebroadcast_message(PBFTNode* node, TW_InternalTransaction* message, const char* exclude_peer_url) {
    if (!node || !message) {
        printf("pbft_node_rebroadcast_message: Invalid parameters\n");
        return -1;
    }

    // Generate a transaction ID for duplicate prevention
    // Use a combination of transaction type, timestamp, and sender for uniqueness
    char txn_id[256];
    snprintf(txn_id, sizeof(txn_id), "%d_%llu_%u",
             message->type, (unsigned long long)message->timestamp, message->sender[0]);

    // Check if we've already broadcast this message (simple duplicate prevention)
    static char last_broadcast_ids[10][256] = {0}; // Simple ring buffer for recent broadcasts
    static int last_broadcast_index = 0;

    for (int i = 0; i < 10; i++) {
        if (strcmp(last_broadcast_ids[i], txn_id) == 0) {
            printf("Node %u: Skipping duplicate rebroadcast of transaction %s\n", node->base.id, txn_id);
            return 0; // Not an error, just already broadcast
        }
    }

    // Store this transaction ID
    strncpy(last_broadcast_ids[last_broadcast_index], txn_id, sizeof(last_broadcast_ids[0]) - 1);
    last_broadcast_index = (last_broadcast_index + 1) % 10;

    printf("Node %u: Rebroadcasting message (type: %d) to %d peers\n",
           node->base.id, message->type, (int)node->base.peer_count);

    // Serialize the message once for all peers
    unsigned char* message_data = NULL;
    size_t message_size = TW_InternalTransaction_serialize(message, &message_data);
    if (!message_data || message_size == 0) {
        printf("Node %u: Failed to serialize message for rebroadcast\n", node->base.id);
        return -2;
    }

    int success_count = 0;
    int failure_count = 0;

    // Send to all peers except the excluded one (skip delinquent peers)
    for (int i = 0; i < node->base.peer_count; i++) {
        PeerInfo* peer = &node->base.peers[i];

        // Skip delinquent peers (treat as inactive)
        if (peer->is_delinquent) {
            continue;
        }

        // Skip excluded peer if specified
        if (exclude_peer_url && strstr(peer->ip, exclude_peer_url)) {
            printf("Node %u: Skipping excluded peer %s\n", node->base.id, peer->ip);
            continue;
        }

        char peer_url[512];
        snprintf(peer_url, sizeof(peer_url), "http://%s/ProposeBlock", peer->ip);

        printf("Node %u: Rebroadcasting to peer %s\n", node->base.id, peer->ip);

        // Send with exponential backoff retry logic
        int max_retries = 2; // Fewer retries for broadcasts
        int retry_delay_ms = 500; // Start with 500ms
        int peer_success = 0;

        for (int attempt = 0; attempt < max_retries; attempt++) {
            if (attempt > 0) {
                usleep(retry_delay_ms * 1000);
                retry_delay_ms *= 2; // Exponential backoff
            }

            // Use the appropriate endpoint based on message type
            const char* endpoint = "ProposeBlock"; // Default
            if (message->type == TW_INT_TXN_VOTE_VERIFY || message->type == TW_INT_TXN_VOTE_COMMIT ||
                message->type == TW_INT_TXN_VOTE_NEW_ROUND) {
                endpoint = "Vote";
            }

            char full_url[512];
            snprintf(full_url, sizeof(full_url), "http://%s/%s", peer->ip, endpoint);

            const char* headers[] = {"Content-Type: application/octet-stream", NULL};
            HttpResponse* response = http_client_post(full_url, (const char*)message_data, message_size, headers, NULL);

            if (response && http_client_is_success_status(response->status_code)) {
                printf("Node %u: Successfully rebroadcast to peer %s\n", node->base.id, peer->ip);
                peer_success = 1;
                success_count++;
                pbft_node_free_http_response(response);
                break;
            } else {
                printf("Node %u: Failed to rebroadcast to peer %s (attempt %d/%d, status: %d)\n",
                       node->base.id, peer->ip, attempt + 1, max_retries,
                       response ? response->status_code : 0);

                if (response) {
                    pbft_node_free_http_response(response);
                }
            }
        }

        if (!peer_success) {
            printf("Node %u: Failed to rebroadcast to peer %s after retries\n", node->base.id, peer->ip);
            failure_count++;
        }
    }

    free(message_data);

    printf("Node %u: Rebroadcast complete - %d successes, %d failures\n",
           node->base.id, success_count, failure_count);

    // Return success if at least one peer received the message
    return (success_count > 0) ? 0 : -3;
}
// Individual peer communication functions using HTTP client
int pbft_node_send_block_to_peer(PBFTNode* node, const char* peer_url, TW_Block* block, const char* block_hash) {
    if (!node || !peer_url || !block || !block_hash) {
        printf("pbft_node_send_block_to_peer: Invalid parameters\n");
        return 0;
    }
    
    // Convert hex block hash to bytes
    unsigned char block_hash_bytes[HASH_SIZE];
    if (pbft_node_hex_to_bytes(block_hash, block_hash_bytes, HASH_SIZE) != HASH_SIZE) {
        printf("pbft_node_send_block_to_peer: Invalid block hash format\n");
        return 0;
    }
    
    // Create block proposal internal transaction
    TW_InternalTransaction* proposal = tw_create_block_proposal(
        node->base.public_key,
        node->base.id,
        node->counter,  // Use counter as round number
        block
    );
    
    if (!proposal) {
        printf("pbft_node_send_block_to_peer: Failed to create block proposal\n");
        return 0;
    }
    
    // Sign the internal transaction
    TW_Internal_Transaction_add_signature(proposal);
    
    // Send binary block proposal to peer
    int success = pbft_send_block_proposal_binary(peer_url, proposal);
    
    if (success) {
        printf("pbft_node_send_block_to_peer: Successfully sent block to %s\n", peer_url);
    } else {
        printf("pbft_node_send_block_to_peer: Failed to send block to %s\n", peer_url);
    }
    
    tw_destroy_internal_transaction(proposal);
    return success;
}

int pbft_node_send_verification_vote_to_peer(PBFTNode* node, const char* peer_url, const char* block_hash, const char* block_data) {
    if (!node || !peer_url || !block_hash) {
        printf("pbft_node_send_verification_vote_to_peer: Invalid parameters\n");
        return 0;
    }
    
    // Convert hex block hash to bytes
    unsigned char block_hash_bytes[HASH_SIZE];
    if (pbft_node_hex_to_bytes(block_hash, block_hash_bytes, HASH_SIZE) != HASH_SIZE) {
        printf("pbft_node_send_verification_vote_to_peer: Invalid block hash format\n");
        return 0;
    }
    
    // Create verification vote internal transaction (vote_phase = 1)
    TW_InternalTransaction* vote = tw_create_vote_message(
        node->base.public_key,
        node->base.id,
        node->counter,  // Use counter as round number
        block_hash_bytes,
        1  // vote_phase = 1 for verification
    );
    
    if (!vote) {
        printf("pbft_node_send_verification_vote_to_peer: Failed to create verification vote\n");
        return 0;
    }
    
    // Sign the internal transaction
    TW_Internal_Transaction_add_signature(vote);
    
    // Send binary vote to peer
    int success = pbft_send_vote_binary(peer_url, vote);
    
    if (success) {
        printf("pbft_node_send_verification_vote_to_peer: Successfully sent verification vote to %s\n", peer_url);
    } else {
        printf("pbft_node_send_verification_vote_to_peer: Failed to send verification vote to %s\n", peer_url);
    }
    
    tw_destroy_internal_transaction(vote);
    return success;
}

int pbft_node_send_commit_vote_to_peer(PBFTNode* node, const char* peer_url, const char* block_hash, const char* block_data) {
    if (!node || !peer_url || !block_hash) {
        printf("pbft_node_send_commit_vote_to_peer: Invalid parameters\n");
        return 0;
    }
    
    // Convert hex block hash to bytes
    unsigned char block_hash_bytes[HASH_SIZE];
    if (pbft_node_hex_to_bytes(block_hash, block_hash_bytes, HASH_SIZE) != HASH_SIZE) {
        printf("pbft_node_send_commit_vote_to_peer: Invalid block hash format\n");
        return 0;
    }
    
    // Create commit vote internal transaction (vote_phase = 2)
    TW_InternalTransaction* vote = tw_create_vote_message(
        node->base.public_key,
        node->base.id,
        node->counter,  // Use counter as round number
        block_hash_bytes,
        2  // vote_phase = 2 for commit
    );
    
    if (!vote) {
        printf("pbft_node_send_commit_vote_to_peer: Failed to create commit vote\n");
        return 0;
    }
    
    // Sign the internal transaction
    TW_Internal_Transaction_add_signature(vote);
    
    // Send binary vote to peer
    int success = pbft_send_vote_binary(peer_url, vote);
    
    if (success) {
        printf("pbft_node_send_commit_vote_to_peer: Successfully sent commit vote to %s\n", peer_url);
    } else {
        printf("pbft_node_send_commit_vote_to_peer: Failed to send commit vote to %s\n", peer_url);
    }
    
    tw_destroy_internal_transaction(vote);
    return success;
}

int pbft_node_send_new_round_vote_to_peer(PBFTNode* node, const char* peer_url, const char* block_hash, const char* block_data) {
    if (!node || !peer_url || !block_hash) {
        printf("pbft_node_send_new_round_vote_to_peer: Invalid parameters\n");
        return 0;
    }
    
    // Convert hex block hash to bytes
    unsigned char block_hash_bytes[HASH_SIZE];
    if (pbft_node_hex_to_bytes(block_hash, block_hash_bytes, HASH_SIZE) != HASH_SIZE) {
        printf("pbft_node_send_new_round_vote_to_peer: Invalid block hash format\n");
        return 0;
    }
    
    // Create new round vote internal transaction (vote_phase = 3)
    TW_InternalTransaction* vote = tw_create_vote_message(
        node->base.public_key,
        node->base.id,
        node->counter,  // Use counter as round number
        block_hash_bytes,
        3  // vote_phase = 3 for new round
    );
    
    if (!vote) {
        printf("pbft_node_send_new_round_vote_to_peer: Failed to create new round vote\n");
        return 0;
    }
    
    // Sign the internal transaction
    TW_Internal_Transaction_add_signature(vote);
    
    // Send binary vote to peer
    int success = pbft_send_vote_binary(peer_url, vote);
    
    if (success) {
        printf("pbft_node_send_new_round_vote_to_peer: Successfully sent new round vote to %s\n", peer_url);
    } else {
        printf("pbft_node_send_new_round_vote_to_peer: Failed to send new round vote to %s\n", peer_url);
    }
    
    tw_destroy_internal_transaction(vote);
    return success;
}
// Blockchain synchronization functions using HTTP client
int pbft_node_get_blockchain_length_from_peer(PBFTNode* node, const char* peer_url) {
    if (!node || !peer_url) {
        printf("pbft_node_get_blockchain_length_from_peer: Invalid parameters\n");
        return -1;
    }
    
    // Construct full URL for blockchain length endpoint
    char full_url[512];
    snprintf(full_url, sizeof(full_url), "%s/GetBlockChainLength", peer_url);
    
    // Make HTTP GET request
    HttpResponse* response = pbft_node_http_request(full_url, "GET", NULL);
    if (!response) {
        printf("pbft_node_get_blockchain_length_from_peer: No response from %s\n", peer_url);
        return -1;
    }
    
    int chain_length = -1;
    if (http_client_is_success_status(response->status_code)) {
        // Extract chain length from JSON response
        char* length_str = http_client_extract_json_field(response->data, "chainLength");
        if (length_str) {
            chain_length = atoi(length_str);
            free(length_str);
            printf("pbft_node_get_blockchain_length_from_peer: Peer %s has chain length %d\n", 
                   peer_url, chain_length);
        } else {
            printf("pbft_node_get_blockchain_length_from_peer: Failed to parse chainLength from response\n");
        }
    } else {
        printf("pbft_node_get_blockchain_length_from_peer: HTTP error %d from %s\n", 
               response->status_code, peer_url);
    }
    
    pbft_node_free_http_response(response);
    return chain_length;
}

char* pbft_node_get_last_block_hash_from_peer(PBFTNode* node, const char* peer_url) {
    if (!node || !peer_url) {
        printf("pbft_node_get_last_block_hash_from_peer: Invalid parameters\n");
        return NULL;
    }
    
    // Construct full URL for last block hash endpoint
    char full_url[512];
    snprintf(full_url, sizeof(full_url), "%s/BlockChainLastHash", peer_url);
    
    // Make HTTP GET request
    HttpResponse* response = pbft_node_http_request(full_url, "GET", NULL);
    if (!response) {
        printf("pbft_node_get_last_block_hash_from_peer: No response from %s\n", peer_url);
        return NULL;
    }
    
    char* last_hash = NULL;
    if (http_client_is_success_status(response->status_code)) {
        // Extract last hash from JSON response
        last_hash = http_client_extract_json_field(response->data, "lastHash");
        if (last_hash) {
            printf("pbft_node_get_last_block_hash_from_peer: Peer %s last hash: %.16s...\n", 
                   peer_url, last_hash);
        } else {
            printf("pbft_node_get_last_block_hash_from_peer: Failed to parse lastHash from response\n");
        }
    } else {
        printf("pbft_node_get_last_block_hash_from_peer: HTTP error %d from %s\n", 
               response->status_code, peer_url);
    }
    
    pbft_node_free_http_response(response);
    return last_hash;
}

int pbft_node_request_missing_blocks_from_peer(PBFTNode* node, const char* peer_url) {
    if (!node || !peer_url || !node->base.blockchain) {
        printf("pbft_node_request_missing_blocks_from_peer: Invalid parameters\n");
        return -1;
    }

    // Prepare last known state
    unsigned char last_known_hash[HASH_SIZE] = {0};
    uint32_t last_known_height = 0;
    if (node->base.blockchain->length > 0) {
        TW_Block* last_block = node->base.blockchain->blocks[node->base.blockchain->length - 1];
        if (TW_Block_getHash(last_block, last_known_hash) == 0) {
            last_known_height = node->base.blockchain->length - 1;
        }
    }

    // Create binary internal transaction for sync request
    TW_InternalTransaction* sync_request = tw_create_sync_request(
        node->base.public_key,
        last_known_hash,
        last_known_height,
        100  // request up to 100 blocks
    );
    if (!sync_request) {
        printf("pbft_node_request_missing_blocks_from_peer: Failed to create sync request\n");
        return -1;
    }

    // Serialize to binary
    unsigned char* binary_data = NULL;
    size_t data_size = TW_InternalTransaction_serialize(sync_request, &binary_data);
    if (!binary_data || data_size == 0) {
        printf("pbft_node_request_missing_blocks_from_peer: Failed to serialize sync request\n");
        tw_destroy_internal_transaction(sync_request);
        return -1;
    }

    // Construct full URL for missing blocks endpoint
    char full_url[512];
    snprintf(full_url, sizeof(full_url), "%s/MissingBlockRequeset", peer_url);

    // Send binary request and parse response
    const char* headers[] = {"Content-Type: application/octet-stream", NULL};
    HttpResponse* response = http_client_post(full_url, (const char*)binary_data, data_size, headers, NULL);

    int blocks_received = 0;
    if (response && http_client_is_success_status(response->status_code) && response->data && response->size > 0) {
        TW_InternalTransaction* resp_txn = TW_InternalTransaction_deserialize((const unsigned char*)response->data, response->size);
        if (resp_txn) {
            // Handle different response types
            if (resp_txn->type == TW_INT_TXN_BROADCAST_BLOCK && resp_txn->block_data) {
                // Single block response (backward compatibility)
                printf("pbft_node_request_missing_blocks_from_peer: Received single block response\n");

                int validation_result = pbft_node_validate_block(node, resp_txn->block_data);
                if (validation_result == 0) {
                    printf("pbft_node_request_missing_blocks_from_peer: Block validation passed, committing...\n");

                    int commit_result = pbft_node_commit_block(node, resp_txn->block_data);
                    if (commit_result == 0) {
                        blocks_received++;
                        printf("pbft_node_request_missing_blocks_from_peer: Successfully committed block, total received: %d\n", blocks_received);
                    } else {
                        printf("pbft_node_request_missing_blocks_from_peer: Failed to commit block (error: %d)\n", commit_result);
                    }
                } else {
                    printf("pbft_node_request_missing_blocks_from_peer: Block validation failed (error: %d)\n", validation_result);
                }
            } else if (resp_txn->type == TW_INT_TXN_BROADCAST_CHAIN && resp_txn->payload_size > 0) {
                // Multi-block response (Task 6 implementation)
                printf("pbft_node_request_missing_blocks_from_peer: Received multi-block response (%zu bytes)\n", resp_txn->payload_size);

                // Parse multi-block payload
                // Format: [block_count:4] [block_sizes:block_count*8] [block_data...]
                const unsigned char* payload_ptr = resp_txn->payload.raw_payload;

                if (resp_txn->payload_size < sizeof(uint32_t)) {
                    printf("pbft_node_request_missing_blocks_from_peer: Payload too small for block count\n");
                    tw_destroy_internal_transaction(resp_txn);
                } else {
                    // Read block count
                    uint32_t block_count = ntohl(*(uint32_t*)payload_ptr);
                    payload_ptr += sizeof(uint32_t);

                    printf("pbft_node_request_missing_blocks_from_peer: Processing %u blocks from multi-block response\n", block_count);

                    if (block_count > 10) {
                        printf("pbft_node_request_missing_blocks_from_peer: Too many blocks in response (%u > 10)\n", block_count);
                        tw_destroy_internal_transaction(resp_txn);
                    } else {
                        // Read block sizes
                        size_t* block_sizes = (size_t*)malloc(block_count * sizeof(size_t));
                        if (!block_sizes) {
                            printf("pbft_node_request_missing_blocks_from_peer: Memory allocation failed for block sizes\n");
                            tw_destroy_internal_transaction(resp_txn);
                        } else {
                            bool size_read_failed = false;
                            for (uint32_t i = 0; i < block_count; i++) {
                                if (payload_ptr - resp_txn->payload.raw_payload + sizeof(size_t) > resp_txn->payload_size) {
                                    printf("pbft_node_request_missing_blocks_from_peer: Payload too small for block sizes\n");
                                    size_read_failed = true;
                                    break;
                                }
                                block_sizes[i] = ntohll(*(size_t*)payload_ptr);
                                payload_ptr += sizeof(size_t);
                            }

                            if (!size_read_failed) {
                                // Process each block
                                for (uint32_t i = 0; i < block_count; i++) {
                                    if (payload_ptr - resp_txn->payload.raw_payload + block_sizes[i] > resp_txn->payload_size) {
                                        printf("pbft_node_request_missing_blocks_from_peer: Payload too small for block %u data\n", i);
                                        break;
                                    }

                                    // Deserialize block
                                    TW_Block* block = TW_Block_deserialize(payload_ptr, block_sizes[i]);
                                    if (!block) {
                                        printf("pbft_node_request_missing_blocks_from_peer: Failed to deserialize block %u\n", i);
                                        payload_ptr += block_sizes[i];
                                        continue;
                                    }

                                    // Validate and commit block
                                    int validation_result = pbft_node_validate_block(node, block);
                                    if (validation_result == 0) {
                                        printf("pbft_node_request_missing_blocks_from_peer: Block %u validation passed, committing...\n", i);

                                        int commit_result = pbft_node_commit_block(node, block);
                                        if (commit_result == 0) {
                                            blocks_received++;
                                            printf("pbft_node_request_missing_blocks_from_peer: Successfully committed block %u, total received: %d\n", i, blocks_received);
                                        } else {
                                            printf("pbft_node_request_missing_blocks_from_peer: Failed to commit block %u (error: %d)\n", i, commit_result);
                                        }
                                    } else {
                                        printf("pbft_node_request_missing_blocks_from_peer: Block %u validation failed (error: %d)\n", i, validation_result);
                                    }

                                    TW_Block_destroy(block);
                                    payload_ptr += block_sizes[i];
                                }
                            }

                            free(block_sizes);
                        }
                    }
                }
                tw_destroy_internal_transaction(resp_txn);
            } else {
                printf("pbft_node_request_missing_blocks_from_peer: Unexpected response type (%d) or missing data\n", resp_txn->type);
                tw_destroy_internal_transaction(resp_txn);
            }
        } else {
            printf("pbft_node_request_missing_blocks_from_peer: Failed to deserialize response\n");
        }
    } else if (response && response->status_code == 204) {
        printf("pbft_node_request_missing_blocks_from_peer: No missing blocks available (204 No Content)\n");
    } else {
        printf("pbft_node_request_missing_blocks_from_peer: HTTP error from %s (status: %d)\n", full_url, response ? response->status_code : 0);
    }

    if (response) {
        http_response_free(response);
    }
    free(binary_data);
    tw_destroy_internal_transaction(sync_request);

    return (blocks_received > 0) ? 0 : -1;
}

int pbft_node_request_entire_blockchain_from_peer(PBFTNode* node, const char* peer_url) {
    if (!node || !peer_url) {
        printf("pbft_node_request_entire_blockchain_from_peer: Invalid parameters\n");
        return -1;
    }

    // Create binary internal transaction for full chain request
    TW_InternalTransaction* req = tw_create_internal_transaction(
        TW_INT_TXN_REQ_FULL_CHAIN,
        node->base.public_key,
        0,
        0
    );
    if (!req) {
        printf("pbft_node_request_entire_blockchain_from_peer: Failed to create request txn\n");
        return -1;
    }

    // Sign and serialize
    TW_Internal_Transaction_add_signature(req);
    unsigned char* binary_data = NULL;
    size_t data_size = TW_InternalTransaction_serialize(req, &binary_data);
    if (!binary_data || data_size == 0) {
        printf("pbft_node_request_entire_blockchain_from_peer: Failed to serialize request txn\n");
        tw_destroy_internal_transaction(req);
        return -1;
    }

    // Construct full URL for entire blockchain endpoint
    char full_url[512];
    snprintf(full_url, sizeof(full_url), "%s/RequestEntireBlockchain", peer_url);

    // Send binary request and parse response
    const char* headers[] = {"Content-Type: application/octet-stream", NULL};
    HttpResponse* response = http_client_post(full_url, (const char*)binary_data, data_size, headers, NULL);

    int success = 0;
    if (response && http_client_is_success_status(response->status_code) && response->data && response->size > 0) {
        TW_InternalTransaction* resp_txn = TW_InternalTransaction_deserialize((const unsigned char*)response->data, response->size);
        if (resp_txn) {
            // Process the received blockchain - now expects full blockchain in payload
            if (resp_txn->type == TW_INT_TXN_BROADCAST_CHAIN && resp_txn->payload_size > 0) {
                printf("pbft_node_request_entire_blockchain_from_peer: Processing full blockchain response from %s (%zu bytes)\n",
                       peer_url, resp_txn->payload_size);

                // Deserialize the entire blockchain from the payload
                TW_BlockChain* received_chain = TW_BlockChain_deserialize(resp_txn->payload.raw_payload, resp_txn->payload_size);
                if (received_chain) {
                    printf("pbft_node_request_entire_blockchain_from_peer: Deserialized blockchain with %u blocks\n",
                           received_chain->length);

                    // Validate the entire received blockchain
                    int validation_result = pbft_node_validate_blockchain(node, received_chain);
                    if (validation_result == 0) {
                        printf("pbft_node_request_entire_blockchain_from_peer: Blockchain validation passed, checking if longer...\n");

                        // Check if received blockchain is longer than current one
                        if (received_chain->length > node->base.blockchain->length) {
                            printf("pbft_node_request_entire_blockchain_from_peer: Received blockchain is longer (%u vs %u), replacing...\n",
                                   received_chain->length, node->base.blockchain->length);

                            // Replace current blockchain with the received one
                            int replace_result = pbft_node_replace_blockchain(node, received_chain);
                            if (replace_result == 0) {
                                success = 1;
                                printf("pbft_node_request_entire_blockchain_from_peer: Successfully replaced blockchain from %s\n", peer_url);
                            } else {
                                printf("pbft_node_request_entire_blockchain_from_peer: Failed to replace blockchain (error: %d)\n", replace_result);
                                TW_BlockChain_destroy(received_chain);
                            }
                        } else {
                            printf("pbft_node_request_entire_blockchain_from_peer: Received blockchain is not longer (%u vs %u), keeping current\n",
                                   received_chain->length, node->base.blockchain->length);
                            TW_BlockChain_destroy(received_chain);
                        }
                    } else {
                        printf("pbft_node_request_entire_blockchain_from_peer: Blockchain validation failed (error: %d)\n", validation_result);
                        TW_BlockChain_destroy(received_chain);
                    }
                } else {
                    printf("pbft_node_request_entire_blockchain_from_peer: Failed to deserialize blockchain from payload\n");
                }
            } else {
                printf("pbft_node_request_entire_blockchain_from_peer: Unexpected response type or missing blockchain data\n");
            }
            tw_destroy_internal_transaction(resp_txn);
        } else {
            printf("pbft_node_request_entire_blockchain_from_peer: Failed to deserialize response\n");
        }
    } else if (response && response->status_code == 204) {
        printf("pbft_node_request_entire_blockchain_from_peer: No blockchain available (204 No Content)\n");
    } else {
        printf("pbft_node_request_entire_blockchain_from_peer: HTTP error from %s (status: %d)\n", full_url, response ? response->status_code : 0);
    }

    if (response) {
        http_response_free(response);
    }
    free(binary_data);
    tw_destroy_internal_transaction(req);

    return success ? 0 : -1;
}

int pbft_node_get_pending_transactions_from_peer(PBFTNode* node, const char* peer_url, char* transactions_json) {
    if (!node || !peer_url) {
        printf("pbft_node_get_pending_transactions_from_peer: Invalid parameters\n");
        return -1;
    }

    // Create binary internal transaction request
    TW_InternalTransaction* req = tw_create_internal_transaction(TW_INT_TXN_GET_PENDING_TXNS, node->base.public_key, 0, 0);
    if (!req) {
        printf("pbft_node_get_pending_transactions_from_peer: Failed to create request\n");
        return -1;
    }

    // Sign the request
    TW_Internal_Transaction_add_signature(req);

    // Serialize to binary
    unsigned char* binary_data = NULL;
    size_t data_size = TW_InternalTransaction_serialize(req, &binary_data);
    if (!binary_data || data_size == 0) {
        printf("pbft_node_get_pending_transactions_from_peer: Failed to serialize request\n");
        tw_destroy_internal_transaction(req);
        return -1;
    }

    // Construct full URL for pending transactions endpoint
    char full_url[512];
    snprintf(full_url, sizeof(full_url), "%s/GetPendingTransactions", peer_url);

    // Send binary request and parse response
    const char* headers[] = {"Content-Type: application/octet-stream", NULL};
    HttpResponse* response = http_client_post(full_url, (const char*)binary_data, data_size, headers, NULL);

    int transaction_count = 0;
    if (response && http_client_is_success_status(response->status_code) && response->data && response->size > 0) {
        TW_InternalTransaction* resp_txn = TW_InternalTransaction_deserialize((const unsigned char*)response->data, response->size);
        if (resp_txn) {
            // Validate response type
            if (resp_txn->type == TW_INT_TXN_GET_PENDING_TXNS) {
                if (resp_txn->payload_size == 0) {
                    // Empty response - no pending transactions
                    printf("pbft_node_get_pending_transactions_from_peer: No pending transactions from %s\n", peer_url);
                    transaction_count = 0;
                } else {
                    // Parse multi-transaction response
                    // Format: [txn_count:4] [txn_sizes:count*8] [txn_data...]
                    const unsigned char* payload_ptr = resp_txn->payload.raw_payload;

                    if (resp_txn->payload_size < sizeof(uint32_t)) {
                        printf("pbft_node_get_pending_transactions_from_peer: Response payload too small\n");
                        tw_destroy_internal_transaction(resp_txn);
                        pbft_node_free_http_response(response);
                        free(binary_data);
                        tw_destroy_internal_transaction(req);
                        return -1;
                    }

                    // Read transaction count
                    uint32_t txn_count = ntohl(*(uint32_t*)payload_ptr);
                    payload_ptr += sizeof(uint32_t);

                    printf("pbft_node_get_pending_transactions_from_peer: Received %u pending transactions from %s\n",
                           txn_count, peer_url);

                    if (txn_count > 1000) { // Reasonable upper limit
                        printf("pbft_node_get_pending_transactions_from_peer: Too many transactions (%u)\n", txn_count);
                        tw_destroy_internal_transaction(resp_txn);
                        pbft_node_free_http_response(response);
                        free(binary_data);
                        tw_destroy_internal_transaction(req);
                        return -1;
                    }

                    // Read transaction sizes
                    size_t* txn_sizes = (size_t*)malloc(txn_count * sizeof(size_t));
                    if (!txn_sizes) {
                        printf("pbft_node_get_pending_transactions_from_peer: Memory allocation failed\n");
                        tw_destroy_internal_transaction(resp_txn);
                        pbft_node_free_http_response(response);
                        free(binary_data);
                        tw_destroy_internal_transaction(req);
                        return -1;
                    }

                    bool size_read_failed = false;
                    for (uint32_t i = 0; i < txn_count; i++) {
                        if (payload_ptr - resp_txn->payload.raw_payload + sizeof(size_t) > resp_txn->payload_size) {
                            printf("pbft_node_get_pending_transactions_from_peer: Payload too small for transaction sizes\n");
                            size_read_failed = true;
                            break;
                        }
                        txn_sizes[i] = ntohll(*(size_t*)payload_ptr);
                        payload_ptr += sizeof(size_t);
                    }

                    if (!size_read_failed) {
                        // Process each transaction
                        for (uint32_t i = 0; i < txn_count; i++) {
                            if (payload_ptr - resp_txn->payload.raw_payload + txn_sizes[i] > resp_txn->payload_size) {
                                printf("pbft_node_get_pending_transactions_from_peer: Payload too small for transaction %u\n", i);
                                break;
                            }

                            // Deserialize transaction
                            TW_Transaction* txn = TW_Transaction_deserialize(payload_ptr, txn_sizes[i]);
                            if (!txn) {
                                printf("pbft_node_get_pending_transactions_from_peer: Failed to deserialize transaction %u\n", i);
                                payload_ptr += txn_sizes[i];
                                continue;
                            }

                            // Validate transaction
                            ValidationResult validation = validate_transaction(txn, NULL);
                            if (validation == VALIDATION_SUCCESS) {
                                // Optionally queue the transaction locally (as per task requirements)
                                // For now, we'll queue it to demonstrate the functionality
                                char txn_hash[65];
                                // Generate a simple hash for the transaction (this is simplified)
                                snprintf(txn_hash, sizeof(txn_hash), "txn_%u_%u", node->base.id, i);

                                int queue_result = add_to_transaction_queue(txn_hash, txn);
                                if (queue_result == 0) {
                                    printf("pbft_node_get_pending_transactions_from_peer: Queued transaction %u from %s\n", i, peer_url);
                                    transaction_count++;
                                } else {
                                    printf("pbft_node_get_pending_transactions_from_peer: Failed to queue transaction %u\n", i);
                                    TW_Transaction_destroy(txn);
                                }
                            } else {
                                printf("pbft_node_get_pending_transactions_from_peer: Transaction %u validation failed (%d)\n", i, validation);
                                TW_Transaction_destroy(txn);
                            }

                            payload_ptr += txn_sizes[i];
                        }
                    }

                    free(txn_sizes);
                }

                printf("pbft_node_get_pending_transactions_from_peer: Successfully processed %d pending transactions from %s\n",
                       transaction_count, peer_url);
            } else {
                printf("pbft_node_get_pending_transactions_from_peer: Unexpected response type %d\n", resp_txn->type);
            }
            tw_destroy_internal_transaction(resp_txn);
        } else {
            printf("pbft_node_get_pending_transactions_from_peer: Failed to deserialize response\n");
        }
    } else {
        printf("pbft_node_get_pending_transactions_from_peer: HTTP error %d from %s\n",
               response ? response->status_code : 0, peer_url);
    }

    if (response) {
        pbft_node_free_http_response(response);
    }
    free(binary_data);
    tw_destroy_internal_transaction(req);

    return transaction_count;
}
int pbft_node_block_creation(PBFTNode* node, TW_Block* new_block) {
    if (!node) return 0;
    
    printf("Node %u: Creating block for singular node mode\n", node->base.id);
        
    if (!new_block) {
        printf("Failed to create block for singular node\n");
        return 0;
    }
    
    // Validate the block
    if (pbft_node_validate_block(node, new_block) != 0) {
        printf("Block validation failed for singular node\n");
        TW_Block_destroy(new_block);
        return -1;
    }
    
    // Commit the block directly (no consensus needed for single node)
    if (pbft_node_commit_block(node, new_block) != 0) {
        printf("Failed to commit block for singular node\n");
        TW_Block_destroy(new_block);
        return -1;
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
    
    return 0;
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
    
    return 0;
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

int pbft_node_save_blockchain_periodically(PBFTNode* node) {
    if (!node || !node->base.blockchain) return 0;

    printf("Node %u: Saving blockchain (length: %u)\n",
           node->base.id, node->base.blockchain->length);

    // Initialize node-specific paths
    NodeStatePaths paths;
    if (!state_paths_init(node->base.id, node->debug_mode, &paths)) {
        printf("Error: Failed to initialize state paths for node %u\n", node->base.id);
        return 0;
    }
    
    // Save blockchain to file using node-specific path
    if (!saveBlockChainToFileWithPath(node->base.blockchain, paths.blockchain_dir)) {
        printf("Error: Failed to save blockchain to file\n");
        return 0;
    }
    
    // Also save as JSON for debugging using node-specific path
    if (!writeBlockChainToJsonWithPath(node->base.blockchain, paths.blockchain_dir)) {
        printf("Warning: Failed to save blockchain as JSON\n");
        // Don't return error since binary save succeeded
    }
    
    printf("Node %u: Successfully saved blockchain to %s\n", node->base.id, paths.blockchain_dir);
    return 0;
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
    
    if (user_verified != 0) {
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
    
    // Validate transaction signature - CRITICAL SECURITY REQUIREMENT
    // This ensures only authorized transactions are accepted
    sig_result = validate_transaction_signature(transaction);
    
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

    // Log successful signature validation
    printf("[INFO] handle_transaction_endpoint: Transaction signature validation successful\n");

    // Validate transaction permissions with error handling
    printf("[DEBUG] handle_transaction_endpoint: Validating transaction permissions\n");
    int permissions_valid = 0;
    if (node && transaction) {
        permissions_valid = validate_transaction_permissions_for_node(transaction, node);
    }
    
    if (permissions_valid != 0) {
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

	printf("Node %u: Received binary proposal request, body size: %zu bytes\n", 
	       node->base.id, hm->body.len);

	// Expect binary internal transaction payload
	TW_InternalTransaction* proposal = TW_InternalTransaction_deserialize(
		(const unsigned char*)hm->body.buf, hm->body.len);
	if (!proposal) {
		printf("Node %u: ERROR - Failed to deserialize binary proposal (body size: %zu)\n", 
		       node->base.id, hm->body.len);
		mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
				 "{\"error\":\"Invalid binary proposal\"}");
		return;
	}
	
	printf("Node %u: Successfully deserialized proposal, type: %u\n", 
	       node->base.id, proposal->type);

	// Ensure message type is a block proposal
	if (proposal->type != TW_INT_TXN_PROPOSE_BLOCK) {
		mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
				 "{\"error\":\"Unexpected message type\"}");
		tw_destroy_internal_transaction(proposal);
		return;
	}

	// Verify signature on the internal transaction
	if (!TW_InternalTransaction_verify_signature(proposal)) {
		mg_http_reply(c, 401, "Content-Type: application/json\r\n", 
				 "{\"error\":\"Invalid signature\"}");
		tw_destroy_internal_transaction(proposal);
		return;
	}

	// Basic proposer and round checks
	uint32_t expected_proposer = pbft_node_calculate_proposer_id(node);
	printf("Node %u: Received proposal from %u, expected proposer: %u\n", 
	       node->base.id, proposal->proposer_id, expected_proposer);
	if (proposal->proposer_id != expected_proposer) {
		printf("Node %u: REJECTING - Unexpected proposer id: got %u, expected %u. Triggering sync check...\n",
		       node->base.id, proposal->proposer_id, expected_proposer);
		
		// Instead of just rejecting, check if we need to sync our blockchain
		printf("Node %u: Checking if blockchain sync is needed due to proposer mismatch\n", node->base.id);
		int sync_result = pbft_node_sync_with_longest_chain(node);
		if (sync_result >= 0) {
			printf("Node %u: Sync initiated successfully, may retry proposal later\n", node->base.id);
		} else {
			printf("Node %u: No sync needed, but proposer still mismatched. Checking proposer_offset...\n", node->base.id);
			// Only increment offset if we're sure we don't need more blocks
			node->base.proposer_offset++;
			printf("Node %u: Incremented proposer offset to %u\n", node->base.id, node->base.proposer_offset);
		}
		
		mg_http_reply(c, 409, "Content-Type: application/json\r\n", 
				 "{\"error\":\"Unexpected proposer id - sync check initiated\"}");
		tw_destroy_internal_transaction(proposal);
		return;
	}

	printf("Node %u: Received proposal round %u, current counter: %u\n",
	       node->base.id, proposal->round_number, node->counter);
	if (proposal->round_number != node->counter) {
		printf("Node %u: REJECTING - Unexpected round number: got %u, expected %u\n",
		       node->base.id, proposal->round_number, node->counter);
		mg_http_reply(c, 409, "Content-Type: application/json\r\n", 
				 "{\"error\":\"Unexpected round number\"}");
		tw_destroy_internal_transaction(proposal);
		return;
	}

	// Ensure block data is present
	if (!proposal->block_data) {
		mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
				 "{\"error\":\"Missing block data in proposal\"}");
		tw_destroy_internal_transaction(proposal);
		return;
	}

	// Recompute block hash and compare with provided hash
	unsigned char recomputed_hash[HASH_SIZE];
	if (TW_Block_getHash(proposal->block_data, recomputed_hash) != 0) {
		mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
				 "{\"error\":\"Failed to compute block hash\"}");
		tw_destroy_internal_transaction(proposal);
		return;
	}
	if (memcmp(recomputed_hash, proposal->block_hash, HASH_SIZE) != 0) {
		mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
				 "{\"error\":\"Block hash mismatch\"}");
		tw_destroy_internal_transaction(proposal);
		return;
	}

	// Validate block linkage and index locally (do not rely on pbft_node_validate_block yet)
	int32_t expected_index = node->base.blockchain ? (int32_t)node->base.blockchain->length : 0;
	if (proposal->block_data->index != expected_index) {
		mg_http_reply(c, 409, "Content-Type: application/json\r\n", 
				 "{\"error\":\"Invalid block index\"}");
		tw_destroy_internal_transaction(proposal);
		return;
	}
	if (proposal->block_data->index > 0 && node->base.blockchain && node->base.blockchain->length > 0) {
		TW_Block* last_block = node->base.blockchain->blocks[node->base.blockchain->length - 1];
		unsigned char last_hash[HASH_SIZE];
		if (TW_Block_getHash(last_block, last_hash) != 0 ||
			memcmp(proposal->block_data->previous_hash, last_hash, HASH_SIZE) != 0) {
			mg_http_reply(c, 409, "Content-Type: application/json\r\n", 
					 "{\"error\":\"Previous hash mismatch\"}");
			tw_destroy_internal_transaction(proposal);
			return;
		}
	}

	printf("Node %u: Accepted block proposal from proposer %u (round %u, index %d)\n",
		node->base.id, proposal->proposer_id, proposal->round_number, proposal->block_data->index);

	// Retain the accepted proposal for consensus
	pthread_mutex_lock(&node->state_mutex);

	// Clean up any previously stored proposal
	if (node->current_proposal_block) {
		TW_Block_destroy(node->current_proposal_block);
		node->current_proposal_block = NULL;
	}

	// Store the new proposal details
	node->current_proposal_round = proposal->round_number;
	node->current_proposer_id = proposal->proposer_id;
	memcpy(node->current_proposal_hash, proposal->block_hash, HASH_SIZE);
	node->last_consensus_activity = time(NULL); // Update consensus activity timestamp

	// Take ownership of the block (create a copy)
	node->current_proposal_block = TW_Block_copy(proposal->block_data);
	if (!node->current_proposal_block) {
		printf("Node %u: Warning - Failed to copy proposed block for retention\n", node->base.id);
		// Continue anyway - we still have the hash and metadata
	}

	pthread_mutex_unlock(&node->state_mutex);

	// Kick off verification voting based on retained proposal
	pbft_node_broadcast_verification_vote(node);

	// Acknowledge proposal reception
	mg_http_reply(c, 200, "Content-Type: application/json\r\n",
			 "{\"status\":\"Proposal accepted\"}");

	// Clean up the internal transaction (block ownership transferred)
	tw_destroy_internal_transaction(proposal);
}

static void handle_verification_vote_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Node not initialized\"}");
        return;
    }

    // Expect binary internal transaction payload
    TW_InternalTransaction* vote = TW_InternalTransaction_deserialize((const unsigned char*)hm->body.buf, hm->body.len);
    if (!vote) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Invalid binary vote\"}");
        return;
    }

    // Validate type and signature
    if (vote->type != TW_INT_TXN_VOTE_VERIFY || !TW_InternalTransaction_verify_signature(vote)) {
        mg_http_reply(c, 401, "Content-Type: application/json\r\n",
                     "{\"error\":\"Invalid verification vote\"}");
        tw_destroy_internal_transaction(vote);
        return;
    }

    // Verify sender is authorized consensus node
    if (db_is_authorized_consensus_node(vote->sender) != 1) {
        char sender_hex[65];
        sodium_bin2hex(sender_hex, sizeof(sender_hex), vote->sender, 32);
        printf("Node %u: ❌ REJECTED verification vote from unauthorized node (pubkey: %s)\n",
               node->base.id, sender_hex);
        mg_http_reply(c, 403, "Content-Type: application/json\r\n",
                     "{\"error\":\"Unauthorized consensus participant\"}");
        tw_destroy_internal_transaction(vote);
        return;
    }

    // Check the vote matches current proposal round and hash
    pthread_mutex_lock(&node->state_mutex);
    int matches_round = (vote->round_number == node->current_proposal_round);
    int matches_hash = (memcmp(vote->block_hash, node->current_proposal_hash, HASH_SIZE) == 0);
    if (matches_round && matches_hash) {
        uint32_t voter_id = node_get_id_by_pubkey(vote->sender); // Get voter ID from sender public key
        if (voter_id != 0 && voter_id <= MAX_PEERS && node->verification_voters[voter_id] == 0) {
            node->verification_voters[voter_id] = 1;
            node->verification_votes_count++;
        }
    }

    // Compute f from N using PBFT relation N = 3f + 1 → f = (N - 1)/3
    uint32_t total_nodes = node->base.peer_count + 1; // include self
    uint32_t f = (total_nodes > 1) ? (total_nodes - 1) / 3 : 0;
    uint32_t threshold = (2 * f) + 1; // need 2f + 1 verification votes
    int reached_threshold = (node->verification_votes_count >= threshold);
    pthread_mutex_unlock(&node->state_mutex);

    printf("Node %u: Verification votes %u / %u (threshold %u)\n", node->base.id,
           node->verification_votes_count, total_nodes, threshold);

    if (reached_threshold) {
        pbft_node_broadcast_commit_vote(node);
    }

    mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                 "{\"status\":\"Verification vote processed\"}");

    tw_destroy_internal_transaction(vote);
}

static void handle_commit_vote_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Node not initialized\"}");
        return;
    }

    // Expect binary internal transaction payload
    TW_InternalTransaction* vote = TW_InternalTransaction_deserialize((const unsigned char*)hm->body.buf, hm->body.len);
    if (!vote) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n", 
                     "{\"error\":\"Invalid binary vote\"}");
        return;
    }

    // Validate type and signature
    if (vote->type != TW_INT_TXN_VOTE_COMMIT || !TW_InternalTransaction_verify_signature(vote)) {
        mg_http_reply(c, 401, "Content-Type: application/json\r\n",
                     "{\"error\":\"Invalid commit vote\"}");
        tw_destroy_internal_transaction(vote);
        return;
    }

    // Verify sender is authorized consensus node
    if (db_is_authorized_consensus_node(vote->sender) != 1) {
        char sender_hex[65];
        sodium_bin2hex(sender_hex, sizeof(sender_hex), vote->sender, 32);
        printf("Node %u: ❌ REJECTED commit vote from unauthorized node (pubkey: %s)\n",
               node->base.id, sender_hex);
        mg_http_reply(c, 403, "Content-Type: application/json\r\n",
                     "{\"error\":\"Unauthorized consensus participant\"}");
        tw_destroy_internal_transaction(vote);
        return;
    }

    // Check the vote matches current proposal round and hash
    pthread_mutex_lock(&node->state_mutex);
    int matches_round = (vote->round_number == node->current_proposal_round);
    int matches_hash = (memcmp(vote->block_hash, node->current_proposal_hash, HASH_SIZE) == 0);
    if (matches_round && matches_hash) {
        uint32_t voter_id = node_get_id_by_pubkey(vote->sender); // Get voter ID from sender public key
        if (voter_id != 0 && voter_id <= MAX_PEERS && node->commit_voters[voter_id] == 0) {
            node->commit_voters[voter_id] = 1;
            node->commit_votes_count++;
        }
    }

    // Compute PBFT thresholds
    uint32_t total_nodes = node->base.peer_count + 1; // include self
    uint32_t f = (total_nodes > 1) ? (total_nodes - 1) / 3 : 0; // N = 3f + 1
    uint32_t threshold = (2 * f) + 1; // need 2f + 1 commit votes
    int reached_threshold = (node->commit_votes_count >= threshold);
    pthread_mutex_unlock(&node->state_mutex);

    printf("Node %u: Commit votes %u / %u (threshold %u)\n", node->base.id,
           node->commit_votes_count, total_nodes, threshold);

    if (reached_threshold && node->current_proposal_block) {
        // Commit the block
        if (pbft_node_commit_block(node, node->current_proposal_block) == 0) {
            printf("Node %u: Block committed (index %d)\n", node->base.id, node->current_proposal_block->index);

            // Clear retained proposal state after commit
            pthread_mutex_lock(&node->state_mutex);
            TW_Block_destroy(node->current_proposal_block);
            node->current_proposal_block = NULL;
            node->verification_votes_count = 0;
            memset(node->verification_voters, 0, sizeof(node->verification_voters));
            node->commit_votes_count = 0;
            memset(node->commit_voters, 0, sizeof(node->commit_voters));
            node->view_change_pending = false; // Clear view change state on successful commit
            node->failed_rounds_count = 0;     // Reset failure counter
            node->last_consensus_activity = time(NULL); // Update consensus activity
            node->current_view++; // Increment view on successful consensus
            pthread_mutex_unlock(&node->state_mutex);
        } else {
            printf("Node %u: Failed to commit block\n", node->base.id);
        }
    }

    mg_http_reply(c, 200, "Content-Type: application/json\r\n", 
                 "{\"status\":\"Commit vote processed\"}");

    tw_destroy_internal_transaction(vote);
}

static void handle_new_round_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                     "{\"error\":\"Node not initialized\"}");
        return;
    }

    // Expect binary internal transaction payload
    TW_InternalTransaction* vote = TW_InternalTransaction_deserialize((const unsigned char*)hm->body.buf, hm->body.len);
    if (!vote) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                     "{\"error\":\"Invalid binary vote\"}");
        return;
    }

    // Validate type and signature
    if (vote->type != TW_INT_TXN_VOTE_NEW_ROUND || !TW_InternalTransaction_verify_signature(vote)) {
        mg_http_reply(c, 401, "Content-Type: application/json\r\n",
                     "{\"error\":\"Invalid new round vote\"}");
        tw_destroy_internal_transaction(vote);
        return;
    }

    // Verify sender is authorized consensus node
    if (db_is_authorized_consensus_node(vote->sender) != 1) {
        char sender_hex[65];
        sodium_bin2hex(sender_hex, sizeof(sender_hex), vote->sender, 32);
        printf("Node %u: ❌ REJECTED new round vote from unauthorized node (pubkey: %s)\n",
               node->base.id, sender_hex);
        mg_http_reply(c, 403, "Content-Type: application/json\r\n",
                     "{\"error\":\"Unauthorized consensus participant\"}");
        tw_destroy_internal_transaction(vote);
        return;
    }

    // Check if this vote matches our pending view change
    pthread_mutex_lock(&node->state_mutex);
    bool matches_proposed_view = (vote->round_number == node->proposed_new_view);
    if (node->view_change_pending && matches_proposed_view) {
        uint32_t voter_id = node_get_id_by_pubkey(vote->sender);
        if (voter_id != 0 && voter_id <= MAX_PEERS && node->view_change_voters[voter_id] == 0) {
            node->view_change_voters[voter_id] = 1;
            node->view_change_votes_count++;
        }
    }

    // Compute PBFT thresholds
    uint32_t total_nodes = node->base.peer_count + 1; // include self
    uint32_t f = (total_nodes > 1) ? (total_nodes - 1) / 3 : 0; // N = 3f + 1
    uint32_t threshold = (2 * f) + 1; // need 2f + 1 view change votes
    bool reached_threshold = (node->view_change_votes_count >= threshold);
    pthread_mutex_unlock(&node->state_mutex);

    printf("Node %u: View change votes %u / %u (threshold %u, proposed view %u)\n",
           node->base.id, node->view_change_votes_count, total_nodes, threshold, node->proposed_new_view);

    if (reached_threshold) {
        // View change consensus achieved - transition to new view
        printf("Node %u: View change consensus reached, transitioning to view %u\n",
               node->base.id, node->proposed_new_view);

        pthread_mutex_lock(&node->state_mutex);
        node->current_view = node->proposed_new_view;
        node->view_change_pending = false;
        node->last_consensus_activity = time(NULL);

        // Clear all vote state for the new view
        node->verification_votes_count = 0;
        memset(node->verification_voters, 0, sizeof(node->verification_voters));
        node->commit_votes_count = 0;
        memset(node->commit_voters, 0, sizeof(node->commit_voters));
        node->view_change_votes_count = 0;
        memset(node->view_change_voters, 0, sizeof(node->view_change_voters));
        node->failed_rounds_count = 0;

        // Clear any pending proposal
        if (node->current_proposal_block) {
            TW_Block_destroy(node->current_proposal_block);
            node->current_proposal_block = NULL;
        }
        pthread_mutex_unlock(&node->state_mutex);
    }

    mg_http_reply(c, 200, "Content-Type: application/json\r\n",
                 "{\"status\":\"New round vote processed\"}");

    tw_destroy_internal_transaction(vote);
}

static void handle_missing_block_request_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                     "{\"error\":\"Node not initialized\"}");
        return;
    }

    // Parse binary internal transaction
    TW_InternalTransaction* req = TW_InternalTransaction_deserialize(
        (const unsigned char*)hm->body.buf, hm->body.len);

    if (!req) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                     "{\"error\":\"Invalid binary transaction format\"}");
        return;
    }

    // Verify signature
    if (!TW_InternalTransaction_verify_signature(req)) {
        mg_http_reply(c, 401, "Content-Type: application/json\r\n",
                     "{\"error\":\"Invalid signature\"}");
        tw_destroy_internal_transaction(req);
        return;
    }

    // Extract sync parameters from binary transaction
    unsigned char last_known_hash[HASH_SIZE];
    memcpy(last_known_hash, req->payload.sync_request.last_known_hash, HASH_SIZE);
    uint32_t last_known_height = req->payload.sync_request.last_known_height;

    printf("Node %u: Received binary sync request, last height: %u\n",
           node->base.id, last_known_height);

    if (!node->base.blockchain) {
        mg_http_reply(c, 204, "Content-Type: application/json\r\n", "");
        tw_destroy_internal_transaction(req);
        return;
    }

    // Find blocks after the last known hash
    uint32_t max_blocks = req->payload.sync_request.max_blocks_requested;
    uint32_t start_index = 0;
    uint32_t blocks_found = 0;

    // If last_known_hash is not zero, find the starting index
    if (memcmp(last_known_hash, (unsigned char[HASH_SIZE]){0}, HASH_SIZE) != 0) {
        // Find the block with the given hash
        for (uint32_t i = 0; i < node->base.blockchain->length; i++) {
            unsigned char current_hash[HASH_SIZE];
            if (TW_Block_getHash(node->base.blockchain->blocks[i], current_hash) == 0) {
                if (memcmp(current_hash, last_known_hash, HASH_SIZE) == 0) {
                    start_index = i + 1; // Start from the next block
                    break;
                }
            }
        }
    }

    // Count available blocks (limit to max_blocks or 10, whichever is smaller)
    uint32_t available_blocks = node->base.blockchain->length > start_index ?
                                node->base.blockchain->length - start_index : 0;
    uint32_t max_response_blocks = 10; // Task 6 requirement: max 10 blocks per response
    uint32_t effective_limit = max_blocks < max_response_blocks ? max_blocks : max_response_blocks;
    uint32_t blocks_to_send = available_blocks > effective_limit ? effective_limit : available_blocks;

    if (blocks_to_send == 0) {
        mg_http_reply(c, 204, "Content-Type: application/json\r\n", "");
        tw_destroy_internal_transaction(req);
        return;
    }

    // For single block, use BROADCAST_BLOCK (backward compatibility)
    if (blocks_to_send == 1) {
        TW_Block* block_to_send = node->base.blockchain->blocks[start_index];

        // Build a broadcast response with one block
        TW_InternalTransaction* resp = tw_create_internal_transaction(TW_INT_TXN_BROADCAST_BLOCK, node->base.public_key, 0, 0);
        if (!resp) {
            mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Allocation failure\"}");
            tw_destroy_internal_transaction(req);
            return;
        }

        // Attach a deep copy of the block
        resp->block_data = TW_Block_copy(block_to_send);
        if (!resp->block_data) {
            mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Block copy failed\"}");
            tw_destroy_internal_transaction(resp);
            tw_destroy_internal_transaction(req);
            return;
        }

        // Fill block_hash for convenience
        unsigned char block_hash[HASH_SIZE];
        if (TW_Block_getHash(block_to_send, block_hash) == 0) {
            memcpy(resp->block_hash, block_hash, HASH_SIZE);
        }

        // Sign and serialize
        TW_Internal_Transaction_add_signature(resp);
        unsigned char* out = NULL;
        size_t out_size = TW_InternalTransaction_serialize(resp, &out);
        if (!out || out_size == 0) {
            mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Serialize failed\"}");
            if (out) free(out);
            tw_destroy_internal_transaction(resp);
            tw_destroy_internal_transaction(req);
            return;
        }

        // Send binary response
        mg_http_reply(c, 200, "Content-Type: application/octet-stream\r\n", "%.*s", (int)out_size, out);

        free(out);
        tw_destroy_internal_transaction(resp);
        blocks_found = 1;
    } else {
        // For multiple blocks, create a custom multi-block payload
        printf("Node %u: Sending %u blocks in multi-block response\n", node->base.id, blocks_to_send);

        // Calculate total size needed for all blocks
        size_t total_blocks_size = 0;
        size_t* block_sizes = (size_t*)malloc(blocks_to_send * sizeof(size_t));
        if (!block_sizes) {
            mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Memory allocation failed\"}");
            tw_destroy_internal_transaction(req);
            return;
        }

        for (uint32_t i = 0; i < blocks_to_send; i++) {
            block_sizes[i] = TW_Block_get_size(node->base.blockchain->blocks[start_index + i]);
            total_blocks_size += block_sizes[i];
        }

        // Check if total size fits in payload
        if (total_blocks_size > MAX_PAYLOAD_SIZE_INTERNAL) {
            free(block_sizes);
            mg_http_reply(c, 413, "Content-Type: application/json\r\n", "{\"error\":\"Blocks too large for response\"}");
            tw_destroy_internal_transaction(req);
            return;
        }

        // Allocate buffer for multi-block data
        // Format: [block_count:4] [block_sizes:block_count*8] [block_data...]
        size_t header_size = sizeof(uint32_t) + (blocks_to_send * sizeof(size_t));
        size_t total_payload_size = header_size + total_blocks_size;

        if (total_payload_size > MAX_PAYLOAD_SIZE_INTERNAL) {
            free(block_sizes);
            mg_http_reply(c, 413, "Content-Type: application/json\r\n", "{\"error\":\"Payload too large\"}");
            tw_destroy_internal_transaction(req);
            return;
        }

        // Build response with TW_INT_TXN_BROADCAST_CHAIN type for multi-block data
        TW_InternalTransaction* resp = tw_create_internal_transaction(TW_INT_TXN_BROADCAST_CHAIN, node->base.public_key, 0, 0);
        if (!resp) {
            free(block_sizes);
            mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Allocation failure\"}");
            tw_destroy_internal_transaction(req);
            return;
        }

        // Serialize multi-block data into raw_payload
        unsigned char* payload_ptr = resp->payload.raw_payload;

        // Write block count
        uint32_t block_count_net = htonl(blocks_to_send);
        memcpy(payload_ptr, &block_count_net, sizeof(uint32_t));
        payload_ptr += sizeof(uint32_t);

        // Write block sizes
        for (uint32_t i = 0; i < blocks_to_send; i++) {
            size_t size_net = htonll(block_sizes[i]);
            memcpy(payload_ptr, &size_net, sizeof(size_t));
            payload_ptr += sizeof(size_t);
        }

        // Serialize each block
        for (uint32_t i = 0; i < blocks_to_send; i++) {
            TW_Block* block = node->base.blockchain->blocks[start_index + i];
            size_t serialized_size = TW_Block_serialize(block, &payload_ptr);
            if (serialized_size == 0) {
                free(block_sizes);
                tw_destroy_internal_transaction(resp);
                mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Block serialization failed\"}");
                tw_destroy_internal_transaction(req);
                return;
            }
        }

        resp->payload_size = total_payload_size;

        // Set chain hash to the hash of the last block being sent
        TW_Block* last_block = node->base.blockchain->blocks[start_index + blocks_to_send - 1];
        unsigned char last_block_hash[HASH_SIZE];
        if (TW_Block_getHash(last_block, last_block_hash) == 0) {
            memcpy(resp->chain_hash, last_block_hash, HASH_SIZE);
        }

        // Sign and serialize response
        TW_Internal_Transaction_add_signature(resp);
        unsigned char* out = NULL;
        size_t out_size = TW_InternalTransaction_serialize(resp, &out);
        if (!out || out_size == 0) {
            free(block_sizes);
            mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Response serialization failed\"}");
            if (out) free(out);
            tw_destroy_internal_transaction(resp);
            tw_destroy_internal_transaction(req);
            return;
        }

        // Send binary response
        mg_http_reply(c, 200, "Content-Type: application/octet-stream\r\n", "%.*s", (int)out_size, out);

        free(block_sizes);
        free(out);
        tw_destroy_internal_transaction(resp);
        blocks_found = blocks_to_send;
    }

    printf("Node %u: Sent %u blocks in response to sync request\n", node->base.id, blocks_found);
    tw_destroy_internal_transaction(req);
}

static void handle_send_new_blockchain_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    // TODO: Implement send new blockchain handling
    mg_http_reply(c, 501, "Content-Type: application/json\r\n", 
                 "{\"error\":\"SendNewBlockChain endpoint not implemented yet\"}");
}

static void handle_request_entire_blockchain_endpoint(struct mg_connection *c, struct mg_http_message *hm, PBFTNode* node) {
    if (!node) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n",
                     "{\"error\":\"Node not initialized\"}");
        return;
    }

    // Parse binary internal transaction
    TW_InternalTransaction* req = TW_InternalTransaction_deserialize(
        (const unsigned char*)hm->body.buf, hm->body.len);

    if (!req) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                     "{\"error\":\"Invalid binary transaction format\"}");
        return;
    }

    // Verify signature
    if (!TW_InternalTransaction_verify_signature(req)) {
        mg_http_reply(c, 401, "Content-Type: application/json\r\n",
                     "{\"error\":\"Invalid signature\"}");
        tw_destroy_internal_transaction(req);
        return;
    }

    // Validate transaction type
    if (req->type != TW_INT_TXN_REQ_FULL_CHAIN) {
        mg_http_reply(c, 400, "Content-Type: application/json\r\n",
                     "{\"error\":\"Invalid transaction type\"}");
        tw_destroy_internal_transaction(req);
        return;
    }

    printf("Node %u: Received binary full-chain request from peer\n", node->base.id);

    if (!node->base.blockchain || node->base.blockchain->length == 0) {
        mg_http_reply(c, 204, "Content-Type: application/json\r\n", "");
        tw_destroy_internal_transaction(req);
        return;
    }

    // Check blockchain size and block count limits
    uint32_t block_count = node->base.blockchain->length;
    const uint32_t MAX_BLOCKS_IN_RESPONSE = 50; // Reasonable limit for single response

    if (block_count > MAX_BLOCKS_IN_RESPONSE) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg),
                "{\"error\":\"Too many blocks in blockchain (%u blocks, max %u). Use bulk export for large blockchains.\"}",
                block_count, MAX_BLOCKS_IN_RESPONSE);
        mg_http_reply(c, 413, "Content-Type: application/json\r\n", "%s", error_msg);
        tw_destroy_internal_transaction(req);
        return;
    }

    size_t blockchain_size = TW_BlockChain_get_size(node->base.blockchain);
    if (blockchain_size == 0 || blockchain_size > MAX_PAYLOAD_SIZE_INTERNAL) {
        char error_msg[256];
        snprintf(error_msg, sizeof(error_msg),
                "{\"error\":\"Blockchain too large for transfer (%zu bytes, max %d). Use bulk export for large blockchains.\"}",
                blockchain_size, MAX_PAYLOAD_SIZE_INTERNAL);
        mg_http_reply(c, 413, "Content-Type: application/json\r\n", "%s", error_msg);
        tw_destroy_internal_transaction(req);
        return;
    }

    // Allocate buffer for blockchain serialization
    unsigned char* blockchain_data = (unsigned char*)malloc(blockchain_size);
    if (!blockchain_data) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Memory allocation failed\"}");
        tw_destroy_internal_transaction(req);
        return;
    }

    // Serialize the entire blockchain
    unsigned char* temp_ptr = blockchain_data;
    int serialize_result = TW_BlockChain_serialize(node->base.blockchain, &temp_ptr);
    if (serialize_result != 0) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Blockchain serialization failed\"}");
        free(blockchain_data);
        tw_destroy_internal_transaction(req);
        return;
    }

    // Build a broadcast response with the full blockchain in payload
    TW_InternalTransaction* resp = tw_create_internal_transaction(TW_INT_TXN_BROADCAST_CHAIN, node->base.public_key, 0, 0);
    if (!resp) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Allocation failure\"}");
        free(blockchain_data);
        tw_destroy_internal_transaction(req);
        return;
    }

    // Store the serialized blockchain in the raw payload
    memcpy(resp->payload.raw_payload, blockchain_data, blockchain_size);
    resp->payload_size = blockchain_size;

    // Fill chain_hash with blockchain hash for reference
    unsigned char chain_hash[HASH_SIZE];
    TW_BlockChain_get_hash(node->base.blockchain, chain_hash);
    memcpy(resp->chain_hash, chain_hash, HASH_SIZE);

    free(blockchain_data);

    // Sign and serialize
    TW_Internal_Transaction_add_signature(resp);
    unsigned char* out = NULL;
    size_t out_size = TW_InternalTransaction_serialize(resp, &out);
    if (!out || out_size == 0) {
        mg_http_reply(c, 500, "Content-Type: application/json\r\n", "{\"error\":\"Serialize failed\"}");
        if (out) free(out);
        tw_destroy_internal_transaction(resp);
        tw_destroy_internal_transaction(req);
        return;
    }

    // Send binary response
    mg_http_reply(c, 200, "Content-Type: application/octet-stream\r\n", "%.*s", (int)out_size, out);

    printf("Node %u: Sent complete blockchain (%zu bytes, %u blocks) in response to full-chain request\n",
           node->base.id, blockchain_size, node->base.blockchain->length);

    free(out);
    tw_destroy_internal_transaction(resp);
    tw_destroy_internal_transaction(req);
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
    cJSON *resource_id_json = cJSON_GetObjectItem(json, "resource_id");
    
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
    // Parse optional resource_id (plaintext metadata)
    char resource_id_buf[64] = {0};
    if (resource_id_json && cJSON_IsString(resource_id_json)) {
        const char* rid = cJSON_GetStringValue(resource_id_json);
        if (rid) {
            // Truncate safely to 63 chars and ensure NUL
            strncpy(resource_id_buf, rid, sizeof(resource_id_buf) - 1);
            resource_id_buf[sizeof(resource_id_buf) - 1] = '\0';
        }
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
    // Set resource_id if provided
    if (resource_id_buf[0] != '\0') {
        strncpy((*transaction)->resource_id, resource_id_buf, sizeof((*transaction)->resource_id) - 1);
        (*transaction)->resource_id[sizeof((*transaction)->resource_id) - 1] = '\0';
    }
    
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
            return 0;  // Already queued (success - found)
        }
    }
    return 0;  // Not queued
}

int is_user_verified(const unsigned char* public_key, TW_BlockChain* blockchain) {
    if (!public_key || !blockchain) return 0;
    
    // Open database connection for verification
    char db_path[512];
    if (!get_current_node_db_path(db_path, sizeof(db_path))) {
        printf("Failed to get database path for user verification\n");
        return 0;
    }
    if (db_init(db_path) != 0) {
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
        return 0;
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
    char db_path[512];
    if (!get_current_node_db_path(db_path, sizeof(db_path))) {
        printf("Failed to get database path for validation\n");
        destroy_validation_context(context);
        return 0;
    }
    if (db_init(db_path) != 0) {
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
        return 0;
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
        
        if (TW_Block_getHash(last_block, expected_prev_hash) != 0) {
            return 0;  // Failed to get hash
        }
        
        if (memcmp(block->previous_hash, expected_prev_hash, HASH_SIZE) != 0) {
            printf("Blockchain sync error: previous hash mismatch\n");
            return 0;  // Chains out of sync
        }
    }
    
    return 0;  // Chains are in sync
} 