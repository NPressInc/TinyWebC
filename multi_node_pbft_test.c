#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <time.h>

// Test configuration
#define NUM_NODES 3
#define BASE_PORT 5001
#define TEST_DURATION 30  // seconds
#define BLOCK_CREATION_INTERVAL 5  // seconds

// HTTP response structure
struct HTTPResponse {
    char *memory;
    size_t size;
};

// Callback function to write HTTP response data
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct HTTPResponse *mem = (struct HTTPResponse *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        printf("Not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = '\0';

    return realsize;
}

// Make HTTP request to a node
struct HTTPResponse* make_http_request(const char* url, const char* method, const char* json_data) {
    CURL *curl;
    CURLcode res;
    struct HTTPResponse *response = malloc(sizeof(struct HTTPResponse));
    
    if (!response) return NULL;
    
    response->memory = malloc(1);
    response->size = 0;
    response->memory[0] = '\0';

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
        
        if (json_data && strcmp(method, "POST") == 0) {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_data);
            struct curl_slist *headers = NULL;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        }

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        if (res != CURLE_OK) {
            free(response->memory);
            free(response);
            return NULL;
        }
    }

    return response;
}

// Free HTTP response
void free_http_response(struct HTTPResponse* response) {
    if (response) {
        if (response->memory) {
            free(response->memory);
        }
        free(response);
    }
}

// Get blockchain length from a node
int get_blockchain_length(int node_id) {
    char url[256];
    snprintf(url, sizeof(url), "http://localhost:%d/GetBlockChainLength", BASE_PORT + node_id);
    
    struct HTTPResponse* response = make_http_request(url, "GET", NULL);
    if (!response) {
        return -1;
    }
    
    cJSON *json = cJSON_Parse(response->memory);
    int length = -1;
    
    if (json) {
        cJSON *chain_length = cJSON_GetObjectItem(json, "chainLength");
        if (chain_length && cJSON_IsNumber(chain_length)) {
            length = (int)cJSON_GetNumberValue(chain_length);
        }
        cJSON_Delete(json);
    }
    
    free_http_response(response);
    return length;
}

// Check if a node is responding
int is_node_responding(int node_id) {
    char url[256];
    snprintf(url, sizeof(url), "http://localhost:%d/", BASE_PORT + node_id);
    
    struct HTTPResponse* response = make_http_request(url, "GET", NULL);
    if (response) {
        free_http_response(response);
        return 1;
    }
    return 0;
}

// Send a test transaction to a node
int send_test_transaction(int node_id, int tx_count) {
    char url[256];
    snprintf(url, sizeof(url), "http://localhost:%d/Transaction", BASE_PORT + node_id);
    
    // Use the actual registered user from the blockchain (64 hex chars = 32 bytes)
    const char* registered_sender = "d25e49d4bb495f3e3fa9757164337ad354184282a0bde7ca940bd53b526be522";
    const char* registered_recipient = "d25e49d4bb495f3e3fa9757164337ad354184282a0bde7ca940bd53b526be522";
    
    // Create a proper signature (64 hex chars for Ed25519 signature)
    const char* valid_signature = "ca4a1875cdeb2e8b4e2b01677c9e6568dba53cffec270941f2e233ca34f229f3311576068c537e167cf4e6908c797d713723db83cf817164ccbb3b5e51cb5a08";
    
    // Create a simple test transaction JSON
    cJSON *json = cJSON_CreateObject();
    cJSON *sender = cJSON_CreateString(registered_sender);
    cJSON *type = cJSON_CreateNumber(1);  // TW_TXN_MESSAGE
    cJSON *timestamp = cJSON_CreateNumber((double)time(NULL));
    cJSON *recipients = cJSON_CreateArray();
    cJSON *recipient = cJSON_CreateString(registered_recipient);
    cJSON_AddItemToArray(recipients, recipient);
    cJSON *signature = cJSON_CreateString(valid_signature);
    
    char payload_text[256];
    snprintf(payload_text, sizeof(payload_text), "Test transaction %d from node %d", tx_count, node_id);
    cJSON *payload = cJSON_CreateString(payload_text);
    
    cJSON_AddItemToObject(json, "sender", sender);
    cJSON_AddItemToObject(json, "type", type);
    cJSON_AddItemToObject(json, "timestamp", timestamp);
    cJSON_AddItemToObject(json, "recipients", recipients);
    cJSON_AddItemToObject(json, "signature", signature);
    cJSON_AddItemToObject(json, "payload", payload);
    
    char *json_string = cJSON_Print(json);
    
    struct HTTPResponse* response = make_http_request(url, "POST", json_string);
    int success = 0;
    
    if (response) {
        printf("Node %d transaction response: %s\n", node_id, response->memory);
        // Check if the response indicates success
        if (strstr(response->memory, "\"status\":\"ok\"") || 
            strstr(response->memory, "Transaction Already Queued")) {
            success = 1;
        }
        free_http_response(response);
    } else {
        printf("Node %d: No response to transaction\n", node_id);
    }
    
    free(json_string);
    cJSON_Delete(json);
    
    return success;
}

// Print node status
void print_node_status(int node_id) {
    int length = get_blockchain_length(node_id);
    int responding = is_node_responding(node_id);
    
    printf("Node %d (Port %d): %s, Blockchain Length: %d\n", 
           node_id, BASE_PORT + node_id, 
           responding ? "ONLINE" : "OFFLINE", 
           length);
}

// Print status of all nodes
void print_all_node_status() {
    printf("\n=== Node Status ===\n");
    for (int i = 0; i < NUM_NODES; i++) {
        print_node_status(i);
    }
    printf("==================\n\n");
}

// Wait for all nodes to be online
int wait_for_nodes_online(int timeout_seconds) {
    printf("Waiting for all nodes to come online...\n");
    
    for (int t = 0; t < timeout_seconds; t++) {
        int all_online = 1;
        for (int i = 0; i < NUM_NODES; i++) {
            if (!is_node_responding(i)) {
                all_online = 0;
                break;
            }
        }
        
        if (all_online) {
            printf("All nodes are online after %d seconds\n", t + 1);
            return 1;
        }
        
        sleep(1);
    }
    
    printf("Timeout: Not all nodes came online within %d seconds\n", timeout_seconds);
    return 0;
}

// Check if all nodes have the same blockchain length
int check_consensus(int expected_length) {
    int consensus = 1;
    int first_length = get_blockchain_length(0);
    
    printf("Checking consensus (expected length: %d):\n", expected_length);
    
    for (int i = 0; i < NUM_NODES; i++) {
        int length = get_blockchain_length(i);
        printf("  Node %d: %d blocks\n", i, length);
        
        if (length != first_length || length < expected_length) {
            consensus = 0;
        }
    }
    
    if (consensus && first_length >= expected_length) {
        printf("✓ Consensus achieved: All nodes have %d blocks\n", first_length);
        return first_length;
    } else {
        printf("✗ Consensus failed: Nodes have different blockchain lengths\n");
        return -1;
    }
}

int main() {
    pid_t node_pids[NUM_NODES];
    int test_passed = 1;
    
    printf("=================================================================\n");
    printf("🏗️  Multi-Node PBFT Consensus Test\n");
    printf("=================================================================\n");
    printf("Testing %d PBFT nodes with ports %d-%d\n", 
           NUM_NODES, BASE_PORT, BASE_PORT + NUM_NODES - 1);
    printf("Test duration: %d seconds\n", TEST_DURATION);
    printf("=================================================================\n\n");
    
    // Initialize curl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Start all nodes
    printf("Phase 1: Starting PBFT nodes...\n");
    for (int i = 0; i < NUM_NODES; i++) {
        printf("Starting node %d on port %d...\n", i, BASE_PORT + i);
        
        pid_t pid = fork();
        if (pid == 0) {
            // Child process - start PBFT node
            char node_id_str[16];
            char port_str[16];
            snprintf(node_id_str, sizeof(node_id_str), "%d", i);
            snprintf(port_str, sizeof(port_str), "%d", BASE_PORT + i);
            
            // Redirect output to log files
            char log_file[64];
            snprintf(log_file, sizeof(log_file), "node_%d.log", i);
            freopen(log_file, "w", stdout);
            freopen(log_file, "w", stderr);
            
            execl("./pbft_node", "pbft_node", "--id", node_id_str, "--port", port_str, NULL);
            exit(1);  // If execl fails
        } else if (pid > 0) {
            // Parent process - store PID
            node_pids[i] = pid;
            printf("Node %d started with PID %d\n", i, pid);
        } else {
            printf("Failed to start node %d\n", i);
            test_passed = 0;
            break;
        }
        
        sleep(1);  // Brief delay between node starts
    }
    
    if (!test_passed) {
        printf("Failed to start all nodes\n");
        goto cleanup;
    }
    
    // Wait for nodes to initialize
    printf("\nPhase 2: Waiting for node initialization...\n");
    if (!wait_for_nodes_online(20)) {
        printf("Not all nodes came online - test failed\n");
        test_passed = 0;
        goto cleanup;
    }
    
    print_all_node_status();
    
    // Check initial state
    printf("Phase 3: Checking initial blockchain state...\n");
    int initial_consensus = check_consensus(1);  // Should all have genesis block
    if (initial_consensus < 1) {
        printf("Initial consensus check failed\n");
        test_passed = 0;
        goto cleanup;
    }
    
    // Send test transactions
    printf("\nPhase 4: Sending test transactions...\n");
    int total_transactions = 0;
    for (int round = 1; round <= 3; round++) {
        printf("Transaction round %d:\n", round);
        for (int i = 0; i < NUM_NODES; i++) {
            printf("  Sending transaction %d to node %d...\n", total_transactions + 1, i);
            if (send_test_transaction(i, total_transactions + 1)) {
                total_transactions++;
            }
            sleep(1);
        }
        sleep(2);  // Allow time for transaction processing
    }
    
    printf("Sent %d total transactions\n", total_transactions);
    
    // Monitor consensus for the test duration
    printf("\nPhase 5: Monitoring consensus for %d seconds...\n", TEST_DURATION);
    time_t start_time = time(NULL);
    time_t last_status_time = start_time;
    int last_consensus_length = initial_consensus;
    
    while (time(NULL) - start_time < TEST_DURATION) {
        sleep(2);
        
        // Print status every 10 seconds
        if (time(NULL) - last_status_time >= 10) {
            print_all_node_status();
            last_status_time = time(NULL);
        }
        
        // Check for consensus improvements
        int current_consensus = check_consensus(last_consensus_length);
        if (current_consensus > last_consensus_length) {
            printf("🎉 New consensus achieved! Blockchain grew to %d blocks\n", current_consensus);
            last_consensus_length = current_consensus;
        }
    }
    
    // Final consensus check
    printf("\nPhase 6: Final consensus verification...\n");
    print_all_node_status();
    int final_consensus = check_consensus(1);
    
    if (final_consensus >= initial_consensus) {
        printf("\n✅ MULTI-NODE PBFT TEST PASSED!\n");
        printf("Final Results:\n");
        printf("  - Started: %d nodes\n", NUM_NODES);
        printf("  - All nodes online: ✓\n");
        printf("  - Transactions sent: %d\n", total_transactions);
        printf("  - Final blockchain length: %d blocks\n", final_consensus);
        printf("  - Consensus maintained: ✓\n");
        
        if (final_consensus > initial_consensus) {
            printf("  - New blocks created: %d\n", final_consensus - initial_consensus);
            printf("  - PBFT consensus working: ✓\n");
        }
    } else {
        printf("\n❌ MULTI-NODE PBFT TEST FAILED!\n");
        printf("Consensus was not maintained across all nodes\n");
        test_passed = 0;
    }

cleanup:
    printf("\nPhase 7: Cleaning up...\n");
    
    // Stop all nodes
    for (int i = 0; i < NUM_NODES; i++) {
        if (node_pids[i] > 0) {
            printf("Stopping node %d (PID %d)...\n", i, node_pids[i]);
            kill(node_pids[i], SIGTERM);
        }
    }
    
    // Wait for nodes to stop
    sleep(2);
    for (int i = 0; i < NUM_NODES; i++) {
        if (node_pids[i] > 0) {
            int status;
            waitpid(node_pids[i], &status, WNOHANG);
        }
    }
    
    // Force kill any remaining processes
    system("pkill -f pbft_node");
    
    // Cleanup curl
    curl_global_cleanup();
    
    printf("\n=================================================================\n");
    if (test_passed) {
        printf("🎉 MULTI-NODE PBFT CONSENSUS TEST COMPLETED SUCCESSFULLY!\n");
    } else {
        printf("❌ MULTI-NODE PBFT CONSENSUS TEST FAILED!\n");
    }
    printf("=================================================================\n");
    
    return test_passed ? 0 : 1;
} 