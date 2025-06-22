#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <time.h>

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
struct HTTPResponse* make_http_request(const char* url) {
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
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L);

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
int get_blockchain_length() {
    struct HTTPResponse* response = make_http_request("http://localhost:5001/GetBlockChainLength");
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
int is_node_responding() {
    struct HTTPResponse* response = make_http_request("http://localhost:5001/");
    if (response) {
        free_http_response(response);
        return 1;
    }
    return 0;
}

int main() {
    pid_t node_pid;
    
    printf("=================================================================\n");
    printf("🔍 Simple Node Stability Test\n");
    printf("=================================================================\n");
    printf("Testing single PBFT node stability on port 5001\n");
    printf("=================================================================\n\n");
    
    // Initialize curl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Start node
    printf("Phase 1: Starting PBFT node...\n");
    node_pid = fork();
    if (node_pid == 0) {
        // Child process - start PBFT node
        printf("Starting node with output to stdout...\n");
        execl("./pbft_node", "pbft_node", "--id", "0", "--port", "5001", NULL);
        exit(1);  // If execl fails
    } else if (node_pid > 0) {
        printf("Node started with PID %d\n", node_pid);
    } else {
        printf("Failed to start node\n");
        return 1;
    }
    
    // Wait for node to initialize
    printf("\nPhase 2: Waiting for node initialization...\n");
    for (int i = 0; i < 10; i++) {
        sleep(1);
        if (is_node_responding()) {
            printf("Node is responding after %d seconds\n", i + 1);
            break;
        }
        printf("Waiting... (%d/10)\n", i + 1);
    }
    
    if (!is_node_responding()) {
        printf("Node failed to come online\n");
        kill(node_pid, SIGTERM);
        return 1;
    }
    
    // Monitor node for 30 seconds
    printf("\nPhase 3: Monitoring node stability for 30 seconds...\n");
    int stable_count = 0;
    int total_checks = 0;
    
    for (int i = 0; i < 30; i++) {
        sleep(1);
        total_checks++;
        
        if (is_node_responding()) {
            int length = get_blockchain_length();
            printf("Second %d: Node ONLINE, Blockchain Length: %d\n", i + 1, length);
            stable_count++;
        } else {
            printf("Second %d: Node OFFLINE\n", i + 1);
        }
        
        // Check if process is still running
        int status;
        pid_t result = waitpid(node_pid, &status, WNOHANG);
        if (result != 0) {
            printf("Node process has exited! Status: %d\n", status);
            break;
        }
    }
    
    printf("\nPhase 4: Results...\n");
    printf("Stability: %d/%d checks passed (%.1f%%)\n", 
           stable_count, total_checks, 
           (float)stable_count / total_checks * 100.0);
    
    if (stable_count == total_checks) {
        printf("✅ NODE STABILITY TEST PASSED!\n");
        printf("Node remained stable throughout the test period\n");
    } else {
        printf("❌ NODE STABILITY TEST FAILED!\n");
        printf("Node went offline during the test period\n");
    }
    
    // Cleanup
    printf("\nPhase 5: Cleaning up...\n");
    kill(node_pid, SIGTERM);
    sleep(2);
    
    int status;
    waitpid(node_pid, &status, WNOHANG);
    
    // Force kill if still running
    system("pkill -f pbft_node");
    
    curl_global_cleanup();
    
    printf("\n=================================================================\n");
    printf("Simple Node Stability Test Complete\n");
    printf("=================================================================\n");
    
    return (stable_count == total_checks) ? 0 : 1;
} 