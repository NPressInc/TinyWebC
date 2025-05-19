#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "init.h"

void print_usage(const char* program_name) {
    printf("Usage: %s [options]\n", program_name);
    printf("Options:\n");
    printf("  -n, --nodes N       Number of nodes to create (default: 3)\n");
    printf("  -u, --users N       Number of users to create (default: 3)\n");
    printf("  -k, --keystore PATH Path to keystore (default: state/keys/)\n");
    printf("  -b, --blockchain PATH Path to blockchain (default: state/blockchain/)\n");
    printf("  -p, --passphrase S  Passphrase for keystore (default: testpass)\n");
    printf("  -P, --port N        Base port number (default: 8000)\n");
    printf("  -h, --help          Show this help message\n");
}

int main(int argc, char* argv[]) {
    InitConfig config = {
        .keystore_path = "state/keys/",
        .blockchain_path = "state/blockchain/",
        .passphrase = "testpass",
        .base_port = BASE_PORT,
        .node_count = 3,
        .user_count = 3
    };

    static struct option long_options[] = {
        {"nodes", required_argument, 0, 'n'},
        {"users", required_argument, 0, 'u'},
        {"keystore", required_argument, 0, 'k'},
        {"blockchain", required_argument, 0, 'b'},
        {"passphrase", required_argument, 0, 'p'},
        {"port", required_argument, 0, 'P'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "n:u:k:b:p:P:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'n':
                config.node_count = (uint32_t)strtoul(optarg, NULL, 10);
                if (config.node_count > MAX_NODES) {
                    fprintf(stderr, "Error: Maximum number of nodes is %d\n", MAX_NODES);
                    return 1;
                }
                break;
            case 'u':
                config.user_count = (uint32_t)strtoul(optarg, NULL, 10);
                if (config.user_count > MAX_USERS) {
                    fprintf(stderr, "Error: Maximum number of users is %d\n", MAX_USERS);
                    return 1;
                }
                break;
            case 'k':
                config.keystore_path = optarg;
                break;
            case 'b':
                config.blockchain_path = optarg;
                break;
            case 'p':
                config.passphrase = optarg;
                break;
            case 'P':
                config.base_port = (uint16_t)strtoul(optarg, NULL, 10);
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    printf("Initializing network with:\n");
    printf("  Nodes: %u\n", config.node_count);
    printf("  Users: %u\n", config.user_count);
    printf("  Keystore: %s\n", config.keystore_path);
    printf("  Blockchain: %s\n", config.blockchain_path);
    printf("  Base Port: %u\n", config.base_port);

    int result = initialize_network(&config);
    if (result != 0) {
        fprintf(stderr, "Error: Network initialization failed\n");
        return 1;
    }

    printf("Network initialization completed successfully\n");
    return 0;
} 