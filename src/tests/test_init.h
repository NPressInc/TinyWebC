#ifndef TEST_INIT_H
#define TEST_INIT_H

// Initialize test environment using full network config
// Reads network_config.json and initializes in test_state/ directory
int test_init_environment(void);

// Cleanup test state
void test_cleanup_environment(void);

// Get test paths
const char* test_get_base_path(void);          // Returns "test_state"
const char* test_get_db_path(void);            // Returns "test_state/database/gossip.db"
const char* test_get_keys_dir(void);           // Returns "test_state/keys/users"
const char* test_get_user_key_path(const char* user_id);  // Returns path to specific user key

#endif // TEST_INIT_H

