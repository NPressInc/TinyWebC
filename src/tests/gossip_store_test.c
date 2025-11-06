#include "tests/gossip_store_test.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "packages/sql/database_gossip.h"
#include "packages/sql/gossip_store.h"
#include "packages/sql/gossip_peers.h"
#include "packages/initialization/init.h"

// Include implementation to exercise initialize_network in tests
#include "packages/initialization/init.c"

#define ASSERT_OR_FAIL(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "[gossip_store_test] %s\n", msg); \
            return -1; \
        } \
    } while (0)

static void ensure_directory_exists(const char* path) {
    if (mkdir(path, 0755) == -1 && errno != EEXIST) {
        fprintf(stderr, "Failed to create directory %s: %s\n", path, strerror(errno));
    }
}

static void cleanup_path_recursive(const char* path) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
    system(cmd);
}

static int test_gossip_seen_cache(void) {
    printf("  - verifying gossip_seen cache lifecycle...\n");

    ensure_directory_exists("test_state");
    const char* db_path = "test_state/gossip_seen_test.db";
    remove(db_path);

    ASSERT_OR_FAIL(db_init_gossip(db_path) == 0, "db_init_gossip failed");
    ASSERT_OR_FAIL(gossip_store_init() == 0, "gossip_store_init failed");

    unsigned char digest[GOSSIP_SEEN_DIGEST_SIZE];
    for (size_t i = 0; i < GOSSIP_SEEN_DIGEST_SIZE; ++i) {
        digest[i] = (unsigned char)(i + 1);
    }

    int seen = 0;
    ASSERT_OR_FAIL(gossip_store_has_seen(digest, &seen) == 0, "has_seen initial query failed");
    ASSERT_OR_FAIL(seen == 0, "digest unexpectedly marked as seen");

    uint64_t now = (uint64_t)time(NULL);
    ASSERT_OR_FAIL(gossip_store_mark_seen(digest, now + 5) == 0, "mark_seen failed");

    seen = 0;
    ASSERT_OR_FAIL(gossip_store_has_seen(digest, &seen) == 0, "has_seen after mark failed");
    ASSERT_OR_FAIL(seen == 1, "digest was not recorded as seen");

    ASSERT_OR_FAIL(gossip_store_cleanup(now + 10) == 0, "cleanup failed");

    seen = 1;
    ASSERT_OR_FAIL(gossip_store_has_seen(digest, &seen) == 0, "has_seen after cleanup failed");
    ASSERT_OR_FAIL(seen == 0, "digest was not expired by cleanup");

    ASSERT_OR_FAIL(db_close() == 0, "db_close failed");
    remove(db_path);

    printf("    ✓ gossip_seen lifecycle verified\n");
    return 0;
}

static int query_single_int(sqlite3* db, const char* sql, int* out_value) {
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        *out_value = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        return 0;
    }
    sqlite3_finalize(stmt);
    return -1;
}

static int test_initialize_network_seeding(void) {
    printf("  - verifying initialize_network seeding behavior...\n");

    cleanup_path_recursive("test_state");

    InitNodeConfig nodes[1];
    memset(&nodes, 0, sizeof(nodes));

    static char node_id[] = "node_001";
    static char node_name[] = "Test Node";
    static char node_type[] = "primary";
    static char hostname[] = "node1.test-tailnet.ts.net";
    static char tags[] = "tag:test";

    nodes[0].id = node_id;
    nodes[0].name = node_name;
    nodes[0].type = node_type;
    nodes[0].hostname = hostname;
    nodes[0].gossip_port = 9100;
    nodes[0].api_port = 8100;
    nodes[0].tags = tags;
    nodes[0].peers = NULL;
    nodes[0].peer_count = 0;

    InitUserRecord admins[1];
    memset(admins, 0, sizeof(admins));
    static char admin_id[] = "admin_001";
    static char admin_name[] = "Alice";
    static char admin_role[] = "admin";
    admins[0].id = admin_id;
    admins[0].name = admin_name;
    admins[0].role = admin_role;
    admins[0].age = 42;

    InitUserRecord members[1];
    memset(members, 0, sizeof(members));
    static char member_id[] = "member_001";
    static char member_name[] = "Bob";
    static char member_role[] = "member";
    members[0].id = member_id;
    members[0].name = member_name;
    members[0].role = member_role;
    members[0].age = 12;

    InitUsersConfig users = {
        .admins = admins,
        .admin_count = 1,
        .members = members,
        .member_count = 1
    };

    InitNetworkConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.network_name = "Test Gossip Network";
    cfg.base_port = 9000;
    cfg.node_count = 1;
    cfg.debug_mode = 1;
    cfg.nodes = nodes;
    cfg.users = users;

    ASSERT_OR_FAIL(initialize_network(&cfg) == 0, "initialize_network failed");

    const char* db_path = "test_state/node_1/blockchain/blockchain.db";
    sqlite3* db = NULL;
    ASSERT_OR_FAIL(sqlite3_open(db_path, &db) == SQLITE_OK, "Failed to open seeded database");

    int value = 0;
    ASSERT_OR_FAIL(query_single_int(db, "SELECT COUNT(*) FROM roles", &value) == 0, "roles query failed");
    ASSERT_OR_FAIL(value >= 2, "roles not seeded");

    ASSERT_OR_FAIL(query_single_int(db, "SELECT COUNT(*) FROM permissions", &value) == 0, "permissions query failed");
    ASSERT_OR_FAIL(value >= 2, "permissions not seeded");

    ASSERT_OR_FAIL(query_single_int(db, "SELECT COUNT(*) FROM users", &value) == 0, "users query failed");
    ASSERT_OR_FAIL(value == 2, "unexpected user count");

    ASSERT_OR_FAIL(query_single_int(db, "SELECT COUNT(*) FROM transaction_permissions", &value) == 0, "txn permissions query failed");
    ASSERT_OR_FAIL(value > 0, "transaction permissions not seeded");

    ASSERT_OR_FAIL(query_single_int(db, "SELECT COUNT(*) FROM gossip_peers", &value) == 0, "gossip_peers query failed");
    ASSERT_OR_FAIL(value >= 1, "gossip peers not seeded");

    sqlite3_close(db);

    cleanup_path_recursive("test_state");

    printf("    ✓ initialize_network seeding verified\n");
    return 0;
}

int gossip_store_test_main(void) {
    int failures = 0;

    if (test_gossip_seen_cache() != 0) {
        failures++;
    }

    if (test_initialize_network_seeding() != 0) {
        failures++;
    }

    return (failures == 0) ? 0 : -1;
}

