set(PBFT_FEATURE_ROOT ${CMAKE_SOURCE_DIR}/src/features/blockchain)

file(GLOB_RECURSE BLOCKCHAIN_CORE_SOURCES
    "${PBFT_FEATURE_ROOT}/core/*.c"
    "${PBFT_FEATURE_ROOT}/persistence/*.c"
    "${PBFT_FEATURE_ROOT}/pbft/*.c"
)

# Exclude the application entry point from the shared support library
list(FILTER BLOCKCHAIN_CORE_SOURCES EXCLUDE REGEX "${PBFT_FEATURE_ROOT}/app/.*")

set(PBFT_PACKAGE_SOURCES
    ${CMAKE_SOURCE_DIR}/src/packages/transactions/transaction.c
    ${CMAKE_SOURCE_DIR}/src/packages/comm/pbftApi.c
    ${CMAKE_SOURCE_DIR}/src/packages/comm/blockChainQueryApi.c
    ${CMAKE_SOURCE_DIR}/src/packages/comm/accessApi.c
    ${CMAKE_SOURCE_DIR}/src/packages/comm/httpClient.c
    ${CMAKE_SOURCE_DIR}/src/packages/comm/nodeApi.c
    ${CMAKE_SOURCE_DIR}/src/packages/sql/database.c
    ${CMAKE_SOURCE_DIR}/src/packages/sql/schema.c
    ${CMAKE_SOURCE_DIR}/src/packages/sql/queries.c
    ${CMAKE_SOURCE_DIR}/src/packages/utils/statePaths.c
    ${CMAKE_SOURCE_DIR}/src/packages/utils/byteorder.c
    ${CMAKE_SOURCE_DIR}/src/packages/utils/jsonUtils.c
    ${CMAKE_SOURCE_DIR}/src/packages/utils/print.c
    ${CMAKE_SOURCE_DIR}/src/packages/encryption/encryption.c
    ${CMAKE_SOURCE_DIR}/src/packages/signing/signing.c
    ${CMAKE_SOURCE_DIR}/src/packages/keystore/keystore.c
    ${CMAKE_SOURCE_DIR}/src/packages/fileIO/compression.c
    ${CMAKE_SOURCE_DIR}/src/structs/permission/permission.c
)

add_library(pbft_support STATIC
    ${BLOCKCHAIN_CORE_SOURCES}
    ${PBFT_PACKAGE_SOURCES}
)

target_include_directories(pbft_support PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${MICROHTTPD_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
    /usr/include/cjson
    ${LZ4_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/src/external/mongoose
)

target_link_libraries(pbft_support PUBLIC
    ${MICROHTTPD_LIBRARIES}
    cjson
    ${SODIUM_LIBRARIES}
    OpenSSL::Crypto
    ${LZ4_LIBRARIES}
    SQLite::SQLite3
    pthread
    m
)

add_executable(tinyweb_pbft
    ${PBFT_FEATURE_ROOT}/app/main_pbft.c
)
target_link_libraries(tinyweb_pbft PRIVATE pbft_support)

add_executable(pbft_node_runner
    ${CMAKE_SOURCE_DIR}/pbft_node_runner.c
)
target_link_libraries(pbft_node_runner PRIVATE pbft_support)

add_executable(init_tool
    ${CMAKE_SOURCE_DIR}/src/packages/initialization/init_tool.c
    ${CMAKE_SOURCE_DIR}/src/packages/initialization/init.c
)
target_link_libraries(init_tool PRIVATE pbft_support)

set(PBFT_TEST_SOURCES
    ${CMAKE_SOURCE_DIR}/src/tests/test_runner.c
    ${CMAKE_SOURCE_DIR}/src/tests/blockchain_test.c
    ${CMAKE_SOURCE_DIR}/src/tests/database_test.c
    ${CMAKE_SOURCE_DIR}/src/tests/access_request_test.c
    ${CMAKE_SOURCE_DIR}/src/tests/node_peer_management_test.c
    ${CMAKE_SOURCE_DIR}/src/tests/pbft_http_client_test.c
    ${CMAKE_SOURCE_DIR}/src/tests/pbft_integration_test.c
    ${CMAKE_SOURCE_DIR}/src/tests/init_network_test.c
)

add_executable(tinyweb_pbft_tests ${PBFT_TEST_SOURCES})
target_link_libraries(tinyweb_pbft_tests PRIVATE pbft_support)

if (BUILD_TESTING)
    add_test(NAME PbftBlockchainTest COMMAND tinyweb_pbft_tests blockchain)
    add_test(NAME PbftDatabaseTest COMMAND tinyweb_pbft_tests database)
    add_test(NAME PbftAccessRequestTest COMMAND tinyweb_pbft_tests access_request)
    add_test(NAME PbftNodePeerTest COMMAND tinyweb_pbft_tests node_peer_management)
    add_test(NAME PbftHttpClientTest COMMAND tinyweb_pbft_tests pbft_http_client)
    add_test(NAME PbftIntegrationTest COMMAND tinyweb_pbft_tests pbft_integration)
    add_test(NAME PbftInitNetworkTest COMMAND tinyweb_pbft_tests init_network)
endif()

