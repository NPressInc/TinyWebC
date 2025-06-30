cmake_minimum_required(VERSION 3.10)
project(CTinyWeb)

# Mongoose configuration - add these compile definitions for optimal performance
add_compile_definitions(
    MG_ENABLE_IPV6=1
    MG_ENABLE_LOG=1
    MG_ENABLE_DIRECTORY_LISTING=1
    MG_ENABLE_SSI=0
    MG_MAX_HTTP_REQUEST_SIZE=8192
)

# Main sources (exclude Merkle tree if not needed)
file(GLOB_RECURSE SOURCES "src/*.c")
list(FILTER SOURCES EXCLUDE REGEX "src/tests/.*")
list(FILTER SOURCES EXCLUDE REGEX "src/packages/initialization/init_tool.c")
list(FILTER SOURCES EXCLUDE REGEX "src/packages/PBFT/pbftMain.c")

# Explicitly ensure mongoose source is included
set(MONGOOSE_SOURCES
    src/external/mongoose/mongoose.c
)

add_executable(tinyweb ${SOURCES})
include_directories(src) 

# Dependencies (unchanged)
find_package(PkgConfig REQUIRED)
pkg_check_modules(MICROHTTPD REQUIRED libmicrohttpd)
find_package(cJSON REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
find_package(OpenSSL REQUIRED)
pkg_check_modules(LZ4 REQUIRED liblz4)
find_package(SQLite3 REQUIRED)
find_package(CURL REQUIRED)

target_link_libraries(tinyweb PRIVATE 
    ${MICROHTTPD_LIBRARIES} 
    cjson 
    ${SODIUM_LIBRARIES} 
    OpenSSL::Crypto
    ${LZ4_LIBRARIES}
    SQLite::SQLite3
    pthread  # Mongoose uses pthreads for async operations
    m        # Math library for mongoose
)

target_include_directories(tinyweb PRIVATE 
    ${MICROHTTPD_INCLUDE_DIRS} 
    ${SODIUM_INCLUDE_DIRS} 
    /usr/include/cjson
    ${LZ4_INCLUDE_DIRS}
    src/external/mongoose  # Add mongoose include directory
)

# Test sources
file(GLOB_RECURSE TEST_SOURCES "src/tests/*.c")
file(GLOB_RECURSE LIB_SOURCES "src/*.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/main.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/tests/.*")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/packages/initialization/init_tool.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/packages/PBFT/pbftMain.c")
# Note: init_network_test.c is now included since it has init_network_test_main instead of main

# Ensure test_runner.c is the main entry point for tests
list(FILTER TEST_SOURCES EXCLUDE REGEX "src/tests/test_runner.c")
set(TEST_MAIN "src/tests/test_runner.c")

add_executable(tinyweb_tests ${TEST_MAIN} ${TEST_SOURCES} ${LIB_SOURCES})
target_link_libraries(tinyweb_tests PRIVATE 
    ${MICROHTTPD_LIBRARIES} 
    cjson 
    ${SODIUM_LIBRARIES} 
    OpenSSL::Crypto
    ${LZ4_LIBRARIES}
    SQLite::SQLite3
    pthread  # Mongoose uses pthreads for async operations
    m        # Math library for mongoose
)

target_include_directories(tinyweb_tests PRIVATE 
    ${MICROHTTPD_INCLUDE_DIRS} 
    ${SODIUM_INCLUDE_DIRS} 
    /usr/include/cjson 
    ${LZ4_INCLUDE_DIRS}
    src
    src/external/mongoose  # Add mongoose include directory
)

# Enable testing and add individual tests
enable_testing()
add_test(NAME EncryptionTest COMMAND tinyweb_tests encryption)
add_test(NAME SigningTest COMMAND tinyweb_tests signing)
add_test(NAME BlockchainTest COMMAND tinyweb_tests blockchain)
add_test(NAME InitNetworkTest COMMAND tinyweb_tests init_network)
add_test(NAME MongooseTest COMMAND tinyweb_tests mongoose)

# Custom target for "make check"
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS tinyweb_tests
    COMMENT "Running all tests..."
)

# Add PBFT Node executable
add_executable(pbft_node
    src/packages/PBFT/pbftMain.c
    src/packages/PBFT/pbftNode.c
    src/packages/PBFT/node.c
    src/packages/comm/pbftApi.c
    src/packages/comm/blockChainQueryApi.c
    src/packages/comm/httpClient.c
    src/packages/utils/jsonUtils.c
    src/packages/keystore/keystore.c
    src/packages/signing/signing.c
    src/packages/structures/blockChain/blockchain.c
    src/packages/structures/blockChain/block.c
    src/packages/structures/blockChain/transaction.c
    src/packages/structures/blockChain/transaction_types.c
    src/packages/structures/blockChain/internalTransaction.c
    src/packages/structures/blockChain/merkleTree.c
    src/packages/structures/blockChain/merkleTreeNode.c
    src/packages/fileIO/blockchainIO.c
    src/packages/encryption/encryption.c
    src/packages/utils/byteorder.c
    src/packages/fileIO/compression.c
    src/packages/sql/database.c
    src/packages/sql/schema.c
    src/packages/sql/queries.c
    src/packages/validation/block_validation.c
    src/packages/validation/transaction_validation.c
    src/structs/permission/permission.c
    src/packages/invitation/invitation.c
    src/packages/invitation/invitationApi.c
    src/external/mongoose/mongoose.c
)

target_include_directories(pbft_node PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${MICROHTTPD_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
    /usr/include/cjson
    ${LZ4_INCLUDE_DIRS}
    src/external/mongoose
)

target_link_libraries(pbft_node
    ${MICROHTTPD_LIBRARIES}
    cjson
    ${SODIUM_LIBRARIES}
    OpenSSL::Crypto
    ${LZ4_LIBRARIES}
    SQLite::SQLite3
    pthread
    m
    ${CURL_LIBRARIES}  # For HTTP client functionality
)

# Add a separate executable for the initialization tool
add_executable(init_tool
    src/packages/initialization/init_tool.c
    src/packages/initialization/init.c
    src/packages/keystore/keystore.c
    src/packages/signing/signing.c
    src/packages/structures/blockChain/blockchain.c
    src/packages/structures/blockChain/block.c
    src/packages/structures/blockChain/merkleTree.c
    src/packages/structures/blockChain/merkleTreeNode.c
    src/packages/fileIO/blockchainIO.c
    src/packages/encryption/encryption.c
    src/packages/structures/blockChain/transaction.c
    src/packages/structures/blockChain/transaction_types.c
    src/packages/utils/byteorder.c
    src/packages/fileIO/compression.c
    src/packages/sql/database.c
    src/packages/sql/schema.c
    src/packages/sql/queries.c
    # Add any other required source files here
)

target_include_directories(init_tool PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${MICROHTTPD_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
    /usr/include/cjson
    ${LZ4_INCLUDE_DIRS}
)

target_link_libraries(init_tool
    ${SODIUM_LIBRARIES}
    OpenSSL::Crypto
    ${LZ4_LIBRARIES}
    cjson
    SQLite::SQLite3
)

# Multi-node PBFT test is built separately in the root directory

# Add simple node test
add_executable(simple_node_test
    simple_node_test.c
)

target_link_libraries(simple_node_test 
    ${CURL_LIBRARIES}
    cjson
)

# Add fixed multi-node PBFT architecture test
add_executable(multi_node_pbft_test_fixed
    multi_node_pbft_test_fixed.c
)

target_link_libraries(multi_node_pbft_test_fixed 
    ${CURL_LIBRARIES}
    cjson
)