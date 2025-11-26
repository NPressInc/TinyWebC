cmake_minimum_required(VERSION 3.10)
project(CTinyWeb)

# AddressSanitizer support (optional)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address)
    message(STATUS "AddressSanitizer enabled")
endif()

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
list(FILTER SOURCES EXCLUDE REGEX "src/packages/initialization/.*")
list(FILTER SOURCES EXCLUDE REGEX "src/packages/comm/pbft.*")
list(FILTER SOURCES EXCLUDE REGEX "src/packages/comm/blockChainQueryApi.c")
list(FILTER SOURCES EXCLUDE REGEX "src/packages/comm/accessApi.c")
list(FILTER SOURCES EXCLUDE REGEX "src/packages/comm/httpClient.c")
list(FILTER SOURCES EXCLUDE REGEX "src/packages/sql/database.c")
list(FILTER SOURCES EXCLUDE REGEX "src/packages/sql/queries.c")
list(FILTER SOURCES EXCLUDE REGEX "src/packages/sql/schema.c")
list(FILTER SOURCES EXCLUDE REGEX "src/packages/validation/block_validation.c")
list(FILTER SOURCES EXCLUDE REGEX "src/packages/validation/transaction_validation.c")
list(FILTER SOURCES EXCLUDE REGEX "pbft_node_runner.c")

# Explicitly ensure mongoose source is included
set(MONGOOSE_SOURCES
    src/external/mongoose/mongoose.c
)

# Gossip-only database layer
set(GOSSIP_DB_SOURCES
    src/packages/sql/database_gossip.c
    src/packages/sql/permissions.c
    src/packages/sql/schema.c
)

# Protobuf-C generation for envelope/content
find_program(PROTOC_EXECUTABLE protoc)
find_program(PROTOC_C_EXECUTABLE protoc-c)
find_package(PkgConfig REQUIRED)
pkg_check_modules(PROTOBUFC REQUIRED libprotobuf-c)

set(PROTO_DIR ${CMAKE_SOURCE_DIR}/src/proto)
set(GEN_DIR ${CMAKE_BINARY_DIR}/generated)
file(MAKE_DIRECTORY ${GEN_DIR})

set(PROTO_FILES
    ${PROTO_DIR}/envelope.proto
    ${PROTO_DIR}/content.proto
    ${PROTO_DIR}/api.proto
)

set(GENERATED_SOURCES)
set(GENERATED_HEADERS)
foreach(PF ${PROTO_FILES})
    get_filename_component(BN ${PF} NAME_WE)
    set(OUT_C ${GEN_DIR}/${BN}.pb-c.c)
    set(OUT_H ${GEN_DIR}/${BN}.pb-c.h)
    add_custom_command(
        OUTPUT ${OUT_C} ${OUT_H}
        COMMAND ${PROTOC_C_EXECUTABLE} --c_out=${GEN_DIR} -I ${PROTO_DIR} ${PF}
        DEPENDS ${PF}
        COMMENT "Generating protobuf-c for ${PF}"
        VERBATIM
    )
    list(APPEND GENERATED_SOURCES ${OUT_C})
    list(APPEND GENERATED_HEADERS ${OUT_H})
endforeach()

# Create a custom target for protobuf generation
add_custom_target(generate_proto DEPENDS ${GENERATED_SOURCES} ${GENERATED_HEADERS})

add_executable(tinyweb ${SOURCES})
include_directories(src) 
target_sources(tinyweb PRIVATE ${GENERATED_SOURCES} ${GOSSIP_DB_SOURCES})
target_include_directories(tinyweb PRIVATE ${GEN_DIR})
add_dependencies(tinyweb generate_proto)

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
    ${PROTOBUFC_LIBRARIES}
    pthread  # Mongoose uses pthreads for async operations
    m        # Math library for mongoose
)

target_include_directories(tinyweb PRIVATE 
    ${MICROHTTPD_INCLUDE_DIRS} 
    ${SODIUM_INCLUDE_DIRS} 
    /usr/include/cjson
    ${LZ4_INCLUDE_DIRS}
    ${PROTOBUFC_INCLUDE_DIRS}
    src/external/mongoose  # Add mongoose include directory
)

# Test sources
file(GLOB_RECURSE TEST_SOURCES "src/tests/*.c")
file(GLOB_RECURSE LIB_SOURCES "src/*.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/main.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/tests/.*")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/packages/initialization/.*")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/packages/comm/pbft.*")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/packages/comm/blockChainQueryApi.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/packages/comm/accessApi.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/packages/comm/httpClient.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/packages/sql/database.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/packages/sql/queries.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/packages/sql/schema.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/packages/validation/block_validation.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/packages/validation/transaction_validation.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "pbft_node_runner.c")

# Ensure test_runner.c is the main entry point for tests
list(FILTER TEST_SOURCES EXCLUDE REGEX "src/tests/test_runner.c")
set(TEST_MAIN "src/tests/test_runner.c")

add_executable(tinyweb_tests ${TEST_MAIN} ${TEST_SOURCES} ${LIB_SOURCES} 
    scripts/init.c
    src/packages/comm/httpClient.c
    src/packages/sql/schema.c)
target_sources(tinyweb_tests PRIVATE ${GENERATED_SOURCES} ${GOSSIP_DB_SOURCES})
add_dependencies(tinyweb_tests generate_proto)
target_link_libraries(tinyweb_tests PRIVATE 
    ${MICROHTTPD_LIBRARIES} 
    cjson 
    ${SODIUM_LIBRARIES} 
    OpenSSL::Crypto
    ${LZ4_LIBRARIES}
    SQLite::SQLite3
    ${PROTOBUFC_LIBRARIES}
    pthread  # Mongoose uses pthreads for async operations
    m        # Math library for mongoose
)

target_include_directories(tinyweb_tests PRIVATE 
    ${MICROHTTPD_INCLUDE_DIRS} 
    ${SODIUM_INCLUDE_DIRS} 
    /usr/include/cjson 
    ${LZ4_INCLUDE_DIRS}
    ${PROTOBUFC_INCLUDE_DIRS}
    ${GEN_DIR}
    src
    scripts
    src/external/mongoose  # Add mongoose include directory
)

# Enable testing and add individual tests
enable_testing()
add_test(NAME EncryptionTest COMMAND tinyweb_tests encryption)
add_test(NAME SigningTest COMMAND tinyweb_tests signing)
add_test(NAME MongooseTest COMMAND tinyweb_tests mongoose)



# Add init_tool executable (before blockchain subdirectory)
add_executable(init_tool 
    scripts/init_tool.c 
    scripts/init.c
    src/packages/sql/schema.c
    src/packages/sql/gossip_peers.c
    src/packages/utils/logger.c
    src/packages/utils/error.c
    src/structs/permission/permission.c
)
target_sources(init_tool PRIVATE ${GOSSIP_DB_SOURCES})
target_link_libraries(init_tool PRIVATE 
    cjson 
    ${SODIUM_LIBRARIES} 
    SQLite::SQLite3
    pthread
    m
)
target_include_directories(init_tool PRIVATE 
    ${SODIUM_INCLUDE_DIRS} 
    /usr/include/cjson 
    src
    scripts
)

