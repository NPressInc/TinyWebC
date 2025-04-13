cmake_minimum_required(VERSION 3.10)
project(CTinyWeb)

# Main sources (exclude Merkle tree if not needed)
file(GLOB_RECURSE SOURCES "src/*.c")
list(FILTER SOURCES EXCLUDE REGEX "src/tests/.*")

add_executable(tinyweb ${SOURCES})
include_directories(src) 

# Dependencies (unchanged)
find_package(PkgConfig REQUIRED)
pkg_check_modules(MICROHTTPD REQUIRED libmicrohttpd)
find_package(cJSON REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
find_package(OpenSSL REQUIRED)
target_link_libraries(tinyweb PRIVATE ${MICROHTTPD_LIBRARIES} cjson ${SODIUM_LIBRARIES} OpenSSL::Crypto)
target_include_directories(tinyweb PRIVATE ${MICROHTTPD_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS} /usr/include/cjson)


# Test sources
file(GLOB_RECURSE TEST_SOURCES "src/tests/*.c")
file(GLOB_RECURSE LIB_SOURCES "src/*.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/main.c")
list(FILTER LIB_SOURCES EXCLUDE REGEX "src/tests/.*")

# Ensure test_runner.c is the main entry point for tests
list(FILTER TEST_SOURCES EXCLUDE REGEX "src/tests/test_runner.c")
set(TEST_MAIN "src/tests/test_runner.c")

add_executable(tinyweb_tests ${TEST_MAIN} ${TEST_SOURCES} ${LIB_SOURCES})
target_link_libraries(tinyweb_tests PRIVATE ${MICROHTTPD_LIBRARIES} cjson ${SODIUM_LIBRARIES} OpenSSL::Crypto)
target_include_directories(tinyweb_tests PRIVATE ${MICROHTTPD_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS} /usr/include/cjson src)

# Enable testing and add individual tests
enable_testing()
add_test(NAME EncryptionTest COMMAND tinyweb_tests encryption)
add_test(NAME SigningTest COMMAND tinyweb_tests signing)
add_test(NAME BlockchainTest COMMAND tinyweb_tests blockchain)

# Custom target for "make check"
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS tinyweb_tests
    COMMENT "Running all tests..."
)