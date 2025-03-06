cmake_minimum_required(VERSION 3.10)
project(CTinyWeb)

# Recursively gather all .c files under src/ and packages/
file(GLOB_RECURSE SOURCES "src/*.c" "packages/structures/merkleTree/*.c")

# Create the executable
add_executable(tinyweb ${SOURCES})

# Include all subdirectories under src/ and packages/ for .h files
include_directories(src packages/structures/merkleTree)

# Find and link libmicrohttpd using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(MICROHTTPD REQUIRED libmicrohttpd)

# Find and link cJSON
find_package(cJSON REQUIRED)
target_link_libraries(tinyweb PRIVATE ${MICROHTTPD_LIBRARIES} cjson)

# Find and link libsodium using pkg-config
pkg_check_modules(SODIUM REQUIRED libsodium)
target_link_libraries(tinyweb PRIVATE ${SODIUM_LIBRARIES})

# Find and link OpenSSL for SHA256
find_package(OpenSSL REQUIRED)
target_link_libraries(tinyweb PRIVATE OpenSSL::Crypto)

# Include directories for all dependencies
target_include_directories(tinyweb PRIVATE ${MICROHTTPD_INCLUDE_DIRS} ${SODIUM_INCLUDE_DIRS} /usr/include/cjson)