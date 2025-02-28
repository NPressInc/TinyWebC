cmake_minimum_required(VERSION 3.10)
project(CTinyWeb)

# Recursively gather all .c files under src/
file(GLOB_RECURSE SOURCES "src/*.c")

# Create the executable
add_executable(tinyweb ${SOURCES})

# Include all subdirectories under src/ for .h files
include_directories(src)

# Find and link libmicrohttpd using pkg-config
find_package(PkgConfig REQUIRED)
pkg_check_modules(MICROHTTPD REQUIRED libmicrohttpd)

# Find and link cJSON
find_package(cJSON REQUIRED)
target_link_libraries(tinyweb PRIVATE ${MICROHTTPD_LIBRARIES} cjson)
target_include_directories(tinyweb PRIVATE ${MICROHTTPD_INCLUDE_DIRS} /usr/include/cjson)