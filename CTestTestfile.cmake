# CMake generated Testfile for 
# Source directory: /home/dolla/TinyWebC
# Build directory: /home/dolla/TinyWebC
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(EncryptionTest "/home/dolla/TinyWebC/tinyweb_tests" "encryption")
set_tests_properties(EncryptionTest PROPERTIES  _BACKTRACE_TRIPLES "/home/dolla/TinyWebC/CMakeLists.txt;37;add_test;/home/dolla/TinyWebC/CMakeLists.txt;0;")
add_test(SigningTest "/home/dolla/TinyWebC/tinyweb_tests" "signing")
set_tests_properties(SigningTest PROPERTIES  _BACKTRACE_TRIPLES "/home/dolla/TinyWebC/CMakeLists.txt;38;add_test;/home/dolla/TinyWebC/CMakeLists.txt;0;")
add_test(BlockchainTest "/home/dolla/TinyWebC/tinyweb_tests" "blockchain")
set_tests_properties(BlockchainTest PROPERTIES  _BACKTRACE_TRIPLES "/home/dolla/TinyWebC/CMakeLists.txt;39;add_test;/home/dolla/TinyWebC/CMakeLists.txt;0;")
