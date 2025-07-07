#!/bin/bash

# CTinyWeb Test Suite Runner
# This script runs the complete test suite for CTinyWeb

set -e  # Exit on any error

echo "🧪 CTinyWeb Test Suite Runner"
echo "=============================="

# Check if we're in the right directory
if [ ! -f "CMakeLists.txt" ]; then
    echo "❌ Error: Must be run from the CTinyWeb root directory"
    echo "Expected to find CMakeLists.txt in current directory"
    exit 1
fi

# Clean previous builds
echo "🧹 Cleaning previous builds..."
if [ -f "Makefile" ]; then
    make clean 2>/dev/null || true
fi
rm -f tinyweb tinyweb_tests pbft_node init_tool 2>/dev/null || true

# Build the project
echo "🔨 Building CTinyWeb..."
echo "Running: cmake ."
cmake .

echo "Running: make"
make

# Verify executables were created
echo "✅ Verifying build artifacts..."
if [ ! -f "tinyweb_tests" ]; then
    echo "❌ Error: tinyweb_tests executable not found"
    exit 1
fi

if [ ! -f "tinyweb" ]; then
    echo "❌ Error: tinyweb executable not found"
    exit 1
fi

echo "✅ Build completed successfully"

# Run the test suite
echo ""
echo "🚀 Running test suite..."
echo "========================"
./tinyweb_tests

# Check test results
if [ $? -eq 0 ]; then
    echo ""
    echo "✅ All tests passed!"
    echo "🎉 CTinyWeb is ready for commit"
    exit 0
else
    echo ""
    echo "❌ Tests failed!"
    echo "🚫 Please fix failing tests before committing"
    exit 1
fi 