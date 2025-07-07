#!/bin/bash

# CTinyWeb Dependencies Installation Script
# This script installs all required dependencies for building and testing CTinyWeb

set -e  # Exit on any error

echo "🔧 Installing CTinyWeb dependencies..."

# Update package lists
echo "📦 Updating package lists..."
sudo apt-get update

# Install build essentials
echo "🛠️  Installing build tools..."
sudo apt-get install -y \
    build-essential \
    cmake \
    make \
    gcc \
    pkg-config

# Install core libraries
echo "📚 Installing core libraries..."
sudo apt-get install -y \
    libsodium-dev \
    libsqlite3-dev \
    libcjson-dev \
    libcurl4-openssl-dev \
    libmicrohttpd-dev \
    liblz4-dev \
    libp11-kit-dev \
    libssl-dev \
    libcrypto++-dev

# Install additional development tools (optional but helpful)
echo "🔍 Installing development tools..."
sudo apt-get install -y \
    valgrind \
    gdb \
    strace \
    ltrace

echo "✅ All dependencies installed successfully!"

# Verify installation
echo "🧪 Verifying installation..."
echo "CMake version: $(cmake --version | head -n1)"
echo "GCC version: $(gcc --version | head -n1)"
echo "Make version: $(make --version | head -n1)"

echo ""
echo "🚀 Ready to build CTinyWeb!"
echo "Run the following commands to build and test:"
echo "  cd CTinyWeb"
echo "  cmake . && make && ./tinyweb_tests" 