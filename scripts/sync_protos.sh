#!/bin/bash
# Sync proto files from source of truth (src/proto/) to all client applications
# This ensures all clients stay in sync with the backend proto definitions

set -e  # Exit on error

# Get the script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PROTO_SOURCE="$PROJECT_ROOT/src/proto"

# Check that source directory exists
if [ ! -d "$PROTO_SOURCE" ]; then
    echo "Error: Proto source directory not found: $PROTO_SOURCE"
    exit 1
fi

# Count proto files in source
PROTO_COUNT=$(find "$PROTO_SOURCE" -name "*.proto" | wc -l)
if [ "$PROTO_COUNT" -eq 0 ]; then
    echo "Warning: No .proto files found in $PROTO_SOURCE"
    exit 1
fi

echo "Found $PROTO_COUNT proto file(s) in $PROTO_SOURCE"
echo ""

# Function to sync proto files to a client
sync_to_client() {
    local CLIENT_NAME=$1
    local CLIENT_PROTO_DIR=$2
    
    if [ ! -d "$CLIENT_PROTO_DIR" ]; then
        echo "  ⚠️  Skipping $CLIENT_NAME: directory not found ($CLIENT_PROTO_DIR)"
        return
    fi
    
    echo "  📦 Syncing to $CLIENT_NAME..."
    echo "     Target: $CLIENT_PROTO_DIR"
    
    # Copy all proto files
    cp "$PROTO_SOURCE"/*.proto "$CLIENT_PROTO_DIR/"
    
    # Count copied files
    COPIED=$(find "$CLIENT_PROTO_DIR" -name "*.proto" | wc -l)
    echo "     ✓ Copied $COPIED proto file(s)"
}

# List of clients to sync
# Format: "ClientName:proto_directory_path"
# Add new clients here as they are created
echo "Syncing proto files to clients..."
echo ""

# Web UI (React)
sync_to_client "web-ui" "$PROJECT_ROOT/client/web-ui/src/proto"

# Future clients (uncomment as you add them):
# sync_to_client "mobile-gps" "$PROJECT_ROOT/client/mobile-gps/lib/proto"
# sync_to_client "mobile-messenger" "$PROJECT_ROOT/client/mobile-messenger/lib/proto"

echo ""
echo "✅ Proto sync complete!"

