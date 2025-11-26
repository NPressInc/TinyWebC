# Repository Review - Docker Initialization Plan Alignment

## Executive Summary

This document reviews the entire CTinyWeb repository to ensure the Docker initialization plan aligns with the actual codebase implementation. Key findings and required adjustments are documented.

## Project Architecture

### Core Components
- **Main Application**: `src/main.c` - Entry point, handles gossip service and HTTP API
- **Gossip Protocol**: `src/packages/comm/gossip/` - UDP-based message propagation
- **HTTP API**: `src/packages/comm/gossipApi.c` - RESTful endpoints for message ingestion
- **Database Layer**: `src/packages/sql/` - SQLite persistence (gossip_store, gossip_peers, permissions)
- **Initialization**: `scripts/init.c` - Node setup, key generation, database seeding
- **Configuration**: `src/packages/utils/config.c` - Loads from `network_config.json`

### State Directory Structure

**Current Implementation:**
- **Production mode**: `state/blockchain/blockchain.db`, `state/keys/node_private.key`
- **Debug mode**: `test_state/node_{id}/blockchain/blockchain.db`, `test_state/node_{id}/keys/node_private.key`
- **Config files**: `state/node_{id}/network_config.json` (production) or `test_state/node_{id}/network_config.json` (debug)

**Init Tool Structure:**
- Uses: `{base_path}/database/gossip.db` (different from main app!)
- Creates: `{base_path}/database/`, `{base_path}/keys/`

**⚠️ INCONSISTENCY FOUND**: Init tool uses `database/gossip.db` but main app expects `blockchain/blockchain.db`

### Node ID Format

**Current Implementation:**
- Config loading: `node_%03u` (3 digits, zero-padded) - `node_001`, `node_002`, etc.
- State paths (debug): `node_%u` (no padding) - `node_1`, `node_2`, etc.
- State paths (production): No node ID in path (single node per machine)

**⚠️ INCONSISTENCY FOUND**: Config uses 3-digit format, state paths use unpadded format in debug mode

### Peer Discovery

**Current Implementation:**
- `bootstrap_known_peers()` in `main.c` loads peers from database on startup
- No dynamic discovery mechanism exists yet
- Peers stored in `gossip_peers` table with: `hostname`, `gossip_port`, `api_port`, `first_seen`, `last_seen`, `tags`
- `gossip_service_add_peer()` adds peers to in-memory `GossipService` structure
- Max peers: `GOSSIP_MAX_PEERS = 32`

**Required for Plan:**
- Discovery module (`src/packages/discovery/`) - **NOT YET IMPLEMENTED**
- Discovery modes: Tailscale, DNS pattern, Static - **NOT YET IMPLEMENTED**
- Dynamic peer addition on message receive - **NOT YET IMPLEMENTED**

### Node Registration Message

**Current Implementation:**
- Protobuf message exists: `NodeRegistration` in `content.proto`
- Content type: `CONTENT_NODE_REGISTRATION = 40`
- Fields: `node_pubkey`, `node_address`, `node_port`, `node_version`, `stake_proof`
- Handler exists in `envelope_dispatcher.c` but may not be fully implemented

**Required for Plan:**
- Helper function to send node announcement - **NOT YET IMPLEMENTED**
- Handler to process node announcements and add peers - **NOT YET IMPLEMENTED**

### Configuration Loading

**Current Implementation:**
- `config_load_node_from_network_config()` in `config.c`
- Loads from: `state/node_{id}/network_config.json` or `test_state/node_{id}/network_config.json`
- Reads: `node_id`, `node_name`, `hostname`, `gossip_port`, `api_port`, `peers[]`
- No discovery mode field exists yet

**Required for Plan:**
- Add `discovery_mode` field to `NodeConfig` struct
- Read `discovery_mode` from config JSON
- Read `hostname_prefix` and `domain` from discovery config section

### Gossip Service

**Current Implementation:**
- `GossipService` structure with `peers[]` array (max 32)
- `gossip_service_add_peer()` - adds peer to in-memory list
- `gossip_service_broadcast_envelope()` - sends to all peers
- `gossip_service_rebroadcast_envelope()` - sends to all except source
- `gossip_receive_handler()` in `main.c` - processes received messages
- Uses `getaddrinfo()` for DNS resolution of peer addresses

**Required for Plan:**
- Modify `gossip_receive_handler()` to dynamically add unknown peers
- Use reverse DNS (`gethostbyaddr()`) to resolve source hostname

### Port Configuration

**Current Implementation:**
- Fixed ports per node: `gossip_port` and `api_port` from config
- Command-line overrides: `-g/--gossip-port`, `-p/--api-port`
- Defaults: gossip=9000, api=8000

**Plan Alignment:**
- ✅ Plan correctly specifies fixed ports (8000/9000) for all nodes in Docker
- ✅ Each container has isolated network namespace, so no conflicts

### Docker Integration Points

**Current State:**
- No Docker files exist yet
- No Docker Compose files exist yet
- No config generator script exists yet

**Required:**
- `scripts/docker_config_generator.py` - **NOT YET IMPLEMENTED**
- `scripts/Dockerfile.node` - **NOT YET IMPLEMENTED**
- `docker-compose.yml` templates - **NOT YET IMPLEMENTED**
- Tailscale sidecar integration - **NOT YET IMPLEMENTED**

## Critical Issues to Address

### 1. Database Path Inconsistency
**Problem**: Init tool creates `{base_path}/database/gossip.db` but main app expects `{base_path}/blockchain/blockchain.db`

**Solution Options:**
- **Option A**: Update init tool to use `blockchain/blockchain.db` path
- **Option B**: Update main app to use `database/gossip.db` path
- **Option C**: Make both configurable (recommended for Docker)

**Recommendation**: For Docker, use consistent structure: `docker_configs/node_XXX/state/blockchain/blockchain.db`

### 2. Node ID Format Inconsistency
**Problem**: Config uses `node_001` (3 digits) but state paths use `node_1` (unpadded) in debug mode

**Solution**: Standardize on 3-digit format (`node_001`) everywhere for consistency

### 3. Missing Discovery Infrastructure
**Problem**: No discovery module exists yet

**Solution**: Implement as per plan:
- Create `src/packages/discovery/` directory
- Implement `discovery.h` with function pointer interface
- Implement `tailscale_discovery.c`, `dns_pattern_discovery.c`, `static_discovery.c`
- Add discovery mode to `NodeConfig`
- Call discovery before `bootstrap_known_peers()`

### 4. Dynamic Peer Addition Not Implemented
**Problem**: `gossip_receive_handler()` doesn't add unknown peers dynamically

**Solution**: Modify handler to:
- Extract source address from `sockaddr_in`
- Resolve hostname via `gethostbyaddr()`
- Check if peer exists in peer list
- Add peer if unknown via `gossip_service_add_peer()`
- Store in database via `gossip_peers_add_or_update()`

### 5. Node Announcement Not Implemented
**Problem**: No function to send node registration announcements

**Solution**: Implement `send_node_announcement()` that:
- Creates `NodeRegistration` protobuf message
- Includes node_id, hostname, gossip_port (9000), api_port (8000)
- Signs with node's private key
- Broadcasts via `gossip_service_broadcast_envelope()`

## Plan Alignment Checklist

### ✅ Correctly Aligned
- [x] Fixed ports (8000/9000) for all nodes
- [x] Docker Compose approach
- [x] Tailscale sidecar pattern
- [x] Node naming convention (`tw_node01`, `tw_node02`, etc.)
- [x] Hostname pattern matching (`tw_node*`)
- [x] Pluggable discovery system design
- [x] Database peer storage structure
- [x] Gossip service peer management

### ⚠️ Needs Adjustment
- [ ] Database path structure (init tool vs main app mismatch)
- [ ] Node ID format consistency (3-digit vs unpadded)
- [ ] State directory structure for Docker (should use node-specific paths)

### ❌ Not Yet Implemented
- [ ] Discovery module (`src/packages/discovery/`)
- [ ] Discovery mode in config
- [ ] Dynamic peer addition on message receive
- [ ] Node announcement sending
- [ ] Docker config generator script
- [ ] Dockerfile.node
- [ ] Docker Compose files
- [ ] Tailscale sidecar integration

## Recommended Next Steps

1. **Fix Database Path Inconsistency**
   - Decide on unified path structure
   - Update either init tool or main app (or both)
   - Ensure Docker uses consistent structure

2. **Standardize Node ID Format**
   - Use 3-digit format (`node_001`) everywhere
   - Update `statePaths.c` to use `node_%03u` format

3. **Implement Discovery Infrastructure**
   - Create discovery module structure
   - Implement all three discovery modes
   - Integrate with config loading

4. **Implement Dynamic Peer Addition**
   - Modify `gossip_receive_handler()`
   - Add reverse DNS resolution
   - Store discovered peers in database

5. **Implement Node Announcements**
   - Create announcement helper function
   - Call after discovery completes
   - Handle announcements in message handler

6. **Create Docker Infrastructure**
   - Implement config generator script
   - Create Dockerfile.node
   - Generate Docker Compose files
   - Test with Tailscale sidecars

## Code References

### Key Files
- `src/main.c` - Main application entry point
- `src/packages/comm/gossip/gossip.c` - Gossip service implementation
- `src/packages/sql/gossip_peers.c` - Peer database operations
- `src/packages/utils/config.c` - Configuration loading
- `src/packages/utils/statePaths.c` - State directory management
- `scripts/init.c` - Initialization tool
- `scripts/configs/network_config.json` - Master configuration

### Database Schema
- `gossip_peers` table: `hostname`, `gossip_port`, `api_port`, `first_seen`, `last_seen`, `tags`
- `gossip_messages` table: Message storage with TTL
- `roles`, `permissions`, `user_roles` tables: Access control

### Protobuf Messages
- `Tinyweb__Envelope` - Message envelope with signing/encryption
- `Tinyweb__NodeRegistration` - Node announcement message (type 40)
- Various content types (1-60+) for different message types

## Conclusion

The plan is well-designed and aligns with the codebase architecture. However, several inconsistencies need to be resolved, and the discovery infrastructure needs to be implemented. The Docker integration approach is sound and will work once the discovery system is in place.

**Priority**: Fix path inconsistencies first, then implement discovery, then Docker integration.

