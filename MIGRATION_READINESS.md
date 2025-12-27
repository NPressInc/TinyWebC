# Migration Readiness Assessment

## Overview
This document identifies what exists, what needs to be created, and what needs to be modified for the migration from envelope-based messaging to dedicated message structures.

---

## ✅ What Already Exists

### Protobuf Infrastructure
- ✅ **CMake protobuf generation** (`CMakeLists.txt` lines 48-82)
  - Generates `.pb-c.h` and `.pb-c.c` from `.proto` files
  - Currently generates: `envelope.proto`, `content.proto`, `api.proto`
  - **Action**: Add `message.proto` to `PROTO_FILES` list

### Database Infrastructure
- ✅ **SQLite setup** (`src/packages/sql/database_gossip.c`)
  - Database initialization with WAL mode
  - Connection management
- ✅ **Schema management** (`src/packages/sql/schema.c`)
  - Table creation functions
  - Index creation
  - Migration support (schema versioning)
  - **Current tables**: `gossip_envelopes`, `gossip_envelope_recipients`, `gossip_seen`
  - **Action**: Create new `user_messages`, `message_recipients`, `message_seen` tables

### Encryption/Signing
- ✅ **Multi-recipient encryption** (`src/packages/encryption/encryption.c`)
  - `encrypt_envelope_payload()` - supports multiple recipients
  - `decrypt_envelope_payload()` - decrypts for current user
  - Uses ephemeral keys + key wraps (already supports what we need)
- ✅ **Ed25519 signing** (`src/packages/signing/signing.c`)
  - Signature creation and verification
  - **Action**: Verify it works with new Message structure

### Gossip Service
- ✅ **UDP gossip transport** (`src/packages/comm/gossip/gossip.c`)
  - `gossip_service_broadcast_envelope()` - broadcasts to all peers
  - `gossip_service_rebroadcast_envelope()` - rebroadcasts excluding source
  - `GossipEnvelopeHandler` callback type
  - **Action**: Create `gossip_service_broadcast_message()` and `gossip_service_rebroadcast_message()` that work with Message protobuf instead of Envelope

### Validation
- ✅ **Gossip validation** (`src/packages/validation/gossip_validation.c`)
  - `gossip_validate_envelope()` - validates signature, timestamp, payload size
  - `GossipValidationConfig` - configurable TTL, clock skew, max payload
  - **Action**: Create `message_validate()` function for Message protobuf (similar logic)

### HTTP API Infrastructure
- ✅ **Mongoose HTTP server** (`src/packages/comm/gossipApi.c`)
  - HTTP endpoint routing
  - Protobuf body parsing (already accepts raw protobuf)
  - CORS support
  - **Action**: Add new endpoints `/messages/submit` and `/gossip/message`

### Test Infrastructure
- ✅ **Test framework** (`src/tests/test_init.c`, `test_runner.c`)
  - `test_init_environment()` - creates `test_state/` with full network
  - `test_get_db_path()`, `test_get_keys_dir()`, etc.
  - Test runner with individual test support
  - **Action**: Create new test files following existing patterns

### Permissions
- ✅ **Permissions system** (`src/packages/sql/permissions.c`)
  - User/role/permission tables
  - Permission checking functions
  - **Action**: Create `message_permissions_check()` wrapper for messaging-specific rules

---

## ❌ What Needs to Be Created

### 1. Protobuf Definition
- [ ] **`src/proto/message.proto`**
  - `MessageHeader` message
  - `Message` message
  - Support for multi-recipient encryption (keywraps array)
  - **Update**: `CMakeLists.txt` to include `message.proto` in `PROTO_FILES`

### 2. Database Schema
- [ ] **New tables in `src/packages/sql/message_store.c`**:
  - `user_messages` table (individual columns, not serialized blob)
  - `message_recipients` table (per-recipient key wraps)
  - `message_seen` table (deduplication cache)
  - **Indexes**: timestamp, sender, recipient, conversation, group, expires
  - **Function**: `message_store_init()` to create tables

### 3. Storage Functions
- [ ] **`src/packages/sql/message_store.c`** (new file):
  - `message_store_init()` - create tables/indexes
  - `message_store_save()` - extract fields from Message protobuf, store in columns
  - `message_store_has_seen()` - check digest cache
  - `message_store_mark_seen()` - record digest
  - `message_store_fetch_recent()` - query and reconstruct Message protobuf
  - `message_store_fetch_conversation()` - query conversation, reconstruct protobuf
  - `message_store_cleanup()` - TTL cleanup
- [ ] **`src/packages/sql/message_store.h`** (new file)

### 4. HTTP Endpoints
- [ ] **`src/packages/comm/messagesApi.c`** (new file):
  - `POST /messages/submit` handler
    - Accept raw Message protobuf
    - Validate signature, timestamp (60s window), payload size
    - Check permissions
    - Check duplicate
    - Store and broadcast
  - `GET /messages/recent` - update to use new schema
  - `GET /messages/conversation` - update to use new schema
  - `GET /messages/conversations` - update to use new schema
- [ ] **`src/packages/comm/messagesApi.h`** (new file)
- [ ] **Update `gossipApi.c`**:
  - Add `POST /gossip/message` handler (similar to `/messages/submit` but no permission check)

### 5. Gossip Service Updates
- [ ] **Update `src/packages/comm/gossip/gossip.h`**:
  - Add `GossipMessageHandler` typedef (for Message instead of Envelope)
  - Add `gossip_service_broadcast_message()` function
  - Add `gossip_service_rebroadcast_message()` function
- [ ] **Update `src/packages/comm/gossip/gossip.c`**:
  - Implement message broadcast functions (serialize Message protobuf)
  - Update receive loop to handle Message protobuf (or keep Envelope for system messages)

### 6. Validation
- [ ] **`src/packages/validation/message_validation.c`** (new file):
  - `message_validate()` - validate Message signature, timestamp, payload
  - Similar to `gossip_validate_envelope()` but for Message
- [ ] **`src/packages/validation/message_validation.h`** (new file)

### 7. Permissions
- [ ] **`src/packages/comm/message_permissions.c`** (new file):
  - `message_permissions_check()` - check if sender can message recipient
  - Rules: parent-child (any direction), peers (if relationship exists), groups (if member)
- [ ] **`src/packages/comm/message_permissions.h`** (new file)

### 8. Main Loop Updates
- [ ] **Update `src/main.c`**:
  - Remove double-envelope wrapping logic (lines 302-380)
  - Update gossip receive handler to handle Message protobuf directly
  - Remove `tw_envelope_unwrap_from_gossip()` call
  - Update to use new message storage functions

---

## 🔧 What Needs to Be Modified

### 1. Build System
- [ ] **`CMakeLists.txt`**:
  - Add `message.proto` to `PROTO_FILES` (line 58-62)
  - Add `message_store.c` to source files (if needed)
  - Add `messagesApi.c` to source files
  - Add `message_validation.c` to source files
  - Add `message_permissions.c` to source files

### 2. Existing Files
- [ ] **`src/packages/comm/gossipApi.c`**:
  - Add `POST /gossip/message` endpoint
  - Keep `POST /gossip/envelope` for future system messages (or remove if not needed)
- [ ] **`src/packages/comm/userMessagesApi.c`**:
  - Update read endpoints (`/messages/recent`, `/messages/conversation`, `/messages/conversations`)
  - Use `message_store_fetch_*()` functions instead of `gossip_store_fetch_*()`
  - Reconstruct Message protobuf from columns for HTTP responses
- [ ] **`src/main.c`**:
  - Update gossip receive handler (remove double-envelope logic)
  - Use Message validation instead of Envelope validation
  - Use message storage functions instead of envelope storage

### 3. Test Files
- [ ] **`src/tests/test_runner.c`**:
  - Register new test functions: `message_store_test_main()`, `message_api_test_main()`, `message_permissions_test_main()`
- [ ] **`src/tests/schema_test.c`**:
  - Add tests for `user_messages` table creation
  - Add tests for `message_recipients` table creation
  - Add tests for all message-related indexes

---

## 🗑️ What Needs to Be Removed

### 1. Double-Envelope Logic
- [ ] **`src/packages/transactions/envelope.c`**:
  - Remove `tw_envelope_wrap_for_gossip()` function (line 238)
  - Remove `tw_envelope_unwrap_from_gossip()` function (line 341)
- [ ] **`src/packages/transactions/envelope.h`**:
  - Remove function declarations (lines 54-60)
- [ ] **`src/main.c`**:
  - Remove unwrapping logic (lines 302-380)
  - Remove `CONTENT_GOSSIP_WRAPPED_MESSAGE` handling

### 2. Legacy Endpoints
- [ ] **`src/packages/comm/userMessagesApi.c`** or **`transactionsApi.c`**:
  - Remove old `/messages/send` endpoint (JSON+hex encoding)
  - Remove old `/envelopes/submit` endpoint (if exists)
- [ ] **`src/packages/comm/gossipApi.c`**:
  - Consider removing `/gossip/envelope` endpoint (or repurpose for system messages)

### 3. Legacy Storage
- [ ] **`src/packages/sql/schema.c`**:
  - Keep `gossip_envelopes` table for now (may be used for system messages later)
  - Or remove if not needed

---

## ⚠️ Dependencies & Potential Issues

### 1. Protobuf Compatibility
- **Issue**: Existing code uses `Tinyweb__Envelope` everywhere
- **Solution**: New code uses `Tinyweb__Message`, old code can coexist for system messages
- **Risk**: Low - separate protobuf types

### 2. Database Migration
- **Issue**: Existing `gossip_envelopes` table may have data
- **Solution**: 
  - Keep `gossip_envelopes` for system messages
  - Create new `user_messages` table (no migration needed if starting fresh)
  - Or: Migrate existing user messages from `gossip_envelopes` to `user_messages` (if needed)

### 3. Gossip Protocol
- **Issue**: Gossip service currently expects `Tinyweb__Envelope`
- **Solution**: 
  - Option A: Update gossip to handle both Envelope (system) and Message (user messages)
  - Option B: Create separate gossip handlers for each type
  - **Recommendation**: Option A - add message type discriminator in gossip header

### 4. Permissions System
- **Issue**: Need to check parent-child relationships, peer relationships, group membership
- **Solution**: 
  - Use existing `users` table (has `parent_pubkey` field?)
  - Create relationship table if needed
  - Use existing group management (if exists) or create simple group membership table

### 5. Test Data
- **Issue**: Tests need realistic user relationships (parent-child, peers)
- **Solution**: 
  - Use `test_init_environment()` which creates users from `network_config.json`
  - Ensure test config has parent-child relationships defined
  - Create test helper functions to establish peer relationships

### 6. Frontend/Client
- **Issue**: Client code may still use old envelope format
- **Solution**: 
  - Update client to use new `message.proto` structure
  - Or: Keep client compatibility layer temporarily
  - **Note**: Client code is in `client/web-ui/` - separate migration needed

---

## 📋 Migration Checklist

### Phase 1: Foundation
- [ ] Create `message.proto` and regenerate protobuf code
- [ ] Create database schema (`user_messages`, `message_recipients`, `message_seen`)
- [ ] Create `message_store.c` with storage functions
- [ ] Create `message_validation.c` with validation logic
- [ ] Create `message_permissions.c` with permission checks

### Phase 2: API & Gossip
- [ ] Create `messagesApi.c` with `/messages/submit` endpoint
- [ ] Update `gossipApi.c` with `/gossip/message` endpoint
- [ ] Update gossip service to broadcast/receive Message protobuf
- [ ] Update `main.c` gossip receive handler

### Phase 3: Read Endpoints
- [ ] Update `/messages/recent` to use new schema
- [ ] Update `/messages/conversation` to use new schema
- [ ] Update `/messages/conversations` to use new schema

### Phase 4: Cleanup
- [ ] Remove double-envelope wrapping functions
- [ ] Remove old endpoints (`/messages/send`, `/envelopes/submit`)
- [ ] Remove JSON+hex encoding code
- [ ] Clean up unused envelope storage code (if not needed for system messages)

### Phase 5: Testing
- [ ] Create `message_store_test.c`
- [ ] Create `message_api_test.c`
- [ ] Create `message_permissions_test.c`
- [ ] Update `schema_test.c`
- [ ] Update `test_runner.c`
- [ ] Run all tests and verify

---

## 🎯 Critical Success Factors

1. **No serialized protobuf in database** (except `encrypted_payload`)
   - All header fields must be individual columns
   - Verify with direct SQL queries in tests

2. **Protobuf only for transmission**
   - Storage: extract fields → columns
   - Retrieval: columns → reconstruct protobuf

3. **Index optimization**
   - All common queries must use indexes
   - Verify with `EXPLAIN QUERY PLAN`

4. **Backward compatibility** (if needed)
   - System messages may still use Envelope
   - Keep `gossip_envelopes` table for system messages

5. **Test coverage**
   - Multi-recipient encryption
   - Permissions (parent-child, peers, groups)
   - Replay protection (60s window)
   - Gossip rebroadcast and deduplication
   - Database storage/retrieval verification

---

## 📝 Notes

- **Envelope vs Message**: Keep `Tinyweb__Envelope` for system messages (node registration, system config). Use `Tinyweb__Message` for user-to-user messages only.
- **Database**: New `user_messages` table is separate from `gossip_envelopes`. No migration needed if starting fresh.
- **Gossip**: May need to add message type discriminator to gossip protocol to support both Envelope and Message types.
- **Client**: Frontend migration is separate task (not in scope for this phase).

