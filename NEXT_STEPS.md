# Recommended Next Steps for TinyWeb

## Current Status Summary

### ✅ **What's Working Well**
- **Infrastructure**: Excellent (95%+ complete)
  - ✅ Discovery module (Tailscale, DNS, Static) - **FULLY IMPLEMENTED**
  - ✅ Decryption integration - **FULLY INTEGRATED** (envelope_dispatcher.c line 190)
  - ✅ Error handling, logging, config management - **COMPLETE**
  - ✅ Thread safety, retry logic, peer health monitoring - **COMPLETE**
  - ✅ Docker infrastructure with ephemeral keys - **COMPLETE**
  - ✅ Nodes table and schema versioning - **COMPLETE**

- **Core Features**: Partial (20% complete)
  - ✅ DirectMessage handler - **WORKING**
  - ✅ GroupMessage handler - **WORKING**
  - 🟡 LocationUpdate handler - **PARSES BUT DOESN'T PERSIST**
  - 🟡 EmergencyAlert handler - **PARSES BUT DOESN'T PERSIST**

### ❌ **What's Missing for MVP**
- **Business Logic Handlers**: Only 4 of 40+ message types have handlers
- **Integration Tests**: No end-to-end tests
- **Database Persistence**: Location/Emergency handlers don't save data

---

## Priority Recommendations

### 🔴 **IMMEDIATE (This Week) - Complete Existing Handlers**

#### 1. **Complete Location Update Handler** (1-2 days)
**Current State**: Handler exists, parses messages, but doesn't persist to database
**What's Needed**:
- Create `locations` table in database schema
- Store location updates with timestamp, user_pubkey, lat/long
- Add query endpoint for recent locations
- Add location history tracking

**Files to Modify**:
- `src/packages/sql/schema.c` - Add locations table
- `src/packages/comm/envelope_dispatcher.c` - Complete `handle_location_update()`
- `src/packages/sql/gossip_peers.c` or new `locations.c` - Add location storage functions
- `src/packages/comm/gossipApi.c` - Add location query endpoint

**Why First**: It's 80% done, just needs persistence layer

---

#### 2. **Complete Emergency Alert Handler** (1-2 days)
**Current State**: Handler exists, parses messages, but doesn't trigger alerts
**What's Needed**:
- Create `emergency_alerts` table
- Store alerts with timestamp, user_pubkey, alert_type, location
- Add notification system (log for now, webhook/email later)
- Add query endpoint for recent alerts

**Files to Modify**:
- `src/packages/sql/schema.c` - Add emergency_alerts table
- `src/packages/comm/envelope_dispatcher.c` - Complete `handle_emergency_alert()`
- `src/packages/comm/gossipApi.c` - Add alert query endpoint

**Why Second**: Also 80% done, complements location tracking

---

### 🟡 **HIGH PRIORITY (Next 2 Weeks) - MVP Core Features**

#### 3. **Implement User Registration Handler** (2-3 days)
**Current State**: No handler exists
**What's Needed**:
- Parse `UserRegistration` protobuf message
- Validate pubkey uniqueness
- Store user in database (users table exists from init tool)
- Assign default role based on message
- Return success/failure

**Files to Create/Modify**:
- `src/packages/comm/envelope_dispatcher.c` - Add `handle_user_registration()`
- `src/packages/sql/permissions.c` - Add user registration helper
- `src/packages/comm/envelope_dispatcher.c` - Register handler in `envelope_dispatcher_init()`

**Why Third**: Critical for MVP - users need to register before they can do anything

---

#### 4. **Implement Group Management Handlers** (5-7 days)
**Current State**: No handlers exist
**What's Needed**:
- `GroupCreate` - Create groups, store in DB
- `GroupUpdate` - Update group metadata
- `GroupMemberAdd` - Add members with role
- `GroupMemberRemove` - Remove members
- `GroupMemberLeave` - Allow members to leave
- Group storage schema
- Permission checks (only admins can create/modify groups)

**Files to Create/Modify**:
- `src/packages/sql/schema.c` - Add `groups` and `group_members` tables
- `src/packages/sql/groups.c` (NEW) - Group database operations
- `src/packages/comm/envelope_dispatcher.c` - Add 5 handler functions
- `src/packages/comm/envelope_dispatcher.c` - Register all handlers

**Why Fourth**: Core MVP feature - groups are essential for family communication

---

### 🟢 **MEDIUM PRIORITY (After MVP Core) - Integration & Testing**

#### 5. **Add Integration Tests** (3-5 days)
**Current State**: Good unit tests, no integration tests
**What's Needed**:
- End-to-end message flow tests (send → encrypt → gossip → receive → decrypt)
- HTTP API integration tests (actual HTTP requests)
- Multi-node network tests (Docker-based)
- UDP gossip network tests

**Files to Create**:
- `src/tests/integration_test.c` (NEW)
- `src/tests/api_integration_test.c` (NEW)
- `scripts/integration_test_runner.sh` (NEW)

**Why Fifth**: Critical for production readiness - need to verify full system works

---

#### 5a. **Update Web App for Docker Messaging Tests** (2-3 days) ⚠️ **HIGH PRIORITY - VERIFY BASIC MESSAGING WORKS**
**Current State**: 
- `docker_test_runner.sh` launches 4 docker nodes (node_01, node_02, node_03, node_04) and **leaves them running** after tests complete
- Existing web-ui React app (`client/web-ui/`) has envelope utilities, encryption, and mock messaging UI
- No integration exists to test messaging against running docker nodes

**Important**: 
- Docker containers **stay running** after `docker_test_runner.sh` completes
- Containers are only stopped when test runner is re-run (Step 0 cleanup)
- **Web app runs independently** - connects to already-running containers via HTTP
- Web app should detect running containers and connect to them

**Context**: TinyWeb is a **family-focused communication network** where:
- Each node represents a household/family
- Parents control messaging and permissions for kids
- Families can join each other's networks with proper permissions
- Kids can message trusted community members (with parent approval)
- Messages are encrypted, signed, and propagate via gossip protocol

**What's Needed**:
- Create test client program that simulates family communication scenarios
- Use existing `httpClient` library to POST envelopes to `/gossip/envelope` endpoint
- Create properly encrypted/signed envelopes using `tw_envelope_build_and_sign()`
- Test realistic family messaging scenarios:
  - Parent-to-child messages (e.g., "Come home for dinner")
  - Parent-to-parent messages (e.g., coordinating playdates)
  - Child-to-trusted-community-member messages (with proper permissions)
  - Location updates from child to parent
  - Emergency alerts
- Test message propagation across the 4-node network (representing different households)
- Verify messages are received, stored in database, and respect permissions

**Files to Create/Modify** (in `client/web-ui/`):
- `src/utils/api.js` (NEW) - API client for connecting to docker nodes
  - Functions to POST envelopes to `/gossip/envelope` endpoint
  - Functions to GET messages from `/gossip/messages` endpoint
  - Functions to query `/gossip/peers` to detect running nodes
  - Handles multiple node URLs (node_01:8000, node_02:8000, etc.)
  - Uses existing `envelope.js` utilities to create signed envelopes
  
- `src/components/MessagingTest.js` (NEW) - **UI component for manual testing**
  - Test panel in web UI to send messages between nodes
  - Select sender/recipient users (admin_001, admin_002, member_001, member_002)
  - Select target node (node_01, node_02, node_03, node_04)
  - Send DirectMessage, LocationUpdate, EmergencyAlert
  - View sent/received messages
  - Test message propagation across nodes
  
- `src/components/AutoTestRunner.js` (NEW) - **Automated test runner component**
  - Runs automated test suite against docker nodes
  - Tests: parent→child, parent→parent, message propagation
  - Reports test results in UI
  - Can be triggered manually or run on page load
  
- `src/tests/messaging.integration.test.js` (NEW) - **Jest integration tests**
  - Automated tests using Jest/React Testing Library
  - Tests envelope creation, API calls, message sending
  - Mocks or uses real docker node endpoints
  - Can run with `npm test`
  
- `src/components/ConversationView.js` (MODIFY) - Connect to real API
  - Replace mock data with real API calls
  - Use `api.js` to fetch messages from nodes
  - Use `envelope.js` to send real encrypted messages
  
- `src/App.js` (MODIFY) - Add test routes
  - Add route for `/test` - MessagingTest component
  - Add route for `/auto-test` - AutoTestRunner component
  
- `docker_configs/docker-compose.test.yml` (MODIFY) - Add port mappings
  - Add port mappings: `8001:8000`, `8002:8000`, `8003:8000`, `8004:8000`
  - Allows web app to connect from browser to docker nodes

**Implementation Details**:

1. **API Client** (`src/utils/api.js`) - **Core integration layer**:
   - **Functions**:
     - `detectRunningNodes()` - Checks docker compose status or tries to connect to node ports
     - `sendEnvelope(nodeUrl, envelope)` - POST envelope to `/gossip/envelope` endpoint
     - `getMessages(nodeUrl, userPubkey, withPubkey)` - GET messages from `/gossip/messages`
     - `getPeers(nodeUrl)` - GET peer list from `/gossip/peers`
     - `getRecentMessages(nodeUrl, limit)` - GET recent messages from `/gossip/recent`
   - **Uses existing utilities**:
     - `envelope.js` - `createSignedEnvelope()` to create encrypted/signed envelopes
     - `keystore.js` - Load user keys (admin_001, admin_002, member_001, member_002)
     - `encryption.js` - Handle encryption/decryption
   - **Node URLs**: `http://localhost:8001`, `http://localhost:8002`, etc. (via port mappings)

2. **Manual Testing UI** (`src/components/MessagingTest.js`):
   - **UI Components**:
     - Node selector (node_01, node_02, node_03, node_04)
     - User selector (admin_001, admin_002, member_001, member_002)
     - Message type selector (DirectMessage, LocationUpdate, EmergencyAlert)
     - Message input field
     - Send button
     - Message history display
   - **Test Scenarios**:
     - Parent (admin_001) → Child (member_001): "Come home for dinner"
     - Parent (admin_001) → Parent (admin_002): "Can Emma come over for a playdate?"
     - Verify message appears on recipient node
     - Check message propagation (query other nodes)
   - **Real-time feedback**: Shows success/failure, displays received messages

3. **Automated Test Runner** (`src/components/AutoTestRunner.js`):
   - **Automated test suite**:
     - Test 1: Send message from admin_001 to member_001
     - Test 2: Verify message received on target node
     - Test 3: Verify message propagates to other nodes via gossip
     - Test 4: Test permission checks (child without permission)
     - Test 5: Test LocationUpdate message
     - Test 6: Test EmergencyAlert message
   - **UI Display**: Shows test progress, results, pass/fail status
   - **Can run**: On page load, or triggered by button click

4. **Jest Integration Tests** (`src/tests/messaging.integration.test.js`):
   - **Automated tests** using Jest:
     - `test('send direct message', async () => { ... })`
     - `test('message propagation', async () => { ... })`
     - `test('permission checks', async () => { ... })`
   - **Can mock API calls** or use real docker node endpoints
   - **Run with**: `npm test` or `npm test -- messaging.integration.test.js`

2. **Key Management & User Setup** - **ALREADY HANDLED BY INIT TOOL**:
   - ✅ **Users are pre-initialized** by `docker_config_generator` and `init_tool`:
     - Keys created at: `docker_configs/node_XX/state/keys/users/{user_id}/key.bin`
     - Users registered in database with proper roles and permissions
     - From `network_config.json`:
       - `admin_001`, `admin_002` - Parents with admin role (role=0)
       - `member_001`, `member_002` - Children with member role (role=1), supervised by parents
   - ✅ **Database already seeded** with:
     - Roles (admin, member, community)
     - Permissions (SEND_MESSAGE, READ_MESSAGE, etc.)
     - Role-permission mappings
     - User records with proper parent-child relationships
   - **For web app approach**: 
     - **Option A**: Load keys via API endpoint (if exposed) or from local storage
     - **Option B**: Use `keystore.js` to generate/load keys in browser
     - **Option C**: Pre-load test user keys into browser localStorage for testing
     - **Note**: Browser can't directly access docker volume files, so keys need to be:
       - Exposed via API endpoint, OR
       - Loaded into browser keystore for testing, OR
       - Generated in browser and registered via UserRegistration handler

3. **Docker Integration** (for already-running containers):
   - **Web App Approach**: 
     - **Port mappings required**: Add to `docker-compose.test.yml`:
       - node_01: `8001:8000`
       - node_02: `8002:8000`
       - node_03: `8003:8000`
       - node_04: `8004:8000`
     - **Browser connects via**: `http://localhost:8001`, `http://localhost:8002`, etc.
     - **CORS**: May need to add CORS headers to `gossipApi.c` to allow browser requests
     - **Detects running nodes**: Try to connect to each port, or check docker compose status
     - **Works with containers that are already running** - doesn't need test runner
   - **Alternative**: Run web app inside docker network (as separate service):
     - Use service names: `http://node_01:8000`, `http://node_02:8000`
     - Add web app as service to docker-compose.test.yml
     - Web app served from container, accessed via browser
   - ✅ **No health check needed**: Web app assumes containers are already running (started by test runner or manually)

4. **Web App Usage**:
   ```bash
   # Step 1: Start containers (one time, or after cleanup)
   ./scripts/docker_test_runner.sh
   
   # Step 2: Start web app (if not already running)
   cd client/web-ui
   npm start
   # Opens http://localhost:3000
   
   # Step 3: Use web UI to test messaging
   # - Navigate to /test for manual testing
   # - Navigate to /auto-test for automated tests
   # - Use existing /conversation/:userId for real messaging
   ```

5. **Independent Operation**:
   - ✅ **Runs standalone**: Web app is independent of docker_test_runner.sh
   - ✅ **Works with running containers**: Detects and connects to already-running containers
   - ✅ **Can test multiple times**: Test different scenarios without restarting containers
   - ✅ **Both manual and automated**: UI for manual testing, Jest for automated tests
   - ✅ **Leverages existing code**: Uses envelope.js, encryption.js, keystore.js utilities
   - **Usage flow**:
     ```bash
     # Start containers once
     ./scripts/docker_test_runner.sh
     
     # Start web app
     cd client/web-ui && npm start
     
     # In browser:
     # - http://localhost:3000/test - Manual testing UI
     # - http://localhost:3000/auto-test - Automated test runner
     # - http://localhost:3000/conversation/:userId - Real messaging (when connected)
     ```
   - **Run automated tests**: `cd client/web-ui && npm test`

**Why This is Critical**:
- Verifies the complete message flow works end-to-end for **family communication scenarios**
- Tests encryption, signing, HTTP API, gossip propagation, and database storage
- Validates that **parent-child relationships and permissions** work correctly
- Tests realistic use cases: parent-to-child, parent-to-parent, trusted community messaging
- Catches integration issues before building more handlers
- Provides confidence that basic messaging infrastructure is solid for the family network use case

**Dependencies** - **ALREADY SATISFIED**:
- ✅ **Users pre-initialized**: `docker_config_generator` + `init_tool` create users from `network_config.json`
- ✅ **Keys generated**: User keys at `docker_configs/node_XX/state/keys/users/{user_id}/key.bin`
- ✅ **Database seeded**: Roles, permissions, and user records already in database
- ✅ **Parent-child relationships**: `supervised_by` field in config creates relationships
- ⚠️ **May need**: Helper function to read keys and create envelopes (could be shell script or C helper)
- ⚠️ **May need**: Verify user pubkeys are accessible (stored in database, can query via SQL or API)

**Estimated Time**: 2-3 days
- Day 1: Create basic test client, send single message
- Day 2: Add message verification, test propagation
- Day 3: Integrate with docker_test_runner, add error handling

---

#### 6. **Add Missing Handlers** (2-3 weeks)
**Priority Order**:
1. `RoleAssignment` handler (1 day)
2. `PermissionEdit` handler (1-2 days)
3. `ParentalControl` handler (2-3 days)
4. `ContentFilter` handler (2-3 days)
5. `NodeRegistration` handler (1-2 days) - For multi-node networks

---

## Recommended Work Plan

### **Week 0: Verify Basic Messaging Works** ⚠️ **DO THIS FIRST**
- Day 1-2: Create messaging test client (5a)
- Day 3: Test messaging between docker nodes, verify end-to-end flow works
- **Why First**: Need to verify basic messaging infrastructure works before building more handlers

### **Week 1: Complete Existing Features**
- Day 1-2: Complete Location Update handler
- Day 3-4: Complete Emergency Alert handler
- Day 5: Test both handlers end-to-end

### **Week 2: User & Group Management**
- Day 1-3: Implement User Registration handler
- Day 4-7: Implement all 5 Group Management handlers

### **Week 3: Integration & Testing**
- Day 1-3: Add integration tests
- Day 4-5: Test full system with Docker

### **Week 4: Polish & Additional Features**
- Day 1-2: RoleAssignment & PermissionEdit handlers
- Day 3-5: ParentalControl & ContentFilter handlers

---

## Quick Wins (Can Do Anytime)

1. **Update Documentation** (1 hour)
   - Mark completed features as done
   - Update status in feature tracking documents

2. **Enhance Health Check Endpoint** (2 hours)
   - `/health` endpoint already exists (gossipApi.c line 316)
   - Enhance to return service status, database connectivity, peer count

3. **Improve Error Messages** (1 hour)
   - Update handler error messages (some still say "not yet implemented" but work)

4. **Add TTL Cleanup Testing** (2 hours)
   - Add automated test for TTL cleanup job
   - Verify old messages are deleted

---

## Technical Debt to Address

1. **Memory Leak Audit**
   - Run AddressSanitizer on all handlers
   - Fix any leaks found

---

## Success Metrics

**MVP Ready When**:
- ✅ All 4 existing handlers fully functional (Location, Emergency)
- ✅ User Registration working
- ✅ All 5 Group Management handlers working
- ✅ Integration tests passing
- ✅ Can send/receive messages between nodes in Docker

**Current Progress**: ~35% to MVP (infrastructure complete, handlers partial)
**After Week 1**: ~55% to MVP (Location/Emergency persistence complete)
**After Week 2**: ~80% to MVP (User Registration + Groups complete)
**After Week 3**: ~95% to MVP (Integration tests + polish)

---

## My Recommendation: Start with #5a (Messaging Test Client) ⚠️ **CRITICAL FIRST STEP**

**Why This Should Be First**:
1. **Verifies basic infrastructure works** - Need to confirm messaging flow works before building more features
2. **Catches integration issues early** - Encryption, signing, HTTP API, gossip propagation, database storage
3. **Provides confidence** - If basic messaging doesn't work, other handlers won't work either
4. **Quick validation** - 2-3 days to verify the entire message pipeline
5. **Blocks other work** - If messaging is broken, all handler work is blocked

**Estimated Time**: 2-3 days
**Impact**: Critical (validates entire messaging infrastructure)

**Then proceed with**:
- #1 (Location Handler) - Quick win, 80% done
- #2 (Emergency Handler) - Also 80% done
- #3 (User Registration) - Critical for MVP
- #4 (Group Management) - Core MVP feature

**Alternative**: If messaging test client reveals issues, fix those first before proceeding with handlers.

