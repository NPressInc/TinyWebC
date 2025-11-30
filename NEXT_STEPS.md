# Recommended Next Steps for TinyWeb

## Current Status Summary

### ✅ **What's Working Well**
- **Infrastructure**: Excellent (80%+ complete)
  - ✅ Discovery module (Tailscale, DNS, Static) - **IMPLEMENTED**
  - ✅ Decryption integration - **IMPLEMENTED** (docs are outdated)
  - ✅ Error handling, logging, config management - **COMPLETE**
  - ✅ Thread safety, retry logic, peer health monitoring - **COMPLETE**
  - ✅ Docker infrastructure with ephemeral keys - **JUST COMPLETED**

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

#### 6. **Add Missing Handlers** (2-3 weeks)
**Priority Order**:
1. `RoleAssignment` handler (1 day)
2. `PermissionEdit` handler (1-2 days)
3. `ParentalControl` handler (2-3 days)
4. `ContentFilter` handler (2-3 days)
5. `NodeRegistration` handler (1-2 days) - For multi-node networks

---

## Recommended Work Plan

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
   - Fix outdated docs (FOUNDATIONAL_GAPS_ANALYSIS.md, REPOSITORY_REVIEW.md)
   - Mark completed features as done

2. **Add Health Check Endpoint** (2 hours)
   - Add `/health` endpoint to gossipApi.c
   - Return service status, database connectivity, peer count

3. **Improve Error Messages** (1 hour)
   - Update handler error messages (some still say "not yet implemented" but work)

4. **Add TTL Cleanup Testing** (2 hours)
   - Add automated test for TTL cleanup job
   - Verify old messages are deleted

---

## Technical Debt to Address

1. **Database Schema Consistency**
   - Init tool uses `database/gossip.db` but main app uses `blockchain/blockchain.db`
   - Consider standardizing (low priority, works for now)

2. **Node ID Format**
   - Config uses `node_001` (3 digits) but some paths use `node_1`
   - Consider standardizing (low priority, works for now)

3. **Memory Leak Audit**
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

**Current Progress**: ~30% to MVP
**After Week 1**: ~50% to MVP
**After Week 2**: ~75% to MVP
**After Week 3**: ~90% to MVP

---

## My Recommendation: Start with #1 (Location Handler)

**Why**:
1. It's the quickest win (80% done, just needs database persistence)
2. Builds momentum
3. Establishes pattern for other handlers
4. Completes a critical MVP feature

**Estimated Time**: 1-2 days
**Impact**: High (completes location tracking feature)

Then move to #2 (Emergency), then #3 (User Registration), then #4 (Groups).

