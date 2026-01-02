# TinyWeb High-Level Plan of Action

## Current State Assessment

### ✅ **Fully Implemented (MVP Core)**
- **Gossip Protocol**: UDP transport, peer discovery (Tailscale/DNS/Static), dynamic peer addition
- **HTTP API**: Message submission, retrieval, conversations, peer listing
- **Cryptography**: Signing, encryption, key management, validation
- **Storage**: SQLite with schema, message persistence, TTL cleanup
- **Protobuf**: Complete schema definitions for all 4 phases (40+ message types)
- **Docker**: Containerization, multi-node testing, config generation
- **Discovery**: Tailscale, DNS pattern, static discovery modes
- **Web UI**: Basic React client for messaging (proof of concept)

### ⚠️ **Partially Implemented**
- **Content Handlers**: Only 2 of 40+ protobuf types have handlers (LocationUpdate, EmergencyAlert)
- **User Management**: Database schema exists, but no HTTP API for registration/role assignment
- **Permissions**: Structures exist, but not fully integrated with message routing
- **GPS Tracking**: Handler exists but only prints to console (no storage/API)
- **Proximity System**: Backend foundation exists, but not integrated into invitation flow

### ❌ **Not Started (Per Business Plan)**
- **Mobile Apps**: Android apps for kids/parents (mentioned in business plan)
- **Dashboard**: Extension management, app distribution, configuration UI
- **Extensions**: Jellyfin, Immich integration (infrastructure planned, not implemented)
- **Group Management**: Protobuf defined, but no handlers or API endpoints
- **Parental Controls**: Protobuf defined, but no enforcement logic
- **Media Sharing**: Protobuf defined, but no storage/retrieval system
- **Educational Features**: Protobuf defined, but no implementation
- **Events/Playdates**: Protobuf defined, but no implementation

---

## High-Level Roadmap

### **Phase 1: Complete MVP Core (Current Priority)**
**Goal**: Make the basic messaging system fully functional with user management

1. **User Management API**
   - `POST /users/register` - Register new users (parents/children)
   - `POST /users/assign-role` - Role assignment
   - `GET /users` - List users (already exists, verify completeness)
   - Integrate user registration with gossip protocol (broadcast UserRegistration messages)

2. **Content Handler Expansion**
   - Implement handlers for Phase 1 MVP types:
     - `UserRegistration` - Store in database, validate, broadcast
     - `DirectMessage` - Already works via Message API, but add envelope handler
     - `GroupCreate/Update/MemberAdd/Remove` - Group management logic
     - `PermissionEdit` - Integrate with permissions system
   - Remove "no handler" errors for core message types

3. **GPS/Location System**
   - Store LocationUpdate messages in database
   - `GET /location/:user_id` - Retrieve user's last known location
   - `GET /location/history/:user_id` - Location history (for parents)
   - Real-time location tracking for parental monitoring

4. **Permissions Integration**
   - Connect permission system to message routing
   - Enforce permissions on message submission
   - Parental controls enforcement (screen time, content filters)

**Timeline**: 2-3 months

---

### **Phase 2: Family Features**
**Goal**: Enable the core family use cases (GPS tracking, parental controls, group messaging)

1. **Group Messaging**
   - Full group CRUD operations via HTTP API
   - Group message routing and delivery
   - Group permissions and member management

2. **Parental Controls**
   - Screen time limits enforcement
   - Content filtering (keyword blocking)
   - Usage policy enforcement (quiet time, bedtime)
   - Parent dashboard for monitoring

3. **Emergency & Safety**
   - Emergency alert system (handler exists, needs UI/notification)
   - Geofencing (Phase 4 protobuf, but needed for MVP)
   - Location-based alerts

4. **Proximity System Integration**
   - Complete proximity-based invitation flow
   - NFC/BLE/QR code invitation acceptance
   - Secure family member onboarding

**Timeline**: 3-4 months

---

### **Phase 3: Client Applications**
**Goal**: Build the apps that families will actually use

1. **Parent Mobile App (Android)**
   - User registration and key management
   - Message viewing and sending
   - GPS tracking dashboard
   - Parental controls configuration
   - Emergency alerts

2. **Child Mobile App (Android)**
   - Simplified messaging interface
   - Location sharing (automatic)
   - Media sharing (photos/drawings)
   - Game integration (Phase 4)

3. **Web Dashboard (Admin)**
   - Node configuration
   - Extension management (start/stop Jellyfin, Immich)
   - App distribution to network phones
   - Network health monitoring
   - User management UI

**Timeline**: 4-6 months

---

### **Phase 4: Extensions & Ecosystem**
**Goal**: Enable the extensible platform described in business plan

1. **Extension Infrastructure**
   - Bridge communication protocol (Core ↔ Extensions)
   - Extension management API (`/api/extensions/*`)
   - Docker Compose integration for extensions
   - Extension health monitoring

2. **Initial Extensions**
   - Jellyfin integration (media server)
   - Immich integration (photo sharing)
   - Extension discovery and installation

3. **App Distribution System**
   - App registry (metadata, versions, permissions)
   - Network-wide app sync via gossip
   - OTA app updates to phones
   - App permission management

4. **Android Base Image**
   - De-googled Android image preparation
   - TinyWeb app pre-installation
   - Device provisioning system

**Timeline**: 6-8 months

---

### **Phase 5: Advanced Features**
**Goal**: Educational content, games, events, community features

1. **Educational Resources**
   - Book library management
   - Educational content distribution
   - Challenge/achievement system
   - Chore/reward system

2. **Social Features**
   - Events and playdates (create, invite, RSVP)
   - Community posts
   - Shared albums
   - Collaborative projects

3. **Games & Entertainment**
   - Game session management
   - Game permissions (parental controls)
   - Multiplayer game support

**Timeline**: 8-12 months

---

## Critical Gaps to Address

### **Immediate (Blocking MVP)**
1. **User Registration API** - Can't onboard users without this
2. **Content Handler Coverage** - Most protobuf types have no handlers
3. **GPS Storage** - Location tracking is core feature, currently just prints
4. **Permissions Enforcement** - Security critical, currently not enforced

### **Short-term (Blocking Family Use)**
1. **Group Messaging** - Families need group chats
2. **Parental Controls UI** - Parents need to configure limits
3. **Mobile Apps** - Can't use web UI on phones easily
4. **Emergency Alerts** - Handler exists, needs notification system

### **Medium-term (Blocking Business Model)**
1. **Dashboard** - Can't manage extensions without it
2. **Extension Infrastructure** - Core to business plan
3. **App Distribution** - Needed for phone deployment
4. **Android Base Image** - Required for phone setup

---

## Recommendations

### **Focus Areas (Next 3 Months)**
1. **Complete MVP Core** - User management, content handlers, GPS storage
2. **Polish Web UI** - Make it production-ready for early adopters
3. **Documentation** - Setup guides, API docs, deployment instructions

### **Defer Until Later**
- Phase 4/5 features (extensions, games, educational content)
- Advanced proximity validation (multi-modal proofs)
- Complex parental control algorithms

### **Architecture Decisions Needed**
1. **Media Storage** - Where to store photos/videos? (Local SQLite? Separate service?)
2. **Extension Communication** - HTTP REST? gRPC? Message queue?
3. **App Distribution** - How to push apps to phones? (APK over HTTP? App store?)
4. **Android Integration** - How deep to integrate? (System-level? App-level?)

---

## Success Metrics

### **MVP Complete When:**
- ✅ Parents can register themselves and children
- ✅ Families can send messages to each other
- ✅ GPS tracking works end-to-end (location → storage → retrieval)
- ✅ Basic parental controls are enforceable
- ✅ Web UI is usable for daily messaging

### **Beta Ready When:**
- ✅ Mobile apps exist for parents and children
- ✅ Group messaging works
- ✅ Emergency alerts notify parents
- ✅ Dashboard exists for node management

### **Production Ready When:**
- ✅ Extension system works (Jellyfin/Immich integrated)
- ✅ App distribution works
- ✅ Android base image is available
- ✅ Documentation is complete
- ✅ Security audit passed

