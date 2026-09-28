# TinyWeb High-Level Plan of Action

**Last verified:** 2026-09-28 against commit `9c6d4f70a350d05b7107620f6ce509f4dcc69541`

## Current State Assessment

### ✅ **Fully Implemented (MVP Core)**
- **Gossip Protocol**: UDP transport, peer discovery (Tailscale/DNS/Static), dynamic peer addition (`src/packages/comm/gossip/gossip.c`, `src/main.c` `discover_peer_from_source`)
- **HTTP API**: Message submit/retrieve, conversations, peer listing, health, authenticated reads (`src/packages/comm/gossipApi.c`, `messagesApi.c`, `userMessagesApi.c`)
- **Authentication (HTTP)**: Signed request headers (`X-User-Pubkey`, `X-Signature`, `X-Timestamp`) via `validate_request_auth()` in `request_auth.c`; `POST /auth/login` in `authApi.c`
- **Cryptography**: Envelope and message encryption/decryption (`packages/encryption/encryption.c`), Ed25519 signing, gossip and message signature validation (`gossip_validation.c`, `message_validation.c`, `client_request_validation.c`)
- **Storage**: SQLite schema, encrypted message persistence, location store with key wraps, TTL cleanup (`message_store.c`, `location_store.c`, `schema.c`)
- **Protobuf**: Schemas for envelope, content, message, client request, and API (`src/proto/`); **38** `ContentType` values in `envelope.proto` (excluding `CONTENT_UNKNOWN`)
- **Direct messaging (end-to-end)**: `Tinyweb__Message` over HTTP + gossip—not an envelope content type— with encrypted payloads; web UI encrypts/decrypts in `ConversationView.js` and `encryption.js`
- **Location / GPS**: Encrypted `LocationUpdate` envelopes stored in SQLite; gossip handler persists ciphertext (`envelope_dispatcher.c` → `location_store_save_envelope`); HTTP `POST /location/update`, `GET /location/:user_id`, `GET /location/history/:user_id` with decryption for authorized viewers (`locationApi.c`, `location_permissions.c`)
- **ClientRequest pipeline**: Location (and message) submission via signed `ClientRequest` protobuf converted to envelopes (`client_request_converter.c`)
- **Docker**: Containerization, multi-node testing, config generation (`scripts/Dockerfile.node`, `scripts/docker_config_generator.c`)
- **Discovery**: Tailscale, DNS pattern, static discovery modes (`src/packages/discovery/`)
- **Node announcements**: `CONTENT_NODE_REGISTRATION` envelopes handled in `main.c` (`handle_node_announcement`) for peer discovery (separate from the envelope dispatcher registry)
- **Web UI**: React admin dashboard—login with key file + `POST /auth/login`, encrypted conversations, Leaflet location map/history, key management, crypto demo (`client/web-ui/`, especially `App.js`, `Login.js`, `LocationDashboard.js`)
- **User/role seeding (ops)**: `init_tool` / `scripts/init.c` generates keys, inserts users, seeds roles and permissions from network config (not a runtime registration API)
- **Automated tests**: Encryption, signing, gossip validation, permissions, message/location API tests (`src/tests/`, `run_tests.sh`)

### ⚠️ **Partially Implemented**
- **Content handlers (envelope dispatcher)**: **2 of 38** content types registered in `envelope_dispatcher_init()`—`CONTENT_LOCATION_UPDATE` and `CONTENT_EMERGENCY_ALERT`. A third type, `CONTENT_NODE_REGISTRATION`, is handled ad hoc in `main.c`. The other **35** types have protobuf definitions but no dispatcher handler (gossip still stores raw envelopes; dispatch logs *no handler* for unregistered types).
- **Emergency alerts**: Handler decrypts and `printf`s only—no storage, HTTP API, or UI notifications (`handle_emergency_alert` in `envelope_dispatcher.c`).
- **User management (runtime)**: `GET /users` lists active users (`userMessagesApi.c`); database roles/permissions tables populated at init. **No** `POST /users/register`, **no** `POST /users/assign-role`, **no** gossip handler for `UserRegistration` / `RoleAssignment`.
- **Permissions**: Full RBAC schema and `check_user_permission()` (`permissions.c`, `structs/permission/`); **enforced** for location view/submit paths. **Not** enforced for general messaging—`message_permissions_check()` currently allows any registered sender/recipient pair (`message_permissions.c`).
- **Parental controls / content filters**: Protobuf messages defined; no handlers or enforcement logic.
- **Admin dashboard (business-plan sense)**: Web UI covers messaging, locations, and keys; **no** extension management, app distribution, or node configuration UI described in Phase 3/4.
- **Proximity system**: Design docs only (`ideas/proximity_*.md`); no implementation under `src/` or `client/`.

### ❌ **Not Started (Per Business Plan)**
- **Mobile Apps**: Android apps for kids/parents (mentioned in business plan)
- **Extension dashboard & ecosystem UI**: Extension start/stop, Jellyfin/Immich wiring, app push to phones (infrastructure planned, not implemented)
- **Extensions**: Jellyfin, Immich integration (infrastructure planned, not implemented)
- **Group Management**: Protobuf defined; no handlers, HTTP API, or group message routing
- **Parental Controls enforcement**: Protobuf defined; no runtime enforcement (screen time, keyword filters, usage policies)
- **Media Sharing**: Protobuf defined; no storage/retrieval system
- **Educational Features**: Protobuf defined; no implementation
- **Events/Playdates**: Protobuf defined; no implementation
- **Geofencing / usage policies / games / community features**: Phase 4 protobuf only

---

## High-Level Roadmap

### **Phase 1: Complete MVP Core (Current Priority)**
**Goal**: Make the basic messaging system fully functional with user management

1. **User Management API**
   - ~~`GET /users` - List users~~ ✅ (`userMessagesApi.c`)
   - ~~`POST /auth/login` - Authenticate registered users (signed request)~~ ✅ (`authApi.c`)
   - `POST /users/register` - Register new users (parents/children) — **open** (today: `init_tool` / `scripts/init.c` only)
   - `POST /users/assign-role` - Role assignment — **open**
   - Integrate user registration with gossip protocol (broadcast `UserRegistration` messages) — **open**

2. **Content Handler Expansion**
   - Implement handlers for Phase 1 MVP types:
     - `UserRegistration` - Store in database, validate, broadcast — **open**
     - Direct messaging - ✅ via `Tinyweb__Message` + HTTP/gossip (not an envelope `ContentType` handler)
     - `GroupCreate/Update/MemberAdd/Remove` - Group management logic — **open**
     - `PermissionEdit` - Integrate with permissions system — **open**
   - Remove "no handler" errors for core message types — **open** (35 types still unhandled in dispatcher)

3. **GPS/Location System** — **largely complete**
   - ~~Store `LocationUpdate` messages in database~~ ✅ (`location_store.c`, gossip + HTTP submit)
   - ~~`GET /location/:user_id`~~ ✅ (`locationApi.c`)
   - ~~`GET /location/history/:user_id`~~ ✅ (`locationApi.c`)
   - ~~Real-time location tracking for parental monitoring~~ ✅ (encrypted storage + permission-gated API + web map UI); push notifications / mobile background tracking — **open**

4. **Permissions Integration**
   - ~~Connect permission system to location routing~~ ✅ (`location_permissions.c`)
   - Enforce permissions on message submission — **open** (`message_permissions.c` is permissive)
   - Parental controls enforcement (screen time, content filters) — **open**

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
   - Emergency alert system (handler exists, needs storage/UI/notification)
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

   *Note:* A **web admin UI** already exists for messaging, locations, and keys (`client/web-ui/`). Extension management, app distribution, and full node ops UI remain **not started**.

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
1. **User Registration API** - Can't onboard users at runtime without `init_tool` / config seeding
2. **Content Handler Coverage** - **2/38** envelope types have dispatcher handlers (+ node registration handled separately); most gossip content types still fail dispatch
3. ~~**GPS Storage**~~ - **Resolved**: encrypted storage, HTTP API, gossip handler, and web UI map
4. **Permissions Enforcement (messaging & controls)** - Location paths use RBAC; messaging and parental rules are not enforced

### **Short-term (Blocking Family Use)**
1. **Group Messaging** - Families need group chats
2. **Parental Controls UI & enforcement** - Parents need to configure and enforce limits
3. **Mobile Apps** - Can't use web UI on phones easily
4. **Emergency Alerts** - Handler exists (console only); needs persistence and notification system

### **Medium-term (Blocking Business Model)**
1. **Extension / ops dashboard** - Can't manage extensions without it (distinct from current messaging/location web UI)
2. **Extension Infrastructure** - Core to business plan
3. **App Distribution** - Needed for phone deployment
4. **Android Base Image** - Required for phone setup

---

## Recommendations

### **Focus Areas (Next 3 Months)**
1. **Complete MVP Core** - Runtime user registration API, envelope handlers for core types, messaging permission enforcement
2. **Polish Web UI** - Build on existing admin dashboard (messaging + locations) for early adopters
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
- Parents can register themselves and children (self-service API, not only init seeding)
- ✅ Families can send encrypted messages to each other (HTTP + gossip + web UI)
- ✅ GPS tracking works end-to-end (location → encrypted storage → permission-gated retrieval → web map)
- Basic parental controls are enforceable
- ✅ Web UI is usable for daily messaging and location monitoring (admin dashboard; extension/ops dashboard still out of scope)

### **Beta Ready When:**
- Mobile apps exist for parents and children
- Group messaging works
- Emergency alerts notify parents
- Dashboard exists for node management (extensions, app distribution, full ops—not only the current messaging/location web UI)

### **Production Ready When:**
- Extension system works (Jellyfin/Immich integrated)
- App distribution works
- Android base image is available
- Documentation is complete
- Security audit passed
