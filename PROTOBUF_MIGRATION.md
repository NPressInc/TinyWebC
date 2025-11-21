# Protobuf Migration Plan

## Current State

### Two Parallel Systems

1. **Legacy: `/gossip/transaction` (Binary Serialization)**
   - Uses `TW_Transaction` struct with custom binary format
   - ~50 transaction types (enum values 0-99)
   - Uses `EncryptedPayload` struct with flat arrays
   - UDP-based gossip rebroadcasting
   - Status: **Legacy, to be deprecated**

2. **New: `/gossip/envelope` (Protobuf)**
   - Uses protobuf `Envelope` message
   - Now has 40+ content types defined (with room for 200+)
   - Better structured encryption format with `RecipientKeyWrap`
   - HTTP-based gossip rebroadcasting
   - Status: **Active development, future standard**

## Protobuf Schema

### Files
- `src/proto/envelope.proto` - Envelope structure and ContentType enum
- `src/proto/content.proto` - All message type definitions (40+ messages)

### Content Type Categories
- **1-9**: User Management (UserRegistration, RoleAssignment)
- **10-19**: Communication (DirectMessage, GroupMessage)
- **20-29**: Group Management (Create, Update, Add/Remove members)
- **30-39**: Safety & Control (Permissions, Parental Controls, Location, Emergency)
- **40-49**: Network Management (Node Registration, System Config)
- **50-59**: Access Control
- **60-99**: Enhanced Communication & Media
- **100-149**: Educational & Family Features
- **150-199**: Advanced Features (Geofencing, Games, Events, etc.)

## Migration Strategy

### Phase 1: Foundation ✅ COMPLETE
- [x] Design comprehensive protobuf schema
- [x] Add all 40+ message types to content.proto
- [x] Add ContentType enum to envelope.proto
- [x] Generate protobuf-c code
- [x] Add rebroadcasting to /gossip/envelope

### Phase 2: Infrastructure 🔄 IN PROGRESS
- [ ] Create envelope content dispatcher
- [ ] Refactor encryption to work natively with protobuf (remove EncryptedPayload bridge)
- [ ] Add validation handlers for each content type
- [ ] Create helper functions for envelope creation/parsing

### Phase 3: Gradual Migration
- [ ] Migrate Phase 1 (MVP) content types first:
  - User Management (2 types)
  - Communication (2 types) 
  - Group Management (5 types)
  - Safety & Control (5 types)
  - Network & Access (3 types)
- [ ] Update clients to use protobuf envelopes
- [ ] Run both systems in parallel during migration

### Phase 4: Completion
- [ ] Migrate remaining content types (Phases 2-4)
- [ ] Deprecate /gossip/transaction endpoint
- [ ] Remove TW_Transaction and EncryptedPayload code
- [ ] Update documentation

## Current Issues

### Encryption Bridge
The current `envelope.c` bridges between two formats:
1. Calls old `encrypt_payload_multi()` → returns `EncryptedPayload*`
2. Manually unpacks flat arrays into protobuf `RecipientKeyWrap` structs

**Solution**: Refactor `encryption.c` to work directly with protobuf structures.

### Validation
Old system uses `gossip_validate_transaction()` which validates TW_Transaction.

**Solution**: Create new validation system that dispatches based on content_type.

## Next Steps

1. Create envelope content dispatcher (`envelope_dispatcher.c`)
2. Refactor encryption layer
3. Start migrating DirectMessage and GroupMessage first (most used)
4. Gradually migrate other content types
5. Maintain backward compatibility during migration

## Benefits of Migration

1. **Better Compatibility**: Protobuf is language-agnostic
2. **Schema Evolution**: Forward/backward compatibility
3. **Better Structure**: Proper message nesting vs flat structs
4. **Smaller Wire Format**: Protobuf is more compact than custom binary
5. **Code Generation**: Automatic serialization/deserialization
6. **Industry Standard**: Well-tested, widely used

