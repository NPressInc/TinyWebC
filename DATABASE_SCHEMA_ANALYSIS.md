# Database Schema Alignment Analysis

## Current Database Tables

### Tables Created by `gossip_store.c` (used by main.c)
1. **gossip_messages** - Message storage with TTL
2. **gossip_envelopes** - Envelope storage with TTL
3. **gossip_seen** - Deduplication digests
4. **users** - User accounts (INTEGER timestamps, has `registration_transaction_id`)
5. **roles** - Role definitions (INTEGER timestamps)
6. **permissions** - Permission definitions
7. **user_roles** - User-role assignments (INTEGER timestamps, has `assignment_transaction_id`)
8. **role_permissions** - Role-permission mappings (INTEGER timestamps, has `grant_transaction_id`)
9. **transaction_permissions** - Transaction type permissions

### Tables Created by `gossip_peers.c` (used by main.c)
1. **gossip_peers** - Peer information:
   - `hostname` (TEXT PRIMARY KEY)
   - `gossip_port` (INTEGER)
   - `api_port` (INTEGER)
   - `first_seen` (INTEGER)
   - `last_seen` (INTEGER)
   - `tags` (TEXT)
   - **MISSING**: `discovery_mode` (optional per plan)

### Tables Created by `schema.c` (used by init.c and tests)
1. **users** - User accounts (TIMESTAMP fields, NO transaction_id fields)
2. **roles** - Role definitions (TIMESTAMP fields)
3. **permissions** - Permission definitions
4. **user_roles** - User-role assignments (TIMESTAMP fields, NO transaction_id)
5. **role_permissions** - Role-permission mappings (TIMESTAMP fields, NO transaction_id)

### Tables NOT YET CREATED (per plan)
1. **nodes** - Node configuration storage:
   - `node_id` (TEXT PRIMARY KEY)
   - `node_name` (TEXT)
   - `hostname` (TEXT)
   - `gossip_port` (INTEGER)
   - `api_port` (INTEGER)
   - `discovery_mode` (TEXT)
   - `hostname_prefix` (TEXT, nullable)
   - `dns_domain` (TEXT, nullable)
   - `created_at` (TIMESTAMP)
   - `updated_at` (TIMESTAMP)

2. **schema_version** - Schema versioning (exists in schema.c but not in gossip_store.c)

## Critical Issues Found

### 1. Duplicate Table Definitions
**Problem**: Both `schema.c` and `gossip_store.c` define the same tables (users, roles, permissions, user_roles, role_permissions) but with different schemas:

| Table | schema.c | gossip_store.c |
|-------|----------|----------------|
| users | TIMESTAMP fields, no transaction_id | INTEGER timestamps, has registration_transaction_id |
| user_roles | TIMESTAMP fields, no transaction_id | INTEGER timestamps, has assignment_transaction_id |
| role_permissions | TIMESTAMP fields, no transaction_id | INTEGER timestamps, has grant_transaction_id |

**Impact**: 
- `init.c` uses `schema.c` (TIMESTAMP format)
- `main.c` uses `gossip_store.c` (INTEGER format)
- This creates schema conflicts if both are used on the same database

**Recommendation**: 
- Standardize on one schema definition
- Since `main.c` uses `gossip_store.c`, that should be the canonical source
- Update `init.c` to use `gossip_store_init()` instead of `schema_create_all_tables()`

### 2. Missing Nodes Table
**Problem**: The plan requires a `nodes` table to store node configuration (discovery_mode, hostname_prefix, dns_domain), but it doesn't exist.

**Status**: Not implemented yet (per plan section 1.6)

### 3. Schema Version Mismatch
**Problem**: 
- `schema.h` defines `CURRENT_SCHEMA_VERSION` as 1
- Plan requires version 2 for nodes table migration
- `gossip_store.c` doesn't use schema versioning at all

**Impact**: No migration path for adding nodes table

**Recommendation**: 
- Update `CURRENT_SCHEMA_VERSION` to 2 in `schema.h`
- Add schema versioning to `gossip_store.c` or create unified schema management
- Add migration path in `schema_migrate()` for version 1 → 2

### 4. Initialization Flow Inconsistency
**Current flow in `main.c`**:
```c
db_init_gossip(db_path)
gossip_store_init()  // Creates users/roles/permissions with INTEGER timestamps
gossip_peers_init()  // Creates gossip_peers table
```

**Current flow in `init.c`**:
```c
schema_create_all_tables()  // Creates users/roles/permissions with TIMESTAMP
schema_create_all_indexes()
```

**Problem**: Two different initialization paths create conflicting schemas

**Recommendation**: 
- `init.c` should call `gossip_store_init()` and `gossip_peers_init()` instead of `schema_create_all_tables()`
- Or create unified initialization function that both use

### 5. Optional: gossip_peers.discovery_mode
**Status**: Per plan, this is optional but recommended for debugging

**Current**: Not implemented

**Recommendation**: Add as optional enhancement in Phase 1.6

## Alignment Checklist

### Required for Plan Implementation

- [ ] **Create nodes table** (Phase 1.6)
  - [ ] Add SQL_CREATE_NODES to schema.c
  - [ ] Add SQL_CREATE_INDEX_NODES_NODE_ID
  - [ ] Add SQL_INSERT_OR_UPDATE_NODE
  - [ ] Add SQL_SELECT_NODE_BY_ID
  - [ ] Add nodes_insert_or_update() function
  - [ ] Add nodes_get_by_id() function
  - [ ] Update schema_create_all_tables() to include nodes
  - [ ] Update schema_migrate() for version 1 → 2

- [ ] **Update schema version** (Phase 1.6)
  - [ ] Update CURRENT_SCHEMA_VERSION to 2 in schema.h
  - [ ] Add migration path in schema_migrate()

- [ ] **Fix duplicate schema definitions** (Critical)
  - [ ] Decide on canonical schema (gossip_store.c or schema.c)
  - [ ] Update init.c to use same initialization as main.c
  - [ ] Remove duplicate table definitions

- [ ] **Integrate nodes table into initialization** (Phase 1.6)
  - [ ] Update init.c to store node config after initialization
  - [ ] Update main.c to store node config after loading config

- [ ] **Optional: Add discovery_mode to gossip_peers** (Phase 1.6)
  - [ ] Add ALTER TABLE statement
  - [ ] Update gossip_peers_add_or_update() signature
  - [ ] Store discovery_mode when adding peers

## Recommended Actions

### Immediate (Before Phase 1 Implementation)

1. **Resolve schema duplication**:
   - Choose `gossip_store.c` as canonical (since main.c uses it)
   - Update `init.c` to call `gossip_store_init()` instead of `schema_create_all_tables()`
   - Remove duplicate table definitions from `schema.c` OR make `schema.c` the canonical source and update `gossip_store.c`

2. **Unify initialization**:
   - Create single initialization function that both `main.c` and `init.c` can use
   - Ensure consistent table creation across all code paths

### During Phase 1.6 Implementation

1. **Add nodes table**:
   - Add to `schema.c` (or unified schema location)
   - Add migration path
   - Update version to 2

2. **Integrate with initialization**:
   - Update `init.c` to store node config
   - Update `main.c` to store node config

3. **Optional enhancement**:
   - Add `discovery_mode` to `gossip_peers` table

## Files Requiring Updates

1. `src/packages/sql/schema.c` - Add nodes table, update migration
2. `src/packages/sql/schema.h` - Update version, add nodes declarations
3. `src/packages/sql/gossip_peers.c` - Optional: add discovery_mode
4. `src/packages/sql/gossip_store.c` - Consider schema versioning integration
5. `scripts/init.c` - Use unified initialization, store node config
6. `src/main.c` - Store node config after loading

## Notes

- The duplicate schema issue is critical and should be resolved before implementing Phase 1.6
- The nodes table is new and doesn't conflict with existing schemas
- Schema versioning exists in `schema.c` but not in `gossip_store.c` - needs unification
- Timestamp format inconsistency (TIMESTAMP vs INTEGER) needs resolution

