# TinyWeb (C Edition)

TinyWeb is a family-focused communication node that now ships with a **gossip-first runtime**. The default build gives you a lightweight, signed-and-encrypted message relay with local SQLite persistence. A complete PBFT blockchain stack still exists, but it lives under `src/features/blockchain` and is built only when you explicitly opt in.

## Project Goals

- Deliver a private, parent-controlled messaging and location channel for kids and trusted contacts.
- Keep the default experience simple: gossip propagation + local validation + HTTP ingestion.
- Preserve the earlier PBFT work as an optional module that can be re-enabled after launch.

## Runtime Modes

| Mode | Description | Entry Point |
|------|-------------|-------------|
| Gossip (default) | UDP gossip fan-out, HTTP ingestion, SQLite storage with TTL cleanup | `src/main.c` (`tinyweb`) |
| PBFT (optional) | Full blockchain consensus, REST control plane, persistence manager | `src/features/blockchain/app/main_pbft.c` (`tinyweb_pbft`) |

## Quick Start (Gossip Node)

```bash
cmake -S . -B build
cmake --build build

cd build
./tinyweb --id 0 --gossip-port 9000 --api-port 8000
```

HTTP endpoints:

- `POST /gossip/transaction` – JSON body `{ "transaction_hex": "..." }` (serialized transaction in hex)
- `GET /gossip/recent?limit=50` – recent messages with metadata

Gossip packets are validated locally (signature, timestamp, payload size) and persisted with automatic TTL cleanup (default 30 days).

## Optional Blockchain Build

```bash
cmake --build build --target tinyweb_pbft
cmake --build build --target tinyweb_pbft_tests

# run optional tests
ctest --tests-regex Pbft -C Release
```

The blockchain implementation, tests, and utilities reside under `src/features/blockchain`. They link against the shared `pbft_support` library and do not affect the gossip executable unless you build those targets.

## Key Directories

- `src/main.c` – gossip node entry point (UDP + HTTP)
- `src/packages/comm/gossip/` – UDP transport
- `src/packages/comm/gossipApi.*` – HTTP ingestion/extraction
- `src/packages/sql/gossip_store.*` – SQLite persistence for gossip messages
- `src/packages/transactions/` – shared transaction structures & serialization
- `src/features/blockchain/` – legacy PBFT, persistence, and tests (opt-in)

## Data Storage

- Gossip mode initialises SQLite via `db_init_gossip`, enabling WAL but skipping PBFT schema.
- Messages are stored in `gossip_messages` with hex-encoded payloads and expiry timestamps.
- TTL cleanup runs every 60 seconds.

## Contributing

Pull requests and discussions are welcome—especially around expanding the gossip API, refining validation rules, or reintroducing blockchain once the gossip MVP is battle-tested.
