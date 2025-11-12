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
- `GET /gossip/messages?user=<pubkey>&with=<pubkey>` – messages between two users
- `GET /gossip/conversations?user=<pubkey>` – list of conversation partners with recent activity

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

## Networking (Tailscale Optional)

If you want painless private networking across home devices and cloud hosts, use Tailscale.

Quick setup:

```bash
# 1) Create an auth key in the Tailscale admin console (prefer a tag key like tag:tinyweb-node)
# 2) On each node (Raspberry Pi, EC2, etc.):
TS_AUTHKEY=tskey-abcdef TS_HOSTNAME=my-tinyweb-node TS_TAGS=tag:tinyweb-node \
sudo ./scripts/setup_tailscale.sh

# Verify
tailscale status
tailscale ip -4
```

Notes:
- Works with MagicDNS (hostname resolution like `node.tailnet.ts.net`).
- Non-interactive if `TS_AUTHKEY` is provided; otherwise it will prompt with a login URL.
- Open egress to Tailscale (TCP 443/HTTPS, UDP 41641). No inbound ports required.

## Contributing

Pull requests and discussions are welcome—especially around expanding the gossip API, refining validation rules, or reintroducing blockchain once the gossip MVP is battle-tested.


This project is still in MVP stage/proof of concept

Hello. Welcome to Tiny Web, the redundant communication network for families! Why do we exist? These days there is a demand for kids to have a phone and that is valid! Parents want to have communication and be able to track their children when they are out there in the world. Right now there are a couple of options. You have the Gabb phone and competitors which provide calling/texting/GPS features, and they work great. If kids want to be able to communicate with their friends, share content, play games with their friends, then they have to get an Andriod or iPhone. When they do get a full-fledged smartphone, the flood gates are open. In an instant, they can access any information on the entire web, and I am assuming that you wouldn’t want that for your children without some safeguards. Of course, there are parental controls, right? I have one simple example that demonstrates why those are insufficient. Imagine putting your child into a library with all of the world’s content, ripe for the picking. This library lets you access any information that anyone else has put on the internet, uncurated, and unfiltered. Not only is it uncurated, but there are algorithms behind this content that are trying to cause addictive behavior. The current parental locks put metaphorical locks on certain books to make sure that they don’t read them, but what happens of they miss a book? What happens if new books are introduced to the library? Like they are every day? See the problem? Now imagine an empty library, put your child in with a few books, that you approve. This mirrors an older simpler time when content could be controlled and it was not controlling us. And it is the solution.

I propose a decentralized application that runs on nodes within the parent’s households. This "backend" application will be paired with devices for children and apps for parents. This network will allow parents to communicate with their children track GPS as the Gabb phone does, but it will also allow families to join each other’s network with the right permissions. This will allow, for the first time, kids to interact with trusted members of the community in a safe and secure way. They will be able to message, play games, etc. Not only that, this will provide a platform for parents to communicate with each other to set up events, activities, and playdates. Each network will be completely private, encrypted, and free from any intervention since the networks are hosted at home!