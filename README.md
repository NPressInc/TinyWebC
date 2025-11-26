# TinyWeb (C Edition)

TinyWeb is a family-focused communication node built on a **gossip protocol** with **protobuf-based messaging**. It provides a lightweight, signed-and-encrypted message relay with local SQLite persistence, enabling private communication between family members and trusted contacts.

## Project Goals

- Deliver a private, parent-controlled messaging and location channel for kids and trusted contacts.
- Use a simple gossip protocol for message propagation across nodes.
- Leverage protobuf for all message types, ensuring type safety and extensibility.
- Provide local validation, HTTP ingestion, and automatic message expiry.

## Architecture

TinyWeb uses a **gossip protocol** for peer-to-peer message propagation:
- **UDP-based gossip**: Messages are broadcast to known peers via UDP
- **Protobuf serialization**: All message types are defined in protobuf schemas
- **HTTP API**: RESTful endpoints for message ingestion and retrieval
- **SQLite storage**: Local persistence with automatic TTL cleanup

## Quick Start

```bash
cmake -S . -B build
cmake --build build

cd build
./tinyweb --id 0 --gossip-port 9000 --api-port 8000
```

HTTP endpoints:

- `POST /gossip/envelope` – Submit a protobuf-encoded envelope (hex or binary)
- `GET /gossip/recent?limit=50` – recent messages with metadata
- `GET /gossip/messages?user=<pubkey>&with=<pubkey>` – messages between two users
- `GET /gossip/conversations?user=<pubkey>` – list of conversation partners with recent activity

Gossip packets are validated locally (signature, timestamp, payload size) and persisted with automatic TTL cleanup (default 30 days).

## Protobuf Message Types

All message types are defined using Protocol Buffers:

- `src/proto/envelope.proto` – Envelope structure with encryption and signing
- `src/proto/content.proto` – All content message types (40+ message types)

Content types include:
- **User Management** (1-9): UserRegistration, RoleAssignment
- **Communication** (10-19): DirectMessage, GroupMessage
- **Group Management** (20-29): GroupCreate, GroupUpdate, MemberAdd/Remove
- **Safety & Control** (30-39): Permissions, Parental Controls, Location, Emergency
- **Network Management** (40-49): Node Registration, System Config
- **Enhanced Features** (60+): Media, Voice Calls, Educational Resources, Games, Events

## Key Directories

- `src/main.c` – gossip node entry point (UDP + HTTP)
- `src/proto/` – protobuf schema definitions
- `src/packages/comm/gossip/` – UDP gossip transport
- `src/packages/comm/gossipApi.*` – HTTP ingestion/extraction
- `src/packages/comm/envelope_dispatcher.*` – protobuf envelope routing
- `src/packages/sql/gossip_store.*` – SQLite persistence for gossip messages
- `src/packages/transactions/envelope.*` – protobuf envelope utilities
- `src/packages/validation/gossip_validation.*` – message validation

## Data Storage

- SQLite database initialized via `db_init_gossip`, enabling WAL mode.
- Messages are stored in `gossip_messages` with protobuf-encoded payloads and expiry timestamps.
- TTL cleanup runs every 60 seconds.

## Docker Deployment (Recommended)

TinyWeb supports easy deployment via Docker Compose with automatic peer discovery using Tailscale sidecars.

**Quick setup:**

```bash
# 1) Get Tailscale auth key from admin console
export TS_AUTHKEY=tskey-auth-xxxxx

# 2) Generate configs and docker-compose files
python3 scripts/docker_config_generator.py --master-config scripts/configs/network_config.json

# 3) Start all nodes
docker-compose up -d
```

**Features:**
- **Automatic peer discovery**: Nodes discover each other via Tailscale API
- **No manual configuration**: Just provide auth key and run docker-compose
- **Fully containerized**: Tailscale runs in sidecar containers, no host setup needed
- **Dynamic networking**: Nodes automatically find and connect to each other

See `initialization_tasks.txt` for detailed setup instructions.

## Contributing

Pull requests and discussions are welcome—especially around expanding the gossip protocol, adding new protobuf message types, refining validation rules, or improving the HTTP API.


This project is still in MVP stage/proof of concept

Hello. Welcome to Tiny Web, the redundant communication network for families! Why do we exist? These days there is a demand for kids to have a phone and that is valid! Parents want to have communication and be able to track their children when they are out there in the world. Right now there are a couple of options. You have the Gabb phone and competitors which provide calling/texting/GPS features, and they work great. If kids want to be able to communicate with their friends, share content, play games with their friends, then they have to get an Andriod or iPhone. When they do get a full-fledged smartphone, the flood gates are open. In an instant, they can access any information on the entire web, and I am assuming that you wouldn’t want that for your children without some safeguards. Of course, there are parental controls, right? I have one simple example that demonstrates why those are insufficient. Imagine putting your child into a library with all of the world’s content, ripe for the picking. This library lets you access any information that anyone else has put on the internet, uncurated, and unfiltered. Not only is it uncurated, but there are algorithms behind this content that are trying to cause addictive behavior. The current parental locks put metaphorical locks on certain books to make sure that they don’t read them, but what happens of they miss a book? What happens if new books are introduced to the library? Like they are every day? See the problem? Now imagine an empty library, put your child in with a few books, that you approve. This mirrors an older simpler time when content could be controlled and it was not controlling us. And it is the solution.

I propose a decentralized application that runs on nodes within the parent’s households. This "backend" application will be paired with devices for children and apps for parents. This network will allow parents to communicate with their children track GPS as the Gabb phone does, but it will also allow families to join each other’s network with the right permissions. This will allow, for the first time, kids to interact with trusted members of the community in a safe and secure way. They will be able to message, play games, etc. Not only that, this will provide a platform for parents to communicate with each other to set up events, activities, and playdates. Each network will be completely private, encrypted, and free from any intervention since the networks are hosted at home!

Business plan:
I will open source the backend for this application(this repo) and open source some apps for degoogled android. I hope to host a apps/services repo for people. They can download services and apps from this repo and add them to their own networks super easily. The services will be isolated into docker compose files and run alongside the core docker image that runs the main server and communicates with the extensions via bridge. And the associated apps will communicate to the extensions. Everything will be open source and hosting of the extensions/apps will be free. I will only charge for hosting if people want me to host this for them. Extentions and apps should be auto configured via a dashboard(to be built) where they can auto start the extension on their instance and push apps to the network phones via a repo url. The initial extensions will be existing open source projects like jellyfin and immich. The only source of income will be if people decide to host with me. They will have to buy and setup their own phones, i will provide a base image to flash on their android phones based on an open source de-googled andoid image. 