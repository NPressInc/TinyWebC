# TinyWeb (C Edition)

TinyWeb is a private, family-focused communication network built on a **decentralized gossip protocol**. It provides a lightweight, encrypted message relay with local SQLite persistence, designed to give parents control over their children's digital environment without the risks of the open web.

## Quick Start

### Build
```bash
cmake -S . -B build
cmake --build build
```

### Run
```bash
./build/tinyweb --id 1 --gossip-port 9000 --api-port 8000
```

## Core Architecture

TinyWeb nodes communicate over a peer-to-peer network:
- **Gossip Transport (UDP/9000)**: Messages are signed, encrypted, and broadcast to known peers.
- **HTTP API (TCP/8000)**: Used by clients (mobile/web) to submit messages and fetch history.
- **Protobuf**: All messages use strictly defined Protocol Buffer schemas for safety and efficiency.
- **SQLite**: Local persistence with automatic TTL cleanup (default 30 days).

## HTTP API Endpoints

### Messaging
- `POST /messages/submit` – Submit a signed `Tinyweb__Message` protobuf.
- `GET /messages/recent` – Fetch recent message history.
- `GET /messages/conversations` – List active conversation partners.
- `GET /messages/conversation` – Fetch messages for a specific conversation.

### Location Tracking
- `POST /location/update` – Submit a location update (GPS coordinates).
- `GET /location/:user_id` – Get the latest location for a user.
- `GET /location/history/:user_id` – Get location history with pagination.

Location data is encrypted and only accessible to authorized users (self, parents, or admins). All endpoints require authentication.

### Network & Health
- `GET /gossip/peers` – List currently known gossip peers.
- `GET /health` – Node status (useful for Docker/orchestration).

## Project Structure

- `src/main.c` – Node entry point and service orchestration.
- `src/proto/` – Protobuf definitions (`envelope`, `message`, `content`, `client_request`).
- `src/packages/comm/` – Gossip transport and HTTP API handlers.
- `src/packages/sql/` – SQLite storage logic and schema management.
- `src/packages/validation/` – Cryptographic signature and timestamp validation.
- `src/packages/discovery/` – Peer discovery (Tailscale, DNS, Static).

## Deployment

TinyWeb is designed to run in Docker. Configuration is driven by `scripts/network_config.json`, which defines the node topology.

```bash
# Generate Docker Compose configs
python3 scripts/docker_config_generator.py --master-config scripts/configs/network_config.json

# Start the network
docker-compose up -d
```

**Note:** This project is still in MVP stage/proof of concept.

---

## Why TinyWeb?

Hello. Welcome to Tiny Web, the redundant communication network for families! Why do we exist? These days there is a demand for kids to have a phone and that is valid! Parents want to have communication and be able to track their children when they are out there in the world. Right now there are a couple of options. You have the Gabb phone and competitors which provide calling/texting/GPS features, and they work great. If kids want to be able to communicate with their friends, share content, play games with their friends, then they have to get an Andriod or iPhone. When they do get a full-fledged smartphone, the flood gates are open. In an instant, they can access any information on the entire web, and I am assuming that you wouldn't want that for your children without some safeguards. Of course, there are parental controls, right? I have one simple example that demonstrates why those are insufficient. Imagine putting your child into a library with all of the world's content, ripe for the picking. This library lets you access any information that anyone else has put on the internet, uncurated, and unfiltered. Not only is it uncurated, but there are algorithms behind this content that are trying to cause addictive behavior. The current parental locks put metaphorical locks on certain books to make sure that they don't read them, but what happens of they miss a book? What happens if new books are introduced to the library? Like they are every day? See the problem? Now imagine an empty library, put your child in with a few books, that you approve. This mirrors an older simpler time when content could be controlled and it was not controlling us. And it is the solution.

I propose a decentralized application that runs on nodes within the parent's households. This "backend" application will be paired with devices for children and apps for parents. This network will allow parents to communicate with their children track GPS as the Gabb phone does, but it will also allow families to join each other's network with the right permissions. This will allow, for the first time, kids to interact with trusted members of the community in a safe and secure way. They will be able to message, play games, etc. Not only that, this will provide a platform for parents to communicate with each other to set up events, activities, and playdates. Each network will be completely private, encrypted, and free from any intervention since the networks are hosted at home!

## Business Plan

I will open source the backend for this application(this repo) and open source some apps for degoogled android. I hope to host a apps/services repo for people. They can download services and apps from this repo and add them to their own networks super easily. The services will be isolated into docker compose files and run alongside the core docker image that runs the main server and communicates with the extensions via bridge. And the associated apps will communicate to the extensions. Everything will be open source and hosting of the extensions/apps will be free. I will only charge for hosting if people want me to host this for them. Extentions and apps should be auto configured via a dashboard(to be built) where they can auto start the extension on their instance and push apps to the network phones via a repo url. The initial extensions will be existing open source projects like jellyfin and immich. The only source of income will be if people decide to host with me. They will have to buy and setup their own phones, i will provide a base image to flash on their android phones based on an open source de-googled andoid image.
