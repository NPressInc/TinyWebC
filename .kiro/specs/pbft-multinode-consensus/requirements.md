# Multi-Node PBFT Consensus Requirements

## Introduction

This document outlines the requirements for implementing full multi-node Practical Byzantine Fault Tolerance (PBFT) consensus in the TinyWeb blockchain system. Currently, the system operates as a single-node blockchain with stubbed consensus functions. This feature will enable true distributed consensus across multiple nodes in a family network.

The PBFT consensus algorithm ensures Byzantine fault tolerance, allowing the network to continue operating correctly even if up to 1/3 of nodes are faulty or malicious. This is critical for a family communication network where nodes may go offline, have network issues, or experience hardware failures.

## Requirements

### Requirement 1: Peer Discovery and Management

**User Story:** As a PBFT node operator, I want my node to automatically discover and maintain connections with other nodes in the network, so that the distributed consensus can function properly.

#### Acceptance Criteria

1. WHEN a node starts up THEN it SHALL load peer information from the blockchain using `pbft_node_load_peers_from_blockchain()`
2. WHEN a new node joins the network THEN existing nodes SHALL automatically discover and add it to their peer list
3. WHEN a node becomes unresponsive THEN other nodes SHALL mark it as delinquent after a configurable timeout using `pbft_node_mark_peer_delinquent()`
4. WHEN a node recovers from being delinquent THEN it SHALL be automatically re-integrated into the consensus process
5. IF a node is marked delinquent for more than a threshold (15 failures) THEN it SHALL be temporarily excluded from consensus calculations
6. WHEN peer information changes THEN all nodes SHALL update their peer lists within a reasonable time window
7. WHEN peers are loaded THEN the system SHALL maintain ID-to-IP mappings, public key-to-IP mappings, and public key-to-ID mappings
8. WHEN peer lists are updated THEN peers SHALL be shuffled periodically to prevent bias in communication patterns

### Requirement 2: PBFT Message Broadcasting

**User Story:** As a PBFT node, I want to broadcast consensus messages (proposals, votes) to all peers in the network, so that distributed consensus can be achieved.

#### Acceptance Criteria

1. WHEN a node proposes a block THEN it SHALL broadcast the proposal to all active peers using `pbft_node_broadcast_block()`
2. WHEN a node receives a valid block proposal THEN it SHALL broadcast a verification vote to all peers using `pbft_node_broadcast_verification_vote()`
3. WHEN a node receives sufficient verification votes THEN it SHALL broadcast a commit vote to all peers using `pbft_node_broadcast_commit_vote()`
4. WHEN a node receives sufficient commit votes THEN it SHALL commit the block locally
5. IF a message broadcast fails to reach a peer THEN the node SHALL increment the peer's delinquent counter
6. WHEN broadcasting messages THEN the node SHALL use authenticated and signed communication with Ed25519 signatures
7. IF a node receives duplicate messages THEN it SHALL ignore them without processing
8. WHEN a peer fails to respond THEN it SHALL be marked as delinquent and excluded after threshold failures
9. WHEN a delinquent peer recovers THEN its delinquent counter SHALL be reset to zero
10. WHEN broadcasting to new nodes THEN the entire blockchain SHALL be sent using `pbft_node_broadcast_blockchain_to_new_node()`

### Requirement 3: Vote Counting and Consensus Logic

**User Story:** As a PBFT node, I want to count votes from peers and make consensus decisions based on the 2/3 + 1 threshold, so that Byzantine fault tolerance is maintained.

#### Acceptance Criteria

1. WHEN a node receives verification votes THEN it SHALL count votes from unique peers only
2. WHEN verification votes reach 2/3 + 1 threshold THEN the node SHALL proceed to commit phase
3. WHEN commit votes reach 2/3 + 1 threshold THEN the node SHALL commit the block
4. IF insufficient votes are received within timeout THEN the node SHALL trigger a new round
5. WHEN counting votes THEN the node SHALL verify the signature of each vote
6. IF a peer sends conflicting votes for the same round THEN it SHALL be marked as potentially Byzantine
7. WHEN calculating thresholds THEN only active (non-delinquent) peers SHALL be included

### Requirement 4: Blockchain Synchronization

**User Story:** As a PBFT node, I want to synchronize my blockchain with peers to ensure consistency, so that all nodes maintain the same state.

#### Acceptance Criteria

1. WHEN a node detects it has a shorter blockchain THEN it SHALL request missing blocks from peers using `pbft_node_request_missing_blocks_from_peer()`
2. WHEN a node receives a sync request THEN it SHALL provide the requested blocks if available via `/MissingBlockRequeset` endpoint
3. WHEN a node falls significantly behind THEN it SHALL request the entire blockchain from a peer using `pbft_node_request_entire_blockchain_from_peer()`
4. IF conflicting blocks are detected THEN the node SHALL resolve using the longest valid chain rule
5. WHEN syncing blocks THEN the node SHALL validate each block before adding to local chain
6. IF sync fails repeatedly THEN the node SHALL mark the peer as potentially faulty
7. WHEN sync completes THEN the node SHALL resume normal consensus participation
8. WHEN requesting blockchain length THEN nodes SHALL use `pbft_node_get_blockchain_length_from_peer()` function
9. WHEN requesting last block hash THEN nodes SHALL use `pbft_node_get_last_block_hash_from_peer()` function
10. IF blockchains share no common hashes THEN the node SHALL request the entire blockchain from the peer
11. WHEN receiving missing blocks THEN they SHALL be added in reverse order (newest first) after validation

### Requirement 5: Network Communication Layer

**User Story:** As a PBFT node, I want reliable HTTP-based communication with peers, so that consensus messages can be exchanged efficiently.

#### Acceptance Criteria

1. WHEN sending messages to peers THEN the node SHALL use HTTP POST with JSON payloads
2. WHEN a peer is unreachable THEN the node SHALL implement retry logic with timeouts
3. WHEN receiving messages THEN the node SHALL validate message format and signatures
4. IF network partitions occur THEN nodes SHALL continue operating with available peers
5. WHEN network partitions heal THEN nodes SHALL automatically resync and rejoin consensus
6. WHEN sending large data (blockchain sync) THEN the node SHALL implement chunking if needed
7. IF message queues become full THEN the node SHALL implement backpressure mechanisms

### Requirement 6: Round Management and View Changes

**User Story:** As a PBFT node, I want to handle consensus rounds and view changes properly, so that the system can recover from failures and continue making progress.

#### Acceptance Criteria

1. WHEN a consensus round times out THEN the node SHALL increment the round number and retry
2. WHEN the current proposer is unresponsive THEN nodes SHALL trigger a view change
3. WHEN sufficient view change messages are received THEN a new proposer SHALL be selected
4. IF multiple rounds fail THEN the node SHALL increase timeout values exponentially
5. WHEN a new view is established THEN all nodes SHALL reset their round state
6. IF a node rejoins after being offline THEN it SHALL catch up to the current round
7. WHEN view changes occur THEN the proposer selection SHALL follow deterministic rules

### Requirement 7: Performance and Scalability

**User Story:** As a family network operator, I want the consensus system to perform well with typical family network sizes (2-10 nodes), so that communication remains responsive.

#### Acceptance Criteria

1. WHEN the network has 4 nodes THEN consensus SHALL complete within 5 seconds under normal conditions
2. WHEN the network has 10 nodes THEN consensus SHALL complete within 10 seconds under normal conditions
3. WHEN network latency is high THEN the system SHALL adjust timeouts automatically
4. IF message volume is high THEN the system SHALL prioritize consensus messages over other traffic
5. WHEN nodes are added/removed THEN performance SHALL degrade gracefully
6. IF memory usage grows THEN old consensus state SHALL be garbage collected
7. WHEN under load THEN the system SHALL maintain Byzantine fault tolerance guarantees

### Requirement 8: Security and Authentication

**User Story:** As a family network participant, I want all consensus messages to be authenticated and secure, so that malicious actors cannot disrupt the network.

#### Acceptance Criteria

1. WHEN sending consensus messages THEN each message SHALL be cryptographically signed
2. WHEN receiving messages THEN signatures SHALL be verified before processing
3. IF invalid signatures are detected THEN the sender SHALL be marked as potentially malicious
4. WHEN establishing peer connections THEN mutual authentication SHALL be performed
5. IF replay attacks are detected THEN duplicate messages SHALL be rejected
6. WHEN a node exhibits Byzantine behavior THEN it SHALL be excluded from consensus
7. IF more than 1/3 of nodes are Byzantine THEN the system SHALL detect and alert administrators

### Requirement 9: Monitoring and Diagnostics

**User Story:** As a system administrator, I want comprehensive monitoring of the consensus process, so that I can diagnose issues and ensure network health.

#### Acceptance Criteria

1. WHEN consensus is running THEN metrics SHALL be collected on round times, vote counts, and peer status
2. WHEN failures occur THEN detailed logs SHALL be generated for debugging
3. IF performance degrades THEN alerts SHALL be generated with diagnostic information
4. WHEN requested THEN the system SHALL provide real-time status of consensus state
5. IF Byzantine behavior is detected THEN security events SHALL be logged
6. WHEN troubleshooting THEN administrators SHALL have access to peer connectivity status
7. IF network partitions occur THEN the system SHALL log partition detection and recovery

### Requirement 10: Transaction Rebroadcasting and Propagation

**User Story:** As a PBFT node, I want to rebroadcast transactions to peers to ensure network-wide transaction propagation, so that all nodes have access to pending transactions.

#### Acceptance Criteria

1. WHEN a node receives a new transaction THEN it SHALL rebroadcast it to all peers using `pbft_node_rebroadcast_transaction()`
2. WHEN rebroadcasting messages THEN the node SHALL use the original message format without modification
3. IF a rebroadcast fails to a peer THEN the node SHALL mark that peer as potentially unreachable
4. WHEN getting pending transactions THEN nodes SHALL use `pbft_node_get_pending_transactions_from_peer()` function
5. IF transaction rebroadcasting is disabled for certain message types THEN it SHALL be configurable
6. WHEN rebroadcasting THEN the node SHALL avoid infinite loops by tracking message origins
7. IF a peer is consistently unreachable for rebroadcasts THEN it SHALL be marked as delinquent

### Requirement 11: Proposer Selection and Round Management

**User Story:** As a PBFT node, I want deterministic proposer selection and proper round management, so that consensus progresses fairly and efficiently.

#### Acceptance Criteria

1. WHEN calculating the proposer THEN the node SHALL use `pbft_node_calculate_proposer_id()` with round-robin selection
2. WHEN the current proposer fails THEN the proposer offset SHALL be incremented to select the next proposer
3. IF no peers exist THEN the node SHALL always be its own proposer (single-node mode)
4. WHEN blockchain length is zero THEN proposer ID SHALL default to 0 for genesis block
5. IF sync fails and node is not proposer THEN proposer offset SHALL be incremented
6. WHEN calculating proposer ID THEN it SHALL use formula: `(last_proposer_id + 1 + offset) % num_peers`
7. IF proposer becomes unresponsive THEN other nodes SHALL vote for missing proposer using `/MissingProposer` endpoint

### Requirement 12: Configuration and Deployment

**User Story:** As a family network administrator, I want to easily configure and deploy multi-node consensus, so that setting up the network is straightforward.

#### Acceptance Criteria

1. WHEN deploying nodes THEN configuration SHALL support specifying initial peer lists
2. WHEN starting a node THEN it SHALL automatically join the existing network if peers are configured
3. IF no peers are configured THEN the node SHALL operate in single-node mode
4. WHEN adding new nodes THEN existing nodes SHALL automatically accept them after validation
5. IF consensus parameters need tuning THEN they SHALL be configurable via configuration files
6. WHEN upgrading nodes THEN the consensus protocol SHALL remain compatible
7. IF emergency shutdown is needed THEN administrators SHALL be able to gracefully stop consensus
8. WHEN nodes start THEN they SHALL use configurable speed modifiers for consensus timing
9. IF blockchain needs initialization THEN nodes SHALL support first-use configuration