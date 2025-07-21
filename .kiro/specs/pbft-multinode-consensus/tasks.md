# Implementation Plan

- [x] 1. Implement missing base node peer management functions
  - Implement `node_add_peer()` function in `src/packages/PBFT/node.c`
  - Implement `node_remove_peer()` function with proper cleanup
  - Implement `node_mark_peer_delinquent()` with delinquent counter tracking
  - Implement `node_get_ip_by_id()`, `node_get_ip_by_pubkey()`, `node_get_id_by_pubkey()` lookup functions
  - Add peer lookup table management and maintenance
  - Write unit tests for all peer management functions
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7_
  - _Status: Functions declared in node.h but not implemented in node.c_

- [x] 2. Implement HTTP client integration for PBFT functions
  - Replace stubbed `pbft_node_http_request()` with calls to existing `http_client_request()`
  - Update `pbft_node_free_http_response()` to use existing `http_response_free()`
  - Add retry logic with exponential backoff to HTTP client functions
  - Implement timeout handling and connection management
  - Write unit tests for HTTP client integration with PBFT functions
  - _Requirements: 5.1, 5.2, 5.3, 5.4_
  - _Status: HTTP client exists but PBFT integration functions are not implemented_

- [ ] 3. Implement JSON serialization for consensus messages
  - Create `pbft_create_vote_json()` for vote message serialization using existing cJSON
  - Create `pbft_parse_vote_json()` for vote message deserialization using existing cJSON
  - Implement `pbft_create_sync_request_json()` for blockchain sync requests
  - Implement `pbft_parse_sync_request_json()` for parsing sync requests
  - Add comprehensive JSON validation and error handling
  - Write unit tests for JSON serialization functions
  - _Requirements: 2.6, 5.6, 8.1, 8.2_
  - _Status: cJSON integrated but PBFT-specific JSON helper functions not implemented_

- [ ] 4. Implement vote counting and consensus logic
  - Implement vote tracking functions using existing MessageQueues structure from pbftApi.h
  - Create `add_verification_vote()` with duplicate detection using ValidationVotes structure
  - Implement `add_commit_vote()` with signature validation using CommitMessages structure
  - Create `has_sufficient_votes()` function using 2/3 + 1 threshold calculation
  - Implement `calculate_vote_threshold()` based on active peer count
  - Add `clear_votes_for_block()` for cleanup after consensus using existing message queue functions
  - Write unit tests for vote counting logic
  - _Requirements: 3.1, 3.2, 3.3, 3.5, 3.6, 3.7_
  - _Status: MessageQueues structure exists but vote counting functions not implemented_

- [ ] 5. Implement peer-to-peer message broadcasting functions
  - Implement `pbft_node_send_block_to_peer()` using HTTP client and JSON serialization
  - Create `pbft_node_send_verification_vote_to_peer()` using JSON messages
  - Implement `pbft_node_send_commit_vote_to_peer()` with signature validation
  - Create `pbft_node_send_new_round_vote_to_peer()` for view changes
  - Implement `pbft_node_broadcast_block()` to iterate through peers and send to each
  - Implement `pbft_node_broadcast_verification_vote()` with vote counting integration
  - Implement `pbft_node_broadcast_commit_vote()` with consensus decision logic
  - Write unit tests for message broadcasting functions
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.8, 2.9_
  - _Status: Functions declared in pbftNode.h but not implemented_

- [ ] 6. Implement blockchain synchronization functions
  - Implement `pbft_node_get_blockchain_length_from_peer()` using HTTP requests to `/GetBlockChainLength`
  - Create `pbft_node_get_last_block_hash_from_peer()` using `/BlockChainLastHash` endpoint
  - Implement `pbft_node_request_missing_blocks_from_peer()` using `/MissingBlockRequeset` endpoint
  - Create `pbft_node_request_entire_blockchain_from_peer()` using `/RequestEntireBlockchain` endpoint
  - Update `pbft_node_sync_with_longest_chain()` with proper peer communication
  - Add conflict resolution using longest valid chain rule
  - Write unit tests for blockchain sync functions
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.8, 4.9, 4.10, 4.11_
  - _Status: Functions declared in pbftNode.h but not implemented_

- [ ] 7. Implement PBFT node peer management integration
  - Implement `pbft_node_load_peers_from_blockchain()` to extract peer info from blockchain transactions
  - Update `pbft_node_add_peer()` to use base `node_add_peer()` with NodeState integration
  - Update `pbft_node_remove_peer()` to use base `node_remove_peer()` function
  - Update `pbft_node_mark_peer_delinquent()` to use base `node_mark_peer_delinquent()` function
  - Implement `pbft_node_is_peer_active()` based on delinquent status using PeerInfo structure
  - Integrate peer lookup functions with PBFT node operations
  - Write unit tests for PBFT peer management integration
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.7_
  - _Status: PBFT functions declared but base node functions need to be implemented first_

- [ ] 8. Implement transaction rebroadcasting system
  - Implement `pbft_node_rebroadcast_transaction()` using existing HTTP infrastructure
  - Create `pbft_node_get_pending_transactions_from_peer()` for transaction sync
  - Add `pbft_node_rebroadcast_message()` for general message propagation
  - Implement loop prevention for transaction rebroadcasting
  - Add configurable rebroadcast policies for different message types
  - Write unit tests for transaction rebroadcasting
  - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6_
  - _Status: Functions declared in pbftNode.h but not implemented_

- [ ] 9. Enhance PBFT endpoint handlers with vote counting
  - Update `handle_propose_block()` in pbftApi.c to trigger verification vote broadcasting
  - Modify `handle_verification_vote()` to count votes and trigger commit phase when threshold reached
  - Update `handle_commit_vote()` to count votes and commit blocks when threshold reached
  - Add consensus state tracking across all endpoints using MessageQueues
  - Implement automatic progression through PBFT phases based on vote thresholds
  - Add proper error handling for invalid votes and Byzantine behavior detection
  - Write integration tests for full consensus flow
  - _Requirements: 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 8.6_
  - _Status: Basic endpoint handlers exist but only return "ok", need full implementation_

- [ ] 10. Implement blockchain sync endpoint handlers
  - Update `handle_missing_block_request()` in pbftApi.c to provide actual missing blocks
  - Implement `handle_send_new_blockchain()` for new node synchronization (currently returns 501)
  - Implement `handle_request_entire_blockchain()` for full blockchain sync (currently returns 501)
  - Add proper authentication and signature validation for all sync endpoints
  - Implement chunking for large blockchain transfers
  - Add rate limiting to prevent DoS attacks on sync endpoints
  - Write integration tests for blockchain synchronization
  - _Requirements: 4.1, 4.2, 4.3, 4.6, 5.6, 8.4_
  - _Status: Basic endpoint handlers exist but return 501 "not implemented"_

- [ ] 11. Enhance proposer selection and round management
  - Update existing `pbft_node_calculate_proposer_id()` to handle delinquent peers properly
  - Enhance existing `pbft_node_is_proposer()` with round-based logic
  - Add round timeout handling in main consensus loop
  - Implement proposer offset increment for failed rounds (already partially implemented)
  - Add view change protocol for unresponsive proposers
  - Create `/MissingProposer` endpoint handler for proposer failure detection
  - Write unit tests for proposer selection logic
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7_
  - _Status: Basic proposer selection functions exist but need enhancement for delinquent peer handling_

- [x] 12. Remove unnecessary base64 encoding requirement
  - Analysis shows existing binary protocol already handles block transmission correctly
  - Current implementation uses `TW_InternalTransaction_serialize()` for binary data
  - HTTP client sends binary data with `Content-Type: application/octet-stream`
  - No base64 encoding needed - binary data is transmitted directly over HTTP
  - _Requirements: 4.5, 4.10, 4.11_
  - _Status: Task completed - no base64 encoding needed in current architecture_

- [ ] 13. Add comprehensive error handling and recovery
  - Implement exponential backoff for failed HTTP requests
  - Add delinquent peer recovery logic with automatic reintegration
  - Create network partition detection and recovery mechanisms
  - Implement Byzantine behavior detection and peer exclusion
  - Add consensus timeout handling with automatic round progression
  - Create blockchain desync detection and automatic resync
  - Write unit tests for all error handling scenarios
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7, 8.6_

- [ ] 14. Implement monitoring and diagnostics
  - Add consensus round timing metrics collection
  - Create peer connectivity status tracking
  - Implement vote counting and threshold monitoring
  - Add network partition detection logging
  - Create performance metrics for consensus latency
  - Implement security event logging for Byzantine behavior
  - Add real-time status endpoints for consensus state
  - Write tests for monitoring functionality
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7_

- [ ] 15. Write comprehensive unit tests
  - Create unit tests for all peer management functions
  - Write unit tests for vote counting and threshold calculations
  - Add unit tests for HTTP client functionality and error handling
  - Create unit tests for JSON serialization functions
  - Write unit tests for blockchain synchronization logic
  - Add unit tests for proposer selection and round management
  - Create unit tests for error handling and recovery mechanisms
  - _Requirements: All requirements - validation through testing_

- [ ] 16. Write integration tests for multi-node scenarios
  - Create 4-node network consensus integration tests
  - Write Byzantine fault tolerance tests with 1 faulty node
  - Add network partition and recovery integration tests
  - Create node restart and rejoin integration tests
  - Write proposer failure and view change integration tests
  - Add blockchain desync and recovery integration tests
  - Create performance tests for consensus latency and throughput
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7_

- [ ] 17. Optimize performance and finalize implementation
  - Optimize memory usage in vote tracking and consensus state
  - Implement connection pooling for frequent peer communication
  - Add message batching where possible for efficiency
  - Optimize JSON parsing performance
  - Implement garbage collection for old consensus state
  - Add compression for large blockchain sync operations
  - Conduct final security review and penetration testing
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 8.1, 8.2, 8.3, 8.4_