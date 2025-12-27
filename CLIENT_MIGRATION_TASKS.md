# Client/Web-UI Migration Tasks

## Overview
The backend has migrated from the "Envelope" paradigm to a separate "Message" structure for user-to-user messaging. The client/web-ui needs to be updated to work with the new Message protobuf structure and binary API responses.

## Current State Analysis

### Backend Changes (What the UI Must Adapt To)
- **New Protobuf**: `message.proto` defines `Message`, `MessageHeader`, `MessageList` (separate from `envelope.proto`)
- **New Endpoint**: `POST /messages/submit` (replaces `/messages/send`)
- **Response Format**: Binary protobuf (`Content-Type: application/x-protobuf`) instead of JSON+hex
- **Response Types**: `MessageList` (not `EnvelopeList`) for `/messages/recent` and `/messages/conversation`
- **Response Types**: `ConversationList` (unchanged) for `/messages/conversations`
- **Signing Domain**: Uses `"TWMESSAGE\0"` domain separator (not `"TWENVELOPE\0"`)

### Current UI State (What Needs Changing)
- Uses `Envelope` structure for all messages
- Sends JSON with hex-encoded envelopes to `/messages/send`
- Expects JSON responses with `envelope_list_hex` field
- Uses `EnvelopeList` protobuf for decoding responses
- Computes digest with `"TWENVELOPE\0"` domain

---

## Task List

### Phase 1: Create Message Protobuf Support

#### 1.1 Add message.proto to Client
- [ ] **Location**: `client/web-ui/src/proto/message.proto`
- [ ] Copy `message.proto` from `src/proto/message.proto` to client
- [ ] Verify it matches backend exactly (Message, MessageHeader, MessageRecipientKeyWrap, MessageList)

#### 1.2 Create Message Protobuf Helper
- [ ] **Location**: Create `client/web-ui/src/utils/messageHelper.js`
- [ ] Create `loadMessageProtobufSchema()` function:
  - Loads `message.proto` schema using protobufjs
  - Returns `MessageType`, `MessageHeaderType`, `MessageRecipientKeyWrapType`, `MessageListType`
  - Caches schema (lazy loading)
- [ ] Create `serializeMessageToProtobuf()` function:
  - Takes JavaScript Message object
  - Serializes to binary protobuf using MessageType
  - Returns `Uint8Array`
- [ ] Create `deserializeMessageFromProtobuf()` function:
  - Takes binary protobuf (`Uint8Array` or hex string)
  - Deserializes using MessageType
  - Returns JavaScript Message object
- [ ] Create `serializeMessageListToProtobuf()` function:
  - Takes array of Message objects
  - Creates MessageList protobuf
  - Serializes to binary
- [ ] Create `deserializeMessageListFromProtobuf()` function:
  - Takes binary MessageList protobuf
  - Deserializes and returns array of Message objects

#### 1.3 Create Message Structure Builder
- [ ] **Location**: Create `client/web-ui/src/utils/message.js`
- [ ] Create `MessageHeader` class (similar to `EnvelopeHeader`):
  - `version`, `timestamp`, `senderPubkey`, `recipientsPubkey[]`, `group_id`
- [ ] Create `createSignedMessage()` function:
  - Takes `MessageHeader` and plaintext
  - Encrypts payload for recipients (using existing `encryptPayloadMulti`)
  - Computes digest with `"TWMESSAGE\0"` domain (not `"TWENVELOPE\0"`)
  - Signs digest using Ed25519
  - Returns JavaScript Message object
- [ ] Create `computeMessageDigest()` function:
  - Matches backend `message_validation.c` logic exactly
  - Uses domain: `"TWMESSAGE\0"` (10 bytes with null terminator)
  - Hashes: domain || version || timestamp || sender || recipients_count || recipients || group_id_len || group_id || payload_hash
  - Returns SHA256 digest (32 bytes)
- [ ] Create `verifyMessageSignature()` function:
  - Takes Message object
  - Computes digest using `computeMessageDigest()`
  - Verifies Ed25519 signature
  - Returns boolean
- [ ] Create `createDirectMessage()` function:
  - Takes recipient pubkey and message text
  - Creates MessageHeader with single recipient
  - Calls `createSignedMessage()`
  - Returns signed Message object
- [ ] Create `createGroupMessage()` function:
  - Takes array of recipient pubkeys, message text, optional group_id
  - Creates MessageHeader with multiple recipients
  - Calls `createSignedMessage()`
  - Returns signed Message object

---

### Phase 2: Update API Client

#### 2.1 Update sendEnvelope() to sendMessage()
- [ ] **Location**: `client/web-ui/src/utils/api.js`
- [ ] Rename `sendEnvelope()` to `sendMessage()` (or create new function, keep old for compatibility)
- [ ] Change endpoint from `/messages/send` to `/messages/submit`
- [ ] Change request format:
  - Remove JSON wrapper `{ envelope_hex: ... }`
  - Send raw binary protobuf in request body
  - Set `Content-Type: application/x-protobuf`
  - Use `response.arrayBuffer()` instead of `response.json()`
- [ ] Update to accept Message object (not envelope hex string)
- [ ] Serialize Message to binary using `messageHelper.js`
- [ ] Handle response:
  - Backend returns JSON: `{"status":"accepted"}` or `{"error":"..."}`
  - Parse JSON response for status/error
- [ ] Update error handling for new response format

#### 2.2 Update getMessages() for Binary Response
- [ ] **Location**: `client/web-ui/src/utils/api.js`
- [ ] Change response handling:
  - Remove `response.json()` call
  - Use `response.arrayBuffer()` to get binary data
  - Check `Content-Type: application/x-protobuf` header
  - Deserialize binary `MessageList` using `messageHelper.js`
- [ ] Return array of Message objects (not envelope objects)
- [ ] Update error handling for binary responses

#### 2.3 Update getRecentMessages() for Binary Response
- [ ] **Location**: `client/web-ui/src/utils/api.js`
- [ ] Change response handling:
  - Remove `response.json()` call
  - Use `response.arrayBuffer()` to get binary data
  - Deserialize binary `MessageList` using `messageHelper.js`
- [ ] Return array of Message objects
- [ ] Update error handling

#### 2.4 Update getConversations() for Binary Response
- [ ] **Location**: `client/web-ui/src/utils/api.js`
- [ ] Change response handling:
  - Remove `response.json()` call
  - Use `response.arrayBuffer()` to get binary data
  - Deserialize binary `ConversationList` using `protobufDecode.js` (already supports this)
- [ ] Verify `ConversationList` structure matches backend
- [ ] Update error handling

#### 2.5 Keep getUsers() Unchanged
- [ ] **Location**: `client/web-ui/src/utils/api.js`
- [ ] Verify `/users` endpoint still returns JSON (should be unchanged)
- [ ] No changes needed if it returns JSON

---

### Phase 3: Update Protobuf Decoding

#### 3.1 Update protobufDecode.js for MessageList
- [ ] **Location**: `client/web-ui/src/utils/protobufDecode.js`
- [ ] Add `decodeMessageList()` function:
  - Takes binary MessageList protobuf (Uint8Array or hex string)
  - Deserializes using MessageListType from `messageHelper.js`
  - Returns array of Message objects
- [ ] Keep `decodeEnvelopeList()` for backward compatibility (if needed for system messages)
- [ ] Keep `decodeConversationList()` unchanged (still valid)

#### 3.2 Update protobufHelper.js
- [ ] **Location**: `client/web-ui/src/utils/protobufHelper.js`
- [ ] Remove `CONTENT_DIRECT_MESSAGE` and `CONTENT_GROUP_MESSAGE` from enum (already done in cleanup)
- [ ] Verify envelope schema is only for system messages now
- [ ] No other changes needed (envelope helper still used for system messages)

---

### Phase 4: Update Components

#### 4.1 Update ConversationView.js
- [ ] **Location**: `client/web-ui/src/components/ConversationView.js`
- [ ] Replace `decodeEnvelopeList()` with `decodeMessageList()`
- [ ] Update message decryption:
  - Messages now have `payload_ciphertext` directly (not wrapped in envelope)
  - Use `decryptPayload()` with `message.encryptedPayload` structure
  - Message structure: `message.payload_ciphertext`, `message.payload_nonce`, `message.ephemeral_pubkey`, `message.keywraps[]`
- [ ] Update message sending:
  - Replace `createDirectMessage()` from `envelope.js` with `createDirectMessage()` from `message.js`
  - Replace `serializeEnvelopeToProtobufHex()` with `serializeMessageToProtobuf()` from `messageHelper.js`
  - Replace `sendEnvelope()` with `sendMessage()` from `api.js`
- [ ] Update message structure access:
  - Change `envelope.header.senderPubkey` to `message.header.senderPubkey`
  - Change `envelope.encryptedPayload` to `message.encryptedPayload` (structure may differ)
  - Verify keywraps structure matches
- [ ] Update timestamp handling:
  - Backend uses UNIX epoch seconds (not milliseconds)
  - Convert appropriately when displaying
- [ ] Test message display, sending, and decryption

#### 4.2 Update ConversationsList.js
- [ ] **Location**: `client/web-ui/src/components/ConversationsList.js`
- [ ] Replace `decodeEnvelopeList()` with `decodeMessageList()`
- [ ] Update message decryption (same changes as ConversationView)
- [ ] Update message structure access (same changes as ConversationView)
- [ ] Test conversation list display and message preview

#### 4.3 Update Other Components (if they use messaging)
- [ ] **Location**: Check `CryptoDemo.js`, `KeyManagement.js`, etc.
- [ ] Search for `envelope`, `Envelope`, `sendEnvelope`, `decodeEnvelopeList`
- [ ] Update any messaging-related code to use Message structure
- [ ] Verify system message handling (LocationUpdate, EmergencyAlert) still uses Envelope

---

### Phase 5: Update Encryption/Decryption

#### 5.1 Verify Encryption Compatibility
- [ ] **Location**: `client/web-ui/src/utils/encryption.js`
- [ ] Verify `encryptPayloadMulti()` works with Message structure:
  - Message uses same encryption scheme as Envelope
  - `payload_nonce`, `ephemeral_pubkey`, `payload_ciphertext` fields match
  - `keywraps` array structure matches `MessageRecipientKeyWrap`
- [ ] Verify `decryptPayload()` works with Message structure:
  - Can extract keywraps from `message.keywraps[]`
  - Can decrypt using `message.payload_ciphertext`, `message.payload_nonce`, `message.ephemeral_pubkey`
- [ ] No changes needed if encryption/decryption logic is compatible

#### 5.2 Update Decryption Calls
- [ ] **Location**: All components using `decryptPayload()`
- [ ] Verify calls pass correct Message structure:
  - `message.encryptedPayload` should have: `ciphertext`, `nonce`, `ephemeralPubkey`, `encryptedKeys[]`, `keyNonces[]`
  - Or adapt to use `message.payload_ciphertext`, `message.payload_nonce`, `message.ephemeral_pubkey`, `message.keywraps[]` directly
- [ ] Test decryption with real messages from backend

---

### Phase 6: Testing & Validation

#### 6.1 Test Message Creation
- [ ] Test `createDirectMessage()` creates valid Message
- [ ] Test `createGroupMessage()` creates valid Message with multiple recipients
- [ ] Verify signature computation matches backend
- [ ] Verify digest uses `"TWMESSAGE\0"` domain

#### 6.2 Test Message Sending
- [ ] Test `sendMessage()` sends binary protobuf correctly
- [ ] Test endpoint `/messages/submit` accepts message
- [ ] Test error handling (invalid message, permission denied, etc.)
- [ ] Verify message appears in database after sending

#### 6.3 Test Message Retrieval
- [ ] Test `getMessages()` retrieves and decodes MessageList
- [ ] Test `getRecentMessages()` retrieves and decodes MessageList
- [ ] Test `getConversations()` retrieves and decodes ConversationList
- [ ] Verify messages can be decrypted after retrieval

#### 6.4 Test End-to-End Flow
- [ ] Send message from User A to User B
- [ ] Retrieve message as User B
- [ ] Verify message decrypts correctly
- [ ] Verify message appears in conversation list
- [ ] Test group messages with multiple recipients

#### 6.5 Test Backward Compatibility
- [ ] Verify system messages (LocationUpdate, EmergencyAlert) still work with Envelope
- [ ] Verify `/users` endpoint still returns JSON
- [ ] Verify health/peers endpoints still work

---

### Phase 7: Cleanup & Documentation

#### 7.1 Remove Deprecated Code (Optional)
- [ ] **Location**: `client/web-ui/src/utils/envelope.js`
- [ ] Consider deprecating `createDirectMessage()` and `createGroupMessage()` from envelope.js
- [ ] Add comments indicating envelope.js is for system messages only
- [ ] Keep envelope.js for system message support (LocationUpdate, etc.)

#### 7.2 Update API Documentation
- [ ] Document new `/messages/submit` endpoint
- [ ] Document binary protobuf response format
- [ ] Document Message structure vs Envelope structure
- [ ] Update any README or API docs

#### 7.3 Update Comments
- [ ] Add comments explaining Message vs Envelope distinction
- [ ] Document digest domain change (`TWMESSAGE` vs `TWENVELOPE`)
- [ ] Update function documentation

---

## Critical Differences Summary

| Aspect | Old (Envelope) | New (Message) |
|--------|---------------|---------------|
| **Protobuf File** | `envelope.proto` | `message.proto` |
| **Structure** | `Envelope` with `EnvelopeHeader` | `Message` with `MessageHeader` |
| **Send Endpoint** | `POST /messages/send` (JSON+hex) | `POST /messages/submit` (binary) |
| **Request Format** | `{"envelope_hex": "..."}` | Raw binary protobuf |
| **Response Format** | JSON with `envelope_list_hex` | Binary `MessageList` protobuf |
| **Response Type** | `EnvelopeList` | `MessageList` |
| **Digest Domain** | `"TWENVELOPE\0"` | `"TWMESSAGE\0"` |
| **Content Types** | `CONTENT_DIRECT_MESSAGE=10` | N/A (removed from envelope.proto) |
| **Payload Field** | `payload_ciphertext` (same) | `payload_ciphertext` (same) |
| **Keywraps** | `RecipientKeyWrap[]` | `MessageRecipientKeyWrap[]` (same structure) |

---

## Implementation Order

1. **Phase 1** - Create Message protobuf support (foundation)
2. **Phase 2** - Update API client (core functionality)
3. **Phase 3** - Update protobuf decoding (data handling)
4. **Phase 4** - Update components (UI integration)
5. **Phase 5** - Verify encryption (security)
6. **Phase 6** - Testing (validation)
7. **Phase 7** - Cleanup (polish)

---

## Notes

- **Keep Envelope Support**: The `Envelope` structure is still used for system messages (LocationUpdate, EmergencyAlert). Don't remove envelope.js entirely.
- **Binary Responses**: All messaging endpoints now return binary protobuf. Use `response.arrayBuffer()` instead of `response.json()`.
- **Hex Encoding**: Remove hex encoding/decoding for message transmission. Use binary directly.
- **Digest Domain**: Critical - must use `"TWMESSAGE\0"` (10 bytes) for message signing, not `"TWENVELOPE\0"`.
- **Timestamp**: Backend uses UNIX epoch seconds. Frontend may use milliseconds - convert appropriately.

