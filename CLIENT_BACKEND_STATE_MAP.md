# Client/Backend State Mapping

## Current Backend State (What the UI Must Match)

### Messaging Endpoints

#### POST /messages/submit
- **Request**: 
  - Method: `POST`
  - Content-Type: `application/x-protobuf`
  - Body: Raw binary `Message` protobuf (not JSON, not hex-encoded)
- **Response**:
  - Status: `202 Accepted` (success) or `400/403/500` (error)
  - Content-Type: `application/json`
  - Body: `{"status":"accepted"}` or `{"error":"..."}`
- **Handler**: `messages_api_handler()` in `src/packages/comm/messagesApi.c`
- **Validation**: 
  - Signature verification (Ed25519)
  - Timestamp within 60 seconds
  - Payload size limits
  - Permission checks
  - Duplicate detection

#### GET /messages/recent
- **Request**:
  - Method: `GET`
  - Query Params: `user` (hex pubkey), `limit` (optional, default 50)
- **Response**:
  - Status: `200 OK`
  - Content-Type: `application/x-protobuf`
  - Body: Binary `MessageList` protobuf
- **Handler**: `handle_get_recent()` in `src/packages/comm/userMessagesApi.c`
- **Returns**: `MessageList` with array of `Message` objects

#### GET /messages/conversation
- **Request**:
  - Method: `GET`
  - Query Params: `user` (hex pubkey), `with` (hex pubkey), `limit` (optional, default 100)
- **Response**:
  - Status: `200 OK`
  - Content-Type: `application/x-protobuf`
  - Body: Binary `MessageList` protobuf
- **Handler**: `handle_get_conversation()` in `src/packages/comm/userMessagesApi.c`
- **Returns**: `MessageList` with messages between two users (both directions)

#### GET /messages/conversations
- **Request**:
  - Method: `GET`
  - Query Params: `user` (hex pubkey), `limit` (optional, default 100)
- **Response**:
  - Status: `200 OK`
  - Content-Type: `application/x-protobuf`
  - Body: Binary `ConversationList` protobuf
- **Handler**: `handle_get_conversations()` in `src/packages/comm/userMessagesApi.c`
- **Returns**: `ConversationList` with array of `ConversationSummary` objects

#### GET /users
- **Request**:
  - Method: `GET`
- **Response**:
  - Status: `200 OK`
  - Content-Type: `application/json`
  - Body: `{"users": [{"pubkey": "...", "username": "...", "age": ...}, ...]}`
- **Handler**: `handle_get_users()` in `src/packages/comm/userMessagesApi.c`
- **Note**: Still returns JSON (unchanged)

---

### Protobuf Structures

#### Message (from message.proto)
```protobuf
message MessageHeader {
  uint32 version = 1;
  uint64 timestamp = 2;              // UNIX epoch seconds
  bytes sender_pubkey = 3;             // 32 bytes Ed25519
  repeated bytes recipients_pubkey = 4; // 32 bytes each
  bytes group_id = 5;                  // Optional: 16 bytes (empty if direct message)
}

message MessageRecipientKeyWrap {
  bytes recipient_pubkey = 1;         // 32 bytes Ed25519
  bytes key_nonce = 2;                 // 24 bytes
  bytes wrapped_key = 3;               // Encrypted symmetric key + MAC
}

message Message {
  MessageHeader header = 1;
  bytes payload_nonce = 2;             // 24 bytes
  bytes ephemeral_pubkey = 3;          // 32 bytes Ed25519
  bytes payload_ciphertext = 4;        // Encrypted payload + MAC
  repeated MessageRecipientKeyWrap keywraps = 5;
  bytes signature = 6;                 // 64 bytes Ed25519
}

message MessageList {
  repeated Message messages = 1;
  uint32 total_count = 2;
}
```

#### ConversationList (from api.proto - unchanged)
```protobuf
message ConversationSummary {
  bytes partner_pubkey = 1;            // 32 bytes
  uint64 last_message_timestamp = 2;   // UNIX epoch seconds
  uint32 unread_count = 3;
  bytes last_message_preview = 4;
}

message ConversationList {
  repeated ConversationSummary conversations = 1;
  uint32 total_count = 2;
}
```

---

### Signing & Validation

#### Message Digest Computation
- **Domain**: `"TWMESSAGE\0"` (10 bytes: 84, 87, 77, 69, 83, 83, 65, 71, 69, 0)
- **Hash Input** (in order):
  1. Domain separator (10 bytes)
  2. version (uint32, 4 bytes, little-endian)
  3. timestamp (uint64, 8 bytes, little-endian, UNIX epoch seconds)
  4. sender_pubkey (32 bytes)
  5. recipients_count (uint32, 4 bytes, little-endian)
  6. recipients_pubkey[] (each 32 bytes)
  7. group_id_len (uint32, 4 bytes, little-endian)
  8. group_id (if len > 0, otherwise skip)
  9. payload_hash (32 bytes SHA256 of payload_ciphertext)
- **Output**: SHA256 digest (32 bytes)
- **Location**: `src/packages/validation/message_validation.c` function `compute_message_signing_digest()`

#### Signature
- **Algorithm**: Ed25519
- **Input**: SHA256 digest (32 bytes)
- **Output**: Signature (64 bytes)
- **Verification**: Uses `verify_signature()` from `src/packages/signing/signing.c`

#### Validation Rules
- Signature must be valid Ed25519 signature
- Timestamp must be within 60 seconds of current time (replay protection)
- Payload size must be within configured limits
- Sender must have permission to message recipients

---

### Encryption

#### Multi-Recipient Encryption
- **Algorithm**: X25519 (Curve25519) for key exchange, ChaCha20-Poly1305 for payload
- **Process**:
  1. Generate ephemeral keypair (Ed25519, converted to X25519)
  2. Generate random symmetric key
  3. Encrypt payload with symmetric key (ChaCha20-Poly1305)
  4. For each recipient:
     - Convert recipient Ed25519 pubkey to X25519
     - Perform X25519 key exchange with ephemeral key
     - Encrypt symmetric key for recipient
     - Store in `keywraps[]` array
- **Structure**:
  - `payload_nonce`: 24 bytes random nonce
  - `ephemeral_pubkey`: 32 bytes Ed25519 public key
  - `payload_ciphertext`: Encrypted payload + 16-byte MAC
  - `keywraps[]`: Array of `MessageRecipientKeyWrap` (one per recipient)

#### Decryption
- **Process**:
  1. Find matching keywrap for recipient (by comparing pubkeys)
  2. Perform X25519 key exchange with ephemeral_pubkey
  3. Decrypt wrapped_key to get symmetric key
  4. Decrypt payload_ciphertext using symmetric key and payload_nonce
  5. Verify MAC

---

### Current Client State (What Needs Changing)

#### API Client (`api.js`)
- **sendEnvelope()**: 
  - Sends to `/messages/send` (wrong endpoint)
  - Sends JSON `{envelope_hex: "..."}` (wrong format)
  - Expects JSON response (wrong)
- **getMessages()**: 
  - Expects JSON with `envelope_list_hex` field (wrong)
  - Calls `decodeEnvelopeList()` (wrong type)
- **getRecentMessages()**: 
  - Expects JSON with `envelope_list_hex` field (wrong)
  - Calls `decodeEnvelopeList()` (wrong type)
- **getConversations()**: 
  - Expects JSON (should work, but verify binary response)

#### Message Creation (`envelope.js`)
- **createDirectMessage()**: 
  - Creates `Envelope` structure (wrong)
  - Uses `"TWENVELOPE\0"` domain (wrong)
  - Returns envelope object (wrong type)
- **createGroupMessage()**: 
  - Creates `Envelope` structure (wrong)
  - Uses `"TWENVELOPE\0"` domain (wrong)
  - Returns envelope object (wrong type)

#### Protobuf Decoding (`protobufDecode.js`)
- **decodeEnvelopeList()**: 
  - Decodes `EnvelopeList` protobuf (wrong type)
  - Used for message responses (should use `MessageList`)
- **decodeConversationList()**: 
  - Decodes `ConversationList` (correct, no changes needed)

#### Components
- **ConversationView.js**: 
  - Uses `decodeEnvelopeList()` (wrong)
  - Uses `createDirectMessage()` from envelope.js (wrong)
  - Uses `sendEnvelope()` (wrong endpoint/format)
  - Expects envelope structure (wrong)
- **ConversationsList.js**: 
  - Uses `decodeEnvelopeList()` (wrong)
  - Expects envelope structure (wrong)

---

## Migration Checklist

### Critical Changes
1. ✅ Backend uses `Message` protobuf (not `Envelope`)
2. ✅ Backend returns binary protobuf (not JSON+hex)
3. ✅ Backend endpoint is `/messages/submit` (not `/messages/send`)
4. ✅ Backend uses `"TWMESSAGE\0"` domain (not `"TWENVELOPE\0"`)
5. ✅ Backend returns `MessageList` (not `EnvelopeList`)

### Files to Update
- `client/web-ui/src/utils/api.js` - API client functions
- `client/web-ui/src/utils/envelope.js` - Message creation (or create new `message.js`)
- `client/web-ui/src/utils/protobufDecode.js` - Add MessageList decoding
- `client/web-ui/src/utils/protobufHelper.js` - Add Message protobuf support
- `client/web-ui/src/components/ConversationView.js` - Update to use Message
- `client/web-ui/src/components/ConversationsList.js` - Update to use Message
- `client/web-ui/src/proto/message.proto` - Add message.proto file

### Files to Keep (System Messages)
- `client/web-ui/src/utils/envelope.js` - Keep for LocationUpdate, EmergencyAlert
- `client/web-ui/src/proto/envelope.proto` - Keep for system messages

---

## Testing Strategy

### Unit Tests (Frontend)
1. Test `createSignedMessage()` creates valid Message
2. Test `computeMessageDigest()` matches backend exactly
3. Test `serializeMessageToProtobuf()` produces valid binary
4. Test `deserializeMessageFromProtobuf()` decodes correctly
5. Test `sendMessage()` sends correct format
6. Test `getMessages()` decodes binary response

### Integration Tests (Full Stack)
1. Send message from UI → Backend stores it
2. Retrieve message from UI → Backend returns it → UI decrypts it
3. Test conversation list shows messages
4. Test group messages with multiple recipients
5. Test error handling (invalid signature, expired timestamp, etc.)

---

## Backward Compatibility Notes

- **System Messages**: Still use `Envelope` structure (LocationUpdate, EmergencyAlert)
- **Users Endpoint**: Still returns JSON (unchanged)
- **Health/Peers Endpoints**: Still return JSON (unchanged)
- **Envelope Dispatcher**: Still handles system message envelopes

The migration only affects **user-to-user messaging**. System messages continue to use the Envelope structure.

