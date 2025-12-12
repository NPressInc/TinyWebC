# Key Distribution Architecture for TinyWeb

## Overview

This document outlines the secure key distribution model for TinyWeb's family-focused communication network. The core principle: **private keys never leave user devices** - nodes only store public keys for verification.

## Security Principles

1. **Private keys stay on devices** - Generated, stored, and used only on user devices (phones, parent dashboards)
2. **Nodes only store public keys** - For signature verification, not signing
3. **Parent-controlled provisioning** - Parents generate and distribute keys for children
4. **Secure backup/recovery** - Parents can recover child keys if device is lost
5. **End-to-end encryption** - Messages encrypted by clients, nodes cannot decrypt

---

## Phase 1: Initial Setup (Parent Creates Child Account)

### Flow

```
1. Parent Device (Dashboard/App)
   ├─> Generates keypair for child locally
   ├─> Stores child's private key encrypted with parent's master key
   ├─> Sends UserRegistration message to node (with child's PUBLIC key only)
   └─> Creates encrypted backup of child's private key
```

### Implementation Notes

- Parent dashboard generates Ed25519 keypair for child
- Private key encrypted with parent's master key (derived from parent's credentials)
- Only public key sent to network via `UserRegistration` message
- Encrypted backup stored on parent's device for recovery

---

## Phase 2: Phone Provisioning (QR Code Method)

### Overview

QR code transfer is the recommended method for provisioning custom phones. It provides a secure, user-friendly way to transfer keys without exposing them to the network.

### Flow

```
1. Parent Dashboard
   ├─> Generates encrypted key package:
   │   ├─> Child's private key (encrypted with one-time password)
   │   ├─> Network config (node URLs, network ID)
   │   ├─> Parent's public key (for supervision)
   │   └─> Metadata (display name, role, age)
   └─> Displays QR code

2. Custom Phone (First Boot)
   ├─> Scans QR code
   ├─> Prompts for one-time password (shown on parent dashboard)
   ├─> Decrypts and stores private key in secure hardware (if available)
   └─> Registers with network using UserRegistration message
```

### QR Code Contents

The QR code contains a JSON payload (base64 encoded):

```json
{
  "version": 1,
  "type": "key_provisioning",
  "encrypted_key": "<base64 encrypted private key>",
  "network_config": {
    "network_id": "family_network_001",
    "node_urls": [
      "http://node_01:8000",
      "http://node_02:8000"
    ],
    "discovery_mode": "static"
  },
  "user_info": {
    "display_name": "Emma Smith",
    "role": 1,
    "age": 12,
    "parent_pubkey": "<parent's public key hex>"
  },
  "encryption_method": "aes256_gcm",
  "timestamp": 1234567890,
  "expires_at": 1234567890
}
```

### Security Properties

- **One-time password**: Generated on parent dashboard, shown separately (not in QR)
- **Time-limited**: QR code expires after 5-10 minutes
- **Single-use**: Once scanned, QR code is invalidated
- **Encrypted payload**: Private key encrypted with OTP + device-specific salt

### Alternative: USB/Physical Transfer

For environments where QR codes aren't feasible:

```
1. Parent Dashboard
   ├─> Exports encrypted key file to USB
   └─> Includes one-time password separately (printed or shown)

2. Custom Phone
   ├─> Reads encrypted key from USB during setup
   ├─> Prompts for password
   └─> Stores key securely
```

---

## Phase 3: Key Storage on Devices

### Custom Phone Storage Hierarchy

**Priority order (most secure first):**

1. **Hardware Security Module (HSM)** - if available
   - Private key in secure enclave
   - Never leaves hardware
   - Best security

2. **Android Keystore** - fallback
   - Private key encrypted with device credentials
   - Backed by hardware-backed keystore if available
   - Good security for most devices

3. **Encrypted file storage** - last resort
   - Private key encrypted with user PIN + device ID
   - Stored in app's secure directory
   - Acceptable for older devices

### Parent Dashboard Storage

```
Parent's Master Key:
├─> Encrypts all children's private keys
├─> Stored in parent's secure keystore
└─> Used for:
    ├─> Key recovery (if child loses phone)
    ├─> Account migration (new phone)
    └─> Emergency access (with proper controls)
```

### Storage Format

```javascript
// Encrypted key storage structure
{
  "version": 1,
  "key_id": "child_001",
  "encrypted_private_key": "<base64 encrypted>",
  "public_key": "<hex public key>",
  "encryption_method": "aes256_gcm",
  "salt": "<random salt>",
  "created_at": "2024-01-01T00:00:00Z",
  "backed_up_at": "2024-01-01T00:00:00Z"
}
```

---

## Phase 4: Network Registration Flow

### Complete Flow

```
1. Device generates keypair (or receives from parent)
   └─> Private key NEVER leaves device

2. Device creates UserRegistration message:
   {
     user_pubkey: <32 bytes public key>,
     display_name: "Emma Smith",
     role: CHILD,
     parent_pubkey: <parent's public key>,
     age: 12
   }

3. Device signs UserRegistration with its private key
   └─> Node verifies signature using public key

4. Node stores:
   ├─> Public key (for verification)
   ├─> Display name
   ├─> Role and permissions
   └─> Parent relationship
   
5. Node does NOT store private key
```

### UserRegistration Message Structure

```protobuf
message UserRegistration {
  bytes user_pubkey = 1;           // 32 bytes Ed25519 public key
  string display_name = 2;
  uint32 role = 3;               // 0=parent, 1=child, 2=community
  bytes parent_pubkey = 4;        // Optional: child's parent
  uint64 age = 5;                 // Optional: for age-based controls
}
```

### Node Database Schema

```sql
-- Nodes store this in database (PUBLIC KEYS ONLY)
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  pubkey TEXT UNIQUE,             -- Public key only!
  display_name TEXT,
  role INTEGER,
  parent_pubkey TEXT,              -- For parent-child relationships
  age INTEGER,
  registered_at TIMESTAMP,
  is_active BOOLEAN DEFAULT 1
);

-- Index for fast lookups
CREATE INDEX idx_users_pubkey ON users(pubkey);
CREATE INDEX idx_users_parent ON users(parent_pubkey);
```

---

## Phase 5: Key Backup & Recovery

### Parent-Controlled Backup

**Backup Process:**
```
1. Parent authenticates (biometric/PIN)
2. Parent dashboard encrypts child's private key with parent's master key
3. Stores encrypted backup locally (parent's device)
4. Optionally: Encrypted cloud backup (parent controls)
```

**Recovery Process:**
```
1. Parent authenticates (biometric/PIN)
2. Parent dashboard decrypts child's key
3. Generate new QR code for child's new phone
4. Child scans QR code to restore account
5. Old device's key is invalidated (if device recovered)
```

### Backup Storage Format

```json
{
  "version": 1,
  "backup_id": "backup_001",
  "child_pubkey": "<hex>",
  "encrypted_private_key": "<base64>",
  "encrypted_with": "parent_master_key",
  "created_at": "2024-01-01T00:00:00Z",
  "parent_pubkey": "<parent's pubkey>"
}
```

### Recovery Scenarios

1. **Lost Phone**: Parent generates new QR code, child scans on new device
2. **Broken Phone**: Same as lost phone, old key invalidated
3. **Upgrade Phone**: Parent generates migration QR code
4. **Emergency Access**: Parent can decrypt child's messages (with proper controls)

---

## Implementation Details

### 1. Key Generation (Client-Side Only)

```javascript
// In phone app or parent dashboard
async function generateChildKeypair() {
  await sodium.ready;
  const keypair = sodium.crypto_sign_keypair();
  
  // Store private key securely on device
  await secureStorage.save('child_private_key', keypair.privateKey);
  
  // Send ONLY public key to network
  return keypair.publicKey;
}
```

### 2. QR Code Generation (Parent Dashboard)

```javascript
async function generateProvisioningQR(childKeypair, networkConfig, userInfo) {
  // Generate one-time password
  const otp = generateOTP(); // 6-8 digit code
  
  // Encrypt private key with OTP + salt
  const salt = sodium.randombytes_buf(16);
  const encryptionKey = await deriveKey(otp, salt);
  const encryptedKey = await encrypt(childKeypair.privateKey, encryptionKey);
  
  // Create provisioning package
  const package = {
    version: 1,
    type: "key_provisioning",
    encrypted_key: base64Encode(encryptedKey),
    salt: base64Encode(salt),
    network_config: networkConfig,
    user_info: userInfo,
    encryption_method: "aes256_gcm",
    timestamp: Date.now(),
    expires_at: Date.now() + (10 * 60 * 1000) // 10 minutes
  };
  
  // Generate QR code
  const qrData = base64Encode(JSON.stringify(package));
  return { qrCode: qrData, otp: otp };
}
```

### 3. QR Code Scanning (Phone App)

```javascript
async function scanProvisioningQR(qrData, otp) {
  // Decode QR data
  const package = JSON.parse(base64Decode(qrData));
  
  // Verify expiration
  if (Date.now() > package.expires_at) {
    throw new Error("QR code expired");
  }
  
  // Decrypt private key
  const salt = base64Decode(package.salt);
  const encryptionKey = await deriveKey(otp, salt);
  const privateKey = await decrypt(
    base64Decode(package.encrypted_key),
    encryptionKey
  );
  
  // Store securely on device
  await secureStorage.save('private_key', privateKey);
  
  // Extract public key
  const publicKey = sodium.crypto_sign_ed25519_sk_to_pk(privateKey);
  
  // Register with network
  await registerWithNetwork(publicKey, package.user_info, package.network_config);
}
```

### 4. UserRegistration Message (Device)

```javascript
// Device sends this (signed with its private key)
const registration = {
  user_pubkey: childPublicKey,  // 32 bytes
  display_name: "Emma Smith",
  role: 1,  // CHILD
  parent_pubkey: parentPublicKey,  // For supervision
  age: 12
};

// Sign with child's private key
const envelope = await createSignedEnvelope(header, registration);
// Send to node - node only sees public key
```

### 5. Node Handler (Backend)

```c
// Node receives UserRegistration, verifies signature, stores public key
int handle_user_registration(const Envelope* envelope) {
    // Extract UserRegistration from envelope
    UserRegistration* reg = unpack_user_registration(envelope);
    
    // Verify signature using public key from message
    if (!verify_envelope_signature(envelope, reg->user_pubkey)) {
        return -1; // Invalid signature
    }
    
    // Store PUBLIC KEY ONLY in database
    store_user_public_key(reg->user_pubkey, reg->display_name, 
                          reg->role, reg->parent_pubkey, reg->age);
    
    // DO NOT store private key
    return 0;
}
```

---

## Migration Path from Current System

### Phase 1: Phase Out Node-Stored Keys

1. **Remove key storage from nodes:**
   - Delete `state/keys/users/` directories from nodes
   - Keep only for migration/legacy support (temporary)

2. **Update init tool:**
   - Stop generating user keys on nodes
   - Only generate node keys

### Phase 2: Add Client-Side Key Generation

1. **Phone app:**
   - Add key generation on first boot
   - Add QR code scanning for provisioning
   - Add secure key storage

2. **Parent dashboard:**
   - Add child key generation
   - Add QR code generation
   - Add key backup/recovery

### Phase 3: Update UserRegistration Handler

1. **Backend changes:**
   - Accept public keys only
   - Verify signature from client
   - Store public key in database
   - Remove any private key handling

### Phase 4: Add Provisioning System

1. **QR code generation:**
   - Implement in parent dashboard
   - Add OTP generation
   - Add expiration handling

2. **QR code scanning:**
   - Implement in phone app
   - Add OTP input
   - Add secure decryption

3. **Secure key transfer protocol:**
   - Define message format
   - Implement encryption/decryption
   - Add validation

---

## Security Considerations

### Threat Model

1. **Compromised Node:**
   - ✅ Safe: Only has public keys, cannot impersonate users
   - ✅ Safe: Cannot decrypt messages (end-to-end encrypted)

2. **Lost/Stolen Phone:**
   - ✅ Mitigated: Private key encrypted with device credentials
   - ✅ Mitigated: Parent can revoke and re-provision

3. **Malicious Parent:**
   - ⚠️ Risk: Parent has backup of child's key
   - ✅ Mitigated: This is by design (parental control)
   - ✅ Mitigated: Audit logs for parent actions

4. **Network Interception:**
   - ✅ Safe: QR code encrypted with OTP
   - ✅ Safe: OTP shown separately
   - ✅ Safe: QR code expires quickly

### Best Practices

1. **Key Rotation:**
   - Support key rotation for compromised devices
   - Invalidate old keys when new key registered

2. **Audit Logging:**
   - Log all key generation events
   - Log all provisioning events
   - Log all recovery events

3. **Rate Limiting:**
   - Limit QR code generation (prevent abuse)
   - Limit registration attempts
   - Limit recovery attempts

4. **Multi-Factor Authentication:**
   - Require parent authentication for key operations
   - Use biometrics where available
   - Support hardware tokens

---

## Future Enhancements

1. **Hardware Security Modules:**
   - Support for hardware-backed keystores
   - TPM integration for parent devices
   - Secure element support for phones

2. **Key Escrow:**
   - Optional encrypted key escrow service
   - Multi-party key recovery
   - Time-locked key release

3. **Advanced Provisioning:**
   - NFC-based key transfer
   - Bluetooth secure pairing
   - Encrypted email/SMS provisioning

4. **Key Rotation:**
   - Automatic key rotation
   - Forward secrecy
   - Key versioning

---

## References

- Ed25519 Signature Scheme: https://ed25519.cr.yp.to/
- Android Keystore: https://developer.android.com/training/articles/keystore
- QR Code Standards: ISO/IEC 18004
- Secure Key Derivation: PBKDF2, Argon2, or scrypt

---

**Document Version:** 1.0  
**Last Updated:** 2024-12-12  
**Status:** Design Document - For Future Implementation

