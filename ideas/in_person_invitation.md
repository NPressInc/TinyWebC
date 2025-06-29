# In-Person Invitation Security for TinyWeb

## Overview
Physical proximity-based invitation system to ensure network security through mandatory in-person meetings for all invitations.

## Core Concept
- **Security Principle**: Only allow network joins through physical presence verification
- **Target**: Family-focused, parent-controlled blockchain network
- **Current Code Length**: 32 characters (31 alphanumeric + null terminator)
- **Character Set**: A-Z, 0-9 (36 possible characters per position)

## Technical Approaches

### 1. NFC/Bluetooth Low Energy (BLE) Handshake
**Mechanism**: Direct device-to-device communication
- **Range**: NFC (contact), BLE (~2 meters)
- **Security**: Physical proximity required, remote attacks nearly impossible
- **UX**: Parent taps phone to child's device
- **Implementation**: Apps exchange cryptographic challenges over local radio

### 2. Ultrasonic Audio Exchange
**Mechanism**: High-frequency audio communication
- **Process**: Device A plays inaudible tones, Device B records/validates
- **Security**: Audio requires physical proximity, can't be transmitted over internet
- **UX**: "Hold phones close together for 10 seconds"
- **Advantage**: Works on any device with speakers/microphone

### 3. Enhanced QR Code + Camera Validation
**Mechanism**: Visual exchange with anti-spoofing
- **Process**: QR contains time-limited challenge + requires live camera
- **Anti-spoofing**: Camera detects real vs. screen display
- **Validation**: Both devices must simultaneously use cameras

### 4. Synchronized Challenge-Response
**Components**:
- Timestamp synchronization (30-second window)
- GPS/WiFi location fingerprinting
- Hardware device signatures
- **Validation**: Network confirms simultaneous signature creation at same location

### 5. Physical Token Exchange
**Mechanism**: Short-lived PIN system
- **Process**: Inviter generates 6-digit PIN (60-second expiry)
- **Security**: PIN displayed on screen, manually entered by invitee
- **Advantage**: No network transmission, visual confirmation required

### 6. Multi-Modal Verification (Recommended)
**Layered Approach**:
1. Bluetooth proximity detection
2. Audio challenge-response
3. Camera-based QR exchange
4. Time-synchronized signatures

**Benefits**:
- Multiple independent proximity proofs
- Attack resistance (must spoof multiple channels)
- Graceful degradation if sensors unavailable

## Recommended Implementation Tiers

### Tier 1: Quick & Easy (Parent → Child)
```
NFC Tap → Ultrasonic handshake → Invitation created
```

### Tier 2: Secure (Parent → Teen/Adult)
```
QR Code exchange → GPS validation → Time-synchronized signatures
```

### Tier 3: Maximum Security (Node Invitations)
```
All of above + Physical meeting confirmation + 24-hour delay
```

## Client App Flow Example

1. Parent opens TinyWeb app: "Invite Family Member"
2. App: "Bring your devices close together"
3. Both devices: [Proximity detection + Audio exchange]
4. App: "Hold steady for 10 seconds..." [Multi-modal validation]
5. Success: "Invitation created! [CODE] expires in 1 hour"
6. Network: Validates all proximity proofs before accepting invitation

## Environmental Context Validation

**Additional Security Layer**:
- Ambient light sensors
- Noise fingerprinting
- WiFi network detection
- Magnetic field readings
- **Validation**: Environmental signatures must match between devices

## Security Benefits

- **Physics-based security**: Leverages fundamental limitations of physical proximity
- **Multi-channel validation**: Attackers must compromise multiple independent systems
- **Family-friendly**: Aligns with parent-controlled, supervised network philosophy
- **Scalable**: Different security tiers for different relationship types

## Implementation Notes

- Current invitation system already supports 32-character codes
- Proximity validation would be client-app feature
- Network validation occurs before invitation acceptance
- Maintains TinyWeb's "locked-down, isolated" design philosophy

## Future Enhancements

- Hardware security modules for device signatures
- Blockchain-based proximity proof storage
- Community validation for extended family invitations
- Integration with existing permission and supervision systems 