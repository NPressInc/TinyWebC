#!/usr/bin/env python3

import json
import requests
import time
import nacl.signing
import nacl.encoding

def read_private_key_from_file(filepath):
    """Read private key from binary file and derive public key"""
    try:
        with open(filepath, 'rb') as f:
            # Read first 32 bytes (private key)
            private_key_bytes = f.read(32)
            if len(private_key_bytes) != 32:
                raise ValueError(f"Expected 32 bytes for private key, got {len(private_key_bytes)}")
            
            # Create signing key from private key
            signing_key = nacl.signing.SigningKey(private_key_bytes)
            
            # Get public key
            public_key_bytes = signing_key.verify_key.encode()
            
            # Convert to hex string
            private_key_hex = private_key_bytes.hex()
            public_key_hex = public_key_bytes.hex()
            
            return private_key_hex, public_key_hex
    except Exception as e:
        print(f"Error reading key file {filepath}: {e}")
        return None, None

# Read user_0 keys from file
private_key_hex, public_key_hex = read_private_key_from_file('state/keys/user_0_key.bin')
if not private_key_hex or not public_key_hex:
    print("❌ Failed to read user_0 keys")
    exit(1)

print(f"🔑 Loaded user_0 keys:")
print(f"   Private key: {private_key_hex[:16]}...")
print(f"   Public key:  {public_key_hex}")

# Your transaction payload - using dynamically loaded keys
transaction_data = {
    "type": 15,
    "sender": public_key_hex,
    "timestamp": int(time.time()),  # Use current timestamp
    "recipients": [
        public_key_hex,  # user_0 (admin) - only include the user making the access request
    ],
    "groupId": "00000000000000000000000000000000",
    "payload": "0000000000000003000000000000004be9098a775cc394be4ad17911f01dc45301e92f2c27b169a017f2c02a29cbd83f27381bb1db56bd15000ba2933845f74286a2b59636598ff44588bd08d87e4c09e5d39bf0fa0c18f39bcf6e25246d6c7094096222fed91010ad93038224b815f80d228a6a82e939bf4dab655a1634a50a1720fbbee3e573438f89a35396b0faeff39629f814327311e0f4c297fb95bedd64175c3ee93a671479fca2e37636efb2c864826bc395b7d4f0f411d076e16654f5af3e901f04149b891fd65fc20772f9e4cd7862cc096095d95166ae905fd7d22fd26793e801674b2fdb0505bf6a513828a03c9a4801c1ef393fecfc5f63c6ae0628688d50f028a383a3277d331c31ab15140b61cff27d53a53f61864262cc25342e59b43e1f8689de76e4cd425049739073dc9f36e59c8087e528160632acc197f1aa9dfde0ab5a598cdd98ebed2e1034d8666834b1cab54da6eba74dd486e24192f7b7a10357b3bb1e6c",
    "signature": "9d681b072d264c93fe85fd956812e23375b527d63d5178fc9142823593fcb73b9977670a4caab6923484178891b2c26751cca84170794c4f19770f8adaf6d404"  # This signature won't match, but let's test the user verification first
}

def test_transaction():
    print("🧪 Testing transaction submission...")
    print(f"Transaction type: {transaction_data['type']} (Access Request)")
    print(f"Sender: {transaction_data['sender'][:16]}...")
    print(f"Recipients: {len(transaction_data['recipients'])}")
    print(f"Timestamp: {transaction_data['timestamp']}")
    
    try:
        # Test the transaction submission
        response = requests.post(
            'http://localhost:8000/Transaction',
            json=transaction_data,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        
        print(f"\n📡 Response Status: {response.status_code}")
        print(f"📄 Response Headers: {dict(response.headers)}")
        
        try:
            response_data = response.json()
            print(f"📋 Response Body: {json.dumps(response_data, indent=2)}")
        except:
            print(f"📋 Response Body (raw): {response.text}")
            
        if response.status_code == 200:
            print("✅ Transaction accepted!")
        else:
            print(f"❌ Transaction rejected: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Connection failed - is the TinyWeb backend running on port 8000?")
    except requests.exceptions.Timeout:
        print("❌ Request timed out")
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    print("=== TinyWeb Transaction Test ===")
    test_transaction() 