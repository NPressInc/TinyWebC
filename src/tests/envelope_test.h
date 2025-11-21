#ifndef ENVELOPE_TEST_H
#define ENVELOPE_TEST_H

// Test envelope lifecycle: create, sign, verify
int test_envelope_create_sign_verify(void);

// Test multi-recipient encryption
int test_envelope_multi_recipient_encryption(void);

// Test protobuf serialization round-trip
int test_envelope_serialization(void);

// Test gossip storage operations
int test_envelope_gossip_storage(void);

// Main entry point for all envelope tests
int envelope_test_main(void);

#endif // ENVELOPE_TEST_H
