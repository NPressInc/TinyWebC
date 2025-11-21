// Quick test script to verify encryption/decryption works
import sodium from 'libsodium-wrappers';
import { encryptPayloadMulti, decryptPayload } from './src/utils/encryption.js';

async function testEncryption() {
  await sodium.ready;
  console.log('Testing encryption/decryption...');

  // Generate test keys
  const aliceKeypair = sodium.crypto_box_keypair();
  const bobKeypair = sodium.crypto_box_keypair();

  console.log('Alice pubkey:', sodium.to_hex(aliceKeypair.publicKey).slice(0, 16) + '...');
  console.log('Bob pubkey:', sodium.to_hex(bobKeypair.publicKey).slice(0, 16) + '...');

  // Test message
  const message = new TextEncoder().encode('Hello from Alice!');
  console.log('Original message:', new TextDecoder().decode(message));

  // Encrypt for Bob
  const recipients = [bobKeypair.publicKey];
  const encrypted = await encryptPayloadMulti(message, recipients);
  console.log('Encrypted successfully');

  // Decrypt with Bob's keys
  const decrypted = await decryptPayload(encrypted, recipients, bobKeypair.privateKey, bobKeypair.publicKey);
  const decryptedText = new TextDecoder().decode(decrypted);
  console.log('Decrypted message:', decryptedText);

  // Verify
  if (decryptedText === 'Hello from Alice!') {
    console.log('✅ Test PASSED!');
  } else {
    console.log('❌ Test FAILED!');
  }
}

testEncryption().catch(console.error);
